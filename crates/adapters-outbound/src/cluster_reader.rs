//! [`KubeClusterReader`]: the [`ClusterReader`] and [`PolicySource`] ports
//! over the Kubernetes API — the `StalwartNamespacePolicy` objects and the
//! claims of the other CRs the reconcilers and the admission webhook
//! decide on — on the operator's watch scope: an object outside its label
//! selector, or a namespaced one outside the namespace it is limited to,
//! doesn't exist for it.
//!
//! The policies, the claiming kinds, the domains and the instances (whose
//! servers a claim compares) are read from the binary's live
//! reflector stores when it wires them in ([`KubeClusterReader::with_stores`]),
//! from the API otherwise: a claim check reads every CR of four kinds, on
//! every creation — from the API, a burst of N creations is N² objects
//! listed and deserialized.

use api::common::{InstanceKind, SecretStoreBackend};
use api::namespace_policy::NamespaceRule;
use api::status::Status;
use api::{
    Account, Domain, Group, Instance, LocalInstance, MailingList, NamespacePolicy, ServiceAccount,
};
use application::ports::{
    BoundInstance, ClaimKind, ClusterError, ClusterReader, DomainState, InstanceSettings,
    PolicySource, VaultSettings,
};
use std::sync::Arc;

use kube::api::ListParams;
use kube::core::{Selector, SelectorExt};
use kube::runtime::reflector::Store;
use kube::{Api, Client, Resource, ResourceExt};
use serde::de::DeserializeOwned;
use weebo_kit_adapters::instance::STORE_READY_TIMEOUT;
use weebo_kit_adapters::wait_synced;

/// The binary's live stores, each on the operator's watch scope (its
/// namespace and label selector, as the API reads).
#[derive(Clone, Default)]
pub struct ClaimStores {
    pub policies: Option<Store<NamespacePolicy>>,
    pub service_accounts: Option<Store<ServiceAccount>>,
    pub accounts: Option<Store<Account>>,
    pub groups: Option<Store<Group>>,
    pub mailing_lists: Option<Store<MailingList>>,
    pub instances: Option<Store<Instance>>,
    pub local_instances: Option<Store<LocalInstance>>,
    pub domains: Option<Store<Domain>>,
}

pub struct KubeClusterReader {
    client: Client,
    /// The namespace the operator is limited to, `None`: the whole cluster.
    watched_namespace: Option<String>,
    selector: Option<Selector>,
    cluster_kinds: bool,
    stores: ClaimStores,
}

/// Picks a kind's store out of [`ClaimStores`].
trait Stored:
    Resource<DynamicType = ()> + Clone + std::fmt::Debug + DeserializeOwned + 'static
{
    fn store(stores: &ClaimStores) -> Option<&Store<Self>>;
}

macro_rules! stored {
    ($($kind:ty => $field:ident),+ $(,)?) => {$(
        impl Stored for $kind {
            fn store(stores: &ClaimStores) -> Option<&Store<Self>> {
                stores.$field.as_ref()
            }
        }
    )+};
}
stored!(
    NamespacePolicy => policies,
    ServiceAccount => service_accounts,
    Account => accounts,
    Group => groups,
    MailingList => mailing_lists,
    Instance => instances,
    LocalInstance => local_instances,
    Domain => domains,
);

impl KubeClusterReader {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            watched_namespace: None,
            selector: None,
            cluster_kinds: true,
            stores: ClaimStores::default(),
        }
    }

    /// Reads the policies and the claiming kinds from these stores (once
    /// they listed) instead of the API.
    pub fn with_stores(mut self, stores: ClaimStores) -> Self {
        self.stores = stores;
        self
    }

    /// Every `K` of `api` on the scope: from its store once listed, else
    /// listed from the API.
    async fn read<K: Stored>(&self, api: Api<K>) -> Result<Vec<Arc<K>>, ClusterError> {
        // `wait_synced`, not `Store::wait_until_ready`: kube's readiness
        // wakes only the last waiter, every other concurrent read would sit
        // out the whole timeout. It warns before the API fallback.
        if let Some(store) = K::store(&self.stores)
            && wait_synced(store, STORE_READY_TIMEOUT).await
        {
            return Ok(store
                .state()
                .into_iter()
                .filter(|o| self.selects(o.as_ref()))
                .collect());
        }
        let list = api
            .list(&self.params())
            .await
            .map_err(|e| ClusterError(format!("listing {}: {e}", K::kind(&()))))?;
        Ok(list
            .items
            .into_iter()
            .filter(|o| self.selects(o))
            .map(Arc::new)
            .collect())
    }

    /// The operator's watch scope (`WatchScope`): the namespace it is
    /// limited to, its label selector, and whether it watches
    /// cluster-scoped kinds at all.
    pub fn with_scope(
        mut self,
        watched_namespace: Option<String>,
        selector: Option<Selector>,
        cluster_kinds: bool,
    ) -> Self {
        self.watched_namespace = watched_namespace;
        self.selector = selector;
        self.cluster_kinds = cluster_kinds;
        self
    }

    fn selects<K: Resource>(&self, obj: &K) -> bool {
        let Some(selector) = &self.selector else {
            return true;
        };
        let empty = Default::default();
        selector.matches(obj.meta().labels.as_ref().unwrap_or(&empty))
    }

    /// A namespaced kind, on the watch scope.
    fn namespaced<K>(&self) -> Api<K>
    where
        K: Resource<Scope = kube::core::NamespaceResourceScope, DynamicType = ()>,
    {
        match &self.watched_namespace {
            Some(ns) => Api::namespaced(self.client.clone(), ns),
            None => Api::all(self.client.clone()),
        }
    }

    /// Every `K` visible to the operator, as `(Kind/namespace/name,
    /// status, aliases)`.
    async fn owners<K>(
        &self,
        aliases: fn(&K) -> &[String],
    ) -> Result<Vec<(String, Option<Status>, Vec<String>)>, ClusterError>
    where
        K: Resource<Scope = kube::core::NamespaceResourceScope> + Stored + HasStatus,
    {
        Ok(self
            .read(self.namespaced::<K>())
            .await?
            .into_iter()
            .map(|cr| {
                let id = format!(
                    "{}/{}/{}",
                    K::kind(&()),
                    cr.namespace().unwrap_or_default(),
                    cr.name_any()
                );
                (id, cr.status_of().cloned(), aliases(&cr).to_vec())
            })
            .collect())
    }

    fn params(&self) -> ListParams {
        match &self.selector {
            Some(selector) => ListParams::default().labels_from(selector),
            None => ListParams::default(),
        }
    }

    /// The server each visible instance points at (on the scope, as the
    /// instance resolution sees them): its URL, lowercased, without a
    /// trailing `/`.
    async fn servers(&self) -> Result<Vec<(BoundInstance, String)>, ClusterError> {
        let server = |url: &str| url.trim_end_matches('/').to_ascii_lowercase();
        let mut servers = Vec::new();
        if self.cluster_kinds {
            let instances = self.read(Api::<Instance>::all(self.client.clone())).await?;
            servers.extend(instances.iter().map(|i| {
                let name = i.meta().name.clone().unwrap_or_default();
                (BoundInstance::cluster(name), server(&i.spec.url))
            }));
        }
        let locals = self.read(self.namespaced::<LocalInstance>()).await?;
        servers.extend(locals.iter().map(|i| {
            let meta = i.meta();
            let bound = BoundInstance::local(
                meta.namespace.clone().unwrap_or_default(),
                meta.name.clone().unwrap_or_default(),
            );
            (bound, server(&i.spec.url))
        }));
        Ok(servers)
    }
}

#[async_trait::async_trait]
impl PolicySource<NamespaceRule> for KubeClusterReader {
    async fn policies(&self) -> Result<Vec<Vec<NamespaceRule>>, ClusterError> {
        if !self.cluster_kinds {
            return Ok(Vec::new());
        }
        Ok(self
            .read(Api::<NamespacePolicy>::all(self.client.clone()))
            .await?
            .into_iter()
            .map(|p| p.spec.rules.clone())
            .collect())
    }
}

#[async_trait::async_trait]
impl ClusterReader for KubeClusterReader {
    async fn claimants(
        &self,
        kind: ClaimKind,
        name: &str,
        instance: &BoundInstance,
    ) -> Result<Vec<String>, ClusterError> {
        let found = self
            .claimants_of_any(kind, &[name.to_string()], instance)
            .await?;
        Ok(found.into_iter().map(|(_, claimant)| claimant).collect())
    }

    /// One read of the instances and of the claiming kinds for all of
    /// `names`: an object's address and its aliases cost the same as one.
    async fn claimants_of_any(
        &self,
        kind: ClaimKind,
        names: &[String],
        instance: &BoundInstance,
    ) -> Result<Vec<(String, String)>, ClusterError> {
        let mut claimed = Vec::new();
        if names.is_empty() {
            return Ok(claimed);
        }
        let servers = self.servers().await?;
        let server_of = |bound: Option<&BoundInstance>| {
            let bound = bound?;
            servers
                .iter()
                .find(|(b, _)| b == bound)
                .map(|(_, url)| url.clone())
        };
        let Some(target) = server_of(Some(instance)) else {
            return Ok(claimed);
        };
        // Owning a remote object on the same server.
        let on_target = |s: &Status| {
            s.remote_id.is_some() && server_of(s.instance.as_ref()).as_ref() == Some(&target)
        };
        match kind {
            ClaimKind::Address => {
                let mut owners = self.owners::<ServiceAccount>(|cr| &cr.spec.aliases).await?;
                owners.extend(self.owners::<Account>(|cr| &cr.spec.aliases).await?);
                owners.extend(self.owners::<Group>(|cr| &cr.spec.aliases).await?);
                owners.extend(self.owners::<MailingList>(|cr| &cr.spec.aliases).await?);
                // An address is owned by the CR it was confirmed for, and so
                // are its aliases' (in the same domain).
                let owned: Vec<(String, Vec<String>)> = owners
                    .into_iter()
                    .filter_map(|(id, status, aliases)| {
                        let s = status.filter(|s| on_target(s))?;
                        let address = s.address?;
                        let domain = address
                            .rsplit_once('@')
                            .map(|(_, d)| d.to_string())
                            .unwrap_or_default();
                        let mut all: Vec<String> = aliases
                            .iter()
                            .map(|a| domain::mail::address(a, &domain))
                            .collect();
                        all.push(address);
                        Some((id, all))
                    })
                    .collect();
                for name in names {
                    for (id, addresses) in &owned {
                        if addresses.iter().any(|a| a.eq_ignore_ascii_case(name)) {
                            claimed.push((name.clone(), id.clone()));
                        }
                    }
                }
            }
            ClaimKind::Domain => {
                if !self.cluster_kinds {
                    return Ok(claimed);
                }
                let domains = self.read(Api::<Domain>::all(self.client.clone())).await?;
                for name in names {
                    for d in &domains {
                        let owns = d.status.as_ref().is_some_and(|s| {
                            on_target(s)
                                && s.address
                                    .as_deref()
                                    .is_some_and(|a| a.eq_ignore_ascii_case(name))
                        });
                        if owns {
                            claimed.push((
                                name.clone(),
                                format!(
                                    "StalwartDomain/{}",
                                    d.metadata.name.clone().unwrap_or_default()
                                ),
                            ));
                        }
                    }
                }
            }
        }
        Ok(claimed)
    }

    async fn domain(&self, name: &str) -> Result<Option<DomainState>, ClusterError> {
        if !self.cluster_kinds {
            return Ok(None);
        }
        let domain = Api::<Domain>::all(self.client.clone())
            .get_opt(name)
            .await
            .map_err(|e| ClusterError(format!("reading StalwartDomain {name}: {e}")))?
            .filter(|d| self.selects(d));
        Ok(domain.map(|d| {
            let status = d.status.unwrap_or_default();
            let ready = weebo_kit_api::status::ready(&status.conditions)
                .is_some_and(|c| c.status == "True");
            DomainState {
                remote_id: status.remote_id,
                name: status.address,
                instance: status.instance,
                ready,
            }
        }))
    }

    async fn account_address(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<String>, ClusterError> {
        if self
            .watched_namespace
            .as_deref()
            .is_some_and(|w| w != namespace)
        {
            return Ok(None);
        }
        let account = Api::<Account>::namespaced(self.client.clone(), namespace)
            .get_opt(name)
            .await
            .map_err(|e| ClusterError(format!("reading StalwartAccount {namespace}/{name}: {e}")))?
            .filter(|a| self.selects(a));
        Ok(account
            .and_then(|a| a.status)
            .filter(|s| s.remote_id.is_some())
            .and_then(|s| s.address))
    }

    async fn instance_settings(
        &self,
        instance: &BoundInstance,
    ) -> Result<Option<InstanceSettings>, ClusterError> {
        let failed = |e: kube::Error| ClusterError(format!("reading {instance}: {e}"));
        Ok(match (instance.kind, instance.namespace.as_deref()) {
            (InstanceKind::LocalInstance, Some(ns)) => {
                Api::<LocalInstance>::namespaced(self.client.clone(), ns)
                    .get_opt(&instance.name)
                    .await
                    .map_err(failed)?
                    .map(|l| InstanceSettings {
                        submission: l.spec.submission,
                        default_backend: SecretStoreBackend::Kubernetes,
                        vault: None,
                    })
            }
            _ => Api::<Instance>::all(self.client.clone())
                .get_opt(&instance.name)
                .await
                .map_err(failed)?
                .map(|i| InstanceSettings {
                    submission: i.spec.submission,
                    default_backend: i.spec.secret_store.backend,
                    vault: i.spec.secret_store.vault.map(|v| VaultSettings {
                        path_prefix: v.path_prefix,
                        path_grants: v.path_grants,
                    }),
                }),
        })
    }
}

/// The status of every namespaced kind.
trait HasStatus {
    fn status_of(&self) -> Option<&Status>;
}

macro_rules! has_status {
    ($($kind:ty),+) => {$(
        impl HasStatus for $kind {
            fn status_of(&self) -> Option<&Status> {
                self.status.as_ref()
            }
        }
    )+};
}
has_status!(ServiceAccount, Account, Group, MailingList);
