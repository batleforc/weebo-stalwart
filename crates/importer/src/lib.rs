//! `weebo-stalwart-importer`: the only way an existing Stalwart object
//! comes under a CR (D9) — the domain and the accounts the phase-0 plan
//! created, an account or a group the OpenID Connect login created before
//! its CR (`StalwartObjectAlreadyExists`).
//!
//! It reads the CRs to link (YAML, as in Git), finds the object each
//! describes **by name** ([`application::use_cases::import`]), and — with
//! `--apply` — applies the CR paused (`stalwart.weebo.io/import-pending`),
//! seeds its `status.remoteId`/`status.address`/`status.instance` and
//! unpauses it (the kit's
//! `Adopter`): the operator never sees the CR without its id, so it can't
//! create a duplicate, and reads it by id from then on. An object another
//! CR already owns on the same server is refused (`RemoteObjectClaimed`).
//!
//! D21: a `StalwartServiceAccount` is linked with a fresh
//! `stalwart.weebo.io/rotate-secret` nonce: its first reconcile creates an
//! App Password of the operator's and writes it to the CR's targets,
//! replacing the credential another tool wrote there (Terraform's, without
//! a Vault owner). The operator never touches a `Password` credential: the
//! old password stops working once the default directory is OIDC (D24),
//! or when removed by hand. Remove that tool's resource first.

use std::collections::BTreeMap;
use std::fmt::Debug;

use adapters_outbound::{KubeClusterReader, OperatorInstances};
use anyhow::{Context, bail};
use api::common::InstanceRef;
use api::{Account, Domain, Group, MailingList, ServiceAccount, Status};
use application::ports::{
    BoundInstance, ClaimKind, ClusterReader, InstanceDirectory, RemoteGateway,
};
use application::use_cases::import::{Found, IMPORT_ROTATION_PREFIX, Wanted, locate};
use domain::account::AccountType;
use domain::mail;
use kube::api::Api;
use kube::{Client, Resource, ResourceExt};
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use weebo_kit_adapters::{Adopter, Adoption};

pub use weebo_kit_adapters::Summary;

const FIELD_MANAGER: &str = "weebo-stalwart-importer";

/// The kit's adoption flow, as this importer.
const ADOPTER: Adopter = Adopter {
    field_manager: FIELD_MANAGER,
    annotations: api::ANNOTATIONS,
};

/// A CR to link.
#[derive(Debug, Clone)]
pub enum Cr {
    Domain(Box<Domain>),
    ServiceAccount(Box<ServiceAccount>),
    Account(Box<Account>),
    Group(Box<Group>),
    MailingList(Box<MailingList>),
}

/// Runs `$body` with `$cr` bound to the typed CR, whatever its kind.
macro_rules! each {
    ($value:expr, |$cr:ident| $body:expr) => {
        match $value {
            Cr::Domain($cr) => $body,
            Cr::ServiceAccount($cr) => $body,
            Cr::Account($cr) => $body,
            Cr::Group($cr) => $body,
            Cr::MailingList($cr) => $body,
        }
    };
}

/// The CRs of a multi-document YAML stream (empty documents skipped);
/// a namespaced CR without a namespace is put in `namespace`.
pub fn parse(yaml: &str, namespace: &str) -> anyhow::Result<Vec<Cr>> {
    let mut crs = Vec::new();
    for (i, document) in serde_norway::Deserializer::from_str(yaml).enumerate() {
        let value = serde_json::Value::deserialize(document)
            .with_context(|| format!("document {}: not YAML", i + 1))?;
        if value.is_null() {
            continue;
        }
        let api_version = value["apiVersion"].as_str().unwrap_or_default();
        if api_version != format!("{}/v1alpha1", api::GROUP) {
            bail!(
                "document {}: apiVersion {api_version:?} is not {}/v1alpha1",
                i + 1,
                api::GROUP
            );
        }
        let kind = value["kind"].as_str().unwrap_or_default().to_string();
        let mut cr = match kind.as_str() {
            "StalwartDomain" => Cr::Domain(Box::new(serde_json::from_value(value)?)),
            "StalwartServiceAccount" => {
                Cr::ServiceAccount(Box::new(serde_json::from_value(value)?))
            }
            "StalwartAccount" => Cr::Account(Box::new(serde_json::from_value(value)?)),
            "StalwartGroup" => Cr::Group(Box::new(serde_json::from_value(value)?)),
            "StalwartMailingList" => Cr::MailingList(Box::new(serde_json::from_value(value)?)),
            other => bail!("document {}: kind {other:?} has nothing to import", i + 1),
        };
        if !matches!(cr, Cr::Domain(_)) {
            each!(&mut cr, |c| {
                if c.metadata.namespace.is_none() {
                    c.metadata.namespace = Some(namespace.to_string());
                }
            });
        }
        crs.push(cr);
    }
    Ok(crs)
}

impl Cr {
    /// `Kind/name`, `Kind/namespace/name`: how claims name a CR.
    pub fn id(&self) -> String {
        match self {
            Cr::Domain(d) => format!("StalwartDomain/{}", d.name_any()),
            _ => each!(self, |c| format!(
                "{}/{}/{}",
                kind_of(c.as_ref()),
                c.namespace().unwrap_or_default(),
                c.name_any()
            )),
        }
    }

    fn namespace(&self) -> Option<String> {
        each!(self, |c| c.namespace())
    }

    fn instance_ref(&self) -> Option<&InstanceRef> {
        each!(self, |c| c.spec.instance_ref.as_ref())
    }

    fn status(&self) -> Option<&Status> {
        each!(self, |c| c.status.as_ref())
    }

    /// The `StalwartDomain` a namespaced CR lives in.
    fn domain_ref(&self) -> Option<&str> {
        match self {
            Cr::Domain(_) => None,
            Cr::ServiceAccount(c) => Some(&c.spec.domain_ref.name),
            Cr::Account(c) => Some(&c.spec.domain_ref.name),
            Cr::Group(c) => Some(&c.spec.domain_ref.name),
            Cr::MailingList(c) => Some(&c.spec.domain_ref.name),
        }
    }

    /// The name and the aliases a namespaced CR claims.
    fn names(&self) -> (String, Vec<String>) {
        match self {
            Cr::Domain(d) => (d.domain_name(), Vec::new()),
            Cr::ServiceAccount(c) => (c.local_part(), c.spec.aliases.clone()),
            Cr::Account(c) => (c.local_part(), c.spec.aliases.clone()),
            Cr::Group(c) => (c.local_part(), c.spec.aliases.clone()),
            Cr::MailingList(c) => (c.local_part(), c.spec.aliases.clone()),
        }
    }

    /// What the CR describes, its domain (`(id, name)`) resolved.
    fn wanted(&self, domain: Option<&(String, String)>) -> Wanted {
        let (name, _) = self.names();
        let (domain_id, domain) = domain.cloned().unwrap_or_default();
        match self {
            Cr::Domain(_) => Wanted::Domain { name },
            Cr::ServiceAccount(_) | Cr::Account(_) => Wanted::Account {
                kind: AccountType::User,
                domain_id,
                domain,
                name,
            },
            Cr::Group(_) => Wanted::Account {
                kind: AccountType::Group,
                domain_id,
                domain,
                name,
            },
            Cr::MailingList(_) => Wanted::MailingList {
                domain_id,
                domain,
                name,
            },
        }
    }

    /// The claims linking `found` makes: the domain's name, or the address
    /// and the aliases' addresses.
    fn claims(&self, found: &Found) -> (ClaimKind, Vec<String>) {
        match self {
            Cr::Domain(_) => (ClaimKind::Domain, vec![found.address.clone()]),
            _ => {
                let domain = found.address.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
                let (_, aliases) = self.names();
                let mut addresses = vec![found.address.clone()];
                addresses.extend(aliases.iter().map(|a| mail::address(a, domain)));
                (ClaimKind::Address, addresses)
            }
        }
    }

    /// The CR as it is applied: its status seeded with `found`, and for a
    /// `StalwartServiceAccount`, a rotation nonce (D21).
    fn seeded(mut self, found: &Found, nonce: &str) -> Self {
        each!(&mut self, |c| {
            c.status = Some(Status {
                remote_id: Some(found.remote_id.clone()),
                address: Some(found.address.clone()),
                ..Status::default()
            });
        });
        if let Cr::ServiceAccount(sa) = &mut self {
            sa.annotations_mut().insert(
                api::ANNOTATIONS.key(weebo_kit_api::annotations::ROTATE_SECRET),
                nonce.to_string(),
            );
        }
        self
    }
}

fn kind_of<K: Resource<DynamicType = ()>>(_: &K) -> String {
    K::kind(&()).to_string()
}

/// One CR, and the object it links to.
#[derive(Debug, Clone)]
pub struct Planned {
    /// Seeded: what `--apply` writes, or what is printed.
    pub cr: Cr,
    pub found: Found,
}

/// A CR that can't be linked, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub cr: String,
    pub why: String,
}

/// The D21 nonce of this run: `import-<unix seconds>`.
// RFC 0001 Q22: the forced rotation of D21 goes through the kit's own
// mechanism — a fresh `rotate-secret` nonce on the linked CR, consumed by
// its first reconcile (`emit::rotation_requested` against an unseeded
// `lastRotation`) — rather than a special case in the reconcile. The
// importer also seeds `status.instance`, so that a CR it just linked claims
// its object at once (`RemoteObjectClaimed` for a second import).
pub fn rotation_nonce() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    format!("{IMPORT_ROTATION_PREFIX}{seconds}")
}

/// The object of every CR: domains first — the accounts of a domain in
/// the same batch use it —, then the others, whose `StalwartDomain` is
/// either in the batch or linked already (read through `cluster`).
pub async fn plan(
    crs: Vec<Cr>,
    gateway: &dyn RemoteGateway,
    cluster: Option<&dyn ClusterReader>,
    nonce: &str,
) -> (Vec<Planned>, Vec<Refused>) {
    let (domains, others): (Vec<Cr>, Vec<Cr>) =
        crs.into_iter().partition(|c| matches!(c, Cr::Domain(_)));
    let mut linked: BTreeMap<String, (String, String)> = BTreeMap::new();
    let (mut planned, mut refused) = (Vec::new(), Vec::new());
    for cr in domains.into_iter().chain(others) {
        let id = cr.id();
        let domain = match cr.domain_ref() {
            None => None,
            Some(name) => match domain_of(name, &linked, cluster).await {
                Ok(domain) => Some(domain),
                Err(why) => {
                    refused.push(Refused { cr: id, why });
                    continue;
                }
            },
        };
        match locate(gateway, &cr.wanted(domain.as_ref())).await {
            Ok(found) => {
                if let Cr::Domain(d) = &cr {
                    linked.insert(
                        d.name_any(),
                        (found.remote_id.clone(), found.address.clone()),
                    );
                }
                planned.push(Planned {
                    cr: cr.seeded(&found, nonce),
                    found,
                });
            }
            Err(e) => refused.push(Refused {
                cr: id,
                why: e.to_string(),
            }),
        }
    }
    (planned, refused)
}

/// The `StalwartDomain` `name`'s id and domain name: linked in this batch,
/// or recorded in its status.
async fn domain_of(
    name: &str,
    linked: &BTreeMap<String, (String, String)>,
    cluster: Option<&dyn ClusterReader>,
) -> Result<(String, String), String> {
    if let Some(domain) = linked.get(name) {
        return Ok(domain.clone());
    }
    let Some(cluster) = cluster else {
        return Err(format!(
            "StalwartDomain {name:?} is neither in the input nor readable (no cluster): add it to \
             the input"
        ));
    };
    let state = cluster
        .domain(name)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no StalwartDomain {name:?}: import it first"))?;
    state.remote_id.zip(state.name).ok_or_else(|| {
        format!("StalwartDomain {name:?} owns no Stalwart domain yet: import it, or wait for it")
    })
}

/// Every planned CR as one multi-document YAML stream, `status` included
/// (ignored by `kubectl apply`, kept as a record of the linked ids).
pub fn to_yaml(planned: &[Planned]) -> anyhow::Result<String> {
    let mut out = String::new();
    for p in planned {
        out.push_str("---\n");
        out.push_str(&each!(&p.cr, |c| serde_norway::to_string(c.as_ref()))?);
    }
    Ok(out)
}

/// Links every planned CR, in order; a failure is reported (on stderr)
/// and the others carry on. `force` also takes over a CR that exists but
/// owns nothing yet (the operator may be creating its object: by default,
/// refused).
pub async fn apply_all(client: &Client, planned: &[Planned], force: bool) -> Summary {
    let reader = KubeClusterReader::new(client.clone());
    let instances = OperatorInstances::new(client.clone());
    let mut summary = Summary::default();
    for p in planned {
        let result = match claimed(&reader, &instances, p).await {
            Ok(instance) => each!(&p.cr, |c| adopt(
                client,
                c.as_ref(),
                &p.found,
                instance.as_ref(),
                force
            )
            .await),
            Err(e) => Err(e),
        };
        // The claim check fails with a `String`, not an `AdoptError`: a
        // failure is counted here rather than through `Summary::record`.
        match result {
            Ok(adoption) => summary.record(&Ok(adoption)),
            Err(e) => {
                eprintln!("error: {}: {e}", p.cr.id());
                summary.failed = summary.failed.saturating_add(1);
            }
        }
    }
    summary
}

/// The unique claim at import: an object another CR owns on the same
/// server is not linked twice (`RemoteObjectClaimed`). The instance the CR
/// resolves to, seeded with the id: the CR claims its object at once.
async fn claimed(
    reader: &KubeClusterReader,
    instances: &OperatorInstances,
    p: &Planned,
) -> Result<Option<BoundInstance>, String> {
    let recorded = p.cr.status().and_then(|s| s.instance.as_ref());
    // No instance to resolve yet: no server to compare claims on.
    let Ok(instance) = instances
        .resolve(p.cr.namespace().as_deref(), p.cr.instance_ref(), recorded)
        .await
    else {
        return Ok(None);
    };
    let (kind, names) = p.cr.claims(&p.found);
    let me = p.cr.id();
    for name in names {
        let others = reader
            .claimants(kind, &name, &instance)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(other) = others.into_iter().find(|o| *o != me) {
            return Err(format!(
                "RemoteObjectClaimed: {} {name:?} on this server is already owned by {other}",
                kind.as_str()
            ));
        }
    }
    Ok(Some(instance))
}

async fn adopt<K>(
    client: &Client,
    cr: &K,
    found: &Found,
    instance: Option<&BoundInstance>,
    force: bool,
) -> Result<Adoption, String>
where
    K: Resource<DynamicType = ()> + Clone + Debug + Serialize + DeserializeOwned + HasSeed,
{
    let api = K::api(client.clone(), cr.namespace().as_deref());
    ADOPTER
        .adopt(
            &api,
            cr,
            &found.remote_id,
            json!({ "remoteId": found.remote_id, "address": found.address, "instance": instance }),
            |existing: &K| existing.seed().and_then(|s| s.remote_id.clone()),
            force,
        )
        .await
        .map_err(|e| e.to_string())
}

/// The status and the API of every kind the importer links.
trait HasSeed: Sized {
    fn seed(&self) -> Option<&Status>;
    fn api(client: Client, namespace: Option<&str>) -> Api<Self>;
}

impl HasSeed for Domain {
    fn seed(&self) -> Option<&Status> {
        self.status.as_ref()
    }

    fn api(client: Client, _: Option<&str>) -> Api<Self> {
        Api::all(client)
    }
}

macro_rules! has_seed {
    ($($kind:ty),+) => {$(
        impl HasSeed for $kind {
            fn seed(&self) -> Option<&Status> {
                self.status.as_ref()
            }

            fn api(client: Client, namespace: Option<&str>) -> Api<Self> {
                Api::namespaced(client, namespace.unwrap_or("default"))
            }
        }
    )+};
}
has_seed!(ServiceAccount, Account, Group, MailingList);

#[cfg(test)]
mod tests {
    use application::test_support::{FakeCluster, FakeGateway};

    use super::*;

    const INPUT: &str = r#"
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartDomain
metadata: {name: weebo}
spec: {name: weebo.internal}
---
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartServiceAccount
metadata: {name: forgejo}
spec:
  domainRef: {name: weebo}
  aliases: [noreply]
  secretTargets: [{backend: vault, name: smtp}]
---
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartAccount
metadata: {name: alice, namespace: mail}
spec: {domainRef: {name: weebo}}
---
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartGroup
metadata: {name: ghost, namespace: mail}
spec: {domainRef: {name: weebo}}
"#;

    #[test]
    fn crs_are_read_with_their_namespace() {
        let crs = parse(INPUT, "forgejo").unwrap();
        let ids: Vec<String> = crs.iter().map(Cr::id).collect();
        assert_eq!(
            ids,
            [
                "StalwartDomain/weebo",
                "StalwartServiceAccount/forgejo/forgejo",
                "StalwartAccount/mail/alice",
                "StalwartGroup/mail/ghost"
            ]
        );
        assert!(parse("apiVersion: v1\nkind: Secret\n", "x").is_err());
        assert!(
            parse(
                "apiVersion: stalwart.weebo.io/v1alpha1\nkind: StalwartInstance\n",
                "x"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn existing_objects_are_planned_and_service_accounts_rotate() {
        let gateway = FakeGateway::default();
        let domain = gateway.seed_domain("weebo.internal");
        let forgejo = gateway.seed_account(AccountType::User, "forgejo", &domain);
        let alice = gateway.seed_account(AccountType::User, "alice", &domain);
        let crs = parse(INPUT, "forgejo").unwrap();
        let (planned, refused) = plan(crs, &gateway, None, "import-1").await;
        let found: Vec<(String, String)> = planned
            .iter()
            .map(|p| (p.found.remote_id.clone(), p.found.address.clone()))
            .collect();
        assert_eq!(
            found,
            [
                (domain, "weebo.internal".to_string()),
                (forgejo.clone(), "forgejo@weebo.internal".to_string()),
                (alice, "alice@weebo.internal".to_string()),
            ]
        );
        // Nothing named `ghost`: the operator will create it.
        assert_eq!(refused.len(), 1);
        assert!(refused[0].why.contains("nothing to import"), "{refused:?}");
        let Cr::ServiceAccount(sa) = &planned[1].cr else {
            panic!()
        };
        assert_eq!(
            api::ANNOTATIONS.rotate_nonce(&sa.metadata).as_deref(),
            Some("import-1")
        );
        assert_eq!(
            sa.status.as_ref().unwrap().remote_id.as_deref(),
            Some(forgejo.as_str())
        );
        let yaml = to_yaml(&planned).unwrap();
        assert!(yaml.contains("remoteId"), "{yaml}");
        // Planning only reads: the App Password is the first reconcile's.
        assert_eq!(gateway.writes(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn an_account_needs_its_domain_linked() {
        let gateway = FakeGateway::default();
        let domain = gateway.seed_domain("weebo.internal");
        gateway.seed_account(AccountType::User, "alice", &domain);
        let only_alice: Vec<Cr> = parse(INPUT, "x")
            .unwrap()
            .into_iter()
            .skip(2)
            .take(1)
            .collect();
        let (planned, refused) = plan(only_alice.clone(), &gateway, None, "n").await;
        assert!(planned.is_empty());
        assert!(refused[0].why.contains("add it to the input"));
        let cluster = FakeCluster::default();
        let (_, refused) = plan(only_alice.clone(), &gateway, Some(&cluster), "n").await;
        assert!(refused[0].why.contains("import it first"));
        cluster.set_domain_state(
            "weebo",
            application::ports::DomainState {
                remote_id: Some(domain.clone()),
                name: Some("weebo.internal".into()),
                instance: None,
                ready: false,
            },
        );
        let (planned, _) = plan(only_alice, &gateway, Some(&cluster), "n").await;
        assert_eq!(planned[0].found.address, "alice@weebo.internal");
    }
}
