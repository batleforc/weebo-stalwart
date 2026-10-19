//! Integration test of the namespaced kinds' controllers: a real
//! `kube-apiserver` + `etcd` (envtest), the real controllers of
//! `StalwartDomain`, `StalwartServiceAccount`, `StalwartAccount`,
//! `StalwartGroup` and `StalwartMailingList` running against it, the
//! gateway swapped for an in-memory Stalwart (`testkit::FakeGateway`), the
//! secrets for an in-memory store, and the domain, the claims and the
//! instance's settings read from the cluster (`KubeClusterReader`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::KubeClusterReader;
use api::instance::{InstanceSpec, SecretKeyRef};
use api::{Account, Domain, Group, MailingList, ServiceAccount};
use application::ports::SecretStore;
use domain::account::RemotePermissions;
use k8s_openapi::api::core::v1::{Event, Namespace};
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use kube::{Client, Resource};
use serde::Serialize;
use serde::de::DeserializeOwned;
use testkit::{FakeGateway, FakeSecretStore, StaticGatewayFactory, StaticSecretStoreFactory};
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(200);

fn ctx(client: Client, gateway: Arc<FakeGateway>, secrets: Arc<FakeSecretStore>) -> Arc<Ctx> {
    let instances = Arc::new(StaticGatewayFactory::new(gateway));
    let cluster = Arc::new(KubeClusterReader::new(client.clone()));
    let secrets: Arc<dyn SecretStore> = secrets;
    Arc::new(Ctx {
        client: client.clone(),
        gateways: instances.clone(),
        secrets: Arc::new(StaticSecretStoreFactory(secrets)),
        cluster: cluster.clone(),
        policies: cluster,
        instances,
        recorder: Recorder::new(
            client,
            Reporter {
                controller: controller::FIELD_MANAGER.into(),
                instance: None,
            },
        ),
        shutdown: Shutdown::never(),
        health: Arc::new(Health::default()),
        scope: WatchScope::cluster(),
    })
}

/// envtest, the instance `main`, the namespaces, every controller, and the
/// domain `weebo.internal` Ready.
async fn start(
    namespaces: &[&str],
) -> (
    testkit::envtest::EnvTestCluster,
    Client,
    Arc<FakeGateway>,
    Arc<FakeSecretStore>,
) {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let spec = InstanceSpec {
        url: "https://stalwart.example".into(),
        token_secret_ref: SecretKeyRef {
            name: "token".into(),
            namespace: "default".into(),
            key: "token".into(),
        },
        app_password_token_secret_ref: None,
        tls: Default::default(),
        secret_store: Default::default(),
        submission: Default::default(),
    };
    Api::<api::Instance>::all(client.clone())
        .create(&PostParams::default(), &api::Instance::new("main", spec))
        .await
        .unwrap();
    for ns in namespaces {
        let namespace: Namespace =
            serde_json::from_value(serde_json::json!({"metadata": {"name": ns}})).unwrap();
        Api::<Namespace>::all(client.clone())
            .create(&PostParams::default(), &namespace)
            .await
            .unwrap();
    }
    let gateway = Arc::new(FakeGateway::default());
    let secrets = Arc::new(FakeSecretStore::default());
    let ctx = ctx(client.clone(), gateway.clone(), secrets.clone());
    tokio::spawn(controller::stalwart_domain::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::stalwart_service_account::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::stalwart_account::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::stalwart_group::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::stalwart_mailing_list::run(client.clone(), ctx));

    let domains: Api<Domain> = Api::all(client.clone());
    let domain: Domain = serde_json::from_value(serde_json::json!({
        "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartDomain",
        "metadata": {"name": "weebo.internal"}, "spec": {"instanceRef": {"name": "main"}},
    }))
    .unwrap();
    domains
        .create(&PostParams::default(), &domain)
        .await
        .unwrap();
    testkit::polling::wait_for(&domains, "weebo.internal", TIMEOUT, POLL, |d| {
        ready(d.status.as_ref()).filter(|(s, _)| s == "True")
    })
    .await;
    (cluster, client, gateway, secrets)
}

/// A namespaced CR of kind `K` from its spec, on the instance `main` and
/// the domain `weebo.internal`.
fn cr<K: DeserializeOwned + Resource<DynamicType = ()>>(
    namespace: &str,
    name: &str,
    spec: serde_json::Value,
) -> K {
    let mut spec = spec;
    spec["instanceRef"] = serde_json::json!({"name": "main"});
    if spec.get("domainRef").is_none() {
        spec["domainRef"] = serde_json::json!({"name": "weebo.internal"});
    }
    serde_json::from_value(serde_json::json!({
        "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": K::kind(&()),
        "metadata": {"name": name, "namespace": namespace}, "spec": spec,
    }))
    .unwrap()
}

fn ready(status: Option<&api::Status>) -> Option<(String, String)> {
    let c = weebo_kit_api::status::ready(&status?.conditions)?;
    Some((c.status.clone(), c.reason.clone()))
}

trait Status {
    fn status_of(&self) -> Option<&api::Status>;
}

macro_rules! status_of {
    ($($kind:ty),+) => {$(
        impl Status for $kind {
            fn status_of(&self) -> Option<&api::Status> {
                self.status.as_ref()
            }
        }
    )+};
}
status_of!(ServiceAccount, Account, Group, MailingList);

/// Waits for `Ready` with the current generation observed, returns its
/// status and reason.
async fn settled<K>(api: &Api<K>, name: &str) -> (String, String)
where
    K: Resource<DynamicType = ()> + Clone + std::fmt::Debug + DeserializeOwned + Status,
{
    testkit::polling::wait_for(api, name, TIMEOUT, POLL, |cr| {
        let status = cr.status_of()?;
        let r = ready(Some(status))?;
        let current = r.0 == "False" || status.observed_generation == cr.meta().generation;
        current.then_some(r)
    })
    .await
}

async fn create<K>(api: &Api<K>, cr: &K)
where
    K: Resource<DynamicType = ()> + Clone + std::fmt::Debug + DeserializeOwned + Serialize,
{
    api.create(&PostParams::default(), cr).await.unwrap();
}

async fn merge<K>(api: &Api<K>, name: &str, patch: serde_json::Value)
where
    K: Resource<DynamicType = ()> + Clone + std::fmt::Debug + DeserializeOwned,
{
    api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .unwrap();
}

/// Waits for an Event of `reason` on `namespace/name`, returns its note.
async fn wait_for_event(client: &Client, namespace: &str, name: &str, reason: &str) -> String {
    let events: Api<Event> = Api::namespaced(client.clone(), namespace);
    let params = ListParams::default().fields(&format!("involvedObject.name={name}"));
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let found = events
                .list(&params)
                .await
                .unwrap()
                .items
                .into_iter()
                .find(|e| e.reason.as_deref() == Some(reason));
            if let Some(event) = found {
                return event.message.unwrap_or_default();
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {reason} Event on {namespace}/{name}"))
}

async fn has_event(client: &Client, namespace: &str, name: &str, reason: &str) -> bool {
    let events: Api<Event> = Api::namespaced(client.clone(), namespace);
    let params = ListParams::default().fields(&format!("involvedObject.name={name}"));
    events
        .list(&params)
        .await
        .unwrap()
        .items
        .iter()
        .any(|e| e.reason.as_deref() == Some(reason))
}

#[tokio::test]
async fn service_accounts_emit_rotate_claim_and_delete() {
    let (_cluster, client, gateway, secrets) = start(&["forgejo", "other", "mail"]).await;
    let sas: Api<ServiceAccount> = Api::namespaced(client.clone(), "forgejo");

    // Created: its password set and written with the SMTP settings.
    create(
        &sas,
        &cr(
            "forgejo",
            "forgejo",
            serde_json::json!({"aliases": ["noreply"]}),
        ),
    )
    .await;
    assert_eq!(
        settled(&sas, "forgejo").await,
        ("True".into(), "Reconciled".into())
    );
    let sa = sas.get("forgejo").await.unwrap();
    let status = sa.status.unwrap();
    let id = status.remote_id.unwrap();
    assert_eq!(status.address.as_deref(), Some("forgejo@weebo.internal"));
    let secret: BTreeMap<String, String> = secrets.get("forgejo/forgejo").unwrap();
    assert_eq!(secret["password"], gateway.app_password(&id).unwrap());
    assert_eq!(secret["from"], "noreply@weebo.internal");
    wait_for_event(&client, "forgejo", "forgejo", "Created").await;

    // A rotation nonce: a new password, recorded once.
    let before = secret["password"].clone();
    merge(
        &sas,
        "forgejo",
        serde_json::json!({"metadata": {"annotations": {"stalwart.weebo.io/rotate-secret": "r1"}}}),
    )
    .await;
    testkit::polling::wait_for(&sas, "forgejo", TIMEOUT, POLL, |sa| {
        (sa.status.as_ref()?.last_rotation.as_deref()? == "r1").then_some(())
    })
    .await;
    let after = secrets.get("forgejo/forgejo").unwrap()["password"].clone();
    assert_ne!(after, before);
    assert_eq!(gateway.app_password(&id).unwrap(), after);

    // The same address claimed by another namespace's CR, and an alias of
    // an account of a third: never created.
    let others: Api<ServiceAccount> = Api::namespaced(client.clone(), "other");
    create(&others, &cr("other", "forgejo", serde_json::json!({}))).await;
    assert_eq!(
        settled(&others, "forgejo").await,
        ("False".into(), "RemoteObjectClaimed".into())
    );
    let accounts: Api<Account> = Api::namespaced(client.clone(), "mail");
    create(
        &accounts,
        &cr("mail", "max", serde_json::json!({"aliases": ["noreply"]})),
    )
    .await;
    assert_eq!(
        settled(&accounts, "max").await,
        ("False".into(), "RemoteObjectClaimed".into())
    );

    // A domain that doesn't exist.
    create(
        &others,
        &cr(
            "other",
            "lost",
            serde_json::json!({"domainRef": {"name": "missing.internal"}}),
        ),
    )
    .await;
    assert_eq!(
        settled(&others, "lost").await,
        ("False".into(), "DomainNotFound".into())
    );

    // Deleted (`Delete`, the default): the account and its secret.
    sas.delete("forgejo", &DeleteParams::default())
        .await
        .unwrap();
    testkit::polling::wait_for_absence(&sas, "forgejo", TIMEOUT, POLL).await;
    assert!(gateway.account(&id).is_none());
    assert!(secrets.get("forgejo/forgejo").is_none());
    // Its address is free: the other namespace's CR now gets it.
    merge(
        &others,
        "forgejo",
        serde_json::json!({"metadata": {"labels": {"touched": "1"}}}),
    )
    .await;
    testkit::polling::wait_for(&others, "forgejo", TIMEOUT, POLL, |sa| {
        ready(sa.status.as_ref()).filter(|(s, _)| s == "True")
    })
    .await;
}

#[tokio::test]
async fn accounts_lock_groups_wait_for_their_members_lists_resolve_accounts() {
    let (_cluster, client, gateway, _secrets) = start(&["mail"]).await;
    let accounts: Api<Account> = Api::namespaced(client.clone(), "mail");
    create(
        &accounts,
        &cr("mail", "alice", serde_json::json!({"quota": "2Gi"})),
    )
    .await;
    assert_eq!(
        settled(&accounts, "alice").await,
        ("True".into(), "Reconciled".into())
    );
    let id = accounts
        .get("alice")
        .await
        .unwrap()
        .status
        .unwrap()
        .remote_id
        .unwrap();
    assert_eq!(
        gateway.account(&id).unwrap().quotas["maxDiskQuota"],
        2_147_483_648
    );

    // Locked: `Ready: True`, `Reconciled` (D20); a spec change, not a drift.
    merge(
        &accounts,
        "alice",
        serde_json::json!({"spec": {"state": "Locked"}}),
    )
    .await;
    testkit::polling::wait_for(&accounts, "alice", TIMEOUT, POLL, |a| {
        let s = a.status.as_ref()?;
        (s.observed_generation == a.metadata.generation).then_some(())
    })
    .await;
    assert_eq!(
        settled(&accounts, "alice").await,
        ("True".into(), "Reconciled".into())
    );
    let RemotePermissions::Merge { disabled, .. } = gateway.account(&id).unwrap().permissions
    else {
        panic!("not locked")
    };
    assert_eq!(disabled, ["authenticate", "emailSend", "emailReceive"]);
    assert!(!has_event(&client, "mail", "alice", "DriftCorrected").await);

    // Unlocked by hand in Stalwart: locked again, and announced.
    gateway.edit_account(&id, |a| a.permissions = RemotePermissions::Inherit);
    merge(
        &accounts,
        "alice",
        serde_json::json!({"metadata": {"labels": {"touched": "1"}}}),
    )
    .await;
    let note = wait_for_event(&client, "mail", "alice", "DriftCorrected").await;
    assert!(note.contains("permissions"), "{note}");

    // A list whose recipient is the account: its confirmed address.
    let lists: Api<MailingList> = Api::namespaced(client.clone(), "mail");
    create(
        &lists,
        &cr(
            "mail",
            "team",
            serde_json::json!({"recipients": [{"accountRef": {"name": "alice"}}, {"address": "Bob@Example.com"}]}),
        ),
    )
    .await;
    assert_eq!(
        settled(&lists, "team").await,
        ("True".into(), "Reconciled".into())
    );
    let list_id = lists
        .get("team")
        .await
        .unwrap()
        .status
        .unwrap()
        .remote_id
        .unwrap();
    assert_eq!(
        gateway.mailing_list(&list_id).unwrap().recipients,
        ["alice@weebo.internal", "bob@example.com"]
    );
    create(
        &lists,
        &cr(
            "mail",
            "ghosts",
            serde_json::json!({"recipients": [{"accountRef": {"name": "nobody"}}]}),
        ),
    )
    .await;
    assert_eq!(
        settled(&lists, "ghosts").await,
        ("False".into(), "AccountNotFound".into())
    );

    // A group with members: its deletion waits (`ObjectIsLinked`).
    let groups: Api<Group> = Api::namespaced(client.clone(), "mail");
    create(
        &groups,
        &cr(
            "mail",
            "staff",
            serde_json::json!({"deletionPolicy": "Delete"}),
        ),
    )
    .await;
    assert_eq!(
        settled(&groups, "staff").await,
        ("True".into(), "Reconciled".into())
    );
    let group_id = groups
        .get("staff")
        .await
        .unwrap()
        .status
        .unwrap()
        .remote_id
        .unwrap();
    gateway.link(&group_id);
    groups
        .delete("staff", &DeleteParams::default())
        .await
        .unwrap();
    wait_for_event(&client, "mail", "staff", "ObjectIsLinked").await;
    assert!(groups.get_opt("staff").await.unwrap().is_some(), "kept");
    gateway.unlink(&group_id);
    testkit::polling::wait_for_absence(&groups, "staff", Duration::from_secs(60), POLL).await;
    assert!(gateway.account(&group_id).is_none());

    // The mailbox is `Orphan` by default: left in Stalwart.
    accounts
        .delete("alice", &DeleteParams::default())
        .await
        .unwrap();
    testkit::polling::wait_for_absence(&accounts, "alice", TIMEOUT, POLL).await;
    assert!(gateway.account(&id).is_some());
}
