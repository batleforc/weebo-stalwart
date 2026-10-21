//! Live end to end: envtest, the real controllers, the real factories
//! (`JmapGatewayFactory` reading the token `Secret` on every call,
//! `KubeClusterReader`), against a real Stalwart v0.16.27 (`task
//! stalwart:container:start ENGINE=podman`, then `task
//! test:live-stalwart`). The gateway is only wrapped to count the writes:
//! a reconcile with nothing to change writes nothing to the real server
//! ("reste silencieux", RFC 0003 rule 3).

// Test helpers outside `#[test]`: a fixture that does not hold fails
// the test that called it, with its message.
#![expect(clippy::unwrap_used, reason = "test helpers: a panic is a failed test")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{JmapGatewayFactory, KubeClusterReader, OperatorInstances};
use api::instance::{InstanceSpec, SecretKeyRef};
use api::{Account, Domain, Instance, ServiceAccount};
use application::ports::{
    AccountPatch, BoundInstance, DesiredAccount, DesiredDomain, DesiredMailingList, DomainPatch,
    GatewayError, GatewayFactory, GatewayFactoryError, MailingListPatch, RemoteAccount,
    RemoteDomain, RemoteGateway, RemoteMailingList,
};
use k8s_openapi::api::core::v1::{Event, Secret};
use kube::Client;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use testkit::{FakeSecretStore, LiveStalwart, StaticSecretStoreFactory};
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(250);

/// The real gateway, its writes counted.
struct Counting {
    inner: Arc<dyn RemoteGateway>,
    writes: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl RemoteGateway for Counting {
    async fn ping(&self) -> Result<(), GatewayError> {
        self.inner.ping().await
    }
    async fn get_domain(&self, id: &str) -> Result<Option<RemoteDomain>, GatewayError> {
        self.inner.get_domain(id).await
    }
    async fn find_domain(&self, name: &str) -> Result<Option<String>, GatewayError> {
        self.inner.find_domain(name).await
    }
    async fn create_domain(&self, domain: &DesiredDomain) -> Result<String, GatewayError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.create_domain(domain).await
    }
    async fn update_domain(&self, id: &str, patch: &DomainPatch) -> Result<(), GatewayError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.update_domain(id, patch).await
    }
    async fn get_account(&self, id: &str) -> Result<Option<RemoteAccount>, GatewayError> {
        self.inner.get_account(id).await
    }
    async fn find_account(&self, domain: &str, name: &str) -> Result<Option<String>, GatewayError> {
        self.inner.find_account(domain, name).await
    }
    async fn create_account(&self, account: &DesiredAccount) -> Result<String, GatewayError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.create_account(account).await
    }
    async fn update_account(&self, id: &str, patch: &AccountPatch) -> Result<(), GatewayError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.update_account(id, patch).await
    }
    async fn app_password_key(&self) -> Result<(), GatewayError> {
        self.inner.app_password_key().await
    }
    async fn rotate_app_password(&self, id: &str) -> Result<String, GatewayError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.rotate_app_password(id).await
    }
    async fn delete_account(&self, id: &str) -> Result<bool, GatewayError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.delete_account(id).await
    }
    async fn get_mailing_list(&self, id: &str) -> Result<Option<RemoteMailingList>, GatewayError> {
        self.inner.get_mailing_list(id).await
    }
    async fn find_mailing_list(
        &self,
        domain: &str,
        name: &str,
    ) -> Result<Option<String>, GatewayError> {
        self.inner.find_mailing_list(domain, name).await
    }
    async fn create_mailing_list(&self, list: &DesiredMailingList) -> Result<String, GatewayError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.create_mailing_list(list).await
    }
    async fn update_mailing_list(
        &self,
        id: &str,
        patch: &MailingListPatch,
    ) -> Result<(), GatewayError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.update_mailing_list(id, patch).await
    }
    async fn delete_mailing_list(&self, id: &str) -> Result<bool, GatewayError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.delete_mailing_list(id).await
    }
}

struct CountingFactory {
    inner: JmapGatewayFactory,
    writes: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl GatewayFactory for CountingFactory {
    async fn gateway_for(
        &self,
        instance: &BoundInstance,
    ) -> Result<Arc<dyn RemoteGateway>, GatewayFactoryError> {
        let inner = self.inner.gateway_for(instance).await?;
        Ok(Arc::new(Counting {
            inner,
            writes: self.writes.clone(),
        }))
    }
}

fn ctx(client: Client, writes: Arc<AtomicUsize>) -> Arc<Ctx> {
    ctx_with(client, writes, Arc::new(FakeSecretStore::default()))
}

fn ctx_with(client: Client, writes: Arc<AtomicUsize>, secrets: Arc<FakeSecretStore>) -> Arc<Ctx> {
    let secrets: Arc<dyn application::ports::SecretStore> = secrets;
    let instances = Arc::new(OperatorInstances::new(client.clone()));
    let cluster = Arc::new(KubeClusterReader::new(client.clone()));
    Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(CountingFactory {
            inner: JmapGatewayFactory::new(client.clone(), instances.clone()),
            writes,
        }),
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
        watches: Default::default(),
    })
}

/// `Ready`'s status and reason, once there is one.
fn ready(status: Option<&api::Status>) -> Option<(String, String)> {
    let c = weebo_kit_api::status::ready(&status?.conditions)?;
    Some((c.status.clone(), c.reason.clone()))
}

/// The operator's two keys, in one Secret: `token` and
/// `appPasswordToken`.
async fn token_secret(client: &Client, token: &str, app_password_token: &str) {
    let secret: Secret = serde_json::from_value(serde_json::json!({
        "metadata": {"name": "stalwart-operator-token", "namespace": "default"},
        "stringData": {
            "token": format!("{token}\n"),
            "appPasswordToken": app_password_token,
        },
    }))
    .unwrap();
    let secrets: Api<Secret> = Api::namespaced(client.clone(), "default");
    let params = PatchParams::apply("live-test").force();
    secrets
        .patch("stalwart-operator-token", &params, &Patch::Apply(&secret))
        .await
        .unwrap();
}

async fn events(client: &Client, name: &str, reason: &str) -> Vec<String> {
    events_in(client, "default", name, reason).await
}

async fn events_in(client: &Client, namespace: &str, name: &str, reason: &str) -> Vec<String> {
    let events: Api<Event> = Api::namespaced(client.clone(), namespace);
    let params = ListParams::default().fields(&format!("involvedObject.name={name}"));
    events
        .list(&params)
        .await
        .unwrap()
        .items
        .into_iter()
        .filter(|e| e.reason.as_deref() == Some(reason))
        .map(|e| e.message.unwrap_or_default())
        .collect()
}

#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn instance_and_domain_against_a_real_stalwart() {
    // Err: another test installed it first, which is as good.
    tracing_subscriber::fmt().with_test_writer().try_init().ok();
    let live = LiveStalwart::from_env();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let writes = Arc::new(AtomicUsize::new(0));
    let ctx = ctx(client.clone(), writes.clone());
    tokio::spawn(controller::instance::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::stalwart_domain::run(client.clone(), ctx));

    // The instance: the token read from its Secret (a trailing newline
    // trimmed), the server answering with a supported schema.
    token_secret(&client, &live.token, &live.app_password_token).await;
    let instances: Api<Instance> = Api::all(client.clone());
    let spec = InstanceSpec {
        url: live.url.clone(),
        token_secret_ref: SecretKeyRef {
            name: "stalwart-operator-token".into(),
            namespace: "default".into(),
            key: "token".into(),
        },
        app_password_token_secret_ref: None,
        tls: Default::default(),
        secret_store: Default::default(),
        submission: Default::default(),
    };
    instances
        .create(&PostParams::default(), &Instance::new("default", spec))
        .await
        .unwrap();
    let instance = testkit::polling::wait_for(&instances, "default", TIMEOUT, POLL, |i| {
        ready(i.status.as_ref())
    })
    .await;
    assert_eq!(instance, ("True".into(), "Reconciled".into()));

    // The domain: created, Ready, then quiet.
    let name = LiveStalwart::unique_domain("e2e");
    let domains: Api<Domain> = Api::all(client.clone());
    let mut domain = Domain::new(
        &name,
        serde_json::from_value(serde_json::json!({})).unwrap(),
    );
    domain.spec.aliases = vec![format!("Alias.{name}")];
    domain.spec.catch_all = Some("All".into());
    domains
        .create(&PostParams::default(), &domain)
        .await
        .unwrap();
    let id = testkit::polling::wait_for(&domains, &name, TIMEOUT, POLL, |d| {
        let s = d.status.as_ref()?;
        (ready(Some(s))?.0 == "True").then(|| s.remote_id.clone())?
    })
    .await;
    assert_eq!(writes.load(Ordering::SeqCst), 1, "one creation");
    let stored = live
        .admin_call(
            "x:Domain/get",
            serde_json::json!({"ids": [&id], "properties": ["name", "catchAllAddress", "aliases"]}),
        )
        .await;
    assert_eq!(stored["list"][0]["catchAllAddress"], format!("all@{name}"));

    // Two more reconciles (label changes trigger them): reads only.
    for n in 1..=2 {
        let touch = serde_json::json!({"metadata": {"labels": {"touched": n.to_string()}}});
        domains
            .patch(&name, &PatchParams::default(), &Patch::Merge(&touch))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert_eq!(
        writes.load(Ordering::SeqCst),
        1,
        "a reconcile in sync wrote to Stalwart"
    );
    assert!(events(&client, &name, "DriftCorrected").await.is_empty());

    // A hand edit in Stalwart: put back, one write, a DriftCorrected
    // naming the field.
    live.admin_call(
        "x:Domain/set",
        serde_json::json!({"update": {&id: {"subAddressing": {"@type": "Disabled"}}}}),
    )
    .await;
    let touch = serde_json::json!({"metadata": {"labels": {"touched": "drift"}}});
    domains
        .patch(&name, &PatchParams::default(), &Patch::Merge(&touch))
        .await
        .unwrap();
    let notes = tokio::time::timeout(TIMEOUT, async {
        loop {
            let notes = events(&client, &name, "DriftCorrected").await;
            if !notes.is_empty() {
                return notes;
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("a DriftCorrected Event");
    assert!(notes[0].contains("subAddressing"), "{notes:?}");
    assert_eq!(writes.load(Ordering::SeqCst), 2);
    let fixed = live
        .admin_call(
            "x:Domain/get",
            serde_json::json!({"ids": [&id], "properties": ["subAddressing"]}),
        )
        .await;
    assert_eq!(fixed["list"][0]["subAddressing"]["@type"], "Enabled");

    // A revoked token: the instance says so.
    token_secret(&client, "API_revoked", &live.app_password_token).await;
    let touch = serde_json::json!({"metadata": {"labels": {"touched": "revoked"}}});
    instances
        .patch("default", &PatchParams::default(), &Patch::Merge(&touch))
        .await
        .unwrap();
    let revoked = testkit::polling::wait_for(&instances, "default", TIMEOUT, POLL, |i| {
        ready(i.status.as_ref()).filter(|(s, _)| s == "False")
    })
    .await;
    assert_eq!(revoked.1, "InstanceUnauthorized");

    // Deleted: released, the domain left in Stalwart (Orphan).
    domains
        .delete(&name, &DeleteParams::default())
        .await
        .unwrap();
    testkit::polling::wait_for_absence(&domains, &name, TIMEOUT, POLL).await;
    let left = live
        .admin_call(
            "x:Domain/get",
            serde_json::json!({"ids": [&id], "properties": ["name"]}),
        )
        .await;
    assert_eq!(left["list"][0]["name"], name.as_str());
    live.destroy_domain(&name).await;
}

async fn namespace(client: &Client, name: &str) {
    let ns: k8s_openapi::api::core::v1::Namespace =
        serde_json::from_value(serde_json::json!({"metadata": {"name": name}})).unwrap();
    Api::<k8s_openapi::api::core::v1::Namespace>::all(client.clone())
        .create(&PostParams::default(), &ns)
        .await
        .unwrap();
}

/// Touches `name` (a label): a reconcile, without a spec change.
async fn touch<K>(api: &Api<K>, name: &str, n: &str)
where
    K: kube::Resource<DynamicType = ()> + Clone + std::fmt::Debug + serde::de::DeserializeOwned,
{
    let touch = serde_json::json!({"metadata": {"labels": {"touched": n}}});
    api.patch(name, &PatchParams::default(), &Patch::Merge(&touch))
        .await
        .unwrap();
}

/// The account kinds end to end against the real server: a sending
/// account whose emitted App Password logs in; a mailbox created, quiet, its
/// drift reverted with a `DriftCorrected`; locked — its owner's login
/// refused — then unlocked — accepted again.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn accounts_against_a_real_stalwart() {
    // Err: another test installed it first, which is as good.
    tracing_subscriber::fmt().with_test_writer().try_init().ok();
    let live = LiveStalwart::from_env();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let writes = Arc::new(AtomicUsize::new(0));
    let secrets = Arc::new(FakeSecretStore::default());
    let ctx = ctx_with(client.clone(), writes.clone(), secrets.clone());
    tokio::spawn(controller::instance::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::stalwart_domain::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::stalwart_service_account::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::stalwart_account::run(client.clone(), ctx));
    namespace(&client, "forgejo").await;
    namespace(&client, "mail").await;

    token_secret(&client, &live.token, &live.app_password_token).await;
    let instances: Api<Instance> = Api::all(client.clone());
    let spec = InstanceSpec {
        url: live.url.clone(),
        token_secret_ref: SecretKeyRef {
            name: "stalwart-operator-token".into(),
            namespace: "default".into(),
            key: "token".into(),
        },
        app_password_token_secret_ref: Some(SecretKeyRef {
            name: "stalwart-operator-token".into(),
            namespace: "default".into(),
            key: "appPasswordToken".into(),
        }),
        tls: Default::default(),
        secret_store: Default::default(),
        submission: Default::default(),
    };
    instances
        .create(&PostParams::default(), &Instance::new("default", spec))
        .await
        .unwrap();
    let name = LiveStalwart::unique_domain("e2e-acc");
    let domains: Api<Domain> = Api::all(client.clone());
    let domain = Domain::new(
        &name,
        serde_json::from_value(serde_json::json!({"dkim": "Manual"})).unwrap(),
    );
    domains
        .create(&PostParams::default(), &domain)
        .await
        .unwrap();
    testkit::polling::wait_for(&domains, &name, TIMEOUT, POLL, |d| {
        ready(d.status.as_ref()).filter(|(s, _)| s == "True")
    })
    .await;

    // The sending account: its App Password, emitted, logs in.
    let sas: Api<ServiceAccount> = Api::namespaced(client.clone(), "forgejo");
    let sa: ServiceAccount = serde_json::from_value(serde_json::json!({
        "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartServiceAccount",
        "metadata": {"name": "forgejo", "namespace": "forgejo"},
        "spec": {"domainRef": {"name": &name}, "aliases": ["noreply"]},
    }))
    .unwrap();
    sas.create(&PostParams::default(), &sa).await.unwrap();
    let sa_id = testkit::polling::wait_for(&sas, "forgejo", TIMEOUT, POLL, |sa| {
        let s = sa.status.as_ref()?;
        (ready(Some(s))?.0 == "True").then(|| s.remote_id.clone())?
    })
    .await;
    let secret = secrets.get("forgejo/forgejo").expect("the SMTP settings");
    assert_eq!(secret["username"], format!("forgejo@{name}"));
    assert_eq!(secret["from"], format!("noreply@{name}"));
    assert!(secret["password"].starts_with("app_"));
    assert_eq!(
        live.login(&secret["username"], &secret["password"]).await,
        200
    );

    // The mailbox: created, then quiet.
    let accounts: Api<Account> = Api::namespaced(client.clone(), "mail");
    let alice: Account = serde_json::from_value(serde_json::json!({
        "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartAccount",
        "metadata": {"name": "alice", "namespace": "mail"},
        "spec": {"domainRef": {"name": &name}, "quota": "2Gi", "locale": "fr-FR"},
    }))
    .unwrap();
    accounts
        .create(&PostParams::default(), &alice)
        .await
        .unwrap();
    let id = testkit::polling::wait_for(&accounts, "alice", TIMEOUT, POLL, |a| {
        let s = a.status.as_ref()?;
        (ready(Some(s))?.0 == "True").then(|| s.remote_id.clone())?
    })
    .await;
    let after_creation = writes.load(Ordering::SeqCst);
    for n in 1..=2 {
        touch(&accounts, "alice", &n.to_string()).await;
        touch(&sas, "forgejo", &n.to_string()).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert_eq!(
        writes.load(Ordering::SeqCst),
        after_creation,
        "a reconcile in sync wrote to Stalwart"
    );
    assert!(
        events_in(&client, "mail", "alice", "DriftCorrected")
            .await
            .is_empty()
    );

    // By hand in Stalwart: an Admin role, another quota — reverted.
    live.admin_call(
        "x:Account/set",
        serde_json::json!({"update": {&id: {"roles": {"@type": "Admin"}, "quotas/maxDiskQuota": 1}}}),
    )
    .await;
    touch(&accounts, "alice", "drift").await;
    let notes = tokio::time::timeout(TIMEOUT, async {
        loop {
            let notes = events_in(&client, "mail", "alice", "DriftCorrected").await;
            if !notes.is_empty() {
                return notes;
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("a DriftCorrected Event");
    assert!(
        notes[0].contains("roles") && notes[0].contains("quotas"),
        "{notes:?}"
    );
    let fixed = live
        .admin_call(
            "x:Account/get",
            serde_json::json!({"ids": [&id], "properties": ["roles", "quotas"]}),
        )
        .await;
    assert_eq!(fixed["list"][0]["roles"]["@type"], "User");
    assert_eq!(fixed["list"][0]["quotas"]["maxDiskQuota"], 2_147_483_648u64);

    // Its owner's password (the OpenID Connect login's, set by hand here):
    // refused while locked, accepted once unlocked.
    let address = format!("alice@{name}");
    let password = "Live-test-alice-password-0123456789";
    live.admin_call(
        "x:Account/set",
        serde_json::json!({"update": {&id: {"credentials/0": {"@type": "Password", "secret": password}}}}),
    )
    .await;
    assert_eq!(live.login(&address, password).await, 200);
    for (state, expected) in [("Locked", 403), ("Active", 200)] {
        let patch = serde_json::json!({"spec": {"state": state}});
        accounts
            .patch("alice", &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .unwrap();
        let reached = testkit::polling::wait_for(&accounts, "alice", TIMEOUT, POLL, |a| {
            let s = a.status.as_ref()?;
            (s.observed_generation == a.metadata.generation).then(|| ready(Some(s)))?
        })
        .await;
        // D20: a lock applied is `Ready: True`, `Reconciled`.
        assert_eq!(reached, ("True".into(), "Reconciled".into()), "{state}");
        assert_eq!(live.login(&address, password).await, expected, "{state}");
    }

    // Deleted: the sending account with it (`Delete`), the mailbox left
    // (`Orphan`).
    sas.delete("forgejo", &DeleteParams::default())
        .await
        .unwrap();
    accounts
        .delete("alice", &DeleteParams::default())
        .await
        .unwrap();
    testkit::polling::wait_for_absence(&sas, "forgejo", TIMEOUT, POLL).await;
    testkit::polling::wait_for_absence(&accounts, "alice", TIMEOUT, POLL).await;
    let left = live
        .admin_call(
            "x:Account/get",
            serde_json::json!({"ids": [&sa_id, &id], "properties": ["name"]}),
        )
        .await;
    assert_eq!(left["notFound"], serde_json::json!([sa_id]));
    assert_eq!(left["list"][0]["name"], "alice");
    assert!(secrets.get("forgejo/forgejo").is_none());
    live.destroy_domain(&name).await;
}
