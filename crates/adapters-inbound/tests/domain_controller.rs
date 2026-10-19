//! Integration test: a real `kube-apiserver` + `etcd` (envtest), the real
//! `StalwartDomain` controller running against it, the gateway swapped for
//! an in-memory Stalwart (`testkit::FakeGateway`) and the claims read from
//! the cluster (`KubeClusterReader`, against StalwartInstances created
//! here). The template for the other kinds' controller tests.

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::KubeClusterReader;
use api::Domain;
use api::common::InstanceRef;
use api::instance::{InstanceSpec, SecretKeyRef};
use k8s_openapi::api::core::v1::Event;
use kube::Client;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use testkit::{FakeGateway, FakeSecretStore, StaticGatewayFactory, StaticSecretStoreFactory};
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(200);

fn ctx(client: Client, gateway: Arc<FakeGateway>) -> Arc<Ctx> {
    let instances = Arc::new(StaticGatewayFactory::new(gateway).without("missing"));
    let cluster = Arc::new(KubeClusterReader::new(client.clone()));
    Arc::new(Ctx {
        client: client.clone(),
        gateways: instances.clone(),
        secrets: Arc::new(StaticSecretStoreFactory(Arc::new(
            FakeSecretStore::default(),
        ))),
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

fn domain(cr: &str, name: Option<&str>, instance: &str) -> Domain {
    let mut d = Domain::new(cr, serde_json::from_value(serde_json::json!({})).unwrap());
    d.spec.instance_ref = Some(InstanceRef::named(instance));
    d.spec.name = name.map(String::from);
    d.spec.catch_all = Some("all".into());
    d
}

/// `Ready`'s status and reason, once there is one.
fn ready(domain: &Domain) -> Option<(String, String)> {
    let c = weebo_kit_api::status::ready(&domain.status.as_ref()?.conditions)?;
    Some((c.status.clone(), c.reason.clone()))
}

/// Waits for an Event of `reason` on `name`, returns its type and note.
async fn wait_for_event(client: &Client, name: &str, reason: &str) -> (String, String) {
    // Events of a cluster-scoped object land in `default`.
    let events: Api<Event> = Api::namespaced(client.clone(), "default");
    let params = ListParams::default().fields(&format!("involvedObject.name={name}"));
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let found = events
                .list(&params)
                .await
                .expect("events must be listable")
                .items
                .into_iter()
                .find(|e| e.reason.as_deref() == Some(reason));
            if let Some(event) = found {
                return (
                    event.type_.unwrap_or_default(),
                    event.message.unwrap_or_default(),
                );
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {reason} Event on {name} within {TIMEOUT:?}"))
}

async fn instance(client: &Client, name: &str) {
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
        .create(&PostParams::default(), &api::Instance::new(name, spec))
        .await
        .unwrap();
}

#[tokio::test]
async fn domain_lifecycle_creates_stays_quiet_corrects_drift_and_orphans() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    instance(&client, "main").await;
    let gateway = Arc::new(FakeGateway::default());
    tokio::spawn(controller::stalwart_domain::run(
        client.clone(),
        ctx(client.clone(), gateway.clone()),
    ));
    let domains: Api<Domain> = Api::all(client.clone());
    let pp = PostParams::default();

    // Created: its id and name recorded, `Ready: True`, a `Created` Event.
    domains
        .create(&pp, &domain("weebo.internal", None, "main"))
        .await
        .unwrap();
    let remote_id = testkit::polling::wait_for(&domains, "weebo.internal", TIMEOUT, POLL, |d| {
        d.status.as_ref()?.remote_id.clone()
    })
    .await;
    let synced = domains.get("weebo.internal").await.unwrap();
    assert_eq!(ready(&synced), Some(("True".into(), "Reconciled".into())));
    assert_eq!(
        synced.status.as_ref().unwrap().address.as_deref(),
        Some("weebo.internal")
    );
    assert_eq!(
        gateway.domain(&remote_id).unwrap().catch_all.as_deref(),
        Some("all@weebo.internal")
    );
    assert_eq!(
        wait_for_event(&client, "weebo.internal", "Created").await.0,
        "Normal"
    );

    // A spec change: written, not announced as a drift.
    gateway.clear_writes();
    let patch = serde_json::json!({"spec": {"aliases": ["weebo.lan"]}});
    domains
        .patch(
            "weebo.internal",
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await
        .unwrap();
    testkit::polling::wait_for(&domains, "weebo.internal", TIMEOUT, POLL, |d| {
        let s = d.status.as_ref()?;
        (s.observed_generation == d.metadata.generation).then_some(())
    })
    .await;
    assert_eq!(gateway.writes(), [format!("update {remote_id} [aliases]")]);

    // A drift: put back, announced by a `DriftCorrected` naming the field.
    gateway.edit_domain(&remote_id, |d| d.allow_relaying = true);
    // A no-op metadata change triggers a reconcile now.
    let touch = serde_json::json!({"metadata": {"labels": {"touched": "1"}}});
    domains
        .patch(
            "weebo.internal",
            &PatchParams::default(),
            &Patch::Merge(&touch),
        )
        .await
        .unwrap();
    let (kind, note) = wait_for_event(&client, "weebo.internal", "DriftCorrected").await;
    assert_eq!(kind, "Normal");
    assert!(note.contains("allowRelaying"), "{note}");
    assert!(!gateway.domain(&remote_id).unwrap().allow_relaying);

    // Another CR naming the same domain on the same server: claimed.
    domains
        .create(&pp, &domain("duplicate", Some("Weebo.Internal"), "main"))
        .await
        .unwrap();
    let claimed = testkit::polling::wait_for(&domains, "duplicate", TIMEOUT, POLL, ready).await;
    assert_eq!(claimed, ("False".into(), "RemoteObjectClaimed".into()));

    // A domain already in Stalwart that no CR created: never adopted.
    gateway.seed_domain("by-hand.internal");
    domains
        .create(&pp, &domain("by-hand.internal", None, "main"))
        .await
        .unwrap();
    let taken =
        testkit::polling::wait_for(&domains, "by-hand.internal", TIMEOUT, POLL, ready).await;
    assert_eq!(
        taken,
        ("False".into(), "StalwartObjectAlreadyExists".into())
    );

    // An unknown instance: `Ready: False` with its reason, and a Warning.
    domains
        .create(&pp, &domain("orphan.internal", None, "missing"))
        .await
        .unwrap();
    let failed =
        testkit::polling::wait_for(&domains, "orphan.internal", TIMEOUT, POLL, ready).await;
    assert_eq!(failed, ("False".into(), "InstanceNotFound".into()));
    assert_eq!(
        wait_for_event(&client, "orphan.internal", "InstanceNotFound")
            .await
            .0,
        "Warning"
    );

    // Deleted: released, the domain left in Stalwart (`Orphan`).
    for name in [
        "weebo.internal",
        "duplicate",
        "by-hand.internal",
        "orphan.internal",
    ] {
        domains
            .delete(name, &DeleteParams::default())
            .await
            .unwrap();
        testkit::polling::wait_for_absence(&domains, name, TIMEOUT, POLL).await;
    }
    assert!(gateway.domain(&remote_id).is_some());
    assert_eq!(
        wait_for_event(&client, "weebo.internal", "Released")
            .await
            .0,
        "Normal"
    );
}

#[tokio::test]
async fn the_schema_refuses_a_domain_to_delete() {
    let cluster = testkit::envtest::start().await;
    let domains: Api<Domain> = Api::all(cluster.client());
    let mut d = domain("weebo.internal", None, "main");
    d.spec.deletion_policy = api::common::DeletionPolicy::Delete;
    let err = domains
        .create(&PostParams::default(), &d)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("deletionPolicy must be Orphan"),
        "{err}"
    );
}
