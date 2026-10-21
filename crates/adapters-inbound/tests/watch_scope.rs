//! Integration tests: the controllers limited to one namespace
//! (`WatchScope`), running as a ServiceAccount that only has the RBAC the
//! chart renders for that scope, with the real instance resolution (the
//! kit's `Instances`) — the gateway alone is in memory. The control plane
//! authorizes with RBAC: a call outside the granted scope is refused.
//!
//! - `watch.namespace` (+ a label selector): cluster-scoped kinds in a
//!   ClusterRole, the namespaced ones in a Role of the watched namespace;
//! - `watch.clusterKinds: false` (full namespaced): that Role only.
//!
//! The rules below mirror the library chart's `clusterRole` and
//! `watchRole` (`weebo-operator.kindRules`): keep them in step.

// Test helpers outside `#[test]`: a fixture that does not hold fails
// the test that called it, with its message.
#![expect(clippy::unwrap_used, reason = "test helpers: a panic is a failed test")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{KubeClusterReader, OperatorInstances};
use api::local_instance::{LocalInstanceSpec, LocalSecretKeyRef};
use api::status::BoundInstance;
use api::{Domain, Instance, LocalInstance};
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::rbac::v1::{
    ClusterRole, ClusterRoleBinding, PolicyRule, Role, RoleBinding, RoleRef, Subject,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::Client;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use testkit::envtest::EnvTestCluster;
use testkit::{FakeGateway, FakeSecretStore, StaticGatewayFactory, StaticSecretStoreFactory};
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(200);
const GROUP: &str = "stalwart.weebo.io";
const OPERATOR_NS: &str = "operator";
const OPERATOR_SA: &str = "operator";
const CLUSTER_KINDS: &[&str] = &[
    "stalwartinstances",
    "stalwartdomains",
    "stalwartnamespacepolicies",
];
const NAMESPACED_KINDS: &[&str] = &["stalwartlocalinstances"];

fn kind_rules(kinds: &[&str]) -> Vec<PolicyRule> {
    let rule = |suffix: &str, verbs: &[&str]| PolicyRule {
        api_groups: Some(vec![GROUP.into()]),
        resources: Some(kinds.iter().map(|k| format!("{k}{suffix}")).collect()),
        verbs: verbs.iter().map(|v| v.to_string()).collect(),
        ..Default::default()
    };
    vec![
        rule("", &["get", "list", "watch", "update", "patch"]),
        rule("/status", &["get", "patch", "update"]),
        rule("/finalizers", &["update"]),
    ]
}

fn secrets_and_events() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            api_groups: Some(vec!["".into()]),
            resources: Some(vec!["secrets".into()]),
            verbs: ["get", "create", "update", "patch", "delete"]
                .map(String::from)
                .to_vec(),
            ..Default::default()
        },
        PolicyRule {
            api_groups: Some(vec!["events.k8s.io".into()]),
            resources: Some(vec!["events".into()]),
            verbs: vec!["create".into(), "patch".into()],
            ..Default::default()
        },
    ]
}

fn meta(name: &str, namespace: Option<&str>) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        namespace: namespace.map(String::from),
        ..Default::default()
    }
}

fn subject() -> Vec<Subject> {
    vec![Subject {
        kind: "ServiceAccount".into(),
        name: OPERATOR_SA.into(),
        namespace: Some(OPERATOR_NS.into()),
        ..Default::default()
    }]
}

fn role_ref(kind: &str, name: &str) -> RoleRef {
    RoleRef {
        api_group: Some("rbac.authorization.k8s.io".into()),
        kind: kind.into(),
        name: name.into(),
    }
}

/// What the chart renders with `watch.namespace: <watched>`, and with
/// `watch.clusterKinds: false` when `cluster_kinds` is false.
async fn grant_rbac(admin: &Client, watched: &str, cluster_kinds: bool) {
    let pp = PostParams::default();
    for ns in [OPERATOR_NS, watched, "elsewhere"] {
        Api::<Namespace>::all(admin.clone())
            .create(
                &pp,
                &Namespace {
                    metadata: meta(ns, None),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    if cluster_kinds {
        let mut rules = kind_rules(CLUSTER_KINDS);
        rules.extend(secrets_and_events());
        Api::<ClusterRole>::all(admin.clone())
            .create(
                &pp,
                &ClusterRole {
                    metadata: meta("operator", None),
                    rules: Some(rules),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        Api::<ClusterRoleBinding>::all(admin.clone())
            .create(
                &pp,
                &ClusterRoleBinding {
                    metadata: meta("operator", None),
                    role_ref: role_ref("ClusterRole", "operator"),
                    subjects: Some(subject()),
                },
            )
            .await
            .unwrap();
    }
    let mut rules = kind_rules(NAMESPACED_KINDS);
    rules.extend(secrets_and_events());
    Api::<Role>::namespaced(admin.clone(), watched)
        .create(
            &pp,
            &Role {
                metadata: meta("operator-watch", Some(watched)),
                rules: Some(rules),
            },
        )
        .await
        .unwrap();
    Api::<RoleBinding>::namespaced(admin.clone(), watched)
        .create(
            &pp,
            &RoleBinding {
                metadata: meta("operator-watch", Some(watched)),
                role_ref: role_ref("Role", "operator-watch"),
                subjects: Some(subject()),
            },
        )
        .await
        .unwrap();
}

fn labelled<K: kube::Resource>(mut object: K, labels: &[(&str, &str)]) -> K {
    object.meta_mut().labels = Some(
        labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    );
    object
}

fn domain(name: &str) -> Domain {
    Domain::new(name, serde_json::from_value(serde_json::json!({})).unwrap())
}

fn local_instance(name: &str) -> LocalInstance {
    LocalInstance::new(
        name,
        LocalInstanceSpec {
            url: "https://remote.example".into(),
            token_secret_ref: LocalSecretKeyRef {
                name: "token".into(),
                key: "token".into(),
            },
            app_password_token_secret_ref: None,
            tls: Default::default(),
            shared_with: None,
            submission: Default::default(),
        },
    )
}

/// The operator's context, as `operator::main` builds it for `scope`, on
/// the operator's own (RBAC-limited) client: the gateway alone is in
/// memory.
fn ctx(operator: &Client, scope: WatchScope) -> (Arc<Ctx>, Arc<Health>) {
    let health = Arc::new(Health::default());
    let instances = Arc::new(OperatorInstances::new(operator.clone()).with_scope(
        scope.watched_namespace().map(String::from),
        scope.selector().cloned(),
        scope.cluster_kinds(),
    ));
    let cluster = Arc::new(KubeClusterReader::new(operator.clone()).with_scope(
        scope.watched_namespace().map(String::from),
        scope.selector().cloned(),
        scope.cluster_kinds(),
    ));
    let ctx = Arc::new(Ctx {
        client: operator.clone(),
        gateways: Arc::new(StaticGatewayFactory::new(Arc::new(FakeGateway::default()))),
        secrets: Arc::new(StaticSecretStoreFactory(Arc::new(
            FakeSecretStore::default(),
        ))),
        cluster: cluster.clone(),
        policies: cluster,
        instances,
        recorder: Recorder::new(
            operator.clone(),
            Reporter {
                controller: controller::FIELD_MANAGER.into(),
                instance: None,
            },
        ),
        shutdown: Shutdown::never(),
        health: health.clone(),
        scope,
        watches: Default::default(),
    });
    (ctx, health)
}

fn ready_of(conditions: &[api::status::Condition]) -> Option<(String, String)> {
    let c = weebo_kit_api::status::ready(conditions)?;
    Some((c.status.clone(), c.reason.clone()))
}

async fn operator_client(cluster: &EnvTestCluster) -> Client {
    cluster
        .client_as_service_account(OPERATOR_NS, OPERATOR_SA)
        .await
}

#[tokio::test]
async fn a_namespaced_scope_runs_on_namespaced_rbac_and_sees_only_its_objects() {
    // Err: another test installed it first, which is as good.
    tracing_subscriber::fmt().with_test_writer().try_init().ok();
    let cluster = testkit::envtest::start().await;
    let admin = cluster.client();
    grant_rbac(&admin, "team-a", true).await;
    let operator = operator_client(&cluster).await;

    // The RBAC is as narrow as intended: no cluster-wide list of the
    // namespaced kind.
    assert!(
        Api::<LocalInstance>::all(operator.clone())
            .list(&Default::default())
            .await
            .is_err(),
        "the operator's account must not list local instances cluster-wide"
    );

    let scope = WatchScope::namespace("team-a")
        .with_labels(LabelSelector {
            match_labels: Some(BTreeMap::from([("shard".into(), "a".into())])),
            ..Default::default()
        })
        .unwrap();
    let (ctx, health) = ctx(&operator, scope);
    tokio::spawn(controller::local_instance::run(
        operator.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::stalwart_domain::run(operator.clone(), ctx));

    let pp = PostParams::default();
    let shard_a = [("shard", "a")];
    let team_a: Api<LocalInstance> = Api::namespaced(admin.clone(), "team-a");
    let elsewhere: Api<LocalInstance> = Api::namespaced(admin.clone(), "elsewhere");
    team_a
        .create(&pp, &labelled(local_instance("main"), &shard_a))
        .await
        .unwrap();
    team_a
        .create(
            &pp,
            &labelled(local_instance("other-shard"), &[("shard", "b")]),
        )
        .await
        .unwrap();
    elsewhere
        .create(&pp, &labelled(local_instance("other-namespace"), &shard_a))
        .await
        .unwrap();
    Api::<Instance>::all(admin.clone())
        .create(
            &pp,
            &labelled(
                Instance::new(
                    "main",
                    api::instance::InstanceSpec {
                        url: "https://remote.example".into(),
                        token_secret_ref: api::instance::SecretKeyRef {
                            name: "token".into(),
                            namespace: OPERATOR_NS.into(),
                            key: "token".into(),
                        },
                        app_password_token_secret_ref: None,
                        tls: Default::default(),
                        secret_store: Default::default(),
                        submission: Default::default(),
                    },
                ),
                &shard_a,
            ),
        )
        .await
        .unwrap();
    let domains: Api<Domain> = Api::all(admin.clone());
    domains
        .create(&pp, &labelled(domain("in-scope.internal"), &shard_a))
        .await
        .unwrap();
    domains
        .create(
            &pp,
            &labelled(domain("other-shard.internal"), &[("shard", "b")]),
        )
        .await
        .unwrap();

    // In scope: the local instance is checked, the domain lands on the
    // only StalwartInstance — the claims read with the scoped RBAC alone.
    let instance_ready = testkit::polling::wait_for(&team_a, "main", TIMEOUT, POLL, |i| {
        ready_of(&i.status.as_ref()?.conditions)
    })
    .await;
    assert_eq!(instance_ready, ("True".into(), "Reconciled".into()));
    let bound = testkit::polling::wait_for(&domains, "in-scope.internal", TIMEOUT, POLL, |d| {
        d.status.as_ref()?.remote_id.as_ref()?;
        d.status.as_ref()?.instance.clone()
    })
    .await;
    assert_eq!(bound, BoundInstance::cluster("main"));

    // Out of scope: never touched (no finalizer, no status), and the
    // watches never failed.
    tokio::time::sleep(Duration::from_secs(2)).await;
    for (api, name) in [(&team_a, "other-shard"), (&elsewhere, "other-namespace")] {
        let untouched = api.get(name).await.unwrap();
        assert!(untouched.status.is_none(), "{name} was reconciled");
    }
    let untouched = domains.get("other-shard.internal").await.unwrap();
    assert!(untouched.status.is_none() && untouched.metadata.finalizers.is_none());
    assert_eq!(health.live(), Ok(()));
}

#[tokio::test]
async fn a_full_namespaced_operator_runs_on_one_role_only() {
    // Err: another test installed it first, which is as good.
    tracing_subscriber::fmt().with_test_writer().try_init().ok();
    let cluster = testkit::envtest::start().await;
    let admin = cluster.client();
    grant_rbac(&admin, "team-a", false).await;
    let operator = operator_client(&cluster).await;

    // Nothing cluster-scoped is granted.
    assert!(
        Api::<Instance>::all(operator.clone())
            .list(&Default::default())
            .await
            .is_err(),
        "the operator's account must not read cluster-scoped instances"
    );

    let scope = WatchScope::namespace("team-a")
        .without_cluster_kinds()
        .unwrap();
    assert!(scope.ensure::<Instance>().is_err());
    assert!(scope.ensure::<Domain>().is_err());
    let (ctx, health) = ctx(&operator, scope);
    // No policy is read (they are cluster-scoped): everything is allowed.
    assert_eq!(ctx.policies.policies().await.unwrap(), Vec::<Vec<_>>::new());
    tokio::spawn(controller::local_instance::run(operator.clone(), ctx));

    let pp = PostParams::default();
    let locals: Api<LocalInstance> = Api::namespaced(admin.clone(), "team-a");
    locals.create(&pp, &local_instance("main")).await.unwrap();
    let instance_ready = testkit::polling::wait_for(&locals, "main", TIMEOUT, POLL, |i| {
        ready_of(&i.status.as_ref()?.conditions)
    })
    .await;
    assert_eq!(instance_ready, ("True".into(), "Reconciled".into()));
    assert_eq!(health.live(), Ok(()));
}
