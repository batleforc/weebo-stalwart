//! Integration test of `StalwartNamespacePolicy` on envtest: its controller
//! reports whether the rules are usable, and the namespaced controllers
//! read the policies live (`KubeClusterReader` as `PolicySource`) — a list
//! refused by the policies becomes Ready once a rule allows it.

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::KubeClusterReader;
use api::{Domain, MailingList, NamespacePolicy};
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use kube::{Client, Resource};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use testkit::{FakeGateway, FakeSecretStore, StaticGatewayFactory, StaticSecretStoreFactory};
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(200);

fn ctx(client: Client) -> Arc<Ctx> {
    let instances = Arc::new(StaticGatewayFactory::new(Arc::new(FakeGateway::default())));
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

fn cr<K: DeserializeOwned + Resource<DynamicType = ()>>(meta: Value, spec: Value) -> K {
    serde_json::from_value(json!({
        "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": K::kind(&()),
        "metadata": meta, "spec": spec,
    }))
    .unwrap()
}

async fn create<K>(api: &Api<K>, obj: &K)
where
    K: Resource + Clone + std::fmt::Debug + DeserializeOwned + Serialize,
{
    api.create(&PostParams::default(), obj).await.unwrap();
}

/// `Ready`'s status, reason and message, once observed for the current
/// generation and `done`.
async fn ready_when<K>(
    api: &Api<K>,
    name: &str,
    status: fn(&K) -> Option<&api::Status>,
    done: impl Fn(&(String, String, String)) -> bool,
) -> (String, String, String)
where
    K: Resource<DynamicType = ()> + Clone + std::fmt::Debug + DeserializeOwned,
{
    testkit::polling::wait_for(api, name, TIMEOUT, POLL, |obj| {
        // A failure leaves `status.observedGeneration` behind: the
        // condition's own is the generation it judged.
        let c = weebo_kit_api::status::ready(&status(obj)?.conditions)?;
        (c.observed_generation == obj.meta().generation).then_some(())?;
        let r = (c.status.clone(), c.reason.clone(), c.message.clone());
        done(&r).then_some(r)
    })
    .await
}

fn policy_status(p: &NamespacePolicy) -> Option<&api::Status> {
    p.status.as_ref()
}

fn list_status(l: &MailingList) -> Option<&api::Status> {
    l.status.as_ref()
}

#[tokio::test]
async fn policies_report_their_rules_and_gate_the_namespaced_kinds_live() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    create(
        &Api::<Namespace>::all(client.clone()),
        &serde_json::from_value(json!({"metadata": {"name": "mail"}})).unwrap(),
    )
    .await;
    let ctx = ctx(client.clone());
    tokio::spawn(controller::namespace_policy::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::stalwart_domain::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::stalwart_mailing_list::run(client.clone(), ctx));

    let domains: Api<Domain> = Api::all(client.clone());
    create(
        &domains,
        &cr(
            json!({"name": "weebo.internal"}),
            json!({"instanceRef": {"name": "main"}}),
        ),
    )
    .await;
    testkit::polling::wait_for(&domains, "weebo.internal", TIMEOUT, POLL, |d| {
        let c = weebo_kit_api::status::ready(&d.status.as_ref()?.conditions)?;
        (c.status == "True").then_some(())
    })
    .await;

    // A rule that can never match is reported; one that can is in force.
    let policies: Api<NamespacePolicy> = Api::all(client.clone());
    let rule = |namespaces: &[&str], kinds: &[&str]| json!({"namespaces": namespaces, "allowedKinds": kinds, "effect": "Allow"});
    create(
        &policies,
        &cr(
            json!({"name": "broken"}),
            json!({"rules": [rule(&["mail"], &[])]}),
        ),
    )
    .await;
    let (status, reason, message) = ready_when(&policies, "broken", policy_status, |_| true).await;
    assert_eq!((status.as_str(), reason.as_str()), ("False", "InvalidSpec"));
    assert!(message.contains("spec.rules[0]"), "{message}");
    create(
        &policies,
        &cr(
            json!({"name": "mail"}),
            json!({"rules": [rule(&["mail"], &["StalwartAccount"])]}),
        ),
    )
    .await;
    let (status, _, message) = ready_when(&policies, "mail", policy_status, |_| true).await;
    assert_eq!(status, "True");
    assert_eq!(message, "1 rule(s) in force");

    // A list: no rule allows the kind yet.
    let lists: Api<MailingList> = Api::namespaced(client.clone(), "mail");
    create(
        &lists,
        &cr(
            json!({"name": "team", "namespace": "mail"}),
            json!({"instanceRef": {"name": "main"}, "domainRef": {"name": "weebo.internal"},
                   "recipients": [{"address": "ops@example.org"}]}),
        ),
    )
    .await;
    let (status, reason, _) = ready_when(&lists, "team", list_status, |_| true).await;
    assert_eq!(status, "False");
    assert_eq!(reason, "NamespaceNotAllowed");

    // Allowed by an edit of the policy: the next reconcile reads it.
    policies
        .patch(
            "mail",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"rules": [
                rule(&["mail"], &["StalwartAccount", "StalwartMailingList"]),
            ]}})),
        )
        .await
        .unwrap();
    let (_, _, message) = ready_when(&policies, "mail", policy_status, |r| r.0 == "True").await;
    assert_eq!(message, "1 rule(s) in force");
    lists
        .patch(
            "team",
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"annotations": {"retry": "1"}}})),
        )
        .await
        .unwrap();
    let (_, reason, _) = ready_when(&lists, "team", list_status, |r| r.0 == "True").await;
    assert_eq!(reason, "Reconciled");
}
