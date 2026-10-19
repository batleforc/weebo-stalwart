//! `--apply` against a real apiserver (envtest): the CRs are created
//! paused, seeded with the object they link to, unpaused; a re-run changes
//! nothing; an object another CR owns on the same server is refused
//! (`RemoteObjectClaimed`).

use api::instance::{InstanceSpec, SecretKeyRef};
use api::{Account, Domain, ServiceAccount};
use application::test_support::FakeGateway;
use domain::account::AccountType;
use importer::{Summary, apply_all, parse, plan};
use k8s_openapi::api::core::v1::Namespace;
use kube::Client;
use kube::api::{Api, PostParams};

const INPUT: &str = r#"
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartDomain
metadata: {name: weebo.internal}
spec: {instanceRef: {name: main}}
---
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartServiceAccount
metadata: {name: forgejo, namespace: forgejo}
spec: {instanceRef: {name: main}, domainRef: {name: weebo.internal}}
---
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartAccount
metadata: {name: alice, namespace: mail}
spec: {instanceRef: {name: main}, domainRef: {name: weebo.internal}}
"#;

async fn setup(client: &Client) {
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
    for ns in ["forgejo", "mail", "other"] {
        let namespace: Namespace =
            serde_json::from_value(serde_json::json!({"metadata": {"name": ns}})).unwrap();
        Api::<Namespace>::all(client.clone())
            .create(&PostParams::default(), &namespace)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn crs_are_linked_once_and_never_twice() {
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    setup(&client).await;
    let gateway = FakeGateway::default();
    let domain = gateway.seed_domain("weebo.internal");
    let forgejo = gateway.seed_account(AccountType::User, "forgejo", &domain);
    let alice = gateway.seed_account(AccountType::User, "alice", &domain);

    let (planned, refused) =
        plan(parse(INPUT, "default").unwrap(), &gateway, None, "import-7").await;
    assert!(refused.is_empty(), "{refused:?}");
    assert_eq!(
        apply_all(&client, &planned, false).await,
        Summary {
            adopted: 3,
            skipped: 0,
            failed: 0
        }
    );
    let d = Api::<Domain>::all(client.clone())
        .get("weebo.internal")
        .await
        .unwrap();
    assert_eq!(d.status.unwrap().remote_id, Some(domain));
    let sa = Api::<ServiceAccount>::namespaced(client.clone(), "forgejo")
        .get("forgejo")
        .await
        .unwrap();
    let status = sa.status.clone().unwrap();
    assert_eq!(status.remote_id, Some(forgejo));
    assert_eq!(status.address.as_deref(), Some("forgejo@weebo.internal"));
    assert_eq!(status.last_rotation, None);
    // D21: the first reconcile rotates its password; never paused.
    assert_eq!(
        api::ANNOTATIONS.rotate_nonce(&sa.metadata).as_deref(),
        Some("import-7")
    );
    assert!(!api::ANNOTATIONS.import_pending(&sa.metadata));
    let a = Api::<Account>::namespaced(client.clone(), "mail")
        .get("alice")
        .await
        .unwrap();
    let status = a.status.unwrap();
    assert_eq!(status.remote_id, Some(alice.clone()));
    // Seeded with its instance: it claims its address at once.
    assert_eq!(status.instance.unwrap().name, "main");

    // A re-run: already linked.
    assert_eq!(
        apply_all(&client, &planned, false).await,
        Summary {
            adopted: 0,
            skipped: 3,
            failed: 0
        }
    );

    // The same mailbox described by another CR: owned already, refused.
    let other = format!(
        "{}\n",
        INPUT
            .split("---")
            .nth(2)
            .unwrap()
            .replace("namespace: mail", "namespace: other")
    );
    // Its domain is linked now: read from the cluster.
    let reader = adapters_outbound::KubeClusterReader::new(client.clone());
    let (planned, refused) = plan(parse(&other, "x").unwrap(), &gateway, Some(&reader), "n").await;
    assert!(refused.is_empty(), "{refused:?}");
    assert_eq!(apply_all(&client, &planned, false).await.failed, 1);
    assert!(
        Api::<Account>::namespaced(client.clone(), "other")
            .get_opt("alice")
            .await
            .unwrap()
            .is_none()
    );
}
