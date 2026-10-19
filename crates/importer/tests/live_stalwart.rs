//! The importer against a real Stalwart v0.16.27 (`task
//! stalwart:container:start ENGINE=podman`, then `task
//! test:live-stalwart`): objects created before the operator — the
//! phase-0 plan's domain and sending account, a mailbox the OpenID
//! Connect login created — linked to their CRs, then reconciled by the real
//! controllers: the mailbox `Ready` (no `StalwartObjectAlreadyExists`), the
//! sending account given an App Password of the operator's (D21, D24) —
//! the emitted one accepted, Terraform's password left alone.

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    JmapClient, JmapGateway, JmapGatewayFactory, KubeClusterReader, OperatorInstances,
};
use api::instance::{InstanceSpec, SecretKeyRef};
use api::{Account, Instance, ServiceAccount};
use application::ports::{RemoteGateway, SecretStore};
use domain::account::{AccountType, DesiredAccount, OwnedPermissions};
use domain::mail_domain::{DesiredDomain, DkimManagement, SubAddressing};
use importer::{apply_all, parse, plan, rotation_nonce};
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::Client;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use testkit::{FakeSecretStore, LiveStalwart, StaticSecretStoreFactory};
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(250);

fn ready(status: Option<&api::Status>) -> Option<(String, String)> {
    let c = weebo_kit_api::status::ready(&status?.conditions)?;
    Some((c.status.clone(), c.reason.clone()))
}

async fn create<K>(client: &Client, object: serde_json::Value)
where
    K: kube::Resource<DynamicType = (), Scope = kube::core::ClusterResourceScope>
        + Clone
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned,
{
    let object: K = serde_json::from_value(object).unwrap();
    Api::<K>::all(client.clone())
        .create(&PostParams::default(), &object)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn phase_zero_objects_are_linked_and_the_sending_account_rotated() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let live = LiveStalwart::from_env();
    let http = JmapClient::client_builder().build().unwrap();
    let gateway = JmapGateway::new(JmapClient::new(&live.url, live.token.clone(), http).unwrap());

    // Before the operator: the domain, a sending account with the
    // password Terraform wrote, a mailbox.
    let name = LiveStalwart::unique_domain("import");
    let domain = gateway
        .create_domain(&DesiredDomain::new(
            &name,
            &[],
            None,
            SubAddressing::Enabled,
            DkimManagement::Manual,
        ))
        .await
        .unwrap();
    let old_password = "Terraform-wrote-this-0123456789";
    let mut argocd = DesiredAccount::new(AccountType::User, "argocd", &domain, &[]);
    argocd.permissions = Some(OwnedPermissions::service_account(false));
    let argocd_id = gateway.create_account(&argocd).await.unwrap();
    live.admin_call(
        "x:Account/set",
        serde_json::json!({"update": {&argocd_id: {"credentials/0": {"@type": "Password", "secret": old_password}}}}),
    )
    .await;
    let alice_id = gateway
        .create_account(&DesiredAccount::new(
            AccountType::User,
            "alice",
            &domain,
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(
        live.login(&format!("argocd@{name}"), old_password).await,
        200
    );

    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    for ns in ["argocd", "mail"] {
        create::<Namespace>(&client, serde_json::json!({"metadata": {"name": ns}})).await;
    }
    let token: Secret = serde_json::from_value(serde_json::json!({
        "metadata": {"name": "token", "namespace": "default"},
        "stringData": {"token": &live.token, "appPasswordToken": &live.app_password_token},
    }))
    .unwrap();
    Api::<Secret>::namespaced(client.clone(), "default")
        .create(&PostParams::default(), &token)
        .await
        .unwrap();
    let spec = InstanceSpec {
        url: live.url.clone(),
        token_secret_ref: SecretKeyRef {
            name: "token".into(),
            namespace: "default".into(),
            key: "token".into(),
        },
        app_password_token_secret_ref: Some(SecretKeyRef {
            name: "token".into(),
            namespace: "default".into(),
            key: "appPasswordToken".into(),
        }),
        tls: Default::default(),
        secret_store: Default::default(),
        submission: Default::default(),
    };
    Api::<Instance>::all(client.clone())
        .create(&PostParams::default(), &Instance::new("default", spec))
        .await
        .unwrap();

    // The CRs, as in Git, linked.
    let input = format!(
        r#"
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartDomain
metadata: {{name: "{name}"}}
spec: {{dkim: Manual}}
---
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartServiceAccount
metadata: {{name: argocd, namespace: argocd}}
spec: {{domainRef: {{name: "{name}"}}}}
---
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartAccount
metadata: {{name: alice, namespace: mail}}
spec: {{domainRef: {{name: "{name}"}}, quota: 1Gi}}
"#
    );
    let nonce = rotation_nonce();
    let (planned, refused) = plan(parse(&input, "default").unwrap(), &gateway, None, &nonce).await;
    assert!(refused.is_empty(), "{refused:?}");
    let summary = apply_all(&client, &planned, false).await;
    assert_eq!((summary.adopted, summary.failed), (3, 0));

    // The controllers take over.
    let instances = Arc::new(OperatorInstances::new(client.clone()));
    let reader = Arc::new(KubeClusterReader::new(client.clone()));
    let secrets = Arc::new(FakeSecretStore::default());
    let store: Arc<dyn SecretStore> = secrets.clone();
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(JmapGatewayFactory::new(client.clone(), instances.clone())),
        secrets: Arc::new(StaticSecretStoreFactory(store)),
        cluster: reader.clone(),
        policies: reader,
        instances,
        recorder: Recorder::new(
            client.clone(),
            Reporter {
                controller: controller::FIELD_MANAGER.into(),
                instance: None,
            },
        ),
        shutdown: Shutdown::never(),
        health: Arc::new(Health::default()),
        scope: WatchScope::cluster(),
    });
    tokio::spawn(controller::stalwart_domain::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::stalwart_service_account::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::stalwart_account::run(client.clone(), ctx));

    // The mailbox: its own account, now with the CR's quota.
    let accounts: Api<Account> = Api::namespaced(client.clone(), "mail");
    let alice = testkit::polling::wait_for(&accounts, "alice", TIMEOUT, POLL, |a| {
        let s = a.status.as_ref()?;
        ready(Some(s))
            .filter(|(s, _)| s == "True")
            .map(|_| s.clone())
    })
    .await;
    assert_eq!(alice.remote_id, Some(alice_id.clone()));
    let quota = gateway
        .get_account(&alice_id)
        .await
        .unwrap()
        .unwrap()
        .quotas["maxDiskQuota"];
    assert_eq!(quota, 1 << 30);

    // D21: the sending account's credential is the operator's now — an
    // App Password (D24).
    let sas: Api<ServiceAccount> = Api::namespaced(client.clone(), "argocd");
    let sa = testkit::polling::wait_for(&sas, "argocd", TIMEOUT, POLL, |sa| {
        let s = sa.status.as_ref()?;
        (s.last_rotation.as_deref() == Some(nonce.as_str())).then(|| s.clone())
    })
    .await;
    assert_eq!(sa.remote_id, Some(argocd_id));
    assert_eq!(ready(Some(&sa)), Some(("True".into(), "Reconciled".into())));
    let secret = secrets.get("argocd/argocd").expect("written");
    let address = format!("argocd@{name}");
    assert_eq!(secret["username"], address);
    assert!(secret["password"].starts_with("app_"));
    assert_eq!(live.login(&address, &secret["password"]).await, 200);
    // Never touched (no `credentials` written): it stops working once the
    // default directory is OIDC (D24), as weebo-si's rollout does.
    assert_eq!(live.login(&address, old_password).await, 200);

    // Quiet afterwards: the nonce consumed, the App Password kept.
    let touch = serde_json::json!({"metadata": {"labels": {"touched": "1"}}});
    sas.patch("argocd", &PatchParams::default(), &Patch::Merge(&touch))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        secrets.get("argocd/argocd").unwrap()["password"],
        secret["password"]
    );
    live.destroy_domain(&name).await;
}
