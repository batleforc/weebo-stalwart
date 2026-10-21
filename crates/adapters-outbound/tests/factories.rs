//! The factories the operator builds its ports with, on envtest (no
//! reflector: `OperatorInstances` reads the API): `JmapGatewayFactory`
//! (the instance, its two tokens — the consent label of a local
//! instance's — its CA) against a mock Stalwart, and `StalwartSecretStoreFactory` (where
//! each kind of instance may write).

// Test helpers outside `#[test]`: a fixture that does not hold fails
// the test that called it, with its message.
#![expect(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test helpers: a panic is a failed test"
)]

use std::collections::BTreeMap;
use std::sync::Arc;

use adapters_outbound::jmap::SUPPORTED_SCHEMAS;
use adapters_outbound::{JmapGatewayFactory, OperatorInstances, StalwartSecretStoreFactory};
use api::{Instance, LocalInstance};
use application::ports::{
    BoundInstance, GatewayError, GatewayFactory, GatewayFactoryError, SecretOwner,
    SecretStoreFactory,
};
use domain::error::ReasonCode;
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::Client;
use kube::api::{Api, PostParams};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A Stalwart answering the session to `Bearer s3cret` only.
async fn stalwart() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jmap/session"))
        .and(header("authorization", "Bearer s3cret"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"primaryAccounts": {"urn:stalwart:jmap": "b"}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/schema"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("/api/schema/{}", SUPPORTED_SCHEMAS[0].0).as_str(),
        ))
        .mount(&server)
        .await;
    server
}

async fn create<K>(api: &Api<K>, value: Value)
where
    K: kube::Resource + Clone + std::fmt::Debug + serde::de::DeserializeOwned + serde::Serialize,
{
    api.create(
        &PostParams::default(),
        &serde_json::from_value(value).unwrap(),
    )
    .await
    .unwrap();
}

/// A Secret of `namespace` holding `data` (string values).
async fn secret(client: &Client, namespace: &str, name: &str, labels: Value, data: Value) {
    create(
        &Api::<Secret>::namespaced(client.clone(), namespace),
        json!({"metadata": {"name": name, "labels": labels}, "stringData": data}),
    )
    .await;
}

async fn instance(client: &Client, name: &str, spec: Value) {
    create(
        &Api::<Instance>::all(client.clone()),
        json!({"apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartInstance",
               "metadata": {"name": name}, "spec": spec}),
    )
    .await;
}

fn token_ref(name: &str, key: &str) -> Value {
    json!({"name": name, "namespace": "default", "key": key})
}

fn err_of<T>(result: Result<T, GatewayFactoryError>) -> GatewayFactoryError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

#[tokio::test]
async fn the_gateway_factory_reads_the_instance_its_token_and_its_ca() {
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let server = stalwart().await;
    let url = server.uri();
    create(
        &Api::<Namespace>::all(client.clone()),
        json!({"metadata": {"name": "team"}}),
    )
    .await;
    // Written with `echo`: the trailing newline is not part of the token.
    secret(
        &client,
        "default",
        "token",
        json!({}),
        json!({"token": "s3cret\n"}),
    )
    .await;
    secret(
        &client,
        "default",
        "ca",
        json!({}),
        json!({"ca.crt": "not a pem"}),
    )
    .await;
    instance(
        &client,
        "main",
        json!({"url": url, "tokenSecretRef": token_ref("token", "token")}),
    )
    .await;
    instance(
        &client,
        "no-key",
        json!({"url": url, "tokenSecretRef": token_ref("token", "other")}),
    )
    .await;
    instance(
        &client,
        "bad-url",
        json!({"url": "mailto:ops@example.org", "tokenSecretRef": token_ref("token", "token")}),
    )
    .await;
    instance(
        &client,
        "missing-ca",
        json!({"url": url, "tokenSecretRef": token_ref("token", "token"),
               "tls": {"caSecretRef": {"name": "ca", "namespace": "default", "key": "missing"}}}),
    )
    .await;
    instance(
        &client,
        "bad-ca",
        json!({"url": url, "tokenSecretRef": token_ref("token", "token"),
               "tls": {"caSecretRef": {"name": "ca", "namespace": "default", "key": "ca.crt"}}}),
    )
    .await;
    // A local instance's token Secret needs the consent label.
    secret(
        &client,
        "team",
        "unlabelled",
        json!({}),
        json!({"token": "s3cret"}),
    )
    .await;
    secret(
        &client,
        "team",
        "labelled",
        json!({"stalwart.weebo.io/instance-token": "true"}),
        json!({"token": "s3cret"}),
    )
    .await;
    let locals = Api::<LocalInstance>::namespaced(client.clone(), "team");
    for (name, secret) in [("consented", "labelled"), ("unconsented", "unlabelled")] {
        create(
            &locals,
            json!({"apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartLocalInstance",
                   "metadata": {"name": name},
                   "spec": {"url": url, "tokenSecretRef": {"name": secret, "key": "token"}}}),
        )
        .await;
    }

    let factory = JmapGatewayFactory::new(
        client.clone(),
        Arc::new(OperatorInstances::new(client.clone())),
    );
    let cluster_bound = BoundInstance::cluster;
    factory
        .gateway_for(&cluster_bound("main"))
        .await
        .unwrap()
        .ping()
        .await
        .unwrap();
    factory
        .gateway_for(&BoundInstance::local("team", "consented"))
        .await
        .unwrap()
        .ping()
        .await
        .unwrap();
    assert!(matches!(
        err_of(factory.gateway_for(&BoundInstance::local("team", "unconsented")).await),
        GatewayFactoryError::TokenNotAllowed(m) if m.contains("instance-token")
    ));
    assert!(matches!(
        err_of(factory.gateway_for(&cluster_bound("gone")).await),
        GatewayFactoryError::InstanceNotFound(_)
    ));
    assert!(matches!(
        err_of(factory.gateway_for(&cluster_bound("no-key")).await),
        GatewayFactoryError::TokenSecret(m) if m.contains("default/token key \"other\" not found")
    ));
    assert!(matches!(
        err_of(factory.gateway_for(&cluster_bound("bad-url")).await),
        GatewayFactoryError::InvalidSpec(m) if m.contains("not an http(s) base URL")
    ));
    assert!(matches!(
        err_of(factory.gateway_for(&cluster_bound("missing-ca")).await),
        GatewayFactoryError::InvalidSpec(m) if m.contains("has no key \"missing\"")
    ));
    assert!(matches!(
        err_of(factory.gateway_for(&cluster_bound("bad-ca")).await),
        GatewayFactoryError::InvalidSpec(m) if m.contains("tls.caSecretRef")
    ));
}

/// RFC 0001 D24: the second key, `appPasswordTokenSecretRef`, read only
/// when an App Password call needs it, with the same rules as the first
/// (the consent label on a local instance's); the factory builds the
/// gateway without it, and only those calls fail.
#[tokio::test]
async fn the_gateway_factory_reads_the_app_password_key_when_a_call_needs_it() {
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let server = stalwart().await;
    let url = server.uri();
    for (jmap_method, args) in [
        ("x:AppPassword/get", json!({"list": []})),
        (
            "x:AppPassword/set",
            json!({"created": {"p": {"id": "e", "secret": "app_s"}}}),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path("/jmap"))
            .and(header("authorization", "Bearer k3y"))
            .and(wiremock::matchers::body_partial_json(
                json!({"methodCalls": [[jmap_method, {}, "0"]]}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [[jmap_method, args, "0"]],
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    create(
        &Api::<Namespace>::all(client.clone()),
        json!({"metadata": {"name": "team"}}),
    )
    .await;
    secret(
        &client,
        "default",
        "token",
        json!({}),
        json!({"token": "s3cret", "app": "k3y\n"}),
    )
    .await;
    for (name, spec) in [
        (
            "with-key",
            json!({"url": url, "tokenSecretRef": token_ref("token", "token"),
                   "appPasswordTokenSecretRef": token_ref("token", "app")}),
        ),
        (
            "without-key",
            json!({"url": url, "tokenSecretRef": token_ref("token", "token")}),
        ),
        (
            "missing-key",
            json!({"url": url, "tokenSecretRef": token_ref("token", "token"),
                   "appPasswordTokenSecretRef": token_ref("token", "nope")}),
        ),
    ] {
        instance(&client, name, spec).await;
    }
    secret(
        &client,
        "team",
        "labelled",
        json!({"stalwart.weebo.io/instance-token": "true"}),
        json!({"token": "s3cret"}),
    )
    .await;
    secret(
        &client,
        "team",
        "unlabelled",
        json!({}),
        json!({"app": "k3y"}),
    )
    .await;
    create(
        &Api::<LocalInstance>::namespaced(client.clone(), "team"),
        json!({"apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartLocalInstance",
               "metadata": {"name": "local"},
               "spec": {"url": url, "tokenSecretRef": {"name": "labelled", "key": "token"},
                        "appPasswordTokenSecretRef": {"name": "unlabelled", "key": "app"}}}),
    )
    .await;

    let factory = JmapGatewayFactory::new(
        client.clone(),
        Arc::new(OperatorInstances::new(client.clone())),
    );
    let gateway = |bound: BoundInstance| {
        let factory = &factory;
        async move { factory.gateway_for(&bound).await.unwrap() }
    };
    let with_key = gateway(BoundInstance::cluster("with-key")).await;
    with_key.app_password_key().await.unwrap();
    assert_eq!(with_key.rotate_app_password("c").await.unwrap(), "app_s");

    let reason = |e: GatewayError| (e.reason(), e.to_string());
    let without = gateway(BoundInstance::cluster("without-key")).await;
    without.ping().await.unwrap();
    let (code, message) = reason(without.app_password_key().await.unwrap_err());
    assert_eq!(code, ReasonCode::TokenSecretMissing);
    assert!(message.contains("appPasswordTokenSecretRef"), "{message}");
    let (code, message) = reason(
        gateway(BoundInstance::cluster("missing-key"))
            .await
            .rotate_app_password("c")
            .await
            .unwrap_err(),
    );
    assert_eq!(code, ReasonCode::TokenSecretMissing);
    assert!(
        message.contains("appPasswordTokenSecretRef: secret default/token key \"nope\" not found"),
        "{message}"
    );
    let local = gateway(BoundInstance::local("team", "local")).await;
    local.ping().await.unwrap();
    let (code, message) = reason(local.app_password_key().await.unwrap_err());
    assert_eq!(code, ReasonCode::TokenSecretNotAllowed);
    assert!(message.contains("appPasswordTokenSecretRef"), "{message}");
}

/// A target of `backend` in `namespace`.
fn target(backend: &str, namespace: &str) -> api::common::SecretTarget {
    serde_json::from_value(json!({"backend": backend, "name": "smtp", "namespace": namespace}))
        .unwrap()
}

#[tokio::test]
async fn the_secret_store_factory_routes_each_instance_to_what_it_may_write() {
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let spec = |store: Value| {
        json!({"url": "https://stalwart.example", "tokenSecretRef": token_ref("token", "token"),
               "secretStore": store})
    };
    instance(&client, "kubernetes", spec(json!({}))).await;
    instance(
        &client,
        "vault",
        spec(json!({"backend": "vault", "vault": {
            "address": "https://vault.example", "mount": "kv", "kubernetesAuthRole": "weebo",
            "caSecretRef": {"name": "vault-ca", "namespace": "default", "key": "ca.crt"},
        }})),
    )
    .await;
    create(
        &Api::<LocalInstance>::namespaced(client.clone(), "default"),
        json!({"apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartLocalInstance",
               "metadata": {"name": "local"},
               "spec": {"url": "https://stalwart.example", "tokenSecretRef": {"name": "t", "key": "token"}}}),
    )
    .await;
    let factory = StalwartSecretStoreFactory::new(
        client.clone(),
        Arc::new(OperatorInstances::new(client.clone())),
    );
    let owner = SecretOwner::namespaced("StalwartServiceAccount", "default", "mailer");
    let data = BTreeMap::from([("password".to_string(), "p".to_string())]);

    // No Vault configured: Kubernetes targets are written, Vault ones refused.
    let store = factory
        .store_for(&BoundInstance::cluster("kubernetes"))
        .await
        .unwrap();
    store
        .write(&target("kubernetes", "default"), &owner, &data)
        .await
        .unwrap();
    assert!(
        store
            .exists(&target("kubernetes", "default"), &owner)
            .await
            .unwrap()
    );
    let refused = store
        .write(&target("vault", "default"), &owner, &data)
        .await
        .unwrap_err();
    assert!(refused.0.contains("no secretStore.vault"), "{refused}");

    // A Vault configured: its default backend, and its login — here its CA
    // Secret, missing — only attempted when a target routes to it.
    let store = factory
        .store_for(&BoundInstance::cluster("vault"))
        .await
        .unwrap();
    assert_eq!(
        store.default_backend(),
        api::common::SecretStoreBackend::Vault
    );
    store
        .delete(&target("kubernetes", "default"), &owner)
        .await
        .unwrap();
    let broken = store
        .write(&target("vault", "default"), &owner, &data)
        .await
        .unwrap_err();
    assert!(broken.0.contains("vault-ca"), "{broken}");

    // A local instance: Kubernetes only, whatever the target asks.
    let store = factory
        .store_for(&BoundInstance::local("default", "local"))
        .await
        .unwrap();
    let refused = store
        .write(&target("vault", "default"), &owner, &data)
        .await
        .unwrap_err();
    assert!(refused.0.contains("Kubernetes Secrets only"), "{refused}");

    let gone = match factory.store_for(&BoundInstance::cluster("gone")).await {
        Ok(_) => panic!("an unknown instance has no store"),
        Err(e) => e,
    };
    assert!(gone.0.contains("not found"), "{gone}");
}
