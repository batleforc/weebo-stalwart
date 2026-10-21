//! The real `weebo-stalwart-operator` binary: its commands without a
//! cluster, `migrate-instance-ref` on envtest, and the operator itself —
//! it takes the leader lease, reconciles a `StalwartInstance` against a
//! scripted Stalwart, and exits as soon as the lease is lost. (The perf
//! test covers the SIGTERM shutdown.)

// Test helpers outside `#[test]`: a fixture that does not hold fails
// the test that called it, with its message.
#![expect(clippy::unwrap_used, reason = "test helpers: a panic is a failed test")]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use api::{Domain, Instance};
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, Patch, PatchParams, PostParams};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LEASE: &str = "weebo-stalwart-operator-leader";

fn operator() -> Command {
    Command::new(env!("CARGO_BIN_EXE_weebo-stalwart-operator"))
}

/// Kills the operator if the test fails before it exits on its own.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        // Err: it exited already.
        self.0.kill().ok();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while !check().await {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[test]
fn prints_its_version_and_refuses_an_unknown_command() {
    let out = operator().arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        format!("weebo-stalwart-operator {}", env!("CARGO_PKG_VERSION"))
    );

    let out = operator().arg("frobnicate").output().unwrap();
    assert!(!out.status.success());
}

fn migrate(kubeconfig: &Path, dry_run: bool) -> String {
    let mut cmd = operator();
    cmd.arg("migrate-instance-ref")
        .env("KUBECONFIG", kubeconfig);
    if dry_run {
        cmd.arg("--dry-run");
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[tokio::test]
async fn migrate_instance_ref_leaves_current_crs_alone() {
    let cluster = testkit::envtest::start().await;
    let dir = std::env::temp_dir().join(format!("operator-migrate-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let kubeconfig = dir.join("kubeconfig.yaml");
    cluster.write_kubeconfig(&kubeconfig);
    Api::<Domain>::all(cluster.client())
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartDomain",
                "metadata": {"name": "weebo.internal"}, "spec": {"instanceRef": {"name": "main"}},
            }))
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(migrate(&kubeconfig, true), "0 to migrate, 1 unchanged\n");
    assert_eq!(migrate(&kubeconfig, false), "0 migrated, 1 unchanged\n");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn leads_reconciles_and_exits_on_lease_loss() {
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let dir = std::env::temp_dir().join(format!("operator-bin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let kubeconfig = dir.join("kubeconfig.yaml");
    cluster.write_kubeconfig(&kubeconfig);

    let stalwart = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jmap/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"primaryAccounts": {"urn:stalwart:jmap": "b"}})),
        )
        .mount(&stalwart)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/schema"))
        .respond_with(
            ResponseTemplate::new(302).insert_header(
                "location",
                format!(
                    "/api/schema/{}",
                    adapters_outbound::jmap::SUPPORTED_SCHEMAS[0].0
                )
                .as_str(),
            ),
        )
        .mount(&stalwart)
        .await;
    Api::<Secret>::namespaced(client.clone(), "default")
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "metadata": {"name": "stalwart-token"}, "stringData": {"token": "t0ken"},
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let instances: Api<Instance> = Api::all(client.clone());
    instances
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartInstance",
                "metadata": {"name": "main"},
                "spec": {"url": stalwart.uri(),
                         "tokenSecretRef": {"name": "stalwart-token", "namespace": "default",
                                            "key": "token"}},
            }))
            .unwrap(),
        )
        .await
        .unwrap();

    let mut op = Running(
        operator()
            .env("KUBECONFIG", &kubeconfig)
            .env("POD_NAMESPACE", "default")
            .env("HOSTNAME", "operator-under-test")
            // No certificate: the server answers the probes in plain HTTP.
            .env("WEBHOOK_TLS_CERT_FILE", dir.join("no-cert"))
            .env("WEBHOOK_PORT", free_port().to_string())
            .env("WEEBO_METRICS_ADDR", format!("127.0.0.1:{}", free_port()))
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("operator starts"),
    );

    let leases: Api<Lease> = Api::namespaced(client.clone(), "default");
    eventually("the leader lease", || {
        let get = leases.get_opt(LEASE);
        async move {
            get.await
                .ok()
                .flatten()
                .and_then(|l| l.spec?.holder_identity)
                .as_deref()
                == Some("operator-under-test")
        }
    })
    .await;
    eventually("StalwartInstance Ready", || {
        let get = instances.get("main");
        async move {
            get.await.ok().and_then(|i| i.status).is_some_and(|s| {
                s.conditions
                    .iter()
                    .any(|c| c.type_ == "Ready" && c.status == "True")
            })
        }
    })
    .await;

    // A deposed leader must never keep reconciling: it exits (1).
    leases
        .patch(
            LEASE,
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {
                "holderIdentity": "someone-else",
                "renewTime": MicroTime(Timestamp::now()),
            }})),
        )
        .await
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = op.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the operator kept running after losing the lease"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert_eq!(status.code(), Some(1));
    std::fs::remove_dir_all(&dir).unwrap();
}
