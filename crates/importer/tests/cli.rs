//! The real `weebo-stalwart-importer` binary against a scripted Stalwart
//! (wiremock): YAML with the seeded status on stdout without a cluster,
//! `--apply` into envtest through `KUBECONFIG` (idempotent), and a non-zero
//! exit when an object can't be found or the input can't be read.

// Test helpers outside `#[test]`: a fixture that does not hold fails
// the test that called it, with its message.
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test helpers: a panic is a failed test"
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use api::{Domain, MailingList};
use kube::api::Api;
use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const INPUT: &str = r#"
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartDomain
metadata: {name: weebo.internal}
spec: {instanceRef: {name: main}}
---
apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartMailingList
metadata: {name: team}
spec: {instanceRef: {name: main}, domainRef: {name: weebo.internal}}
"#;

async fn answer(server: &MockServer, jmap_method: &str, partial: Value, args: Value) {
    Mock::given(method("POST"))
        .and(path("/jmap"))
        .and(body_partial_json(
            json!({"methodCalls": [[jmap_method, partial, "0"]]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "methodResponses": [[jmap_method, args, "0"]],
        })))
        .mount(server)
        .await;
}

/// A Stalwart holding the domain `weebo.internal` (`d`) and its list
/// `team` (`l`).
async fn stalwart() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jmap/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"primaryAccounts": {"urn:stalwart:jmap": "b"}})),
        )
        .mount(&server)
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
        .mount(&server)
        .await;
    answer(
        &server,
        "x:Domain/query",
        json!({"filter": {"name": "weebo.internal"}}),
        json!({"ids": ["d"]}),
    )
    .await;
    answer(
        &server,
        "x:Domain/get",
        json!({"ids": ["d"]}),
        json!({"list": [{"id": "d", "name": "weebo.internal", "aliases": {},
            "subAddressing": {"@type": "Enabled"}, "dkimManagement": {"@type": "Automatic"},
            "dnsManagement": {"@type": "Manual"}, "certificateManagement": {"@type": "Manual"}}]}),
    )
    .await;
    answer(
        &server,
        "x:MailingList/query",
        json!({"filter": {"text": "team"}}),
        json!({"ids": ["l"]}),
    )
    .await;
    answer(
        &server,
        "x:MailingList/get",
        json!({"ids": ["l"]}),
        json!({"list": [{"id": "l", "name": "team", "domainId": "d",
            "emailAddress": "team@weebo.internal", "aliases": {}, "recipients": {}}]}),
    )
    .await;
    server
}

fn input_file(dir: &Path) -> PathBuf {
    let file = dir.join("crs.yaml");
    std::fs::write(&file, INPUT).unwrap();
    file
}

fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("importer-cli-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn importer(url: &str, args: &[&str], kubeconfig: &Path, stdin: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_weebo-stalwart-importer"))
        .args(["--url", url, "--namespace", "mail"])
        .args(args)
        .env("STALWART_TOKEN", "t0ken\n")
        .env("KUBECONFIG", kubeconfig)
        .env_remove("KUBERNETES_SERVICE_HOST")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("importer runs");
    let mut pipe = child.stdin.take().unwrap();
    pipe.write_all(stdin.unwrap_or_default().as_bytes())
        .unwrap();
    drop(pipe);
    child.wait_with_output().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[tokio::test]
async fn prints_the_crs_with_their_seeded_status_without_a_cluster() {
    let server = stalwart().await;
    let dir = scratch("print");
    // No cluster to read: the domain must come with the input (stdin here).
    let out = importer(
        &server.uri(),
        &["-f", "-"],
        &dir.join("no-kubeconfig"),
        Some(INPUT),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("warning: no cluster"),
        "{}",
        stderr(&out)
    );
    let yaml = String::from_utf8(out.stdout).unwrap();
    assert!(yaml.contains("kind: StalwartDomain"), "{yaml}");
    assert!(yaml.contains("remoteId: d"), "{yaml}");
    assert!(yaml.contains("kind: StalwartMailingList"), "{yaml}");
    assert!(yaml.contains("namespace: mail"), "{yaml}");
    assert!(yaml.contains("address: team@weebo.internal"), "{yaml}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn applies_into_the_cluster_and_is_idempotent() {
    let server = stalwart().await;
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let dir = scratch("apply");
    let kubeconfig = dir.join("kubeconfig.yaml");
    cluster.write_kubeconfig(&kubeconfig);
    let ns: k8s_openapi::api::core::v1::Namespace =
        serde_json::from_value(json!({"metadata": {"name": "mail"}})).unwrap();
    Api::all(client.clone())
        .create(&Default::default(), &ns)
        .await
        .unwrap();
    let file = input_file(&dir);
    let file = file.to_str().unwrap();

    let first = importer(&server.uri(), &["-f", file, "--apply"], &kubeconfig, None);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(
        stderr(&first).contains("2 linked, 0 already linked, 0 failed"),
        "{}",
        stderr(&first)
    );
    let domain = Api::<Domain>::all(client.clone())
        .get("weebo.internal")
        .await
        .unwrap();
    assert_eq!(domain.status.unwrap().remote_id.as_deref(), Some("d"));
    let list = Api::<MailingList>::namespaced(client.clone(), "mail")
        .get("team")
        .await
        .unwrap();
    assert_eq!(
        list.status.unwrap().address.as_deref(),
        Some("team@weebo.internal")
    );

    let again = importer(&server.uri(), &["-f", file, "--apply"], &kubeconfig, None);
    assert!(again.status.success(), "{}", stderr(&again));
    assert!(
        stderr(&again).contains("0 linked, 2 already linked, 0 failed"),
        "{}",
        stderr(&again)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn fails_when_an_object_or_the_input_cannot_be_read() {
    // Stalwart knows neither the domain nor the list.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    let dir = scratch("fail");
    let kubeconfig = dir.join("no-kubeconfig");
    let file = input_file(&dir);
    let out = importer(
        &server.uri(),
        &["-f", file.to_str().unwrap()],
        &kubeconfig,
        None,
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("2 CR(s) could not be linked"),
        "{}",
        stderr(&out)
    );

    let missing = dir.join("missing.yaml");
    let out = importer(
        &server.uri(),
        &["-f", missing.to_str().unwrap()],
        &kubeconfig,
        None,
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("reading"), "{}", stderr(&out));

    // `--apply` needs a cluster.
    let out = importer(
        &server.uri(),
        &["-f", file.to_str().unwrap(), "--apply"],
        &kubeconfig,
        None,
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("connecting to Kubernetes"),
        "{}",
        stderr(&out)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
