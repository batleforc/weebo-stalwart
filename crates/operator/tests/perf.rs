//! What the operator costs a cluster (weebo-kit-perf): the release binary
//! against envtest and a fake Stalwart (an in-memory JMAP `x:Domain` /
//! `x:MailingList` store). One `StalwartDomain`, then a warm-up cycle, an
//! idle baseline, then a measured cycle — a burst of
//! `StalwartMailingList`s (an alias each: its address and its alias are
//! both claimed), an idle window with all of them in place, a spec churn
//! on all of them, their deletion (`deletionPolicy: Delete`) — and a final
//! idle window, checked against the kit's small-cluster budget.
//!
//! `task perf` runs it. Tunable: `PERF_OBJECTS` (default 200),
//! `PERF_IDLE_SECS` (default 30); `WEEBO_PERF_REPORT_ONLY=1` reports
//! without failing; `WEEBO_PERF_BASELINE=<previous json>` adds the change
//! from a previous run. The report lands in `target/perf/`.

// Test helpers outside `#[test]`: a fixture that does not hold fails
// the test that called it, with its message.
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test helpers: a panic is a failed test"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api::{Domain, Instance, MailingList};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, PostParams};
use serde_json::{Map, Value, json};
use weebo_kit_perf::{BASELINE, Budget, FINAL, OperatorMetrics, PerfRun, Workload, names};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The management schema this release speaks (`SUPPORTED_SCHEMAS`).
const SCHEMA_HASH: &str = "Pzykh-dZ4p6qVJ7wVulQvyF7-1aRB8fI6GcjdJMWK2Q";

/// The objects of one type, by id.
type Objects = BTreeMap<String, Map<String, Value>>;

/// The objects of the fake Stalwart, by type then id.
#[derive(Default)]
struct Store {
    objects: Mutex<BTreeMap<&'static str, Objects>>,
    next_id: Mutex<u64>,
}

impl Store {
    /// `x:<Type>/<verb>`, answered as Stalwart does for what the operator
    /// sends: `get` by ids, `query` by `name`/`text`, `set` with one
    /// create, update or destroy.
    fn call(&self, method: &str, args: &Value) -> Value {
        let (kind, verb) = match method.split_once('/') {
            Some(("x:Domain", verb)) => ("Domain", verb),
            Some(("x:MailingList", verb)) => ("MailingList", verb),
            _ => return json!(["error", {"type": "unknownMethod"}]),
        };
        let mut objects = self.objects.lock().unwrap();
        let domain_names: BTreeMap<String, String> = objects
            .get("Domain")
            .into_iter()
            .flatten()
            .map(|(id, d)| (id.clone(), d["name"].as_str().unwrap_or("").to_string()))
            .collect();
        let of_kind = objects.entry(kind).or_default();
        let args = match verb {
            "get" => {
                let list: Vec<Value> = args["ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|id| of_kind.get(id.as_str()?))
                    .map(|o| {
                        let mut o = o.clone();
                        if kind == "MailingList" {
                            let domain = domain_names
                                .get(o["domainId"].as_str().unwrap_or(""))
                                .cloned()
                                .unwrap_or_default();
                            let address = format!("{}@{domain}", o["name"].as_str().unwrap_or(""));
                            o.insert("emailAddress".into(), address.into());
                        }
                        Value::Object(o)
                    })
                    .collect();
                json!({"list": list})
            }
            "query" => {
                let wanted = args["filter"]["name"]
                    .as_str()
                    .or_else(|| args["filter"]["text"].as_str())
                    .unwrap_or_default();
                let ids: Vec<&String> = of_kind
                    .iter()
                    .filter(|(_, o)| o["name"].as_str() == Some(wanted))
                    .map(|(id, _)| id)
                    .collect();
                json!({"ids": ids})
            }
            "set" => {
                if let Some(Value::Object(new)) = args.pointer("/create/new") {
                    let taken = of_kind.values().any(|o| {
                        o["name"] == new["name"] && o.get("domainId") == new.get("domainId")
                    });
                    if taken {
                        json!({"notCreated": {"new": {"type": "primaryKeyViolation"}}})
                    } else {
                        let mut next = self.next_id.lock().unwrap();
                        *next = next.saturating_add(1);
                        let id = format!("i{next}");
                        let mut object = new.clone();
                        object.insert("id".into(), id.clone().into());
                        of_kind.insert(id.clone(), object);
                        json!({"created": {"new": {"id": id}}})
                    }
                } else if let Some(Value::Object(update)) = args.get("update") {
                    let (id, patch) = update.iter().next().expect("one update");
                    match of_kind.get_mut(id) {
                        Some(object) => {
                            for (k, v) in patch.as_object().into_iter().flatten() {
                                object.insert(k.clone(), v.clone());
                            }
                            json!({"updated": {id: null}})
                        }
                        None => json!({"notUpdated": {id: {"type": "notFound"}}}),
                    }
                } else {
                    let id = args.pointer("/destroy/0").and_then(Value::as_str);
                    match id.and_then(|id| of_kind.remove(id).map(|_| id)) {
                        Some(id) => json!({"destroyed": [id]}),
                        None => json!({"notDestroyed": {id.unwrap_or(""): {"type": "notFound"}}}),
                    }
                }
            }
            _ => return json!(["error", {"type": "unknownMethod"}]),
        };
        json!([method, args, "0"])
    }
}

/// `POST /jmap`: the method call, on the store.
struct Jmap(Arc<Store>);

impl Respond for Jmap {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let call = &body["methodCalls"][0];
        let reply = self.0.call(call[0].as_str().unwrap_or_default(), &call[1]);
        ResponseTemplate::new(200).set_body_json(json!({"methodResponses": [reply]}))
    }
}

async fn fake_stalwart() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jmap/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"primaryAccounts": {"urn:stalwart:jmap": "a"}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/schema"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("/api/schema/{SCHEMA_HASH}").as_str()),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/jmap"))
        .respond_with(Jmap(Arc::default()))
        .mount(&server)
        .await;
    server
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn from_json<K: serde::de::DeserializeOwned>(value: Value) -> K {
    serde_json::from_value(value).unwrap()
}

fn list(name: &str) -> MailingList {
    from_json(json!({
        "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartMailingList",
        "metadata": {"name": name, "namespace": "default"},
        "spec": {
            "instanceRef": {"name": "perf"},
            "domainRef": {"name": "perf.internal"},
            "aliases": [format!("{name}-alias")],
            "recipients": [{"address": "ops@example.org"}],
        },
    }))
}

/// `Ready: True` for the current generation.
fn converged(l: &MailingList) -> bool {
    let Some(status) = &l.status else {
        return false;
    };
    status.observed_generation == l.metadata.generation
        && status
            .conditions
            .iter()
            .any(|c| c.type_ == "Ready" && c.status == "True")
}

async fn burst(lists: &Workload<MailingList>, names: &[String], timeout: Duration) -> Duration {
    let objects: Vec<_> = names.iter().map(|n| list(n)).collect();
    let started = std::time::Instant::now();
    lists.create(&objects).await;
    lists.wait_all(names, timeout, converged).await;
    started.elapsed()
}

async fn churn(
    lists: &Workload<MailingList>,
    names: &[String],
    round: u32,
    timeout: Duration,
) -> Duration {
    let started = std::time::Instant::now();
    lists
        .patch_all(names, |_| {
            json!({"spec": {"recipients": [{"address": format!("round-{round}@example.org")}]}})
        })
        .await;
    lists.wait_all(names, timeout, converged).await;
    started.elapsed()
}

async fn delete(lists: &Workload<MailingList>, names: &[String], timeout: Duration) -> Duration {
    let started = std::time::Instant::now();
    lists.delete_all(names).await;
    lists.wait_gone(names, timeout).await;
    started.elapsed()
}

/// Creates every object, idles with them in place (`loaded`, when `idle`
/// is set), changes every spec, deletes them all.
async fn cycle(
    run: &mut PerfRun,
    lists: &Workload<MailingList>,
    all: &[String],
    label: &str,
    round: u32,
    idle: Option<Duration>,
    timeout: Duration,
) {
    let n = all.len();
    run.load(&format!("{label} burst"), n, burst(lists, all, timeout))
        .await;
    if let Some(idle) = idle {
        run.idle(&format!("{label} loaded"), idle).await;
    }
    run.load(
        &format!("{label} churn"),
        n,
        churn(lists, all, round, timeout),
    )
    .await;
    run.load(&format!("{label} delete"), n, delete(lists, all, timeout))
        .await;
}

#[tokio::test]
#[ignore = "a perf run (minutes, release build): `task perf`"]
async fn the_operator_fits_a_small_cluster() {
    // Err: another test installed it first, which is as good.
    tracing_subscriber::fmt().with_test_writer().try_init().ok();
    let objects = usize::try_from(env_or("PERF_OBJECTS", 200)).expect("PERF_OBJECTS fits a usize");
    let idle = Duration::from_secs(env_or("PERF_IDLE_SECS", 30));
    let timeout = Duration::from_secs(300);

    let cluster = testkit::envtest::start().await;
    let stalwart = fake_stalwart().await;
    let client = cluster.client();

    // The instance every object goes through, and the domain of the lists.
    Api::<Secret>::namespaced(client.clone(), "default")
        .create(
            &PostParams::default(),
            &from_json(json!({
                "metadata": {"name": "stalwart-token"},
                "stringData": {"token": "perf"},
            })),
        )
        .await
        .unwrap();
    Api::<Instance>::all(client.clone())
        .create(
            &PostParams::default(),
            &from_json(json!({
                "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartInstance",
                "metadata": {"name": "perf"},
                "spec": {
                    "url": stalwart.uri(),
                    "tokenSecretRef": {"name": "stalwart-token", "namespace": "default", "key": "token"},
                },
            })),
        )
        .await
        .unwrap();

    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_weebo-stalwart-operator"));
    command.env("RUST_LOG", "warn");
    let mut run = PerfRun::start(
        "weebo-stalwart",
        &cluster,
        command,
        OperatorMetrics::new("weebo_stalwart"),
    )
    .await;

    let domains = run.workload(Api::<Domain>::all(client.clone()));
    domains
        .create(&[from_json(json!({
            "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartDomain",
            "metadata": {"name": "perf.internal"},
            "spec": {"instanceRef": {"name": "perf"}},
        }))])
        .await;
    domains
        .wait_all(&["perf.internal".to_string()], timeout, |d: &Domain| {
            d.status.as_ref().is_some_and(|s| {
                s.conditions
                    .iter()
                    .any(|c| c.type_ == "Ready" && c.status == "True")
            })
        })
        .await;
    let lists = run.workload(Api::<MailingList>::namespaced(client.clone(), "default"));

    run.idle("startup", idle).await;
    // The warm-up is a whole cycle at full size: the baseline must follow a
    // process that already filled its caches, pools and allocator arenas to
    // what this load needs, or the next cycle's fill reads as a leak.
    let all = names("list", objects);
    cycle(&mut run, &lists, &all, "warm-up", 1, None, timeout).await;
    run.idle(BASELINE, idle).await;
    cycle(&mut run, &lists, &all, "cycle", 2, Some(idle), timeout).await;
    run.idle(FINAL, idle).await;

    run.finish().await.assert_within(&Budget::small_cluster());
}
