//! Contract of `JmapGateway` against a mock Stalwart: the requests it
//! sends (paths, Bearer, JMAP shape), the answers it maps, and the
//! normalizations of "Champs comparés" — each: the form Stalwart v0.16.27
//! stores, read back, no drift (the live suite checks the same against
//! the real image).

// Test helpers outside `#[test]`: a fixture that does not hold fails
// the test that called it, with its message.
#![expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "test helpers: a panic is a failed test"
)]

use adapters_outbound::jmap::{MAX_BODY_BYTES, SUPPORTED_SCHEMAS};
use adapters_outbound::{JmapClient, JmapGateway};
use application::ports::{GatewayError, RemoteGateway};
use domain::mail_domain::{DesiredDomain, DkimManagement, SubAddressing, domain_patch};
use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "API_test-token";

/// A Stalwart answering the session and the schema.
async fn stalwart(schema: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jmap/session"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "capabilities": {"urn:ietf:params:jmap:core": {}},
            "accounts": {"c": {"name": "weebo-stalwart@weebo.internal"}},
            "primaryAccounts": {"urn:ietf:params:jmap:mail": "c", "urn:stalwart:jmap": "c"},
            "username": "weebo-stalwart@weebo.internal",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/schema"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("/api/schema/{schema}").as_str()),
        )
        .mount(&server)
        .await;
    server
}

fn supported() -> &'static str {
    SUPPORTED_SCHEMAS[0].0
}

fn gateway(server: &MockServer) -> JmapGateway {
    let http = JmapClient::client_builder().build().unwrap();
    JmapGateway::new(JmapClient::new(&server.uri(), TOKEN, http).unwrap())
}

/// `method` answered with `args` when the call matches `partial`.
async fn answer(server: &MockServer, jmap_method: &str, partial: Value, args: Value) {
    Mock::given(method("POST"))
        .and(path("/jmap"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(body_partial_json(json!({
            "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
            "methodCalls": [[jmap_method, partial, "0"]],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "methodResponses": [[jmap_method, args, "0"]], "sessionState": "s",
        })))
        .expect(1..)
        .mount(server)
        .await;
}

/// A domain as v0.16.27 returns it after creating `desired()`: name and
/// catch-all lowercased, aliases as sent (a set: a map to `true`),
/// `dkimManagement: Automatic` filled with the server's parameters.
fn stored() -> Value {
    json!({
        "id": "b",
        "name": "weebo.internal",
        "aliases": {"Weebo.Lan": true},
        "catchAllAddress": "all@weebo.internal",
        "allowRelaying": false,
        "subAddressing": {"@type": "Enabled"},
        "dkimManagement": {
            "algorithms": {"Dkim1Ed25519Sha256": true, "Dkim1RsaSha256": true},
            "selectorTemplate": "v{version}-{algorithm}-{date-%Y%m%d}",
            "rotateAfter": 7776000000u64, "retireAfter": 604800000, "deleteAfter": 2592000000u64,
            "@type": "Automatic"
        },
        "dnsManagement": {"@type": "Manual"},
        "certificateManagement": {"@type": "Manual"},
    })
}

fn desired() -> DesiredDomain {
    DesiredDomain::new(
        "Weebo.Internal",
        &["weebo.lan".into()],
        Some("All"),
        SubAddressing::Enabled,
        DkimManagement::Automatic,
    )
}

async fn read_back(object: Value) -> application::ports::RemoteDomain {
    let server = stalwart(supported()).await;
    answer(
        &server,
        "x:Domain/get",
        json!({"accountId": "c", "ids": ["b"]}),
        json!({"accountId": "c", "list": [object], "notFound": []}),
    )
    .await;
    gateway(&server)
        .get_domain("b")
        .await
        .unwrap()
        .expect("found")
}

#[tokio::test]
async fn ping_checks_the_token_and_the_schema() {
    let server = stalwart(supported()).await;
    gateway(&server).ping().await.unwrap();
}

#[tokio::test]
async fn an_unknown_schema_is_an_unsupported_version_and_nothing_is_called() {
    let server = stalwart("aJJKvnpsjjwAEzJ0eKDWdfSLK_RvBKsLhk8BwCq-7qA").await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let gw = gateway(&server);
    assert!(
        matches!(gw.ping().await, Err(GatewayError::UnsupportedVersion(m)) if m.contains("aJJKvnps"))
    );
    assert!(matches!(
        gw.get_domain("b").await,
        Err(GatewayError::UnsupportedVersion(_))
    ));
}

#[tokio::test]
async fn a_server_without_the_schema_redirect_is_not_supported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jmap/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"primaryAccounts": {"urn:stalwart:jmap": "c"}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/schema"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    assert!(matches!(
        gateway(&server).ping().await,
        Err(GatewayError::UnsupportedVersion(_))
    ));
}

#[tokio::test]
async fn a_refused_token_is_unauthorized() {
    let server = MockServer::start().await;
    for status in [401, 403] {
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(status).set_body_json(
                json!({"status": status, "detail": "You have to authenticate first."}),
            ))
            .mount(&server)
            .await;
        assert!(
            matches!(
                gateway(&server).ping().await,
                Err(GatewayError::Unauthorized(_))
            ),
            "{status}"
        );
    }
}

#[tokio::test]
async fn an_unreachable_server_is_unreachable() {
    // Port 9 (discard): nothing listens there.
    let uri = "http://127.0.0.1:9";
    let http = JmapClient::client_builder().build().unwrap();
    let gw = JmapGateway::new(JmapClient::new(uri, TOKEN, http).unwrap());
    assert!(matches!(gw.ping().await, Err(GatewayError::Unreachable(_))));
    let server = stalwart(supported()).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    assert!(matches!(
        gateway(&server).get_domain("b").await,
        Err(GatewayError::Unreachable(_))
    ));
}

#[tokio::test]
async fn an_oversized_answer_is_refused_not_read_whole() {
    let server = stalwart(supported()).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; MAX_BODY_BYTES + 1]))
        .mount(&server)
        .await;
    assert!(
        matches!(gateway(&server).get_domain("b").await, Err(GatewayError::Api(m)) if m.contains("larger than"))
    );
    // An error's body is cut, its status still decides.
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_bytes(vec![b'x'; MAX_BODY_BYTES + 1]))
        .mount(&server)
        .await;
    assert!(
        matches!(gateway(&server).ping().await, Err(GatewayError::Unauthorized(m)) if m.len() < 300)
    );
}

#[tokio::test]
async fn a_method_level_forbidden_is_unauthorized() {
    let server = stalwart(supported()).await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "methodResponses": [["error", {"type": "forbidden", "description": "You are not authorized to destroy objects of this type"}, "0"]],
    }))).mount(&server).await;
    assert!(
        matches!(gateway(&server).get_domain("b").await, Err(GatewayError::Unauthorized(m)) if m.contains("not authorized"))
    );
}

#[tokio::test]
async fn a_read_asks_for_the_compared_fields_and_maps_them() {
    let remote = read_back(stored()).await;
    assert_eq!(remote.name, "weebo.internal");
    assert_eq!(remote.aliases, ["Weebo.Lan"]);
    assert_eq!(remote.catch_all.as_deref(), Some("all@weebo.internal"));
    assert_eq!(
        (remote.sub_addressing.as_str(), remote.dkim.as_str()),
        ("Enabled", "Automatic")
    );
}

#[tokio::test]
async fn an_unknown_id_reads_as_none() {
    let server = stalwart(supported()).await;
    answer(
        &server,
        "x:Domain/get",
        json!({"ids": ["zz"]}),
        json!({"list": [], "notFound": ["zz"]}),
    )
    .await;
    assert_eq!(gateway(&server).get_domain("zz").await.unwrap(), None);
}

#[tokio::test]
async fn normalization_the_name_is_stored_lowercased() {
    let (patch, drift) = domain_patch(&desired(), &read_back(stored()).await);
    assert!(drift.is_empty(), "{drift:?}");
    assert_eq!(patch.name, None);
}

#[tokio::test]
async fn normalization_the_catch_all_is_stored_lowercased() {
    let mut object = stored();
    object["catchAllAddress"] = json!("all@weebo.internal");
    let desired = DesiredDomain::new(
        "weebo.internal",
        &["weebo.lan".into()],
        Some("ALL"),
        SubAddressing::Enabled,
        DkimManagement::Automatic,
    );
    assert!(
        domain_patch(&desired, &read_back(object).await)
            .1
            .is_empty()
    );
}

#[tokio::test]
async fn normalization_aliases_are_a_set_kept_in_the_case_sent() {
    let mut object = stored();
    object["aliases"] = json!({"WEEBO.lan": true, "gone.example": false});
    assert!(
        domain_patch(&desired(), &read_back(object).await)
            .1
            .is_empty()
    );
}

#[tokio::test]
async fn normalization_automatic_dkim_parameters_are_no_opinion() {
    let mut object = stored();
    object["dkimManagement"]["rotateAfter"] = json!(1);
    object["dkimManagement"]["algorithms"] = json!({"Dkim1RsaSha256": true});
    assert!(
        domain_patch(&desired(), &read_back(object).await)
            .1
            .is_empty()
    );
}

#[tokio::test]
async fn normalization_variants_compare_by_type() {
    let mut object = stored();
    object["subAddressing"] = json!({"@type": "Custom", "customRule": {"else": "rcpt"}});
    let (patch, drift) = domain_patch(&desired(), &read_back(object).await);
    assert_eq!(drift.fields(), ["subAddressing"]);
    assert_eq!(patch.sub_addressing, Some(SubAddressing::Enabled));
}

#[tokio::test]
async fn a_creation_sends_every_owned_field() {
    let server = stalwart(supported()).await;
    answer(
        &server,
        "x:Domain/set",
        json!({"accountId": "c", "create": {"new": {
            "name": "weebo.internal", "aliases": {"weebo.lan": true}, "catchAllAddress": "all@weebo.internal",
            "allowRelaying": false, "subAddressing": {"@type": "Enabled"}, "dkimManagement": {"@type": "Automatic"},
            "dnsManagement": {"@type": "Manual"}, "certificateManagement": {"@type": "Manual"},
        }}}),
        json!({"accountId": "c", "created": {"new": {"id": "b"}}}),
    )
    .await;
    assert_eq!(
        gateway(&server).create_domain(&desired()).await.unwrap(),
        "b"
    );
}

#[tokio::test]
async fn a_taken_name_is_already_exists() {
    let server = stalwart(supported()).await;
    answer(&server, "x:Domain/set", json!({"create": {}}), json!({"notCreated": {"new": {
        "type": "primaryKeyViolation", "properties": ["name"], "objectId": {"object": "Domain", "id": "b"},
    }}})).await;
    assert!(
        matches!(gateway(&server).create_domain(&desired()).await, Err(GatewayError::AlreadyExists(m)) if m.contains("Domain b"))
    );
}

#[tokio::test]
async fn a_name_stalwart_refuses_is_invalid() {
    let server = stalwart(supported()).await;
    answer(
        &server,
        "x:Domain/set",
        json!({"create": {}}),
        json!({"notCreated": {"new": {
            "type": "invalidPatch", "description": "Invalid domain name", "properties": ["name"],
        }}}),
    )
    .await;
    assert!(
        matches!(gateway(&server).create_domain(&desired()).await, Err(GatewayError::Invalid(m)) if m.contains("Invalid domain name"))
    );
}

#[tokio::test]
async fn an_update_sends_the_drifted_fields_only() {
    let server = stalwart(supported()).await;
    let mut object = stored();
    object["subAddressing"] = json!({"@type": "Disabled"});
    object["aliases"] = json!({});
    answer(
        &server,
        "x:Domain/get",
        json!({"ids": ["b"]}),
        json!({"list": [object]}),
    )
    .await;
    // Exactly the two fields: the body is matched whole.
    Mock::given(method("POST"))
        .and(path("/jmap"))
        .and(wiremock::matchers::body_json(json!({
            "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
            "methodCalls": [["x:Domain/set", {"accountId": "c", "update": {"b": {
                "aliases": {"weebo.lan": true}, "subAddressing": {"@type": "Enabled"},
            }}}, "0"]],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "methodResponses": [["x:Domain/set", {"updated": {"b": null}}, "0"]],
        })))
        .expect(1)
        .mount(&server)
        .await;
    let gw = gateway(&server);
    let (patch, drift) = domain_patch(&desired(), &gw.get_domain("b").await.unwrap().unwrap());
    assert_eq!(drift.fields(), ["aliases", "subAddressing"]);
    gw.update_domain("b", &patch).await.unwrap();
}

#[tokio::test]
async fn an_update_of_a_gone_domain_is_not_found() {
    let server = stalwart(supported()).await;
    answer(
        &server,
        "x:Domain/set",
        json!({"update": {}}),
        json!({"notUpdated": {"b": {"type": "notFound"}}}),
    )
    .await;
    let patch = domain::mail_domain::DomainPatch {
        allow_relaying: Some(false),
        ..Default::default()
    };
    assert!(matches!(
        gateway(&server).update_domain("b", &patch).await,
        Err(GatewayError::NotFound(_))
    ));
}

#[tokio::test]
async fn find_queries_the_exact_lowercased_name() {
    let server = stalwart(supported()).await;
    answer(
        &server,
        "x:Domain/query",
        json!({"filter": {"name": "weebo.internal"}}),
        json!({"ids": ["b"]}),
    )
    .await;
    assert_eq!(
        gateway(&server)
            .find_domain("Weebo.Internal")
            .await
            .unwrap()
            .as_deref(),
        Some("b")
    );
}

#[tokio::test]
async fn the_session_is_read_once_per_gateway() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jmap/session"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"primaryAccounts": {"urn:stalwart:jmap": "c"}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/schema"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("/api/schema/{}", supported()).as_str()),
        )
        .expect(1)
        .mount(&server)
        .await;
    answer(
        &server,
        "x:Domain/get",
        json!({"ids": ["b"]}),
        json!({"list": [stored()]}),
    )
    .await;
    let gw = gateway(&server);
    gw.ping().await.unwrap();
    gw.get_domain("b").await.unwrap();
    gw.get_domain("b").await.unwrap();
}
