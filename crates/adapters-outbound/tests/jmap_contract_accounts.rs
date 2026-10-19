//! Contract of `JmapGateway` on `x:Account` and `x:MailingList` against a
//! mock Stalwart: the requests it sends, the answers it maps, and one test
//! per normalization of "Champs comparés" for these objects — the form
//! Stalwart v0.16.27 stores (observed on the image, and checked again by
//! the live suite), read back, in sync.

use adapters_outbound::jmap::SUPPORTED_SCHEMAS;
use adapters_outbound::{JmapClient, JmapGateway};
use application::ports::{GatewayError, GatewayFactoryError, RemoteGateway};
use domain::account::{
    AccountPatch, AccountType, DesiredAccount, OwnedPermissions, PermissionsUpdate,
    RemotePermissions, account_patch,
};
use domain::error::ReasonCode;
use domain::mailing_list::{DesiredMailingList, mailing_list_patch};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "API_test-token";
const APP_TOKEN: &str = "API_app-password-key";
const USING: [&str; 2] = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"];

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
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("/api/schema/{}", SUPPORTED_SCHEMAS[0].0).as_str(),
        ))
        .mount(&server)
        .await;
    server
}

fn gateway(server: &MockServer) -> JmapGateway {
    let http = JmapClient::client_builder().build().unwrap();
    JmapGateway::new(JmapClient::new(&server.uri(), TOKEN, http).unwrap())
}

/// `jmap_method` answered with `args` when the call matches `partial`.
async fn answer(server: &MockServer, jmap_method: &str, partial: Value, args: Value) {
    Mock::given(method("POST"))
        .and(path("/jmap"))
        .and(body_partial_json(
            json!({"methodCalls": [[jmap_method, partial, "0"]]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "methodResponses": [[jmap_method, args, "0"]],
        })))
        .expect(1..)
        .mount(server)
        .await;
}

/// `jmap_method` answered with `args` when the call is exactly `call`.
async fn exactly(server: &MockServer, jmap_method: &str, call: Value, args: Value) {
    Mock::given(method("POST"))
        .and(path("/jmap"))
        .and(body_json(
            json!({"using": USING, "methodCalls": [[jmap_method, call, "0"]]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "methodResponses": [[jmap_method, args, "0"]],
        })))
        .expect(1)
        .mount(server)
        .await;
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// The sending account of the RFC's example.
fn service_account() -> DesiredAccount {
    let mut d = DesiredAccount::new(AccountType::User, "Forgejo", "c", &s(&["NoReply"]));
    d.permissions = Some(OwnedPermissions::service_account(false));
    d
}

/// A mailbox with every owned field.
fn mailbox() -> DesiredAccount {
    let mut d = DesiredAccount::new(AccountType::User, "alice", "c", &s(&["Max"]));
    d.permissions = Some(OwnedPermissions::account(false));
    d.quota = Some(2_147_483_648);
    d.locale = Some("fr-FR".into());
    d.time_zone = Some("Europe/Paris".into());
    d
}

/// `service_account()` as v0.16.27 returns it: names lowercased, the
/// alias with its `description`, `permissions: Merge` with an empty
/// `enabledPermissions`, the default locale, no quota.
fn stored_service_account() -> Value {
    json!({
        "id": "c", "@type": "User", "name": "forgejo", "domainId": "c",
        "emailAddress": "forgejo@weebo.internal",
        "aliases": {"0": {"enabled": true, "name": "noreply", "domainId": "c", "description": null}},
        "roles": {"@type": "User"},
        "permissions": {"enabledPermissions": {}, "disabledPermissions": {
            "imapAuthenticate": true, "pop3Authenticate": true, "sieveAuthenticate": true, "emailReceive": true,
        }, "@type": "Merge"},
        "quotas": {}, "locale": "en-US", "timeZone": null,
    })
}

fn stored_mailbox() -> Value {
    json!({
        "id": "d", "@type": "User", "name": "alice", "domainId": "c",
        "emailAddress": "alice@weebo.internal",
        "aliases": {"0": {"enabled": true, "name": "max", "domainId": "c", "description": "set by hand"}},
        "roles": {"@type": "User"},
        "permissions": {"@type": "Inherit"},
        "quotas": {"maxDiskQuota": 2147483648u64, "maxApiKeys": 5},
        "locale": "fr-FR", "timeZone": "Europe/Paris",
    })
}

async fn read_account(object: Value) -> application::ports::RemoteAccount {
    let server = stalwart().await;
    let id = object["id"].as_str().unwrap().to_string();
    answer(
        &server,
        "x:Account/get",
        json!({"accountId": "b", "ids": [&id]}),
        json!({"list": [object], "notFound": []}),
    )
    .await;
    gateway(&server)
        .get_account(&id)
        .await
        .unwrap()
        .expect("found")
}

#[tokio::test]
async fn a_service_account_is_created_without_credentials_and_disabled_logins() {
    let server = stalwart().await;
    exactly(
        &server,
        "x:Account/set",
        json!({"accountId": "b", "create": {"new": {
            "@type": "User", "name": "forgejo", "domainId": "c",
            "roles": {"@type": "User"}, "encryptionAtRest": {"@type": "Disabled"},
            "aliases": {"0": {"name": "noreply", "domainId": "c", "enabled": true}},
            "permissions": {"@type": "Merge", "disabledPermissions": {
                "imapAuthenticate": true, "pop3Authenticate": true, "sieveAuthenticate": true, "emailReceive": true,
            }},
        }}}),
        json!({"created": {"new": {"id": "c"}}}),
    )
    .await;
    let id = gateway(&server)
        .create_account(&service_account())
        .await
        .unwrap();
    assert_eq!(id, "c");
}

#[tokio::test]
async fn a_mailbox_is_created_inheriting_with_its_quota() {
    let server = stalwart().await;
    exactly(
        &server,
        "x:Account/set",
        json!({"accountId": "b", "create": {"new": {
            "@type": "User", "name": "alice", "domainId": "c",
            "roles": {"@type": "User"}, "encryptionAtRest": {"@type": "Disabled"},
            "aliases": {"0": {"name": "max", "domainId": "c", "enabled": true}},
            "permissions": {"@type": "Inherit"},
            "quotas": {"maxDiskQuota": 2147483648u64},
            "locale": "fr-FR", "timeZone": "Europe/Paris",
        }}}),
        json!({"created": {"new": {"id": "d"}}}),
    )
    .await;
    gateway(&server).create_account(&mailbox()).await.unwrap();
}

#[tokio::test]
async fn a_group_has_no_encryption_at_rest_and_the_default_role() {
    let server = stalwart().await;
    exactly(
        &server,
        "x:Account/set",
        json!({"accountId": "b", "create": {"new": {
            "@type": "Group", "name": "team", "domainId": "c", "roles": {"@type": "Default"},
            "aliases": {},
        }}}),
        json!({"created": {"new": {"id": "e"}}}),
    )
    .await;
    let group = DesiredAccount::new(AccountType::Group, "Team", "c", &[]);
    gateway(&server).create_account(&group).await.unwrap();
}

#[tokio::test]
async fn a_taken_address_is_already_exists() {
    let server = stalwart().await;
    answer(&server, "x:Account/set", json!({"create": {}}), json!({"notCreated": {"new": {
        "type": "primaryKeyViolation", "properties": ["email"], "objectId": {"object": "MailingList", "id": "b"},
    }}})).await;
    let result = gateway(&server).create_account(&service_account()).await;
    assert!(
        matches!(&result, Err(GatewayError::AlreadyExists(m)) if m.contains("MailingList b")),
        "{result:?}"
    );
}

#[tokio::test]
async fn normalization_names_and_aliases_are_stored_lowercased() {
    let read = read_account(stored_service_account()).await;
    assert_eq!(read.email_address, "forgejo@weebo.internal");
    let (patch, drift) = account_patch(&service_account(), &read);
    assert!(drift.is_empty(), "{drift:?}");
    assert_eq!(patch, AccountPatch::default());
}

#[tokio::test]
async fn normalization_an_alias_description_and_other_quotas_are_ignored() {
    let read = read_account(stored_mailbox()).await;
    assert_eq!(read.aliases[0].name, "max");
    assert_eq!(read.quotas["maxApiKeys"], 5);
    assert!(account_patch(&mailbox(), &read).1.is_empty());
}

#[tokio::test]
async fn normalization_the_quota_is_compared_in_bytes() {
    let mut object = stored_mailbox();
    object["quotas"]["maxDiskQuota"] = json!(1073741824u64);
    let read = read_account(object).await;
    let (patch, drift) = account_patch(&mailbox(), &read);
    assert_eq!(drift.fields(), ["quotas"]);
    assert_eq!(patch.quota, Some(2_147_483_648));
}

#[tokio::test]
async fn normalization_the_default_locale_is_no_opinion() {
    let mut desired = mailbox();
    desired.locale = None;
    desired.time_zone = None;
    let mut object = stored_mailbox();
    object["locale"] = json!("en-US");
    object["timeZone"] = Value::Null;
    assert!(
        account_patch(&desired, &read_account(object).await)
            .1
            .is_empty()
    );
}

#[tokio::test]
async fn normalization_permissions_compare_on_the_owned_entries_only() {
    let mut object = stored_service_account();
    object["permissions"]["enabledPermissions"] = json!({"impersonate": true});
    object["permissions"]["disabledPermissions"]["jmapEmailGet"] = json!(true);
    let read = read_account(object).await;
    assert!(account_patch(&service_account(), &read).1.is_empty());
    // A remote `Inherit` disables nothing: an active mailbox is in sync.
    let read = read_account(stored_mailbox()).await;
    assert_eq!(read.permissions, RemotePermissions::Inherit);
    assert!(account_patch(&mailbox(), &read).1.is_empty());
}

#[tokio::test]
async fn an_update_sends_the_drifted_fields_only() {
    let server = stalwart().await;
    let mut object = stored_mailbox();
    object["roles"] = json!({"@type": "Admin"});
    object["quotas"]["maxDiskQuota"] = json!(1);
    answer(
        &server,
        "x:Account/get",
        json!({"ids": ["d"]}),
        json!({"list": [object]}),
    )
    .await;
    let mut locked = mailbox();
    locked.permissions = Some(OwnedPermissions::account(true));
    exactly(
        &server,
        "x:Account/set",
        json!({"accountId": "b", "update": {"d": {
            "roles": {"@type": "User"},
            "permissions": {"@type": "Merge", "enabledPermissions": {}, "disabledPermissions": {
                "authenticate": true, "emailSend": true, "emailReceive": true,
            }},
            "quotas/maxDiskQuota": 2147483648u64,
        }}}),
        json!({"updated": {"d": null}}),
    )
    .await;
    let gw = gateway(&server);
    let (patch, drift) = account_patch(&locked, &gw.get_account("d").await.unwrap().unwrap());
    assert_eq!(drift.fields(), ["roles", "permissions", "quotas"]);
    assert!(matches!(
        patch.permissions,
        Some(PermissionsUpdate::Merge { .. })
    ));
    gw.update_account("d", &patch).await.unwrap();
}

/// The gateway with the App Password key `APP_TOKEN` too.
fn with_app_password_key(server: &MockServer) -> JmapGateway {
    let http = JmapClient::client_builder().build().unwrap();
    gateway(server)
        .with_app_password_client(JmapClient::new(&server.uri(), APP_TOKEN, http).unwrap())
}

/// `jmap_method` with the App Password key, answered with `args` when the
/// call is exactly `call`.
async fn with_key(server: &MockServer, jmap_method: &str, call: Value, args: Value) {
    Mock::given(method("POST"))
        .and(path("/jmap"))
        .and(header(
            "authorization",
            format!("Bearer {APP_TOKEN}").as_str(),
        ))
        .and(body_json(
            json!({"using": USING, "methodCalls": [[jmap_method, call, "0"]]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "methodResponses": [[jmap_method, args, "0"]],
        })))
        .expect(1)
        .mount(server)
        .await;
}

fn app_password_create() -> Value {
    json!({"p": {"description": "weebo-stalwart", "permissions": {
        "@type": "Replace", "permissions": {"authenticate": true, "emailSend": true},
    }}})
}

/// RFC 0001 D24: with the second key, one `x:AppPassword/get` (never the
/// secrets) then one `x:AppPassword/set` creating ours and destroying our
/// earlier ones — never the account's others.
#[tokio::test]
async fn a_rotation_creates_ours_and_destroys_only_our_earlier_ones() {
    let server = stalwart().await;
    with_key(
        &server,
        "x:AppPassword/get",
        json!({"accountId": "c", "properties": ["id", "description"]}),
        json!({"list": [
            {"id": "a", "description": "weebo-stalwart"},
            {"id": "b", "description": "thunderbird"},
            {"id": "d", "description": "weebo-stalwart"},
        ], "notFound": []}),
    )
    .await;
    with_key(
        &server,
        "x:AppPassword/set",
        json!({"accountId": "c", "create": app_password_create(), "destroy": ["a", "d"]}),
        json!({"created": {"p": {"id": "e", "secret": "app_n3w"}}, "destroyed": ["a", "d"]}),
    )
    .await;
    let gw = with_app_password_key(&server);
    gw.app_password_key().await.unwrap();
    assert_eq!(gw.rotate_app_password("c").await.unwrap(), "app_n3w");
}

#[tokio::test]
async fn the_first_app_password_destroys_nothing_and_a_kept_one_is_no_failure() {
    let server = stalwart().await;
    with_key(
        &server,
        "x:AppPassword/get",
        json!({"accountId": "c", "properties": ["id", "description"]}),
        json!({"list": [{"id": "b", "description": "thunderbird"}], "notFound": []}),
    )
    .await;
    with_key(
        &server,
        "x:AppPassword/set",
        json!({"accountId": "c", "create": app_password_create()}),
        json!({"created": {"p": {"id": "e", "secret": "app_first"}}, "notDestroyed": {}}),
    )
    .await;
    assert_eq!(
        with_app_password_key(&server)
            .rotate_app_password("c")
            .await
            .unwrap(),
        "app_first"
    );
}

#[tokio::test]
async fn a_refused_app_password_maps_and_never_quotes_the_answer() {
    let server = stalwart().await;
    answer(&server, "x:AppPassword/get", json!({}), json!({"list": []})).await;
    answer(
        &server,
        "x:AppPassword/set",
        json!({"accountId": "c"}),
        json!({"notCreated": {"p": {"type": "forbidden", "description": "You are not an owner of account c"}}}),
    )
    .await;
    let refused = with_app_password_key(&server)
        .rotate_app_password("c")
        .await;
    assert!(
        matches!(&refused, Err(GatewayError::Unauthorized(m)) if m.contains("not an owner")),
        "{refused:?}"
    );

    let server = stalwart().await;
    answer(&server, "x:AppPassword/get", json!({}), json!({"list": []})).await;
    answer(
        &server,
        "x:AppPassword/set",
        json!({"accountId": "c"}),
        json!({"created": {"p": {"id": "e", "secretHash": "app_hidden"}}}),
    )
    .await;
    let odd = with_app_password_key(&server)
        .rotate_app_password("c")
        .await
        .unwrap_err();
    assert!(!odd.to_string().contains("app_hidden"), "{odd}");
}

/// Without the second key: `TokenSecretMissing`, naming the field, before
/// any call — the other methods unaffected.
#[tokio::test]
async fn without_the_second_key_the_app_password_calls_fail_before_any_call() {
    let server = stalwart().await;
    let gw = gateway(&server);
    for result in [
        gw.app_password_key().await.map(|_| String::new()),
        gw.rotate_app_password("c").await,
    ] {
        let err = result.unwrap_err();
        assert_eq!(err.reason(), ReasonCode::TokenSecretMissing);
        assert!(
            err.to_string().contains("appPasswordTokenSecretRef"),
            "{err}"
        );
    }
    // A key that can't be read: the loader's reason.
    let gw = gateway(&server).with_app_password_key(Box::new(|| {
        Box::pin(async {
            Err(GatewayFactoryError::TokenNotAllowed(
                "appPasswordTokenSecretRef: no label".into(),
            ))
        })
    }));
    assert_eq!(
        gw.rotate_app_password("c").await.unwrap_err().reason(),
        ReasonCode::TokenSecretNotAllowed
    );
    let posts = server.received_requests().await.unwrap_or_default();
    assert!(posts.iter().all(|r| r.url.path() != "/jmap"), "{posts:?}");
}

#[tokio::test]
async fn deletion_tells_gone_from_linked() {
    let server = stalwart().await;
    answer(
        &server,
        "x:Account/set",
        json!({"destroy": ["e"]}),
        json!({"notDestroyed": {"e": {"type": "objectIsLinked", "objectId": {"object": "Account", "id": "e"},
            "linkedObjects": [{"object": "Account", "id": "d"}]}}}),
    )
    .await;
    answer(
        &server,
        "x:Account/set",
        json!({"destroy": ["zz"]}),
        json!({"notDestroyed": {"zz": {"type": "notFound"}}}),
    )
    .await;
    answer(
        &server,
        "x:Account/set",
        json!({"destroy": ["d"]}),
        json!({"destroyed": ["d"]}),
    )
    .await;
    let gw = gateway(&server);
    assert!(matches!(
        gw.delete_account("e").await,
        Err(GatewayError::Linked(_))
    ));
    assert_eq!(gw.delete_account("zz").await, Ok(false));
    assert_eq!(gw.delete_account("d").await, Ok(true));
}

#[tokio::test]
async fn an_account_is_found_by_its_lowercased_name_in_its_domain() {
    let server = stalwart().await;
    answer(
        &server,
        "x:Account/query",
        json!({"filter": {"name": "alice", "domainId": "c"}}),
        json!({"ids": ["d"]}),
    )
    .await;
    assert_eq!(
        gateway(&server).find_account("c", "Alice").await.unwrap(),
        Some("d".into())
    );
}

#[tokio::test]
async fn normalization_recipients_are_a_set_kept_in_the_case_sent() {
    let server = stalwart().await;
    answer(
        &server,
        "x:MailingList/get",
        json!({"ids": ["b"]}),
        json!({"list": [{"id": "b", "name": "team", "domainId": "c", "emailAddress": "team@weebo.internal",
            "aliases": {}, "description": null,
            "recipients": {"Alice@Weebo.Internal": true, "bob@example.com": true}}]}),
    )
    .await;
    let read = gateway(&server)
        .get_mailing_list("b")
        .await
        .unwrap()
        .unwrap();
    let desired = DesiredMailingList::new(
        "Team",
        "c",
        &[],
        &s(&["bob@example.com", "alice@weebo.internal"]),
    );
    assert!(mailing_list_patch(&desired, &read).1.is_empty());
}

#[tokio::test]
async fn a_list_is_created_then_found_by_text_and_matched_exactly() {
    let server = stalwart().await;
    exactly(
        &server,
        "x:MailingList/set",
        json!({"accountId": "b", "create": {"new": {
            "name": "team", "domainId": "c", "aliases": {}, "recipients": {"bob@example.com": true},
        }}}),
        json!({"created": {"new": {"id": "b"}}}),
    )
    .await;
    answer(
        &server,
        "x:MailingList/query",
        json!({"filter": {"text": "team"}}),
        json!({"ids": ["a", "b"]}),
    )
    .await;
    answer(
        &server,
        "x:MailingList/get",
        json!({"ids": ["a"]}),
        json!({"list": [{"id": "a", "name": "team-old", "domainId": "c"}]}),
    )
    .await;
    answer(
        &server,
        "x:MailingList/get",
        json!({"ids": ["b"]}),
        json!({"list": [{"id": "b", "name": "team", "domainId": "c"}]}),
    )
    .await;
    let gw = gateway(&server);
    let desired = DesiredMailingList::new("team", "c", &[], &s(&["bob@example.com"]));
    assert_eq!(gw.create_mailing_list(&desired).await.unwrap(), "b");
    assert_eq!(
        gw.find_mailing_list("c", "Team").await.unwrap(),
        Some("b".into())
    );
    assert_eq!(gw.find_mailing_list("z", "team").await.unwrap(), None);
}

#[tokio::test]
async fn a_list_update_sends_the_drifted_fields_only() {
    let server = stalwart().await;
    answer(
        &server,
        "x:MailingList/get",
        json!({"ids": ["b"]}),
        json!({"list": [{"id": "b", "name": "team", "domainId": "c", "emailAddress": "team@weebo.internal",
            "aliases": {"0": {"name": "crew", "domainId": "c", "enabled": true}},
            "recipients": {"bob@example.com": true}}]}),
    )
    .await;
    // The name and the alias are in sync: only the recipients are sent.
    exactly(
        &server,
        "x:MailingList/set",
        json!({"accountId": "b", "update": {"b": {
            "recipients": {"alice@weebo.internal": true, "bob@example.com": true},
        }}}),
        json!({"updated": {"b": null}}),
    )
    .await;
    let gw = gateway(&server);
    let desired = DesiredMailingList::new(
        "team",
        "c",
        &s(&["crew"]),
        &s(&["bob@example.com", "Alice@weebo.internal"]),
    );
    let read = gw.get_mailing_list("b").await.unwrap().unwrap();
    let (patch, drift) = mailing_list_patch(&desired, &read);
    assert_eq!(drift.fields(), ["recipients"]);
    assert!(!patch.renames());
    gw.update_mailing_list("b", &patch).await.unwrap();
}

#[tokio::test]
async fn a_list_moved_to_another_domain_sends_its_name_domain_and_aliases() {
    let server = stalwart().await;
    exactly(
        &server,
        "x:MailingList/set",
        json!({"accountId": "b", "update": {"b": {
            "name": "crew", "domainId": "d",
            "aliases": {"0": {"name": "team", "domainId": "d", "enabled": true}},
        }}}),
        json!({"notUpdated": {"b": {"type": "primaryKeyViolation", "properties": ["email"]}}}),
    )
    .await;
    let desired = DesiredMailingList::new("crew", "d", &s(&["team"]), &[]);
    let patch = domain::mailing_list::MailingListPatch {
        name: Some(desired.name.clone()),
        domain_id: Some(desired.domain_id.clone()),
        aliases: Some(desired.aliases.clone()),
        recipients: None,
    };
    assert!(patch.renames());
    assert!(matches!(
        gateway(&server).update_mailing_list("b", &patch).await,
        Err(GatewayError::AlreadyExists(_))
    ));
}
