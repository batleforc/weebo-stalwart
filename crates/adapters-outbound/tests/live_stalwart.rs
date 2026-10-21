//! Live contract of `JmapGateway` against a real Stalwart v0.16.27
//! (`task stalwart:container:start ENGINE=podman`, then
//! `task test:live-stalwart`): every normalization of "Champs comparés"
//! read back from the server itself — a domain created then read compares
//! as in sync ("reste silencieux" against the image, RFC 0003 rule 3) —
//! and the spike's questions the image answers (RFC 0001, Q1, Q10, D13,
//! D18, D19), as tests that keep answering them on every new image.
//!
//! Ignored by default: run with `--ignored`, one test at a time is not
//! needed (each uses its own domain).

// Test helpers outside `#[test]`: a fixture that does not hold fails
// the test that called it, with its message.
#![expect(clippy::unwrap_used, reason = "test helpers: a panic is a failed test")]

use adapters_outbound::jmap::SUPPORTED_SCHEMAS;
use adapters_outbound::{JmapClient, JmapGateway};
use application::ports::{GatewayError, RemoteGateway};
use domain::mail_domain::{
    DesiredDomain, DkimManagement, DomainPatch, SubAddressing, domain_patch,
};
use serde_json::json;
use testkit::LiveStalwart;

/// The operator's gateway: its main key, and its App Password key.
fn gateway(live: &LiveStalwart) -> JmapGateway {
    let http = JmapClient::client_builder().build().unwrap();
    let app_passwords =
        JmapClient::new(&live.url, live.app_password_token.clone(), http.clone()).unwrap();
    JmapGateway::new(JmapClient::new(&live.url, live.token.clone(), http).unwrap())
        .with_app_password_client(app_passwords)
}

/// A desired domain exercising every normalization: mixed-case name,
/// aliases and catch-all, `Automatic` DKIM (parameters filled by the
/// server), sub-addressing disabled.
fn desired(name: &str) -> DesiredDomain {
    DesiredDomain::new(
        &name.to_uppercase(),
        &[format!("Alias.{name}"), format!("other-{name}")],
        Some("Catch.All"),
        SubAddressing::Disabled,
        DkimManagement::Automatic,
    )
}

#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn ping_accepts_the_bootstrapped_key_and_the_schema() {
    let live = LiveStalwart::from_env();
    gateway(&live).ping().await.unwrap();
}

/// Q10 / D13: the hash the image serves is the one the operator ships.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn spike_the_image_serves_a_supported_schema_hash() {
    let live = LiveStalwart::from_env();
    let http = JmapClient::client_builder().build().unwrap();
    let client = JmapClient::new(&live.url, live.token.clone(), http).unwrap();
    let hash = client.schema_hash().await.unwrap();
    assert_eq!(hash, SUPPORTED_SCHEMAS[0].0);
}

#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn a_created_domain_reads_back_in_sync_then_drift_is_corrected() {
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let name = LiveStalwart::unique_domain("quiet");
    let desired = desired(&name);

    let id = gw.create_domain(&desired).await.unwrap();
    let stored = gw.get_domain(&id).await.unwrap().expect("created");
    // The server's own forms: name and catch-all lowercased, aliases as
    // sent (normalized here before sending), DKIM parameters filled.
    assert_eq!(stored.name, name);
    assert_eq!(stored.catch_all, Some(format!("catch.all@{name}")));
    assert_eq!(stored.dkim, "Automatic");
    let (patch, drift) = domain_patch(&desired, &stored);
    assert!(drift.is_empty(), "drift right after creation: {drift:?}");
    assert_eq!(patch, DomainPatch::default());
    assert_eq!(
        gw.find_domain(&name.to_uppercase()).await.unwrap(),
        Some(id.clone())
    );

    // A hand edit behind the operator's back, aliases in another case and
    // DKIM parameters changed: only the real drift comes back.
    live.admin_call(
        "x:Domain/set",
        json!({"update": {&id: {
            "aliases": {format!("ALIAS.{name}"): true, format!("other-{name}"): true, "by-hand.example": true},
            "subAddressing": {"@type": "Enabled"},
            "allowRelaying": true,
            "dkimManagement/rotateAfter": 86400000,
        }}}),
    )
    .await;
    let edited = gw.get_domain(&id).await.unwrap().unwrap();
    let (patch, drift) = domain_patch(&desired, &edited);
    assert_eq!(
        drift.fields(),
        ["aliases", "allowRelaying", "subAddressing"]
    );
    gw.update_domain(&id, &patch).await.unwrap();
    let corrected = gw.get_domain(&id).await.unwrap().unwrap();
    assert!(
        domain_patch(&desired, &corrected).1.is_empty(),
        "{corrected:?}"
    );

    // Manual → Automatic DKIM: the variant alone is sent, the server fills
    // its parameters, and the result compares in sync.
    let manual = DesiredDomain {
        dkim: DkimManagement::Manual,
        ..desired.clone()
    };
    let (patch, _) = domain_patch(&manual, &corrected);
    gw.update_domain(&id, &patch).await.unwrap();
    let (patch, drift) = domain_patch(&desired, &gw.get_domain(&id).await.unwrap().unwrap());
    assert_eq!(drift.fields(), ["dkimManagement"]);
    gw.update_domain(&id, &patch).await.unwrap();
    assert!(
        domain_patch(&desired, &gw.get_domain(&id).await.unwrap().unwrap())
            .1
            .is_empty()
    );

    // A rename with its catch-all, in one patch (the catch-all must stay in
    // the domain: Stalwart checks it against the new name).
    let renamed_name = LiveStalwart::unique_domain("renamed");
    let renamed = DesiredDomain::new(
        &renamed_name,
        &desired.aliases,
        Some("catch.all"),
        SubAddressing::Disabled,
        DkimManagement::Automatic,
    );
    let (patch, drift) = domain_patch(&renamed, &gw.get_domain(&id).await.unwrap().unwrap());
    assert_eq!(drift.fields(), ["name", "catchAllAddress"]);
    gw.update_domain(&id, &patch).await.unwrap();
    assert!(
        domain_patch(&renamed, &gw.get_domain(&id).await.unwrap().unwrap())
            .1
            .is_empty()
    );

    live.destroy_domain(&renamed_name).await;
    assert_eq!(gw.get_domain(&id).await.unwrap(), None);
}

#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn a_taken_name_is_already_exists() {
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let name = LiveStalwart::unique_domain("taken");
    gw.create_domain(&desired(&name)).await.unwrap();
    let again = gw.create_domain(&desired(&name)).await;
    assert!(
        matches!(again, Err(GatewayError::AlreadyExists(_))),
        "{again:?}"
    );
    live.destroy_domain(&name).await;
}

/// Spike: v0.16.27 refuses a domain whose top-level label it doesn't
/// know — RFC 0001's `weebo.poc` included — and accepts the special-use
/// ones.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn spike_stalwart_refuses_an_unknown_top_level_domain() {
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    for refused in ["weebo.poc", "weebo.abcd"] {
        let result = gw
            .create_domain(&DesiredDomain::new(
                refused,
                &[],
                None,
                SubAddressing::Enabled,
                DkimManagement::Manual,
            ))
            .await;
        assert!(
            matches!(&result, Err(GatewayError::Invalid(m)) if m.contains("Invalid domain name")),
            "{refused}: {result:?}"
        );
    }
    for accepted in ["internal", "lan", "test"] {
        let name = LiveStalwart::unique_domain("tld").replace(".internal", &format!(".{accepted}"));
        gw.create_domain(&DesiredDomain::new(
            &name,
            &[],
            None,
            SubAddressing::Enabled,
            DkimManagement::Manual,
        ))
        .await
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        live.destroy_domain(&name).await;
    }
}

/// D19: ids are short per-type sequences (`"b"`, `"c"`…): a fresh store
/// hands the same ids out again.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn spike_ids_are_short_sequential_strings() {
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let (a, b) = (
        LiveStalwart::unique_domain("seq-a"),
        LiveStalwart::unique_domain("seq-b"),
    );
    let first = gw.create_domain(&desired(&a)).await.unwrap();
    let second = gw.create_domain(&desired(&b)).await.unwrap();
    assert!(first.len() <= 3 && second.len() <= 3, "{first} {second}");
    assert_ne!(first, second);
    live.destroy_domain(&a).await;
    live.destroy_domain(&b).await;
}

/// D18 and Q1: what the bootstrapped key may and may not do.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn spike_the_operator_key_permissions() {
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let name = LiveStalwart::unique_domain("perms");
    let domain = gw.create_domain(&desired(&name)).await.unwrap();

    // D18: no `sysDomainDestroy`, a domain is never destroyed with it.
    let destroy = live
        .token_call("x:Domain/set", json!({"destroy": [&domain]}))
        .await;
    assert_eq!(destroy["type"], "forbidden", "{destroy}");

    // Creating a `User` account works only because the key holds every
    // permission of the User role: a key can't grant what it lacks.
    let created = live
        .token_call(
            "x:Account/set",
            json!({"create": {"u": {"@type": "User", "name": "alice", "domainId": &domain}}}),
        )
        .await;
    let account = created["created"]["u"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{created}"))
        .to_string();

    // It may not make an account an administrator.
    let admin = live
        .token_call(
            "x:Account/set",
            json!({"update": {&account: {"roles": {"@type": "Admin"}}}}),
        )
        .await;
    assert_eq!(
        admin["notUpdated"][&account]["type"], "forbidden",
        "{admin}"
    );

    // Q1, blast radius: `sysAccountUpdate` sets any account's password —
    // whoever holds the key can then log in as that user and read the
    // mailbox.
    let password = "Live-test-password-0123456789";
    let set = live
        .token_call("x:Account/set", json!({"update": {&account: {"credentials": {"0": {"@type": "Password", "secret": password}}}}}))
        .await;
    assert!(set["updated"].get(&account).is_some(), "{set}");
    let session = reqwest::Client::new()
        .get(format!("{}/jmap/session", live.url))
        .basic_auth(format!("alice@{name}"), Some(password))
        .send()
        .await
        .unwrap();
    assert_eq!(session.status(), 200, "the password set by the key logs in");

    live.destroy_domain(&name).await;
}

// ── Accounts, groups, lists ──────────────────────────────────────────────────

mod accounts {
    use domain::account::{
        AccountPatch, AccountType, DesiredAccount, OwnedPermissions, RemotePermissions,
        account_patch,
    };
    use domain::mailing_list::{DesiredMailingList, mailing_list_patch};

    use super::*;

    const PASSWORD: &str = "Live-test-password-0123456789";

    /// A fresh domain (`Manual` DKIM: nothing to clean up but itself): its
    /// name and id.
    async fn domain(gw: &JmapGateway, prefix: &str) -> (String, String) {
        let name = LiveStalwart::unique_domain(prefix);
        let id = gw
            .create_domain(&DesiredDomain::new(
                &name,
                &[],
                None,
                SubAddressing::Enabled,
                DkimManagement::Manual,
            ))
            .await
            .unwrap();
        (name, id)
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// Every normalization of a sending account read back from the server,
    /// in sync right after creation; its App Password (RFC 0001 D24) logs
    /// in, rotates — the old one stops working, its user's own App Password
    /// doesn't —; hand edits come back as drift, only them.
    #[tokio::test]
    #[ignore = "needs a real Stalwart: task stalwart:container:start"]
    async fn a_service_account_reads_back_in_sync_logs_in_and_rotates() {
        let live = LiveStalwart::from_env();
        let gw = gateway(&live);
        let (name, domain) = domain(&gw, "sa").await;
        let mut desired =
            DesiredAccount::new(AccountType::User, "Forgejo", &domain, &s(&["NoReply"]));
        desired.permissions = Some(OwnedPermissions::service_account(false));
        let id = gw.create_account(&desired).await.unwrap();
        let stored = gw.get_account(&id).await.unwrap().expect("created");
        let address = format!("forgejo@{name}");
        assert_eq!(stored.email_address, address);
        assert_eq!(
            stored.locale.as_deref(),
            Some("en-US"),
            "the server's default"
        );
        let (patch, drift) = account_patch(&desired, &stored);
        assert!(drift.is_empty(), "drift right after creation: {drift:?}");
        assert_eq!(patch, AccountPatch::default());

        // No credential: nothing logs in. Its App Password works; a
        // rotation revokes it, and only it.
        assert_eq!(live.login(&address, PASSWORD).await, 401);
        let first = gw.rotate_app_password(&id).await.unwrap();
        assert!(first.starts_with("app_"), "generated by Stalwart");
        assert_eq!(live.login(&address, &first).await, 200);
        let users = live
            .admin_call(
                "x:AppPassword/set",
                json!({"accountId": &id, "create": {"u": {"description": "mua",
                    "permissions": {"@type": "Replace", "permissions": {"authenticate": true}}}}}),
            )
            .await;
        let users = users["created"]["u"]["secret"]
            .as_str()
            .unwrap_or_else(|| panic!("{users}"))
            .to_string();
        let rotated = gw.rotate_app_password(&id).await.unwrap();
        assert_ne!(rotated, first);
        assert_eq!(live.login(&address, &rotated).await, 200);
        assert_eq!(live.login(&address, &first).await, 401);
        assert_eq!(live.login(&address, &users).await, 200, "not ours: kept");

        // By hand: an Admin role (the recovery admin may), an alias more,
        // delivery enabled — put back, those only.
        live.admin_call(
            "x:Account/set",
            json!({"update": {&id: {
                "roles": {"@type": "Admin"},
                "aliases": {"0": {"name": "noreply", "domainId": &domain, "enabled": true},
                            "1": {"name": "extra", "domainId": &domain, "enabled": true}},
                "permissions/disabledPermissions/emailReceive": null,
            }}}),
        )
        .await;
        let edited = gw.get_account(&id).await.unwrap().unwrap();
        let (patch, drift) = account_patch(&desired, &edited);
        assert_eq!(drift.fields(), ["aliases", "roles", "permissions"]);
        gw.update_account(&id, &patch).await.unwrap();
        let fixed = gw.get_account(&id).await.unwrap().unwrap();
        assert!(account_patch(&desired, &fixed).1.is_empty(), "{fixed:?}");
        // The App Password survived the patch.
        assert_eq!(live.login(&address, &rotated).await, 200);
        assert_eq!(
            gw.find_account(&domain, "FORGEJO").await.unwrap(),
            Some(id.clone())
        );
        live.destroy_domain(&name).await;
    }

    /// A mailbox's quota (bytes), locale and time zone, read back in sync;
    /// locked, every login is refused — App Passwords included — and
    /// unlocked, both work again (RFC 0001, "Verrouillage").
    #[tokio::test]
    #[ignore = "needs a real Stalwart: task stalwart:container:start"]
    async fn locking_refuses_every_login_and_unlocking_gives_it_back() {
        let live = LiveStalwart::from_env();
        let gw = gateway(&live);
        let (name, domain) = domain(&gw, "lock").await;
        let mut desired = DesiredAccount::new(AccountType::User, "alice", &domain, &[]);
        desired.permissions = Some(OwnedPermissions::account(false));
        desired.quota = Some(2_147_483_648);
        desired.locale = Some("fr-FR".into());
        desired.time_zone = Some("Europe/Paris".into());
        let id = gw.create_account(&desired).await.unwrap();
        let stored = gw.get_account(&id).await.unwrap().unwrap();
        assert_eq!(stored.permissions, RemotePermissions::Inherit);
        assert_eq!(stored.quotas["maxDiskQuota"], 2_147_483_648);
        assert!(account_patch(&desired, &stored).1.is_empty(), "{stored:?}");

        // Its owner's credentials, as the OpenID Connect login and the web
        // interface would give them: a password (set by the admin here),
        // then an App Password the user creates.
        let address = format!("alice@{name}");
        live.admin_call(
            "x:Account/set",
            json!({"update": {&id: {"credentials/0": {"@type": "Password", "secret": PASSWORD}}}}),
        )
        .await;
        let app = live
            .user_call(
                &address,
                PASSWORD,
                "x:AppPassword/set",
                json!({"create": {"p": {"description": "mua"}}}),
            )
            .await;
        let app = app["created"]["p"]["secret"]
            .as_str()
            .unwrap_or_else(|| panic!("{app}"))
            .to_string();
        assert_eq!(live.login(&address, &app).await, 200);

        let mut locked = desired.clone();
        locked.permissions = Some(OwnedPermissions::account(true));
        let (patch, drift) = account_patch(&locked, &stored);
        assert_eq!(drift.fields(), ["permissions"]);
        gw.update_account(&id, &patch).await.unwrap();
        assert_eq!(live.login(&address, PASSWORD).await, 403);
        assert_eq!(live.login(&address, &app).await, 403, "App Passwords too");
        let now = gw.get_account(&id).await.unwrap().unwrap();
        assert!(account_patch(&locked, &now).1.is_empty(), "locked in sync");

        let (patch, _) = account_patch(&desired, &now);
        gw.update_account(&id, &patch).await.unwrap();
        assert_eq!(live.login(&address, PASSWORD).await, 200);
        assert_eq!(live.login(&address, &app).await, 200, "kept, usable again");
        let unlocked = gw.get_account(&id).await.unwrap().unwrap();
        assert!(
            account_patch(&desired, &unlocked).1.is_empty(),
            "{unlocked:?}"
        );
        live.destroy_domain(&name).await;
    }

    /// A group (`Default` role, no `encryptionAtRest`) in sync after
    /// creation; with a member, its deletion is `Linked`; without, deleted;
    /// gone, `false`.
    #[tokio::test]
    #[ignore = "needs a real Stalwart: task stalwart:container:start"]
    async fn a_group_with_members_is_linked() {
        let live = LiveStalwart::from_env();
        let gw = gateway(&live);
        let (name, domain) = domain(&gw, "group").await;
        let mut desired = DesiredAccount::new(AccountType::Group, "Team", &domain, &s(&["All"]));
        desired.quota = Some(1 << 30);
        let group = gw.create_account(&desired).await.unwrap();
        let stored = gw.get_account(&group).await.unwrap().unwrap();
        assert_eq!(
            (stored.kind.as_str(), stored.role.as_str()),
            ("Group", "Default")
        );
        assert!(account_patch(&desired, &stored).1.is_empty(), "{stored:?}");

        let member = gw
            .create_account(&DesiredAccount::new(AccountType::User, "bob", &domain, &[]))
            .await
            .unwrap();
        live.admin_call(
            "x:Account/set",
            json!({"update": {&member: {"memberGroupIds": {&group: true}}}}),
        )
        .await;
        assert!(matches!(
            gw.delete_account(&group).await,
            Err(GatewayError::Linked(_))
        ));
        assert_eq!(gw.delete_account(&member).await, Ok(true));
        assert_eq!(gw.delete_account(&group).await, Ok(true));
        assert_eq!(gw.delete_account(&group).await, Ok(false));
        live.destroy_domain(&name).await;
    }

    /// A list's recipients kept in the case sent compare as a set; an
    /// address is unique across lists and accounts.
    #[tokio::test]
    #[ignore = "needs a real Stalwart: task stalwart:container:start"]
    async fn a_list_reads_back_in_sync_and_addresses_are_unique_across_kinds() {
        let live = LiveStalwart::from_env();
        let gw = gateway(&live);
        let (name, domain) = domain(&gw, "list").await;
        let desired = DesiredMailingList::new(
            "Team",
            &domain,
            &s(&["crew"]),
            &s(&["Alice@Example.com", "bob@example.com"]),
        );
        let list = gw.create_mailing_list(&desired).await.unwrap();
        // Stored as sent: send another case behind the operator's back.
        live.admin_call(
            "x:MailingList/set",
            json!({"update": {&list: {"recipients": {"ALICE@example.com": true, "bob@example.com": true}}}}),
        )
        .await;
        let stored = gw.get_mailing_list(&list).await.unwrap().unwrap();
        assert!(stored.recipients.contains(&"ALICE@example.com".to_string()));
        assert!(
            mailing_list_patch(&desired, &stored).1.is_empty(),
            "{stored:?}"
        );
        assert_eq!(
            gw.find_mailing_list(&domain, "team").await.unwrap(),
            Some(list.clone())
        );

        // An account named as the list, or as its alias: taken.
        for taken in ["team", "crew"] {
            let result = gw
                .create_account(&DesiredAccount::new(AccountType::User, taken, &domain, &[]))
                .await;
            assert!(
                matches!(&result, Err(GatewayError::AlreadyExists(_))),
                "{taken}: {result:?}"
            );
        }
        assert_eq!(gw.delete_mailing_list(&list).await, Ok(true));
        assert_eq!(gw.get_mailing_list(&list).await, Ok(None));
        live.destroy_domain(&name).await;
    }
}
