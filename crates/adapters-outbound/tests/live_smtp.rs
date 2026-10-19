//! Live SMTP checks against a real Stalwart v0.16.27 (`task
//! stalwart:container:start ENGINE=podman`, then `task test:live-stalwart`):
//! what a service account's published credentials do on submission (587,
//! STARTTLS), and the spike's SMTP-level questions (RFC 0001 Q4, Q8), as
//! tests that keep answering them on every new image.
//!
//! Observed on v0.16.27:
//!
//! - The image listens on 25 (`smtp`) and 465 (`submissions`) only: 587 is
//!   a `NetworkListener` the bootstrap creates (`.tasks/stalwart.yaml`),
//!   bound at the next start. Before `STARTTLS`, 587 offers no password
//!   mechanism (`AUTH XOAUTH2 OAUTHBEARER`); after it, `PLAIN LOGIN`.
//! - Q8: with `mustMatchSender` at its default, an authenticated account
//!   may use its address and its aliases (any case) as `MAIL FROM`; any
//!   other address — a sub-address `+tag` included — is `501 5.5.4`.
//! - Q4: a recipient without `emailReceive` (a locked `StalwartAccount`, a
//!   service account without `receive`) is accepted at `RCPT TO` (`250`,
//!   on 25 and on 587) and bounced by a DSN (`5.5.0 This account is not
//!   authorized to receive email.`); an unknown one is `550 5.1.2` at
//!   `RCPT`. An App Password whose own permissions are `Replace` doesn't
//!   bypass a disabled `authenticate`: Stalwart intersects them with the
//!   account's (`550 5.7.1` at `AUTH`, `403` on JMAP).
//!
//! - D24: a service account has no `Password`; its App Password, created
//!   by the operator's second key (`STALWART_APP_PASSWORD_TOKEN`), works on
//!   submission with or without an OIDC default directory, and a rotation
//!   refuses the old one (`a_service_account_end_to_end_*`).
//!
//! The container's certificate is self-signed (`CN=rcgen self signed
//! cert`): the client here accepts any. Stalwart's default inbound throttle
//! allows 5 connections a second per IP: `connect` retries a dropped one.
//!
//! Ignored by default: run with `--ignored` (each test uses its own
//! domain; [`SERIAL`] runs them one at a time).

use std::sync::Arc;
use std::time::Duration;

use adapters_outbound::{JmapClient, JmapGateway};
use api::ServiceAccount;
use api::common::{Submission, SubmissionSecurity};
use application::ports::{BoundInstance, InstanceSettings, RemoteGateway};
use application::test_support::record;
use application::use_cases::accounts::Ports;
use application::use_cases::reconcile_service_account::{
    credentials, keys, reconcile_service_account,
};
use base64::Engine;
use domain::account::{AccountType, DesiredAccount, OwnedPermissions, account_patch};
use domain::error::ReasonCode;
use domain::mail_domain::{DesiredDomain, DkimManagement, SubAddressing};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{Value, json};
use testkit::{FakeCluster, FakeSecretStore, LiveStalwart};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const PASSWORD: &str = "Live-test-password-0123456789";

/// One test at a time, even when the harness runs them in parallel (`task
/// coverage`): an OIDC default directory is server-wide, and refuses every
/// other test's passwords while it is on.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ── A minimal SMTP client ────────────────────────────────────────────────────

/// One SMTP session: commands and their (multi-line) replies.
struct Smtp<S> {
    io: BufReader<S>,
}

type Reply = (u16, String);

impl<S: AsyncRead + AsyncWrite + Unpin> Smtp<S> {
    async fn read_reply(&mut self) -> std::io::Result<Reply> {
        let mut text = String::new();
        loop {
            let mut line = String::new();
            if self.io.read_line(&mut line).await? == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            text.push_str(&line);
            if line.as_bytes().get(3) != Some(&b'-') {
                let code = line.get(..3).and_then(|c| c.parse().ok()).unwrap_or(0);
                return Ok((code, text));
            }
        }
    }

    async fn cmd(&mut self, line: &str) -> Reply {
        let stream = self.io.get_mut();
        stream
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .unwrap();
        stream.flush().await.unwrap();
        self.read_reply()
            .await
            .unwrap_or_else(|e| panic!("{line}: {e}"))
    }

    /// `AUTH PLAIN` with `user` and `password`.
    async fn auth(&mut self, user: &str, password: &str) -> Reply {
        let token =
            base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{password}"));
        self.cmd(&format!("AUTH PLAIN {token}")).await
    }

    /// `MAIL FROM`, then `RSET` so the next one starts afresh.
    async fn try_sender(&mut self, from: &str) -> Reply {
        let reply = self.cmd(&format!("MAIL FROM:<{from}>")).await;
        assert_eq!(self.cmd("RSET").await.0, 250);
        reply
    }

    /// A whole message from `from` to `to`: every `RCPT` must be `250`.
    async fn send(&mut self, from: &str, to: &[&str], subject: &str) {
        let reply = self.cmd(&format!("MAIL FROM:<{from}>")).await;
        assert_eq!(reply.0, 250, "{reply:?}");
        for rcpt in to {
            let reply = self.cmd(&format!("RCPT TO:<{rcpt}>")).await;
            assert_eq!(reply.0, 250, "{rcpt}: {reply:?}");
        }
        assert_eq!(self.cmd("DATA").await.0, 354);
        let reply = self
            .cmd(&format!(
                "From: <{from}>\r\nTo: <{}>\r\nSubject: {subject}\r\n\r\nLive test.\r\n.",
                to.join(">, <")
            ))
            .await;
        assert_eq!(reply.0, 250, "{reply:?}");
    }
}

/// A plain session on `addr`, past the greeting and `EHLO`: the `EHLO`
/// reply. Retries while Stalwart's per-IP throttle drops the connection.
async fn connect(addr: &str) -> (Smtp<TcpStream>, Reply) {
    for _ in 0..30 {
        if let Ok(tcp) = TcpStream::connect(addr).await {
            let mut smtp = Smtp {
                io: BufReader::new(tcp),
            };
            if let Ok((220, _)) = smtp.read_reply().await {
                let ehlo = smtp.cmd("EHLO client.example.com").await;
                return (smtp, ehlo);
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("no SMTP greeting from {addr}: task stalwart:container:start");
}

/// A submission session on `host:port`, upgraded with `STARTTLS` (any
/// certificate accepted): the session and its `EHLO` replies before and
/// after.
async fn starttls(host: &str, port: &str) -> (Smtp<TlsStream<TcpStream>>, Reply, Reply) {
    let (mut plain, before) = connect(&format!("{host}:{port}")).await;
    assert_eq!(plain.cmd("STARTTLS").await.0, 220);
    let provider = Arc::new(ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let tls = TlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from("localhost").unwrap(),
            plain.io.into_inner(),
        )
        .await
        .expect("TLS handshake");
    let mut smtp = Smtp {
        io: BufReader::new(tls),
    };
    let after = smtp.cmd("EHLO client.example.com").await;
    (smtp, before, after)
}

/// An authenticated submission session on the live container.
async fn submit(live: &LiveStalwart, user: &str, password: &str) -> Smtp<TlsStream<TcpStream>> {
    let (host, port) = submission(live);
    let (mut smtp, _, _) = starttls(&host, &port).await;
    let reply = smtp.auth(user, password).await;
    assert_eq!(reply.0, 235, "{user}: {reply:?}");
    smtp
}

/// `STALWART_SUBMISSION` as `(host, port)`.
fn submission(live: &LiveStalwart) -> (String, String) {
    let addr = live
        .submission
        .as_deref()
        .expect("STALWART_SUBMISSION unset: task stalwart:container:start");
    let (host, port) = addr.rsplit_once(':').expect("host:port");
    (host.to_string(), port.to_string())
}

/// The container's certificate is self-signed: accept any, still checking
/// the handshake's signatures.
#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

// ── Accounts and mailboxes ───────────────────────────────────────────────────

/// The operator's gateway: its main key, and its App Password key.
fn gateway(live: &LiveStalwart) -> JmapGateway {
    let http = JmapClient::client_builder().build().unwrap();
    let app_passwords =
        JmapClient::new(&live.url, live.app_password_token.clone(), http.clone()).unwrap();
    JmapGateway::new(JmapClient::new(&live.url, live.token.clone(), http).unwrap())
        .with_app_password_client(app_passwords)
}

/// A fresh domain (`Manual` DKIM): its name and id.
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

/// A service account as the operator creates it (alias `noreply`,
/// delivery disabled, no credential) and the App Password it gives it
/// (RFC 0001 D24): its id and that secret.
async fn service_account(gw: &JmapGateway, domain: &str) -> (String, String) {
    let mut desired = DesiredAccount::new(AccountType::User, "svc", domain, &["noreply".into()]);
    desired.permissions = Some(OwnedPermissions::service_account(false));
    let id = gw.create_account(&desired).await.unwrap();
    let secret = gw.rotate_app_password(&id).await.unwrap();
    (id, secret)
}

/// A service account given `PASSWORD` by the recovery admin, as before
/// D24 (or a phase-0 account Terraform created): its id.
async fn service_account_with_password(
    live: &LiveStalwart,
    gw: &JmapGateway,
    domain: &str,
) -> String {
    let mut desired = DesiredAccount::new(AccountType::User, "svc", domain, &["noreply".into()]);
    desired.permissions = Some(OwnedPermissions::service_account(false));
    let id = gw.create_account(&desired).await.unwrap();
    set_password(live, &id).await;
    id
}

/// `PASSWORD` set on the account `id` by the recovery admin.
async fn set_password(live: &LiveStalwart, id: &str) {
    let answer = live
        .admin_call(
            "x:Account/set",
            json!({"update": {id: {"credentials/0": {"@type": "Password", "secret": PASSWORD}}}}),
        )
        .await;
    assert!(answer["updated"].get(id).is_some(), "{answer}");
}

/// A mailbox as the operator creates it (`Active`), given `PASSWORD` by
/// the admin as its owner's login would: its desired state and id.
async fn mailbox(
    live: &LiveStalwart,
    gw: &JmapGateway,
    domain: &str,
    name: &str,
) -> (DesiredAccount, String) {
    let mut desired = DesiredAccount::new(AccountType::User, name, domain, &[]);
    desired.permissions = Some(OwnedPermissions::account(false));
    let id = gw.create_account(&desired).await.unwrap();
    set_password(live, &id).await;
    (desired, id)
}

/// Locks (`true`) or unlocks the mailbox `id` the way the operator does.
async fn set_locked(gw: &JmapGateway, desired: &DesiredAccount, id: &str, locked: bool) {
    let mut target = desired.clone();
    target.permissions = Some(OwnedPermissions::account(locked));
    let remote = gw.get_account(id).await.unwrap().unwrap();
    let (patch, _) = account_patch(&target, &remote);
    gw.update_account(id, &patch).await.unwrap();
}

/// The messages of `user`'s mailbox (JMAP Mail as `user`): subject, from
/// and preview of each.
async fn messages(live: &LiveStalwart, user: &str, password: &str) -> Vec<Value> {
    let http = reqwest::Client::new();
    let session: Value = http
        .get(format!("{}/jmap/session", live.url))
        .basic_auth(user, Some(password))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let account = &session["primaryAccounts"]["urn:ietf:params:jmap:mail"];
    let answer: Value = http
        .post(format!("{}/jmap", live.url))
        .basic_auth(user, Some(password))
        .json(&json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [
                ["Email/query", {"accountId": account}, "0"],
                ["Email/get", {"accountId": account, "#ids": {"resultOf": "0", "name": "Email/query", "path": "/ids"}, "properties": ["subject", "from", "preview"]}, "1"],
            ],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    answer["methodResponses"][1][1]["list"]
        .as_array()
        .unwrap_or_else(|| panic!("{answer}"))
        .clone()
}

/// `user`'s messages once one has `subject` (delivery goes through the
/// queue): waits up to 30 s.
async fn wait_for(live: &LiveStalwart, user: &str, subject: &str) -> Vec<Value> {
    wait_for_as(live, user, PASSWORD, subject).await
}

/// [`wait_for`], logging in with `password`.
async fn wait_for_as(live: &LiveStalwart, user: &str, password: &str, subject: &str) -> Vec<Value> {
    for _ in 0..60 {
        let list = messages(live, user, password).await;
        if list.iter().any(|m| m["subject"] == subject) {
            return list;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no {subject:?} in {user}'s mailbox");
}

// ── The tests ────────────────────────────────────────────────────────────────

/// The keys a service account publishes (`host`, `port`, `security`,
/// `username`, `password`, `from`) are enough for a client: STARTTLS on
/// submission, `AUTH PLAIN`, `MAIL FROM` the `from` (its first alias), and
/// the message is delivered. Password mechanisms only after `STARTTLS`; a
/// wrong password is `535`.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn published_credentials_send_on_submission_with_starttls() {
    let _serial = SERIAL.lock().await;
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let (name, domain) = domain(&gw, "smtp-sa").await;
    let (_, app_password) = service_account(&gw, &domain).await;
    let (_, _) = mailbox(&live, &gw, &domain, "bob").await;

    let (host, port) = submission(&live);
    let settings = InstanceSettings {
        submission: Submission {
            host,
            port: port.parse().unwrap(),
            security: SubmissionSecurity::Starttls,
        },
        default_backend: Default::default(),
        vault: None,
    };
    let published = credentials(
        &format!("svc@{name}"),
        Some(&format!("noreply@{name}")),
        &settings,
        &app_password,
    );
    assert_eq!(published[keys::SECURITY], "starttls");

    let (mut smtp, before, after) = starttls(&published[keys::HOST], &published[keys::PORT]).await;
    assert!(!before.1.contains("PLAIN"), "plain text offers {before:?}");
    assert!(after.1.contains("AUTH PLAIN LOGIN"), "{after:?}");
    assert_eq!(
        smtp.auth(&published[keys::USERNAME], "not-the-password")
            .await
            .0,
        535
    );
    let reply = smtp
        .auth(&published[keys::USERNAME], &published[keys::PASSWORD])
        .await;
    assert_eq!(reply.0, 235, "{reply:?}");
    smtp.send(
        &published[keys::FROM],
        &[&format!("bob@{name}")],
        "published",
    )
    .await;
    smtp.cmd("QUIT").await;

    let inbox = wait_for(&live, &format!("bob@{name}"), "published").await;
    assert_eq!(inbox[0]["from"][0]["email"], format!("noreply@{name}"));
    live.destroy_domain(&name).await;
}

/// RFC 0001 Q8: `MtaStageAuth.mustMatchSender` left at its default, an
/// authenticated service account may send from its address and its aliases
/// (any case: the published `from` is its first alias); another account's
/// address, a foreign one and a sub-address are `501 5.5.4`.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn spike_must_match_sender_allows_the_address_and_its_aliases_only() {
    let _serial = SERIAL.lock().await;
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let (name, domain) = domain(&gw, "smtp-from").await;
    let (_, app_password) = service_account(&gw, &domain).await;
    mailbox(&live, &gw, &domain, "bob").await;

    let mut smtp = submit(&live, &format!("svc@{name}"), &app_password).await;
    for allowed in [
        format!("svc@{name}"),
        format!("noreply@{name}"),
        format!("NoReply@{}", name.to_uppercase()),
    ] {
        let reply = smtp.try_sender(&allowed).await;
        assert_eq!(reply.0, 250, "{allowed}: {reply:?}");
    }
    for refused in [
        format!("bob@{name}"),
        "someone@example.com".to_string(),
        format!("svc+tag@{name}"),
    ] {
        let reply = smtp.try_sender(&refused).await;
        assert_eq!(reply.0, 501, "{refused}: {reply:?}");
        assert!(reply.1.contains("5.5.4"), "{reply:?}");
    }
    smtp.cmd("QUIT").await;
    live.destroy_domain(&name).await;
}

/// RFC 0001 Q4, delivery: a recipient without `emailReceive` — a locked
/// mailbox, a service account without `receive` — is accepted at
/// `RCPT TO` (on the MX and on submission) and bounced afterwards: the
/// sender gets a DSN `5.5.0 This account is not authorized to receive
/// email.`, the mailbox nothing (seen once unlocked). An unknown recipient
/// is refused at `RCPT` (`550 5.1.2`).
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn spike_a_recipient_that_may_not_receive_is_accepted_then_bounced() {
    let _serial = SERIAL.lock().await;
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let (name, domain) = domain(&gw, "smtp-rcpt").await;
    service_account(&gw, &domain).await;
    let (alice, alice_id) = mailbox(&live, &gw, &domain, "alice").await;
    mailbox(&live, &gw, &domain, "bob").await;
    set_locked(&gw, &alice, &alice_id, true).await;
    let (locked, svc) = (format!("alice@{name}"), format!("svc@{name}"));

    // The MX: inbound mail from outside.
    let mx = live
        .smtp
        .as_deref()
        .expect("STALWART_SMTP unset: task stalwart:container:start");
    let (mut smtp, _) = connect(mx).await;
    assert_eq!(smtp.cmd("MAIL FROM:<someone@example.com>").await.0, 250);
    for rcpt in [&locked, &svc] {
        let reply = smtp.cmd(&format!("RCPT TO:<{rcpt}>")).await;
        assert_eq!(reply.0, 250, "{rcpt}: {reply:?}");
    }
    let unknown = smtp.cmd(&format!("RCPT TO:<nobody@{name}>")).await;
    assert_eq!(unknown.0, 550, "{unknown:?}");
    assert!(unknown.1.contains("5.1.2"), "{unknown:?}");
    smtp.cmd("QUIT").await;

    // Submission: accepted, then bounced to the sender.
    let mut smtp = submit(&live, &format!("bob@{name}"), PASSWORD).await;
    smtp.send(&format!("bob@{name}"), &[&locked, &svc], "to-locked")
        .await;
    smtp.cmd("QUIT").await;
    let bob = wait_for(&live, &format!("bob@{name}"), "Failed to deliver message").await;
    let preview = bob[0]["preview"].as_str().unwrap();
    assert!(
        preview.contains(&format!("<{locked}>"))
            && preview.contains("5.5.0")
            && preview.contains("not authorized to receive email"),
        "{preview}"
    );
    set_locked(&gw, &alice, &alice_id, false).await;
    assert!(messages(&live, &locked, PASSWORD).await.is_empty());
    live.destroy_domain(&name).await;
}

/// RFC 0001 Q4, App Passwords: one whose own permissions are `Replace`
/// (`authenticate`, `emailSend`…) doesn't bypass the account's disabled
/// `authenticate` — Stalwart intersects them with the account's. Locked:
/// `550 5.7.1` at `AUTH` on submission, `403` on JMAP, for the password
/// and the App Password; unlocked, both work again.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn spike_an_app_password_in_replace_does_not_bypass_a_lock() {
    let _serial = SERIAL.lock().await;
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let (name, domain) = domain(&gw, "smtp-app").await;
    let (alice, id) = mailbox(&live, &gw, &domain, "alice").await;
    let address = format!("alice@{name}");
    let granted = json!({"authenticate": true, "emailSend": true, "jmapEmailGet": true});
    let created = live
        .user_call(
            &address,
            PASSWORD,
            "x:AppPassword/set",
            json!({"create": {"p": {"description": "mua", "permissions": {"@type": "Replace", "permissions": granted}}}}),
        )
        .await;
    let app = created["created"]["p"]["secret"]
        .as_str()
        .unwrap_or_else(|| panic!("{created}"))
        .to_string();
    let stored = live
        .user_call(&address, PASSWORD, "x:AppPassword/get", json!({}))
        .await;
    assert_eq!(
        stored["list"][0]["permissions"]["@type"], "Replace",
        "{stored}"
    );

    let (host, port) = submission(&live);
    let auth = |secret: String| {
        let (host, port, address) = (host.clone(), port.clone(), address.clone());
        async move {
            let (mut smtp, _, _) = starttls(&host, &port).await;
            let reply = smtp.auth(&address, &secret).await;
            smtp.cmd("QUIT").await;
            reply
        }
    };
    assert_eq!(live.login(&address, &app).await, 200);
    assert_eq!(auth(app.clone()).await.0, 235);

    set_locked(&gw, &alice, &id, true).await;
    for secret in [PASSWORD.to_string(), app.clone()] {
        assert_eq!(live.login(&address, &secret).await, 403);
        let reply = auth(secret).await;
        assert_eq!(reply.0, 550, "{reply:?}");
        assert!(reply.1.contains("5.7.1"), "{reply:?}");
    }

    set_locked(&gw, &alice, &id, false).await;
    assert_eq!(auth(app.clone()).await.0, 235);
    assert_eq!(auth(PASSWORD.to_string()).await.0, 235);
    live.destroy_domain(&name).await;
}

// ── An OIDC default directory (option A of the users' OIDC login) ────────────
//
// On the community edition the default directory (`Authentication.
// directoryId`) is the only one, for every domain. An `Oidc` one there —
// what the users' OIDC/JIT login needs — takes every Basic login that isn't
// an App Password (`AppPassword::parse` comes first): a `Password`
// credential stops working, and Stalwart refuses to set one ("Cannot set
// credentials for accounts in an external directory."). Observed on
// v0.16.27:
//
// - the operator's API key (Bearer, `ApiKey::parse` first) keeps working;
//   its `x:Account/set` too, except for a `Password` credential (creation,
//   rotation);
// - `x:Account/set` can't add an App Password (`Secondary credentials
//   cannot be set directly.`; with a `secret`: `invalidPatch`), nor change
//   one's secret; it can remove one (`credentials/<i>: null`);
// - `x:AppPassword/set` on another account needs `impersonate` (`You are
//   not an owner of account <id>`); the server generates the secret and
//   returns it once (`created.<k>.secret`, `app_…`), assigns the credential
//   id (the highest + 1), and never lets it change: a rotation is a create
//   and a destroy in the same call;
// - an App Password with `permissions: Replace {authenticate, emailSend}`
//   created by a key of the operator's account holding `impersonate`,
//   `emailSend` and `sysAppPassword*` only works on submission (and JMAP
//   Basic), `mustMatchSender` as for a password; a locked account refuses
//   it. `Inherit` is refused to that key: it means the creator's own
//   permissions, more than the key holds.

/// What a test sets up for an OIDC default directory, undone by
/// [`Oidc::disable`] or, if the test panics first, on drop: the `Oidc`
/// directory (its issuer a fake IdP served by the test), the default
/// directory, and the narrow key of the operator's account.
struct Oidc {
    live: LiveStalwart,
    directory: String,
    operator_account: String,
    /// The key with `impersonate`: id and secret.
    key: (String, String),
    done: bool,
}

/// What the fake IdP answers: its discovery document and an empty JWKS
/// (Stalwart fetches both when it opens the directory).
async fn fake_idp() -> String {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // The container reaches the host by this name (podman's default; with
    // docker: `--add-host host.containers.internal:host-gateway`).
    let host = std::env::var("STALWART_IDP_HOST")
        .unwrap_or_else(|_| "host.containers.internal".to_string());
    let issuer = format!("http://{host}:{port}");
    let discovery = json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/jwks.json"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "token_endpoint": format!("{issuer}/token"),
        "authorization_endpoint": format!("{issuer}/authorize"),
    })
    .to_string();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let discovery = discovery.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tokio::io::AsyncReadExt::read(&mut tcp, &mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&request);
                let body = if line.starts_with("GET /.well-known/openid-configuration") {
                    discovery
                } else {
                    r#"{"keys":[]}"#.to_string()
                };
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tcp.write_all(answer.as_bytes()).await;
            });
        }
    });
    issuer
}

/// The operator's account: the one its key belongs to.
async fn operator_account(live: &LiveStalwart) -> String {
    let session: Value = reqwest::Client::new()
        .get(format!("{}/jmap/session", live.url))
        .bearer_auth(&live.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    session["primaryAccounts"]["urn:stalwart:jmap"]
        .as_str()
        .unwrap()
        .to_string()
}

/// `ReloadSettings`: the directories are rebuilt (the default one too).
async fn reload(live: &LiveStalwart) {
    let answer = live
        .admin_call(
            "x:Action/set",
            json!({"create": {"r": {"@type": "ReloadSettings"}}}),
        )
        .await;
    assert!(answer["created"]["r"].is_object(), "{answer}");
}

impl Oidc {
    /// The permissions of the narrow key: create, rotate and revoke App
    /// Passwords of any account, granting at most `authenticate` and
    /// `emailSend`.
    const KEY_PERMISSIONS: &[&str] = &[
        "authenticate",
        "impersonate",
        "emailSend",
        "sysAppPasswordCreate",
        "sysAppPasswordGet",
        "sysAppPasswordUpdate",
        "sysAppPasswordDestroy",
        "sysAppPasswordQuery",
    ];

    /// An `Oidc` directory as the default one, and the narrow key — both
    /// by the recovery admin (the operator's key may do neither; under
    /// OIDC, the operator's account can't log in with its password to
    /// create a key of its own).
    async fn enable(live: &LiveStalwart) -> Self {
        let issuer = fake_idp().await;
        let created = live
            .admin_call(
                "x:Directory/set",
                json!({"create": {"o": {"@type": "Oidc", "description": "live test", "issuerUrl": issuer, "claimUsername": "email"}}}),
            )
            .await;
        let directory = created["created"]["o"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{created}"))
            .to_string();
        let operator_account = operator_account(live).await;
        let permissions: serde_json::Map<String, Value> = Self::KEY_PERMISSIONS
            .iter()
            .map(|p| (p.to_string(), Value::Bool(true)))
            .collect();
        let created = live
            .admin_call(
                "x:ApiKey/set",
                json!({"accountId": operator_account, "create": {"k": {"description": "weebo-stalwart app passwords", "permissions": {"@type": "Replace", "permissions": permissions}}}}),
            )
            .await;
        let key = (
            created["created"]["k"]["id"]
                .as_str()
                .unwrap_or_else(|| panic!("{created}"))
                .to_string(),
            created["created"]["k"]["secret"]
                .as_str()
                .unwrap()
                .to_string(),
        );
        let oidc = Self {
            live: live.clone(),
            directory,
            operator_account,
            key,
            done: false,
        };
        let updated = live
            .admin_call(
                "x:Authentication/set",
                json!({"update": {"singleton": {"directoryId": oidc.directory}}}),
            )
            .await;
        assert!(
            updated["updated"]
                .as_object()
                .is_some_and(|u| u.contains_key("singleton")),
            "{updated}"
        );
        reload(live).await;
        oidc
    }

    /// One call with the narrow key.
    async fn key_call(&self, method: &str, args: Value) -> Value {
        let mut live = self.live.clone();
        live.token = self.key.1.clone();
        live.token_call(method, args).await
    }

    async fn undo(live: &LiveStalwart, directory: &str, operator_account: &str, key: &str) {
        live.admin_call(
            "x:Authentication/set",
            json!({"update": {"singleton": {"directoryId": null}}}),
        )
        .await;
        live.admin_call("x:Directory/set", json!({"destroy": [directory]}))
            .await;
        reload(live).await;
        live.admin_call(
            "x:ApiKey/set",
            json!({"accountId": operator_account, "destroy": [key]}),
        )
        .await;
    }

    /// Back to no default directory: passwords work again.
    async fn disable(mut self) {
        Self::undo(
            &self.live,
            &self.directory,
            &self.operator_account,
            &self.key.0,
        )
        .await;
        self.done = true;
    }
}

impl Drop for Oidc {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let (live, directory, account, key) = (
            self.live.clone(),
            self.directory.clone(),
            self.operator_account.clone(),
            self.key.0.clone(),
        );
        let _ = std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(Self::undo(&live, &directory, &account, &key));
        })
        .join();
    }
}

/// `AUTH PLAIN` on submission, then `QUIT`: the reply.
async fn auth_reply(live: &LiveStalwart, user: &str, secret: &str) -> Reply {
    let (host, port) = submission(live);
    let (mut smtp, _, _) = starttls(&host, &port).await;
    let reply = smtp.auth(user, secret).await;
    smtp.cmd("QUIT").await;
    reply
}

/// An OIDC default directory: a service account's `Password` is refused
/// on submission (`454 4.7.0`, the OIDC backend takes no password) and on
/// JMAP Basic (`401`), and can't be set any more — at creation or by a
/// rotation, the recovery admin included. The operator's key keeps
/// working: creating and updating accounts without credentials. Without a
/// default directory again, the password works again.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn spike_an_oidc_default_directory_refuses_passwords_not_the_operator_key() {
    let _serial = SERIAL.lock().await;
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let (name, domain) = domain(&gw, "oidc-pw").await;
    let svc = service_account_with_password(&live, &gw, &domain).await;
    let address = format!("svc@{name}");
    assert_eq!(auth_reply(&live, &address, PASSWORD).await.0, 235);

    let oidc = Oidc::enable(&live).await;
    let reply = auth_reply(&live, &address, PASSWORD).await;
    assert_eq!(reply.0, 454, "{reply:?}");
    assert!(reply.1.contains("4.7.0"), "{reply:?}");
    // Never logged in over HTTP before: no cached login.
    assert_eq!(live.login(&address, PASSWORD).await, 401);

    // The operator's key: reads, creations and updates without credentials.
    assert!(gw.get_account(&svc).await.unwrap().is_some());
    let (bob, bob_id) = {
        let mut desired = DesiredAccount::new(AccountType::User, "bob", &domain, &[]);
        desired.permissions = Some(OwnedPermissions::account(false));
        let id = gw.create_account(&desired).await.unwrap();
        (desired, id)
    };
    set_locked(&gw, &bob, &bob_id, true).await;
    // …not with one, at creation or by a rotation (what the operator did
    // before D24).
    let created = live
        .token_call(
            "x:Account/set",
            json!({"create": {"carol": {"@type": "User", "name": "carol", "domainId": &domain,
                "roles": {"@type": "User"}, "encryptionAtRest": {"@type": "Disabled"},
                "aliases": {}, "permissions": {"@type": "Merge", "disabledPermissions": {"imapAuthenticate": true}},
                "credentials": {"0": {"@type": "Password", "secret": PASSWORD}}}}}),
        )
        .await;
    assert!(
        created["notCreated"]["carol"]
            .to_string()
            .contains("external directory"),
        "{created}"
    );
    let rotated = live
        .token_call(
            "x:Account/set",
            json!({"update": {&svc: {"credentials/0/secret": "Other-live-password-0123456789"}}}),
        )
        .await;
    assert!(
        rotated["notUpdated"][&svc]
            .to_string()
            .contains("external directory"),
        "{rotated}"
    );
    let refused = live
        .admin_call(
            "x:Account/set",
            json!({"update": {&bob_id: {"credentials/0": {"@type": "Password", "secret": PASSWORD}}}}),
        )
        .await;
    assert_eq!(
        refused["notUpdated"][&bob_id]["type"], "forbidden",
        "{refused}"
    );

    oidc.disable().await;
    assert_eq!(auth_reply(&live, &address, PASSWORD).await.0, 235);
    live.destroy_domain(&name).await;
}

/// Option A as first written — the operator's key adding an App Password
/// to the account through `x:Account/set` — is refused whatever the
/// directory: the server alone creates secondary credentials, through
/// `x:AppPassword/set`, which needs `impersonate` on another account.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn spike_the_operator_key_cannot_add_an_app_password() {
    let _serial = SERIAL.lock().await;
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let (name, domain) = domain(&gw, "oidc-a").await;
    let (svc, _) = service_account(&gw, &domain).await;

    let with_secret = live
        .token_call(
            "x:Account/set",
            json!({"update": {&svc: {"credentials/1": {"@type": "AppPassword", "description": "smtp", "secret": "a-secret-of-the-operator-0123456789"}}}}), // gitleaks:allow (refused test value)
        )
        .await;
    assert_eq!(
        with_secret["notUpdated"][&svc]["type"], "invalidPatch",
        "{with_secret}"
    );
    let without = live
        .token_call(
            "x:Account/set",
            json!({"update": {&svc: {"credentials/1": {"@type": "AppPassword", "description": "smtp"}}}}),
        )
        .await;
    assert_eq!(
        without["notUpdated"][&svc]["description"], "Secondary credentials cannot be set directly.",
        "{without}"
    );
    let direct = live
        .token_call(
            "x:AppPassword/set",
            json!({"accountId": svc, "create": {"p": {"description": "smtp"}}}),
        )
        .await;
    assert_eq!(
        direct["description"],
        format!("You are not an owner of account {svc}"),
        "{direct}"
    );
    live.destroy_domain(&name).await;
}

/// Option A with a narrow key (`impersonate`, `emailSend`,
/// `sysAppPassword*`) of the operator's account, under an OIDC default
/// directory: the App Password it creates on a service account created
/// without credentials authenticates on submission and JMAP Basic, sends
/// from the account's alias (and not from another address), and the
/// message is delivered. A rotation (create + destroy in one call) refuses
/// the old one, accepts the new one, leaves the account's other App
/// Passwords alone; the secret can't be changed in place. A locked account
/// refuses it. The operator's main key may revoke one (`credentials/<i>:
/// null`).
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn spike_an_impersonate_key_gives_a_service_account_an_app_password_under_oidc() {
    let _serial = SERIAL.lock().await;
    let live = LiveStalwart::from_env();
    let gw = gateway(&live);
    let (name, domain) = domain(&gw, "oidc-app").await;
    let mut desired = DesiredAccount::new(AccountType::User, "svc", &domain, &["noreply".into()]);
    desired.permissions = Some(OwnedPermissions::service_account(false));
    let svc = gw.create_account(&desired).await.unwrap();
    let mut bob = DesiredAccount::new(AccountType::User, "bob", &domain, &[]);
    bob.permissions = Some(OwnedPermissions::account(false));
    gw.create_account(&bob).await.unwrap();
    let address = format!("svc@{name}");

    let oidc = Oidc::enable(&live).await;
    let create = |key: &str| json!({"accountId": svc, "create": {key: {"description": "weebo-stalwart", "permissions": {"@type": "Replace", "permissions": {"authenticate": true, "emailSend": true}}}}});
    let inherit = oidc
        .key_call(
            "x:AppPassword/set",
            json!({"accountId": svc, "create": {"p": {"description": "weebo-stalwart"}}}),
        )
        .await;
    assert_eq!(inherit["notCreated"]["p"]["type"], "forbidden", "{inherit}");
    // An App Password of the account's own (its user's), to keep.
    let other = oidc.key_call("x:AppPassword/set", create("o")).await;
    let other = other["created"]["o"]["secret"]
        .as_str()
        .unwrap()
        .to_string();
    let created = oidc.key_call("x:AppPassword/set", create("p")).await;
    let (id, app) = (
        created["created"]["p"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{created}"))
            .to_string(),
        created["created"]["p"]["secret"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    assert!(app.starts_with("app_") && app.len() == 40, "{app}");
    let custom = oidc
        .key_call(
            "x:AppPassword/set",
            json!({"accountId": svc, "create": {"c": {"description": "x", "secret": "mine"}}}),
        )
        .await;
    assert_eq!(
        custom["notCreated"]["c"]["type"], "invalidPatch",
        "{custom}"
    );

    // Submission and JMAP Basic, `mustMatchSender`, delivery.
    assert_eq!(live.login(&address, &app).await, 200);
    let mut smtp = submit(&live, &address, &app).await;
    assert_eq!(smtp.try_sender(&format!("noreply@{name}")).await.0, 250);
    assert_eq!(smtp.try_sender("someone@example.com").await.0, 501);
    smtp.send(
        &format!("noreply@{name}"),
        &[&format!("bob@{name}")],
        "app-password",
    )
    .await;
    smtp.cmd("QUIT").await;
    let (admin, admin_password) = live.admin.clone().unwrap();
    let inbox = wait_for_as(
        &live,
        &format!("bob@{name}%{admin}"),
        &admin_password,
        "app-password",
    )
    .await;
    assert_eq!(inbox[0]["from"][0]["email"], format!("noreply@{name}"));

    // Rotation.
    let in_place = oidc
        .key_call(
            "x:AppPassword/set",
            json!({"accountId": svc, "update": {&id: {"secret": "app_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}),
        )
        .await;
    assert_eq!(
        in_place["notUpdated"][&id]["type"], "invalidPatch",
        "{in_place}"
    );
    let mut rotation = create("n");
    rotation["destroy"] = json!([id]);
    let rotated = oidc.key_call("x:AppPassword/set", rotation).await;
    assert_eq!(rotated["destroyed"], json!([id]), "{rotated}");
    let new = rotated["created"]["n"]["secret"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(auth_reply(&live, &address, &app).await.0, 535);
    assert_eq!(auth_reply(&live, &address, &new).await.0, 235);
    assert_eq!(auth_reply(&live, &address, &other).await.0, 235);

    // A lock.
    set_locked(&gw, &desired, &svc, true).await;
    let reply = auth_reply(&live, &address, &new).await;
    assert_eq!(reply.0, 550, "{reply:?}");
    assert_eq!(live.login(&address, &new).await, 403);
    set_locked(&gw, &desired, &svc, false).await;
    assert_eq!(auth_reply(&live, &address, &new).await.0, 235);

    // Revocation by the main key: by index in `credentials`.
    let read = live
        .token_call(
            "x:Account/get",
            json!({"ids": [svc], "properties": ["credentials"]}),
        )
        .await;
    let index = read["list"][0]["credentials"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, c)| c["credentialId"] == rotated["created"]["n"]["id"])
        .map(|(i, _)| i.clone())
        .unwrap_or_else(|| panic!("{read}"));
    live.token_call(
        "x:Account/set",
        json!({"update": {&svc: {format!("credentials/{index}"): null}}}),
    )
    .await;
    assert_eq!(auth_reply(&live, &address, &new).await.0, 535);
    assert_eq!(auth_reply(&live, &address, &other).await.0, 235);

    oidc.disable().await;
    live.destroy_domain(&name).await;
}

// ── A service account end to end (RFC 0001 D24) ──────────────────────────────

/// `reconcile_service_account` against the real server, through the real
/// gateway with the bootstrapped App Password key: created without any
/// credential, its App Password published; the published settings
/// authenticate on submission (`235`) and send from the alias (`250`); a
/// new `rotate-secret` nonce: the old App Password refused, the new one
/// accepted.
async fn a_service_account_end_to_end(live: &LiveStalwart, name: &str, domain: &str) {
    let gw = gateway(live);
    let main = BoundInstance::cluster("main");
    let cluster = FakeCluster::default();
    cluster.set_domain(name, domain, &main);
    let (host, port) = submission(live);
    cluster.set_settings(Some(InstanceSettings {
        submission: Submission {
            host,
            port: port.parse().unwrap(),
            security: SubmissionSecurity::Starttls,
        },
        default_backend: Default::default(),
        vault: None,
    }));
    let secrets = FakeSecretStore::default();
    let mut sa: ServiceAccount = serde_json::from_value(json!({
        "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartServiceAccount",
        "metadata": {"name": "mailer", "namespace": "app"},
        "spec": {"domainRef": {"name": name}, "aliases": ["noreply"]},
    }))
    .unwrap();
    let ports = Ports {
        gateway: &gw,
        cluster: &cluster,
        policies: &cluster,
    };

    let created = reconcile_service_account(&sa, &main, ports, &secrets).await;
    assert_eq!(
        created.reason(),
        ReasonCode::Reconciled,
        "{:?}",
        created.ready
    );
    record(&mut sa.status, &created);
    let published = secrets.get("app/mailer").expect("published");
    let address = format!("mailer@{name}");
    assert_eq!(published[keys::USERNAME], address);
    assert_eq!(published[keys::FROM], format!("noreply@{name}"));
    let first = published[keys::PASSWORD].clone();
    assert!(first.starts_with("app_"), "an App Password");

    let (mut smtp, _, _) = starttls(&published[keys::HOST], &published[keys::PORT]).await;
    let reply = smtp.auth(&published[keys::USERNAME], &first).await;
    assert_eq!(reply.0, 235, "{reply:?}");
    let reply = smtp.try_sender(&published[keys::FROM]).await;
    assert_eq!(reply.0, 250, "{reply:?}");
    smtp.cmd("QUIT").await;

    sa.metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert("stalwart.weebo.io/rotate-secret".into(), "r1".into());
    let rotated = reconcile_service_account(&sa, &main, ports, &secrets).await;
    assert_eq!(
        rotated.reason(),
        ReasonCode::Reconciled,
        "{:?}",
        rotated.ready
    );
    assert_eq!(rotated.last_rotation.as_deref(), Some("r1"));
    let new = secrets.get("app/mailer").unwrap()[keys::PASSWORD].clone();
    assert_ne!(new, first);
    assert_eq!(auth_reply(live, &address, &first).await.0, 535);
    assert_eq!(auth_reply(live, &address, &new).await.0, 235);
}

/// Without a default directory (passwords would work too).
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn a_service_account_end_to_end_without_a_default_directory() {
    let _serial = SERIAL.lock().await;
    let live = LiveStalwart::from_env();
    let (name, domain) = domain(&gateway(&live), "e2e-sa").await;
    a_service_account_end_to_end(&live, &name, &domain).await;
    live.destroy_domain(&name).await;
}

/// Under an OIDC default directory — what weebo-si runs: no password
/// works, the App Password does.
#[tokio::test]
#[ignore = "needs a real Stalwart: task stalwart:container:start"]
async fn a_service_account_end_to_end_under_an_oidc_default_directory() {
    let _serial = SERIAL.lock().await;
    let live = LiveStalwart::from_env();
    let (name, domain) = domain(&gateway(&live), "e2e-oidc").await;
    let oidc = Oidc::enable(&live).await;
    a_service_account_end_to_end(&live, &name, &domain).await;
    oidc.disable().await;
    live.destroy_domain(&name).await;
}
