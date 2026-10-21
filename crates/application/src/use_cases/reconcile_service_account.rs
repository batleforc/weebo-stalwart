//! A `StalwartServiceAccount` → `x:Account` `User` and an App Password
//! (RFC 0001 D24): the account of [`accounts`] — address, aliases,
//! `roles: User`, the logins it doesn't need disabled (IMAP, POP3,
//! ManageSieve, and delivery unless `receive`), no credential — plus an App
//! Password Stalwart generates for it, written to every target with the
//! SMTP settings of the instance (`emit`).
//!
//! The App Password is never read back. A new one is created (the
//! operator's earlier ones revoked in the same call) when the account is
//! created, on a new `rotate-secret` nonce (`emit::rotation_requested`
//! against `status.lastRotation`), when a target lost it
//! (`emit::any_missing`), and after a reconcile that failed to write it
//! (`SecretTargetFailed`: a target may hold an outdated one).
//! `weebo-stalwart-importer` sets a nonce on the accounts it links (D21):
//! an imported account always gets an App Password of the operator's.

use std::collections::BTreeMap;

use api::ServiceAccount;
use domain::Failure;
use domain::RemoteWrite;
use domain::account::{AccountType, DesiredAccount, OwnedPermissions};
use domain::allow_list::Kind;
use domain::error::ReasonCode;
use domain::mail;

use crate::ports::{BoundInstance, InstanceSettings, SecretOwner, SecretStore};
use crate::use_cases::accounts::{self, AccountObject, Ports, Subject, fail};
use crate::use_cases::admission::{check_service_account, check_smtp_targets};
use crate::use_cases::{Outcome, cluster_failure, emit};

pub const KIND: &str = "StalwartServiceAccount";

/// The keys every target receives.
pub mod keys {
    pub const HOST: &str = "host";
    pub const PORT: &str = "port";
    pub const SECURITY: &str = "security";
    pub const USERNAME: &str = "username";
    pub const PASSWORD: &str = "password";
    pub const FROM: &str = "from";
}

/// What the account kinds' reconcile reads of the CR.
pub fn subject(sa: &ServiceAccount) -> Subject<'_> {
    Subject::new(
        KIND,
        Kind::ServiceAccount,
        sa.metadata.namespace.as_deref().unwrap_or_default(),
        sa.metadata.name.as_deref().unwrap_or_default(),
        &sa.metadata,
        sa.status.as_ref(),
        &sa.spec.domain_ref.name,
        sa.local_part(),
        &sa.spec.aliases,
    )
}

/// The CR as the owner of the secrets it writes (and of those it wrote
/// under `previous-owner`).
pub fn owner(sa: &ServiceAccount) -> SecretOwner<'_> {
    SecretOwner::namespaced(
        KIND,
        sa.metadata.namespace.as_deref().unwrap_or_default(),
        sa.metadata.name.as_deref().unwrap_or_default(),
    )
    .formerly(api::ANNOTATIONS.previous_owner(&sa.metadata))
}

/// The keys a target receives. Its `Debug` hides the password.
pub struct Credentials(BTreeMap<String, String>);

impl std::ops::Deref for Credentials {
    type Target = BTreeMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(k, v)| {
                let v = if k == keys::PASSWORD { "<redacted>" } else { v };
                (k, v)
            }))
            .finish()
    }
}

/// What every target receives: the submission service, the account's
/// address as `username`, its App Password as `password`, and `from` — the
/// first alias, or the address.
pub fn credentials(
    address: &str,
    first_alias: Option<&str>,
    settings: &InstanceSettings,
    password: &str,
) -> Credentials {
    let from = first_alias.map_or_else(|| address.to_string(), String::from);
    Credentials(BTreeMap::from([
        (keys::HOST.into(), settings.submission.host.clone()),
        (keys::PORT.into(), settings.submission.port.to_string()),
        (
            keys::SECURITY.into(),
            settings.submission.security.as_str().into(),
        ),
        (keys::USERNAME.into(), address.to_string()),
        (keys::PASSWORD.into(), password.to_string()),
        (keys::FROM.into(), from),
    ]))
}

pub async fn reconcile_service_account(
    sa: &ServiceAccount,
    instance: &BoundInstance,
    ports: Ports<'_>,
    secrets: &dyn SecretStore,
) -> Outcome {
    match reconcile(sa, instance, ports, secrets).await {
        Ok(outcome) => outcome,
        Err(outcome) => *outcome,
    }
}

async fn reconcile(
    sa: &ServiceAccount,
    instance: &BoundInstance,
    ports: Ports<'_>,
    secrets: &dyn SecretStore,
) -> Result<Outcome, Box<Outcome>> {
    check_service_account(sa).map_err(fail)?;
    let subject = subject(sa);
    let owner = owner(sa);
    let targets = emit::targets(&sa.spec.secret_targets, subject.cr_name, secrets);
    check_smtp_targets(&sa.spec.secret_targets, Some(secrets.default_backend())).map_err(fail)?;
    emit::check_targets(&targets, &owner).map_err(fail)?;
    let domain = accounts::admit(&subject, instance, ports.cluster, ports.policies)
        .await
        .map_err(fail)?;
    let settings = ports
        .cluster
        .instance_settings(instance)
        .await
        .map_err(|e| fail(cluster_failure(e)))?
        .ok_or_else(|| {
            fail(Failure::new(
                ReasonCode::InstanceNotFound,
                format!("{instance} not found"),
            ))
        })?;

    let mut desired = DesiredAccount::new(
        AccountType::User,
        &subject.name,
        &domain.id,
        &subject.aliases,
    );
    desired.permissions = Some(OwnedPermissions::service_account(sa.spec.receive));
    // RFC 0001 D24: without the instance's App Password key, no account is
    // created that couldn't be given a credential.
    ports.gateway.app_password_key().await.map_err(fail)?;
    let object = AccountObject {
        kind: AccountType::User,
    };
    let synced = accounts::sync(
        &object,
        &subject,
        &domain,
        &desired,
        instance,
        ports.gateway,
        ports.cluster,
    )
    .await?;
    let (id, address) = (synced.id.clone(), synced.address.clone());
    let owned = |f: Failure| Box::new(Outcome::failed(f).with_id(&id, &address));

    let nonce = api::ANNOTATIONS.rotate_nonce(&sa.metadata);
    // RFC 0001 Q21: forgejo keeps a `secretPending` status field for a
    // password that didn't reach every target; here the previous `Ready`
    // reason says it (`SecretTargetFailed`), and the `Status` stays the
    // RFC's (no field beyond `address` and `lastRotation`).
    let rotate = synced.created
        || emit::rotation_requested(&nonce, &subject.last_rotation())
        || subject.last_failed_on(ReasonCode::SecretTargetFailed)
        || emit::any_missing(&targets, &owner, secrets)
            .await
            .map_err(owned)?;
    let verb = synced.verb();
    if !rotate {
        return Ok(synced.outcome(format!("service account {address:?} {verb}")));
    }
    // A rotation is a write without a drifted field: counted, not
    // announced.
    let write = if synced.created {
        RemoteWrite::Created
    } else {
        RemoteWrite::Drift
    };
    let password = match ports.gateway.rotate_app_password(&id).await {
        Ok(password) => password,
        Err(e) => {
            // Created without its App Password: the next reconcile finds
            // the targets empty and creates one.
            let mut failed = Outcome::failed(e).with_id(&id, &address);
            if synced.created {
                failed = failed.wrote(write);
            } else if !synced.drift.is_empty() {
                failed = failed.corrected(synced.drift);
            }
            return Err(Box::new(failed));
        }
    };
    let first_alias = subject
        .aliases
        .first()
        .map(|a| mail::address(a, &domain.name));
    let data = credentials(&address, first_alias.as_deref(), &settings, &password);
    if let Err(f) = emit::write_all(&targets, &owner, &data, secrets).await {
        // The id matters most here: the next reconcile creates a new App
        // Password instead of failing on a second creation.
        return Err(Box::new(
            Outcome::failed(f).with_id(&id, &address).wrote(write),
        ));
    }
    let message = if synced.created {
        format!("service account {address:?} created, its App Password written")
    } else {
        format!("service account {address:?} {verb}, its App Password rotated")
    };
    let mut outcome = synced.outcome(message).rotated(nonce);
    outcome.write.get_or_insert(write);
    Ok(outcome)
}

/// The finalizer's cleanup: with `deletionPolicy: Delete`, the account
/// (if it is still the one recorded) and the secrets the CR wrote.
pub async fn cleanup_service_account(
    sa: &ServiceAccount,
    gateway: &dyn crate::ports::RemoteGateway,
    secrets: &dyn SecretStore,
) -> Result<Option<RemoteWrite>, Failure> {
    let object = AccountObject {
        kind: AccountType::User,
    };
    let write = accounts::cleanup(&object, &subject(sa), sa.spec.deletion_policy, gateway).await?;
    if sa.spec.deletion_policy == api::common::DeletionPolicy::Delete {
        let cr_name = sa.metadata.name.as_deref().unwrap_or_default();
        let targets = emit::targets(&sa.spec.secret_targets, cr_name, secrets);
        emit::delete_all(&targets, &owner(sa), secrets).await?;
    }
    Ok(write)
}

#[cfg(test)]
mod tests {
    use api::namespace_policy::{Effect, NamespaceRule, NamespacedKind};
    use domain::account::RemotePermissions;

    use super::*;
    use crate::ports::{APP_PASSWORD_DESCRIPTION, DomainState, GatewayError, GatewayFactoryError};
    use crate::test_support::{
        FakeCluster, FakeGateway, FakeSecretStore, VaultDefaultStore, record,
    };

    struct World {
        gateway: FakeGateway,
        cluster: FakeCluster,
        secrets: FakeSecretStore,
        domain: String,
    }

    impl World {
        fn new() -> Self {
            let gateway = FakeGateway::default();
            let domain = gateway.seed_domain("weebo.internal");
            let cluster = FakeCluster::default();
            cluster.set_domain("weebo.internal", &domain, &main());
            Self {
                gateway,
                cluster,
                secrets: FakeSecretStore::default(),
                domain,
            }
        }

        fn ports(&self) -> Ports<'_> {
            Ports {
                gateway: &self.gateway,
                cluster: &self.cluster,
                policies: &self.cluster,
            }
        }

        async fn run(&self, sa: &ServiceAccount) -> Outcome {
            reconcile_service_account(sa, &main(), self.ports(), &self.secrets).await
        }

        /// Reconciles, then records the outcome in `sa`'s status.
        async fn step(&self, sa: &mut ServiceAccount) -> Outcome {
            let outcome = self.run(sa).await;
            record(&mut sa.status, &outcome);
            outcome
        }

        fn secret(&self) -> BTreeMap<String, String> {
            self.secrets
                .get("forgejo/forgejo")
                .expect("the implicit target")
        }
    }

    fn main() -> BoundInstance {
        BoundInstance::cluster("main")
    }

    #[test]
    fn credentials_never_debug_the_password() {
        let settings = InstanceSettings {
            submission: Default::default(),
            default_backend: Default::default(),
            vault: None,
        };
        let data = credentials("svc@weebo.internal", None, &settings, "s3cret");
        assert_eq!(data[keys::PASSWORD], "s3cret");
        let shown = format!("{data:?}");
        assert!(
            !shown.contains("s3cret") && shown.contains("<redacted>"),
            "{shown}"
        );
    }

    fn sa(spec: serde_json::Value) -> ServiceAccount {
        let mut spec = spec;
        spec["domainRef"] = serde_json::json!({"name": "weebo.internal"});
        let mut sa = ServiceAccount::new("forgejo", serde_json::from_value(spec).unwrap());
        sa.metadata.namespace = Some("forgejo".into());
        sa
    }

    fn annotate(sa: &mut ServiceAccount, key: &str, value: &str) {
        sa.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(api::ANNOTATIONS.key(key), value.to_string());
    }

    #[tokio::test]
    async fn creates_then_stays_quiet_until_drift() {
        let w = World::new();
        let mut sa = sa(serde_json::json!({"aliases": ["NoReply"]}));
        let first = w.step(&mut sa).await;
        assert_eq!(first.reason(), ReasonCode::Reconciled, "{:?}", first.ready);
        assert_eq!(first.write, Some(RemoteWrite::Created));
        assert_eq!(first.address.as_deref(), Some("forgejo@weebo.internal"));
        let id = first.remote_id.clone().unwrap();
        assert_eq!(
            w.gateway.writes(),
            [
                "create account forgejo@weebo.internal".to_string(),
                format!("app password {id}")
            ]
        );
        let account = w.gateway.account(&id).unwrap();
        assert_eq!(account.role, "User");
        assert_eq!(
            account.permissions,
            RemotePermissions::Merge {
                enabled: vec![],
                disabled: [
                    "imapAuthenticate",
                    "pop3Authenticate",
                    "sieveAuthenticate",
                    "emailReceive"
                ]
                .map(String::from)
                .to_vec(),
            }
        );
        // The App Password Stalwart generated is the one written, with the
        // SMTP settings and `from` on the first alias.
        let secret = w.secret();
        assert_eq!(secret[keys::PASSWORD], w.gateway.app_password(&id).unwrap());
        assert!(secret[keys::PASSWORD].starts_with("app_"));
        assert_eq!(secret[keys::USERNAME], "forgejo@weebo.internal");
        assert_eq!(secret[keys::FROM], "noreply@weebo.internal");
        assert_eq!(secret[keys::HOST], "stalwart.mail.svc.cluster.local");
        assert_eq!(secret[keys::PORT], "587");
        assert_eq!(secret[keys::SECURITY], "starttls");

        // Nothing changed: reads only, the password kept.
        w.gateway.clear_writes();
        let quiet = w.step(&mut sa).await;
        assert_eq!((quiet.write, quiet.drift.is_empty()), (None, true));
        assert!(w.gateway.writes().is_empty(), "{:?}", w.gateway.writes());
        assert_eq!(w.secret(), secret);

        // Changed by hand: an admin role, delivery enabled — put back, only
        // those, the password kept.
        w.gateway.edit_account(&id, |a| {
            a.role = "Admin".into();
            a.permissions = RemotePermissions::Inherit;
        });
        let corrected = w.step(&mut sa).await;
        assert_eq!(corrected.write, Some(RemoteWrite::Drift));
        assert_eq!(corrected.drift.fields(), ["roles", "permissions"]);
        assert_eq!(
            w.gateway.writes(),
            [format!("update account {id} [roles, permissions]")]
        );
        assert_eq!(w.secret(), secret);

        w.gateway.clear_writes();
        let quiet = w.step(&mut sa).await;
        assert_eq!(quiet.write, None);
        assert!(w.gateway.writes().is_empty());
    }

    #[tokio::test]
    async fn a_new_nonce_rotates_the_password_once() {
        let w = World::new();
        let mut sa = sa(serde_json::json!({}));
        let id = w.step(&mut sa).await.remote_id.unwrap();
        let before = w.secret()[keys::PASSWORD].clone();
        annotate(
            &mut sa,
            weebo_kit_api::annotations::ROTATE_SECRET,
            "2026-10-19",
        );
        w.gateway.clear_writes();
        let rotated = w.step(&mut sa).await;
        assert_eq!(
            rotated.reason(),
            ReasonCode::Reconciled,
            "{:?}",
            rotated.ready
        );
        assert_eq!(rotated.last_rotation.as_deref(), Some("2026-10-19"));
        assert_eq!(rotated.write, Some(RemoteWrite::Drift));
        assert!(rotated.drift.is_empty(), "a rotation is no drift");
        assert_eq!(w.gateway.writes(), [format!("app password {id}")]);
        let after = w.secret()[keys::PASSWORD].clone();
        assert_ne!(after, before);
        assert_eq!(w.gateway.app_password(&id).unwrap(), after);

        // The same nonce never rotates twice.
        w.gateway.clear_writes();
        assert_eq!(w.step(&mut sa).await.write, None);
        assert!(w.gateway.writes().is_empty());
    }

    #[tokio::test]
    async fn a_rotation_revokes_the_operators_app_password_only() {
        let w = World::new();
        let mut sa = sa(serde_json::json!({}));
        let id = w.step(&mut sa).await.remote_id.unwrap();
        let first = w.gateway.app_password(&id).unwrap();
        let users = w.gateway.seed_app_password(&id, "thunderbird");
        annotate(&mut sa, weebo_kit_api::annotations::ROTATE_SECRET, "1");
        w.step(&mut sa).await;
        let after = w.gateway.app_password(&id).unwrap();
        assert_ne!(after, first);
        assert_eq!(
            w.gateway.app_passwords(&id),
            [
                ("thunderbird".to_string(), users),
                (APP_PASSWORD_DESCRIPTION.to_string(), after)
            ]
        );
    }

    #[tokio::test]
    async fn without_the_app_password_key_nothing_is_created() {
        let w = World::new();
        let mut sa = sa(serde_json::json!({}));
        w.gateway
            .fail_app_password_key(Some(GatewayError::AppPasswordKey(Box::new(
                GatewayFactoryError::TokenSecret("appPasswordTokenSecretRef is not set".into()),
            ))));
        let failed = w.step(&mut sa).await;
        assert_eq!(failed.reason(), ReasonCode::TokenSecretMissing);
        assert!(
            failed
                .ready
                .unwrap_err()
                .message
                .contains("appPasswordTokenSecretRef")
        );
        assert!(w.gateway.writes().is_empty());
        assert!(w.secrets.get("forgejo/forgejo").is_none());

        // Set: the account and its App Password.
        w.gateway.fail_app_password_key(None);
        let ok = w.step(&mut sa).await;
        assert_eq!(ok.reason(), ReasonCode::Reconciled, "{:?}", ok.ready);
        let id = ok.remote_id.unwrap();
        assert_eq!(
            w.secret()[keys::PASSWORD],
            w.gateway.app_password(&id).unwrap()
        );
    }

    #[tokio::test]
    async fn a_failed_app_password_keeps_the_account_and_creates_one_next_time() {
        let w = World::new();
        let mut sa = sa(serde_json::json!({}));
        let id = w.step(&mut sa).await.remote_id.unwrap();
        // The account exists, its App Password lost with the target, and
        // Stalwart refuses the rotation once.
        w.secrets.remove("forgejo/forgejo");
        w.gateway
            .fail_with(Some(GatewayError::Unauthorized("403".into())));
        let failed = w.run(&sa).await;
        assert_eq!(failed.reason(), ReasonCode::InstanceUnauthorized);
        w.gateway.fail_with(None);
        let fixed = w.step(&mut sa).await;
        assert_eq!(fixed.reason(), ReasonCode::Reconciled, "{:?}", fixed.ready);
        assert_eq!(fixed.remote_id.as_deref(), Some(id.as_str()));
        assert_eq!(
            w.secret()[keys::PASSWORD],
            w.gateway.app_password(&id).unwrap()
        );
    }

    #[tokio::test]
    async fn a_lost_target_gets_a_new_password() {
        let w = World::new();
        let mut sa = sa(serde_json::json!({}));
        let id = w.step(&mut sa).await.remote_id.unwrap();
        w.secrets.remove("forgejo/forgejo");
        w.gateway.clear_writes();
        let outcome = w.step(&mut sa).await;
        assert_eq!(outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(w.gateway.writes(), [format!("app password {id}")]);
        assert_eq!(
            w.secret()[keys::PASSWORD],
            w.gateway.app_password(&id).unwrap()
        );
    }

    #[tokio::test]
    async fn a_failed_write_keeps_the_account_and_rotates_next_time() {
        let w = World::new();
        let mut sa = sa(serde_json::json!({}));
        w.secrets.fail_writes(true);
        let failed = w.step(&mut sa).await;
        assert_eq!(failed.reason(), ReasonCode::SecretTargetFailed);
        assert_eq!(failed.write, Some(RemoteWrite::Created));
        let id = failed.remote_id.clone().expect("the id is kept");
        assert_eq!(failed.address.as_deref(), Some("forgejo@weebo.internal"));

        // The store is back: a target may hold an outdated password, so a
        // new one is set — no second creation.
        w.secrets.fail_writes(false);
        w.gateway.clear_writes();
        let fixed = w.step(&mut sa).await;
        assert_eq!(fixed.reason(), ReasonCode::Reconciled, "{:?}", fixed.ready);
        assert_eq!(w.gateway.writes(), [format!("app password {id}")]);
        assert_eq!(
            w.secret()[keys::PASSWORD],
            w.gateway.app_password(&id).unwrap()
        );
    }

    #[tokio::test]
    async fn vault_targets_are_named_smtp_and_the_implicit_one_stays_in_kubernetes() {
        let w = World::new();
        for targets in [
            serde_json::json!([{"backend": "vault", "name": "forgejo-smtp"}]),
            serde_json::json!([{"backend": "vault", "name": "smtp", "path": "forgejo/smtp"}]),
        ] {
            let outcome = w
                .run(&sa(serde_json::json!({"secretTargets": targets})))
                .await;
            assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
            assert!(outcome.ready.unwrap_err().message.contains("smtp"));
        }
        let vault = VaultDefaultStore::default();
        let outcome =
            reconcile_service_account(&sa(serde_json::json!({})), &main(), w.ports(), &vault).await;
        assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
        let smtp = sa(serde_json::json!({"secretTargets": [{"backend": "vault", "name": "smtp"}]}));
        let outcome = reconcile_service_account(&smtp, &main(), w.ports(), &vault).await;
        assert_eq!(
            outcome.reason(),
            ReasonCode::Reconciled,
            "{:?}",
            outcome.ready
        );
        assert!(vault.0.get("forgejo/smtp").is_some());
        assert_eq!(w.gateway.writes().len(), 2, "no call before the checks");
    }

    #[tokio::test]
    async fn the_domain_must_be_ready_on_the_same_instance() {
        let w = World::new();
        let mut other = sa(serde_json::json!({}));
        other.spec.domain_ref.name = "missing.internal".into();
        assert_eq!(w.run(&other).await.reason(), ReasonCode::DomainNotFound);
        for state in [
            DomainState {
                remote_id: Some(w.domain.clone()),
                name: Some("weebo.internal".into()),
                instance: Some(main()),
                ready: false,
            },
            DomainState {
                remote_id: Some(w.domain.clone()),
                name: Some("weebo.internal".into()),
                instance: Some(BoundInstance::cluster("other")),
                ready: true,
            },
            DomainState {
                remote_id: None,
                name: None,
                instance: None,
                ready: false,
            },
        ] {
            w.cluster.set_domain_state("weebo.internal", state.clone());
            let outcome = w.run(&sa(serde_json::json!({}))).await;
            assert_eq!(outcome.reason(), ReasonCode::DomainNotReady, "{state:?}");
        }
        assert!(w.gateway.writes().is_empty());
    }

    #[tokio::test]
    async fn the_policy_covers_the_name_and_every_alias() {
        let w = World::new();
        w.cluster.set_policies(vec![vec![NamespaceRule {
            namespaces: vec!["forgejo".into()],
            allowed_kinds: vec![NamespacedKind::StalwartServiceAccount],
            allowed_domains: Some(vec!["weebo.internal".into()]),
            allowed_names: Some(vec!["forgejo".into(), "noreply".into()]),
            effect: Effect::Allow,
        }]]);
        let ok = w
            .run(&sa(serde_json::json!({"aliases": ["noreply"]})))
            .await;
        assert_eq!(ok.reason(), ReasonCode::Reconciled);
        let denied = w.run(&sa(serde_json::json!({"aliases": ["Admin"]}))).await;
        assert_eq!(denied.reason(), ReasonCode::NamespaceNotAllowed);
    }

    #[tokio::test]
    async fn a_taken_address_is_never_adopted_and_a_claimed_one_never_created() {
        let w = World::new();
        w.gateway
            .seed_account(AccountType::User, "forgejo", &w.domain);
        let outcome = w.run(&sa(serde_json::json!({}))).await;
        assert_eq!(outcome.reason(), ReasonCode::StalwartObjectAlreadyExists);
        assert!(outcome.ready.unwrap_err().message.contains("importer"));
        assert!(w.secrets.get("forgejo/forgejo").is_none());

        let w = World::new();
        w.cluster
            .set_claimants(vec!["StalwartAccount/mail/forgejo".into()]);
        let outcome = w.run(&sa(serde_json::json!({}))).await;
        assert_eq!(outcome.reason(), ReasonCode::RemoteObjectClaimed);
        assert!(w.gateway.writes().is_empty());
        w.cluster
            .set_claimants(vec!["StalwartServiceAccount/forgejo/forgejo".into()]);
        assert_eq!(
            w.run(&sa(serde_json::json!({}))).await.reason(),
            ReasonCode::Reconciled
        );
    }

    #[tokio::test]
    async fn an_id_answering_another_address_is_taken_as_gone() {
        let w = World::new();
        // A fresh store: the recorded id now designates someone else.
        let reused = w
            .gateway
            .seed_account(AccountType::User, "alice", &w.domain);
        let mut sa = sa(serde_json::json!({}));
        sa.status = Some(api::Status {
            remote_id: Some(reused.clone()),
            address: Some("forgejo@weebo.internal".into()),
            ..Default::default()
        });
        let outcome = w.run(&sa).await;
        assert_eq!(outcome.write, Some(RemoteWrite::Created));
        assert_ne!(outcome.remote_id.as_deref(), Some(reused.as_str()));
        assert_eq!(w.gateway.app_passwords(&reused), [], "never touched");
    }

    #[tokio::test]
    async fn a_rename_needs_the_disruptive_update_annotation() {
        let w = World::new();
        let mut sa = sa(serde_json::json!({}));
        let id = w.step(&mut sa).await.remote_id.unwrap();
        sa.spec.name = Some("gitea".into());
        w.gateway.clear_writes();
        let refused = w.step(&mut sa).await;
        assert_eq!(refused.reason(), ReasonCode::InvalidSpec);
        assert_eq!(refused.address.as_deref(), Some("forgejo@weebo.internal"));
        assert!(w.gateway.writes().is_empty());
        annotate(&mut sa, "allow-disruptive-update", "true");
        let renamed = w.step(&mut sa).await;
        assert_eq!(
            renamed.reason(),
            ReasonCode::Reconciled,
            "{:?}",
            renamed.ready
        );
        assert_eq!(renamed.address.as_deref(), Some("gitea@weebo.internal"));
        assert_eq!(
            w.gateway.account(&id).unwrap().email_address,
            "gitea@weebo.internal"
        );
    }

    #[tokio::test]
    async fn deletion_follows_the_policy() {
        let w = World::new();
        let mut sa = sa(serde_json::json!({}));
        let id = w.step(&mut sa).await.remote_id.unwrap();
        // Orphan: both left.
        sa.spec.deletion_policy = api::common::DeletionPolicy::Orphan;
        assert_eq!(
            cleanup_service_account(&sa, &w.gateway, &w.secrets).await,
            Ok(None)
        );
        assert!(w.gateway.account(&id).is_some());
        assert!(w.secrets.get("forgejo/forgejo").is_some());
        // Delete: both gone.
        sa.spec.deletion_policy = api::common::DeletionPolicy::Delete;
        assert_eq!(
            cleanup_service_account(&sa, &w.gateway, &w.secrets).await,
            Ok(Some(RemoteWrite::Deleted))
        );
        assert!(w.gateway.account(&id).is_none());
        assert!(w.secrets.get("forgejo/forgejo").is_none());
        // Gone already: nothing to do.
        assert_eq!(
            cleanup_service_account(&sa, &w.gateway, &w.secrets).await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn failures_map_to_their_reason() {
        let w = World::new();
        w.gateway
            .fail_with(Some(GatewayError::Unauthorized("403".into())));
        assert_eq!(
            w.run(&sa(serde_json::json!({}))).await.reason(),
            ReasonCode::InstanceUnauthorized
        );
        w.gateway.fail_with(None);
        w.cluster.set_settings(None);
        assert_eq!(
            w.run(&sa(serde_json::json!({}))).await.reason(),
            ReasonCode::InstanceNotFound
        );
        let invalid = w.run(&sa(serde_json::json!({"name": "a+b"}))).await;
        assert_eq!(invalid.reason(), ReasonCode::InvalidSpec);
        let own = w
            .run(&sa(serde_json::json!({"aliases": ["Forgejo"]})))
            .await;
        assert_eq!(own.reason(), ReasonCode::InvalidSpec);
    }
}
