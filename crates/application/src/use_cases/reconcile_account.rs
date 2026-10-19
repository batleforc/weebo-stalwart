//! A `StalwartAccount` → `x:Account` `User`, without credential: the
//! account of [`accounts`], with its quota, locale, time zone, and its
//! state (RFC 0001, "Verrouillage").
//!
//! `Locked` adds `authenticate`, `emailSend` and `emailReceive` to the
//! account's `disabledPermissions` (`permissions: Merge`): every login goes
//! through the `Authenticate` permission, App Passwords included — they
//! are kept, unusable while locked. The mail, the address and the aliases
//! stay, and so does the claim on them. `Active` removes those three
//! entries only. A lock applied is the desired state reached: `Ready: True`,
//! reason `Reconciled` (D20) — what the link brick's `safe` expression
//! reads (RFC 0002). A lock that fails keeps `Ready: False` with its
//! reason.

use api::Account;
use api::account::AccountState;
use domain::Failure;
use domain::RemoteWrite;
use domain::account::{AccountType, DesiredAccount, OwnedPermissions};
use domain::allow_list::Kind;

use crate::ports::{BoundInstance, RemoteGateway};
use crate::use_cases::Outcome;
use crate::use_cases::accounts::{self, AccountObject, Ports, Subject, fail};
use crate::use_cases::admission::check_account;

pub const KIND: &str = "StalwartAccount";

const OBJECT: AccountObject = AccountObject {
    kind: AccountType::User,
};

pub fn subject(account: &Account) -> Subject<'_> {
    Subject::new(
        KIND,
        Kind::Account,
        account.metadata.namespace.as_deref().unwrap_or_default(),
        account.metadata.name.as_deref().unwrap_or_default(),
        &account.metadata,
        account.status.as_ref(),
        &account.spec.domain_ref.name,
        account.local_part(),
        &account.spec.aliases,
    )
}

pub async fn reconcile_account(
    account: &Account,
    instance: &BoundInstance,
    ports: Ports<'_>,
) -> Outcome {
    match reconcile(account, instance, ports).await {
        Ok(outcome) => outcome,
        Err(outcome) => *outcome,
    }
}

async fn reconcile(
    account: &Account,
    instance: &BoundInstance,
    ports: Ports<'_>,
) -> Result<Outcome, Box<Outcome>> {
    let quota = check_account(account).map_err(fail)?;
    let subject = subject(account);
    let domain = accounts::admit(&subject, instance, ports.cluster, ports.policies)
        .await
        .map_err(fail)?;
    let locked = account.spec.state == AccountState::Locked;
    let mut desired = DesiredAccount::new(
        AccountType::User,
        &subject.name,
        &domain.id,
        &subject.aliases,
    );
    desired.permissions = Some(OwnedPermissions::account(locked));
    desired.quota = quota;
    desired.locale = account.spec.locale.clone();
    desired.time_zone = account.spec.time_zone.clone();
    let synced = accounts::sync(
        &OBJECT,
        &subject,
        &domain,
        &desired,
        instance,
        ports.gateway,
        ports.cluster,
    )
    .await?;
    let message = match (locked, synced.verb()) {
        (true, verb) => format!("account {:?} {verb}, locked", synced.address),
        (false, verb) => format!("account {:?} {verb}", synced.address),
    };
    Ok(synced.outcome(message))
}

/// The finalizer's cleanup: with `deletionPolicy: Delete` only, the
/// mailbox and its mail.
pub async fn cleanup_account(
    account: &Account,
    gateway: &dyn RemoteGateway,
) -> Result<Option<RemoteWrite>, Failure> {
    accounts::cleanup(
        &OBJECT,
        &subject(account),
        account.spec.deletion_policy,
        gateway,
    )
    .await
}

#[cfg(test)]
mod tests {
    use domain::account::RemotePermissions;
    use domain::error::ReasonCode;

    use super::*;
    use crate::ports::GatewayError;
    use crate::test_support::{FakeCluster, FakeGateway, record};

    fn main() -> BoundInstance {
        BoundInstance::cluster("main")
    }

    fn world() -> (FakeGateway, FakeCluster, String) {
        let gateway = FakeGateway::default();
        let domain = gateway.seed_domain("weebo.internal");
        let cluster = FakeCluster::default();
        cluster.set_domain("weebo.internal", &domain, &main());
        (gateway, cluster, domain)
    }

    fn ports<'a>(gateway: &'a FakeGateway, cluster: &'a FakeCluster) -> Ports<'a> {
        Ports {
            gateway,
            cluster,
            policies: cluster,
        }
    }

    fn account(spec: serde_json::Value) -> Account {
        let mut spec = spec;
        spec["domainRef"] = serde_json::json!({"name": "weebo.internal"});
        let mut a = Account::new("alice", serde_json::from_value(spec).unwrap());
        a.metadata.namespace = Some("mail".into());
        a
    }

    async fn step(a: &mut Account, gateway: &FakeGateway, cluster: &FakeCluster) -> Outcome {
        let outcome = reconcile_account(a, &main(), ports(gateway, cluster)).await;
        record(&mut a.status, &outcome);
        outcome
    }

    fn disabled(gateway: &FakeGateway, id: &str) -> Vec<String> {
        match gateway.account(id).unwrap().permissions {
            RemotePermissions::Merge { disabled, .. } => disabled,
            RemotePermissions::Inherit => vec![],
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn creates_then_stays_quiet_until_drift() {
        let (gateway, cluster, _) = world();
        let mut a = account(serde_json::json!({
            "aliases": ["Max"], "quota": "2Gi", "locale": "fr-FR", "timeZone": "Europe/Paris",
        }));
        let first = step(&mut a, &gateway, &cluster).await;
        assert_eq!(first.reason(), ReasonCode::Reconciled, "{:?}", first.ready);
        assert_eq!(first.write, Some(RemoteWrite::Created));
        let id = first.remote_id.clone().unwrap();
        let stored = gateway.account(&id).unwrap();
        assert_eq!(stored.permissions, RemotePermissions::Inherit);
        assert_eq!(stored.quotas["maxDiskQuota"], 2_147_483_648);
        assert_eq!(gateway.app_passwords(&id), [], "no credential");

        gateway.clear_writes();
        assert_eq!(step(&mut a, &gateway, &cluster).await.write, None);
        assert!(gateway.writes().is_empty());

        // What the OpenID Connect login writes is not the operator's.
        gateway.edit_account(&id, |r| {
            r.quotas.insert("maxDiskQuota".into(), 1);
            r.locale = Some("en-US".into());
        });
        let corrected = step(&mut a, &gateway, &cluster).await;
        assert_eq!(corrected.drift.fields(), ["quotas", "locale"]);
        assert_eq!(
            gateway.writes(),
            [format!("update account {id} [quotas, locale]")]
        );
        gateway.clear_writes();
        assert_eq!(step(&mut a, &gateway, &cluster).await.write, None);
        assert!(gateway.writes().is_empty());
    }

    #[tokio::test]
    async fn locked_is_ready_and_unlocking_gives_back_only_the_operators_entries() {
        let (gateway, cluster, _) = world();
        let mut a = account(serde_json::json!({}));
        let id = step(&mut a, &gateway, &cluster).await.remote_id.unwrap();
        // Someone disabled IMAP for this user: not the operator's entry.
        gateway.edit_account(&id, |r| {
            r.permissions = RemotePermissions::Merge {
                enabled: vec![],
                disabled: vec!["imapAuthenticate".into()],
            }
        });

        a.spec.state = AccountState::Locked;
        let locked = step(&mut a, &gateway, &cluster).await;
        // D20: the lock applied is `Ready: True`, `Reconciled`.
        assert_eq!(
            locked.reason(),
            ReasonCode::Reconciled,
            "{:?}",
            locked.ready
        );
        assert!(locked.ready.as_ref().unwrap().contains("locked"));
        assert_eq!(locked.drift.fields(), ["permissions"]);
        assert_eq!(
            disabled(&gateway, &id),
            [
                "imapAuthenticate",
                "authenticate",
                "emailSend",
                "emailReceive"
            ]
        );
        gateway.clear_writes();
        assert_eq!(
            step(&mut a, &gateway, &cluster).await.write,
            None,
            "quiet while locked"
        );
        assert_eq!(locked.address.as_deref(), Some("alice@weebo.internal"));

        a.spec.state = AccountState::Active;
        let unlocked = step(&mut a, &gateway, &cluster).await;
        assert_eq!(unlocked.reason(), ReasonCode::Reconciled);
        assert_eq!(disabled(&gateway, &id), ["imapAuthenticate"]);
    }

    #[tokio::test]
    async fn a_failed_lock_is_not_ready() {
        let (gateway, cluster, _) = world();
        let mut a = account(serde_json::json!({}));
        step(&mut a, &gateway, &cluster).await;
        a.spec.state = AccountState::Locked;
        gateway.fail_with(Some(GatewayError::Unreachable("down".into())));
        let failed = step(&mut a, &gateway, &cluster).await;
        assert_eq!(failed.reason(), ReasonCode::InstanceUnreachable);
    }

    #[tokio::test]
    async fn an_account_created_locked_is_created_with_the_lock() {
        let (gateway, cluster, _) = world();
        let mut a = account(serde_json::json!({"state": "Locked"}));
        let id = step(&mut a, &gateway, &cluster).await.remote_id.unwrap();
        assert_eq!(
            disabled(&gateway, &id),
            ["authenticate", "emailSend", "emailReceive"]
        );
    }

    #[tokio::test]
    async fn an_account_the_login_created_first_needs_the_importer() {
        let (gateway, cluster, domain) = world();
        gateway.seed_account(AccountType::User, "alice", &domain);
        let mut a = account(serde_json::json!({}));
        let outcome = step(&mut a, &gateway, &cluster).await;
        assert_eq!(outcome.reason(), ReasonCode::StalwartObjectAlreadyExists);
    }

    #[tokio::test]
    async fn a_bad_quota_is_an_invalid_spec() {
        let (gateway, cluster, _) = world();
        let mut a = account(serde_json::json!({"quota": "2GB"}));
        let outcome = step(&mut a, &gateway, &cluster).await;
        assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
        assert!(outcome.ready.unwrap_err().message.contains("spec.quota"));
    }

    #[tokio::test]
    async fn a_mailbox_is_only_deleted_explicitly() {
        let (gateway, cluster, _) = world();
        let mut a = account(serde_json::json!({}));
        let id = step(&mut a, &gateway, &cluster).await.remote_id.unwrap();
        assert_eq!(
            cleanup_account(&a, &gateway).await,
            Ok(None),
            "Orphan by default"
        );
        assert!(gateway.account(&id).is_some());
        a.spec.deletion_policy = api::common::DeletionPolicy::Delete;
        assert_eq!(
            cleanup_account(&a, &gateway).await,
            Ok(Some(RemoteWrite::Deleted))
        );
        assert!(gateway.account(&id).is_none());
    }

    #[tokio::test]
    async fn a_group_id_is_not_an_account() {
        let (gateway, cluster, domain) = world();
        // The recorded id answers with a group of the same address.
        let group = gateway.seed_account(AccountType::Group, "alice", &domain);
        let mut a = account(serde_json::json!({}));
        a.status = Some(api::Status {
            remote_id: Some(group.clone()),
            address: Some("alice@weebo.internal".into()),
            ..Default::default()
        });
        a.spec.deletion_policy = api::common::DeletionPolicy::Delete;
        assert_eq!(cleanup_account(&a, &gateway).await, Ok(None));
        assert!(gateway.account(&group).is_some(), "never deleted");
        let outcome = step(&mut a, &gateway, &cluster).await;
        assert_eq!(outcome.reason(), ReasonCode::StalwartObjectAlreadyExists);
    }
}
