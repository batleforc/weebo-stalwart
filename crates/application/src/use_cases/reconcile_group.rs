//! A `StalwartGroup` → `x:Account` `Group` (`roles: Default`): the account
//! of [`accounts`] with its quota. Its members are the OpenID Connect
//! login's (`memberGroupIds`, D6), never compared nor written; nor are its
//! permissions.

use api::Group;
use domain::Failure;
use domain::RemoteWrite;
use domain::account::{AccountType, DesiredAccount};
use domain::allow_list::Kind;

use crate::ports::{BoundInstance, RemoteGateway};
use crate::use_cases::Outcome;
use crate::use_cases::accounts::{self, AccountObject, Ports, Subject, fail};
use crate::use_cases::admission::check_group;

pub const KIND: &str = "StalwartGroup";

const OBJECT: AccountObject = AccountObject {
    kind: AccountType::Group,
};

pub fn subject(group: &Group) -> Subject<'_> {
    Subject::new(
        KIND,
        Kind::Group,
        group.metadata.namespace.as_deref().unwrap_or_default(),
        group.metadata.name.as_deref().unwrap_or_default(),
        &group.metadata,
        group.status.as_ref(),
        &group.spec.domain_ref.name,
        group.local_part(),
        &group.spec.aliases,
    )
}

pub async fn reconcile_group(group: &Group, instance: &BoundInstance, ports: Ports<'_>) -> Outcome {
    match reconcile(group, instance, ports).await {
        Ok(outcome) => outcome,
        Err(outcome) => *outcome,
    }
}

async fn reconcile(
    group: &Group,
    instance: &BoundInstance,
    ports: Ports<'_>,
) -> Result<Outcome, Box<Outcome>> {
    let quota = check_group(group).map_err(fail)?;
    let subject = subject(group);
    let domain = accounts::admit(&subject, instance, ports.cluster, ports.policies)
        .await
        .map_err(fail)?;
    let mut desired = DesiredAccount::new(
        AccountType::Group,
        &subject.name,
        &domain.id,
        &subject.aliases,
    );
    desired.quota = quota;
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
    let message = format!("group {:?} {}", synced.address, synced.verb());
    Ok(synced.outcome(message))
}

/// The finalizer's cleanup: with `deletionPolicy: Delete` only. Stalwart
/// refuses it while accounts are members (`ObjectIsLinked`, retried).
pub async fn cleanup_group(
    group: &Group,
    gateway: &dyn RemoteGateway,
) -> Result<Option<RemoteWrite>, Failure> {
    accounts::cleanup(
        &OBJECT,
        &subject(group),
        group.spec.deletion_policy,
        gateway,
    )
    .await
}

#[cfg(test)]
mod tests {
    use domain::error::ReasonCode;

    use super::*;
    use crate::test_support::{FakeCluster, FakeGateway, record};

    fn main() -> BoundInstance {
        BoundInstance::cluster("main")
    }

    fn group(spec: serde_json::Value) -> Group {
        let mut spec = spec;
        spec["domainRef"] = serde_json::json!({"name": "weebo.internal"});
        let mut g = Group::new("team", serde_json::from_value(spec).unwrap());
        g.metadata.namespace = Some("mail".into());
        g
    }

    fn world() -> (FakeGateway, FakeCluster, String) {
        let gateway = FakeGateway::default();
        let domain = gateway.seed_domain("weebo.internal");
        let cluster = FakeCluster::default();
        cluster.set_domain("weebo.internal", &domain, &main());
        (gateway, cluster, domain)
    }

    async fn step(g: &mut Group, gateway: &FakeGateway, cluster: &FakeCluster) -> Outcome {
        let ports = Ports {
            gateway,
            cluster,
            policies: cluster,
        };
        let outcome = reconcile_group(g, &main(), ports).await;
        record(&mut g.status, &outcome);
        outcome
    }

    #[tokio::test]
    async fn creates_then_stays_quiet_until_drift() {
        let (gateway, cluster, _) = world();
        let mut g = group(serde_json::json!({"aliases": ["all"], "quota": "10Gi"}));
        let first = step(&mut g, &gateway, &cluster).await;
        assert_eq!(first.reason(), ReasonCode::Reconciled, "{:?}", first.ready);
        let id = first.remote_id.clone().unwrap();
        let stored = gateway.account(&id).unwrap();
        assert_eq!(
            (stored.kind.as_str(), stored.role.as_str()),
            ("Group", "Default")
        );
        gateway.clear_writes();
        assert_eq!(step(&mut g, &gateway, &cluster).await.write, None);
        // Members and permissions are the login's: no opinion.
        gateway.edit_account(&id, |r| {
            r.permissions = domain::account::RemotePermissions::Merge {
                enabled: vec![],
                disabled: vec!["authenticate".into()],
            };
            r.aliases.clear();
        });
        let corrected = step(&mut g, &gateway, &cluster).await;
        assert_eq!(corrected.drift.fields(), ["aliases"]);
        gateway.clear_writes();
        assert_eq!(step(&mut g, &gateway, &cluster).await.write, None);
        assert!(gateway.writes().is_empty());
    }

    #[tokio::test]
    async fn a_group_the_login_created_needs_the_importer() {
        let (gateway, cluster, domain) = world();
        gateway.seed_account(AccountType::Group, "team", &domain);
        let mut g = group(serde_json::json!({}));
        assert_eq!(
            step(&mut g, &gateway, &cluster).await.reason(),
            ReasonCode::StalwartObjectAlreadyExists
        );
    }

    #[tokio::test]
    async fn a_group_with_members_is_not_deleted_until_it_has_none() {
        let (gateway, cluster, _) = world();
        let mut g = group(serde_json::json!({"deletionPolicy": "Delete"}));
        let id = step(&mut g, &gateway, &cluster).await.remote_id.unwrap();
        gateway.link(&id);
        let refused = cleanup_group(&g, &gateway).await.unwrap_err();
        assert_eq!(refused.reason, ReasonCode::ObjectIsLinked);
        assert!(gateway.account(&id).is_some());
        gateway.unlink(&id);
        assert_eq!(
            cleanup_group(&g, &gateway).await,
            Ok(Some(RemoteWrite::Deleted))
        );
    }
}
