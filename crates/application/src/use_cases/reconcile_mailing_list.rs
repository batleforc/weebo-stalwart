//! A `StalwartMailingList` → `x:MailingList`: the object of [`accounts`]
//! with its recipients, compared as a set of addresses. An `accountRef`
//! resolves to its `StalwartAccount`'s confirmed `status.address` before
//! the comparison; one that names no account of the namespace, or one
//! without an address yet, is `AccountNotFound` (retried: the account may
//! be on its way).

use api::MailingList;
use domain::allow_list::Kind;
use domain::error::ReasonCode;
use domain::mailing_list::DesiredMailingList;
use domain::{Failure, RemoteWrite};

use crate::ports::{BoundInstance, ClusterReader, RemoteGateway};
use crate::use_cases::accounts::{self, MailingListObject, Ports, Subject, fail};
use crate::use_cases::admission::check_mailing_list;
use crate::use_cases::{Outcome, cluster_failure};

pub const KIND: &str = "StalwartMailingList";

pub fn subject(list: &MailingList) -> Subject<'_> {
    Subject::new(
        KIND,
        Kind::MailingList,
        list.metadata.namespace.as_deref().unwrap_or_default(),
        list.metadata.name.as_deref().unwrap_or_default(),
        &list.metadata,
        list.status.as_ref(),
        &list.spec.domain_ref.name,
        list.local_part(),
        &list.spec.aliases,
    )
}

/// Every recipient as an address: `accountRef`s resolved in `namespace`.
pub async fn recipients(
    list: &MailingList,
    namespace: &str,
    cluster: &dyn ClusterReader,
) -> Result<Vec<String>, Failure> {
    let mut addresses = Vec::with_capacity(list.spec.recipients.len());
    for recipient in &list.spec.recipients {
        match (&recipient.address, &recipient.account_ref) {
            (Some(address), _) => addresses.push(address.clone()),
            (None, Some(account)) => {
                let address = cluster
                    .account_address(namespace, &account.name)
                    .await
                    .map_err(cluster_failure)?
                    .ok_or_else(|| {
                        Failure::new(
                            ReasonCode::AccountNotFound,
                            format!(
                                "spec.recipients: no StalwartAccount {namespace}/{} with a \
                                 confirmed address",
                                account.name
                            ),
                        )
                    })?;
                addresses.push(address);
            }
            (None, None) => {}
        }
    }
    Ok(addresses)
}

pub async fn reconcile_mailing_list(
    list: &MailingList,
    instance: &BoundInstance,
    ports: Ports<'_>,
) -> Outcome {
    match reconcile(list, instance, ports).await {
        Ok(outcome) => outcome,
        Err(outcome) => *outcome,
    }
}

async fn reconcile(
    list: &MailingList,
    instance: &BoundInstance,
    ports: Ports<'_>,
) -> Result<Outcome, Box<Outcome>> {
    check_mailing_list(list).map_err(fail)?;
    let subject = subject(list);
    let domain = accounts::admit(&subject, instance, ports.cluster, ports.policies)
        .await
        .map_err(fail)?;
    let recipients = recipients(list, subject.namespace, ports.cluster)
        .await
        .map_err(fail)?;
    let desired = DesiredMailingList::new(&subject.name, &domain.id, &subject.aliases, &recipients);
    let synced = accounts::sync(
        &MailingListObject,
        &subject,
        &domain,
        &desired,
        instance,
        ports.gateway,
        ports.cluster,
    )
    .await?;
    let message = format!("mailing list {:?} {}", synced.address, synced.verb());
    Ok(synced.outcome(message))
}

/// The finalizer's cleanup: with `deletionPolicy: Delete` only.
pub async fn cleanup_mailing_list(
    list: &MailingList,
    gateway: &dyn RemoteGateway,
) -> Result<Option<RemoteWrite>, Failure> {
    accounts::cleanup(
        &MailingListObject,
        &subject(list),
        list.spec.deletion_policy,
        gateway,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeCluster, FakeGateway, record};

    fn main() -> BoundInstance {
        BoundInstance::cluster("main")
    }

    fn list(spec: serde_json::Value) -> MailingList {
        let mut spec = spec;
        spec["domainRef"] = serde_json::json!({"name": "weebo.internal"});
        let mut l = MailingList::new("team", serde_json::from_value(spec).unwrap());
        l.metadata.namespace = Some("mail".into());
        l
    }

    fn world() -> (FakeGateway, FakeCluster) {
        let gateway = FakeGateway::default();
        let domain = gateway.seed_domain("weebo.internal");
        let cluster = FakeCluster::default();
        cluster.set_domain("weebo.internal", &domain, &main());
        (gateway, cluster)
    }

    async fn step(l: &mut MailingList, gateway: &FakeGateway, cluster: &FakeCluster) -> Outcome {
        let ports = Ports {
            gateway,
            cluster,
            policies: cluster,
        };
        let outcome = reconcile_mailing_list(l, &main(), ports).await;
        record(&mut l.status, &outcome);
        outcome
    }

    #[tokio::test]
    async fn creates_then_stays_quiet_until_drift() {
        let (gateway, cluster) = world();
        cluster.set_account_address("mail", "alice", "alice@weebo.internal");
        let mut l = list(serde_json::json!({
            "recipients": [{"address": "Bob@Example.com"}, {"accountRef": {"name": "alice"}}],
        }));
        let first = step(&mut l, &gateway, &cluster).await;
        assert_eq!(first.reason(), ReasonCode::Reconciled, "{:?}", first.ready);
        assert_eq!(first.address.as_deref(), Some("team@weebo.internal"));
        let id = first.remote_id.clone().unwrap();
        assert_eq!(
            gateway.mailing_list(&id).unwrap().recipients,
            ["alice@weebo.internal", "bob@example.com"]
        );
        gateway.clear_writes();
        assert_eq!(step(&mut l, &gateway, &cluster).await.write, None);
        // Stored in another case: the same set.
        gateway.edit_mailing_list(&id, |r| {
            r.recipients = vec!["BOB@example.com".into(), "alice@weebo.internal".into()]
        });
        assert_eq!(step(&mut l, &gateway, &cluster).await.write, None);
        gateway.edit_mailing_list(&id, |r| r.recipients.push("eve@example.com".into()));
        let corrected = step(&mut l, &gateway, &cluster).await;
        assert_eq!(corrected.drift.fields(), ["recipients"]);
        assert_eq!(gateway.writes(), [format!("update list {id} [recipients]")]);
        gateway.clear_writes();
        assert_eq!(step(&mut l, &gateway, &cluster).await.write, None);
        assert!(gateway.writes().is_empty());
    }

    #[tokio::test]
    async fn an_account_ref_without_an_address_is_account_not_found() {
        let (gateway, cluster) = world();
        let mut l = list(serde_json::json!({"recipients": [{"accountRef": {"name": "ghost"}}]}));
        let outcome = step(&mut l, &gateway, &cluster).await;
        assert_eq!(outcome.reason(), ReasonCode::AccountNotFound);
        assert!(gateway.writes().is_empty());
    }

    #[tokio::test]
    async fn a_recipient_must_be_an_address() {
        let (gateway, cluster) = world();
        for bad in ["nobody", "a@localhost", "a b@example.com"] {
            let mut l = list(serde_json::json!({"recipients": [{"address": bad}]}));
            assert_eq!(
                step(&mut l, &gateway, &cluster).await.reason(),
                ReasonCode::InvalidSpec,
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn deleted_by_default() {
        let (gateway, cluster) = world();
        let mut l = list(serde_json::json!({}));
        let id = step(&mut l, &gateway, &cluster).await.remote_id.unwrap();
        assert_eq!(
            cleanup_mailing_list(&l, &gateway).await,
            Ok(Some(RemoteWrite::Deleted))
        );
        assert!(gateway.mailing_list(&id).is_none());
    }
}
