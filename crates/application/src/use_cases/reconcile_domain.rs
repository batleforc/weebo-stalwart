//! A `StalwartDomain` → `x:Domain`. Read by `status.remoteId`, never by
//! name (D9): with no id recorded, the domain is created — a name already
//! taken in Stalwart fails (`StalwartObjectAlreadyExists`), it is never
//! adopted; the importer links an existing domain to its CR. A read by id
//! is only trusted when the name it answers is the one `status.address`
//! confirmed (D19): ids restart from the beginning on a fresh store, and
//! an id may then designate another domain — taken as gone, recreated,
//! never patched.
//!
//! Present, the domain is compared with the spec on the fields the
//! operator owns (`domain::mail_domain`) and only the drifted ones are
//! sent; nothing at all when in sync. A rename moves every address of the
//! domain: it needs `allow-disruptive-update`. The CR is never deleted
//! remotely (`deletionPolicy: Orphan` only, D18): the finalizer only
//! releases it.

use api::Domain;
use domain::Failure;
use domain::RemoteWrite;
use domain::error::ReasonCode;
use domain::mail_domain::domain_patch;

use crate::ports::{BoundInstance, ClaimKind, ClusterReader, GatewayError, RemoteGateway};
use crate::use_cases::admission::check_domain;
use crate::use_cases::{Outcome, cluster_failure};

/// `StalwartDomain/<name>`: how claims name the CR.
pub fn claim_id(domain: &Domain) -> String {
    format!(
        "StalwartDomain/{}",
        domain.metadata.name.as_deref().unwrap_or_default()
    )
}

/// The unique claim: before creating (or renaming to) `name`, no other CR
/// may own it on the same server.
async fn claimed_elsewhere(
    cluster: &dyn ClusterReader,
    name: &str,
    instance: &BoundInstance,
    me: &str,
) -> Result<Option<Failure>, Failure> {
    let claimants = cluster
        .claimants(ClaimKind::Domain, name, instance)
        .await
        .map_err(cluster_failure)?;
    Ok(claimants.into_iter().find(|c| c != me).map(|other| {
        Failure::new(
            ReasonCode::RemoteObjectClaimed,
            format!("domain {name:?} on this server is already owned by {other}"),
        )
    }))
}

pub async fn reconcile_domain(
    domain: &Domain,
    instance: &BoundInstance,
    gateway: &dyn RemoteGateway,
    cluster: &dyn ClusterReader,
) -> Outcome {
    match reconcile(domain, instance, gateway, cluster).await {
        Ok(outcome) => outcome,
        Err(outcome) => *outcome,
    }
}

/// A failure, boxed: the early return of [`reconcile`].
fn fail(failure: impl Into<Failure>) -> Box<Outcome> {
    Box::new(Outcome::failed(failure))
}

async fn reconcile(
    domain: &Domain,
    instance: &BoundInstance,
    gateway: &dyn RemoteGateway,
    cluster: &dyn ClusterReader,
) -> Result<Outcome, Box<Outcome>> {
    check_domain(domain).map_err(fail)?;
    let desired = domain.desired();
    let status = domain.status.as_ref();
    let me = claim_id(domain);

    // D19: the id answers for the name recorded with it, or for nothing.
    // RFC 0001 Q15: a `remoteId` without `status.address` (a hand-edited
    // status) proves nothing either: the CR falls back to a creation, which
    // fails `StalwartObjectAlreadyExists` if the domain is there.
    let recorded = status.and_then(|s| s.remote_id.as_deref().zip(s.address.as_deref()));
    let remote = match recorded {
        Some((id, confirmed)) => gateway
            .get_domain(id)
            .await
            .map_err(fail)?
            .filter(|r| domain::mail::normalize_domain(&r.name) == confirmed)
            .map(|r| (id.to_string(), r)),
        None => None,
    };

    let Some((id, remote)) = remote else {
        if let Some(claimed) = claimed_elsewhere(cluster, &desired.name, instance, &me)
            .await
            .map_err(fail)?
        {
            return Err(Box::new(Outcome::failed(claimed)));
        }
        return match gateway.create_domain(&desired).await {
            Ok(id) => Ok(
                Outcome::synced(Some(id), format!("domain {:?} created", desired.name))
                    .at(&desired.name)
                    .wrote(RemoteWrite::Created),
            ),
            Err(GatewayError::AlreadyExists(why)) => Err(Box::new(Outcome::failed(Failure::new(
                ReasonCode::StalwartObjectAlreadyExists,
                format!(
                    "{why}: the operator never adopts an existing domain — link it to this CR \
                     with weebo-stalwart-importer, or choose another name"
                ),
            )))),
            Err(e) => Err(Box::new(Outcome::failed(e))),
        };
    };

    let (patch, drift) = domain_patch(&desired, &remote);
    if drift.is_empty() {
        return Ok(
            Outcome::synced(Some(id), format!("domain {:?} in sync", desired.name))
                .at(&desired.name),
        );
    }
    let current = domain::mail::normalize_domain(&remote.name);
    // RFC 0001 Q14: a refused rename reports `InvalidSpec` (the RFC lists
    // no `DisruptiveUpdateRefused`); the CR keeps its id and confirmed name.
    if patch.renames() {
        if !api::ANNOTATIONS.allows_disruptive_update(&domain.metadata) {
            return Err(Box::new(
                Outcome::failed(Failure::new(
                    ReasonCode::InvalidSpec,
                    format!(
                        "renaming domain {current:?} to {:?} moves every address of the domain: \
                     annotate the CR with {}=\"true\" to apply it",
                        desired.name,
                        api::ANNOTATIONS.key(weebo_kit_api::annotations::ALLOW_DISRUPTIVE_UPDATE)
                    ),
                ))
                .with_id(id, current),
            ));
        }
        if let Some(claimed) = claimed_elsewhere(cluster, &desired.name, instance, &me)
            .await
            .map_err(|f| Box::new(Outcome::failed(f).with_id(id.clone(), current.clone())))?
        {
            return Err(Box::new(Outcome::failed(claimed).with_id(id, current)));
        }
    }
    match gateway.update_domain(&id, &patch).await {
        Ok(()) => Ok(
            Outcome::synced(Some(id), format!("domain {:?} synced", desired.name))
                .at(&desired.name)
                .corrected(drift),
        ),
        Err(GatewayError::AlreadyExists(why)) => Err(Box::new(
            Outcome::failed(Failure::new(ReasonCode::StalwartObjectAlreadyExists, why))
                .with_id(id, current),
        )),
        Err(e) => Err(Box::new(Outcome::failed(e).with_id(id, current))),
    }
}

#[cfg(test)]
mod tests {
    use api::Status;

    use super::*;
    use crate::test_support::{FakeCluster, FakeGateway};

    fn domain(name: &str) -> Domain {
        let mut d = Domain::new(name, serde_json::from_value(serde_json::json!({})).unwrap());
        d.spec.aliases = vec!["Weebo.Lan".into()];
        d.spec.catch_all = Some("all".into());
        d
    }

    fn main() -> BoundInstance {
        BoundInstance::cluster("main")
    }

    /// The status the controller publishes from `outcome`.
    fn record(mut d: Domain, outcome: &Outcome) -> Domain {
        let status = d.status.get_or_insert_with(Status::default);
        if outcome.remote_id.is_some() {
            status.remote_id = outcome.remote_id.clone();
        }
        if outcome.address.is_some() {
            status.address = outcome.address.clone();
        }
        d
    }

    #[tokio::test]
    async fn creates_then_stays_quiet_until_drift() {
        let (gateway, cluster) = (FakeGateway::default(), FakeCluster::default());
        let first = reconcile_domain(&domain("weebo.internal"), &main(), &gateway, &cluster).await;
        assert_eq!(first.reason(), ReasonCode::Reconciled, "{:?}", first.ready);
        assert_eq!(first.write, Some(RemoteWrite::Created));
        assert_eq!(first.address.as_deref(), Some("weebo.internal"));
        let id = first.remote_id.clone().expect("an id is recorded");
        assert_eq!(gateway.writes(), ["create weebo.internal"]);
        let d = record(domain("weebo.internal"), &first);

        // Nothing changed: reads only.
        gateway.clear_writes();
        let quiet = reconcile_domain(&d, &main(), &gateway, &cluster).await;
        assert_eq!(quiet.remote_id, Some(id.clone()));
        assert_eq!((quiet.write, quiet.drift.is_empty()), (None, true));
        assert!(gateway.writes().is_empty(), "{:?}", gateway.writes());

        // Changed on the remote side: put back, those fields only.
        gateway.edit_domain(&id, |r| {
            r.sub_addressing = "Disabled".into();
            r.aliases.push("extra.example".into());
        });
        let corrected = reconcile_domain(&d, &main(), &gateway, &cluster).await;
        assert_eq!(corrected.write, Some(RemoteWrite::Drift));
        assert_eq!(corrected.drift.fields(), ["aliases", "subAddressing"]);
        assert_eq!(
            gateway.writes(),
            [format!("update {id} [aliases, subAddressing]")]
        );

        gateway.clear_writes();
        let quiet = reconcile_domain(&d, &main(), &gateway, &cluster).await;
        assert_eq!(quiet.write, None);
        assert!(gateway.writes().is_empty());
    }

    #[tokio::test]
    async fn a_taken_name_is_never_adopted() {
        let (gateway, cluster) = (FakeGateway::default(), FakeCluster::default());
        gateway.seed_domain("weebo.internal");
        let outcome =
            reconcile_domain(&domain("weebo.internal"), &main(), &gateway, &cluster).await;
        assert_eq!(outcome.reason(), ReasonCode::StalwartObjectAlreadyExists);
        assert!(outcome.ready.unwrap_err().message.contains("importer"));
        assert_eq!(outcome.remote_id, None);
        assert_eq!(gateway.writes(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_name_another_cr_owns_is_not_created() {
        let (gateway, cluster) = (FakeGateway::default(), FakeCluster::default());
        cluster.set_claimants(vec!["StalwartDomain/other".into()]);
        let outcome =
            reconcile_domain(&domain("weebo.internal"), &main(), &gateway, &cluster).await;
        assert_eq!(outcome.reason(), ReasonCode::RemoteObjectClaimed);
        assert!(gateway.writes().is_empty());
        // Its own claim is no obstacle.
        cluster.set_claimants(vec!["StalwartDomain/weebo.internal".into()]);
        let outcome =
            reconcile_domain(&domain("weebo.internal"), &main(), &gateway, &cluster).await;
        assert_eq!(outcome.reason(), ReasonCode::Reconciled);
    }

    #[tokio::test]
    async fn an_id_answering_another_name_is_taken_as_gone() {
        let (gateway, cluster) = (FakeGateway::default(), FakeCluster::default());
        // A fresh store: id "1" now designates another domain.
        let reused = gateway.seed_domain("someone-else.internal");
        let mut d = domain("weebo.internal");
        d.status = Some(Status {
            remote_id: Some(reused.clone()),
            address: Some("weebo.internal".into()),
            ..Status::default()
        });
        let outcome = reconcile_domain(&d, &main(), &gateway, &cluster).await;
        assert_eq!(outcome.write, Some(RemoteWrite::Created));
        assert_ne!(outcome.remote_id, Some(reused.clone()));
        assert_eq!(
            gateway.domain(&reused).unwrap().name,
            "someone-else.internal"
        );
        // An id with no confirmed name is no proof of identity either.
        let mut d = domain("weebo.internal");
        d.status = Some(Status {
            remote_id: Some(reused.clone()),
            ..Status::default()
        });
        let outcome = reconcile_domain(&d, &main(), &gateway, &cluster).await;
        assert_eq!(outcome.reason(), ReasonCode::StalwartObjectAlreadyExists);
    }

    #[tokio::test]
    async fn a_gone_domain_is_created_again() {
        let (gateway, cluster) = (FakeGateway::default(), FakeCluster::default());
        let mut d = domain("weebo.internal");
        d.status = Some(Status {
            remote_id: Some("42".into()),
            address: Some("weebo.internal".into()),
            ..Status::default()
        });
        let outcome = reconcile_domain(&d, &main(), &gateway, &cluster).await;
        assert_eq!(outcome.write, Some(RemoteWrite::Created));
    }

    #[tokio::test]
    async fn a_rename_needs_the_disruptive_update_annotation() {
        let (gateway, cluster) = (FakeGateway::default(), FakeCluster::default());
        let first = reconcile_domain(&domain("weebo.internal"), &main(), &gateway, &cluster).await;
        let mut d = record(domain("weebo.internal"), &first);
        d.spec.name = Some("renamed.internal".into());
        gateway.clear_writes();
        let refused = reconcile_domain(&d, &main(), &gateway, &cluster).await;
        assert_eq!(refused.reason(), ReasonCode::InvalidSpec);
        assert_eq!(refused.remote_id, first.remote_id, "still owned");
        assert_eq!(refused.address.as_deref(), Some("weebo.internal"));
        assert!(gateway.writes().is_empty());

        d.metadata.annotations = Some(
            [(
                api::ANNOTATIONS.key("allow-disruptive-update"),
                "true".to_string(),
            )]
            .into(),
        );
        let renamed = reconcile_domain(&d, &main(), &gateway, &cluster).await;
        assert_eq!(
            renamed.reason(),
            ReasonCode::Reconciled,
            "{:?}",
            renamed.ready
        );
        assert_eq!(renamed.address.as_deref(), Some("renamed.internal"));
        assert_eq!(renamed.drift.fields(), ["name", "catchAllAddress"]);
        let id = renamed.remote_id.unwrap();
        assert_eq!(
            gateway.domain(&id).unwrap().catch_all.as_deref(),
            Some("all@renamed.internal")
        );
    }

    #[tokio::test]
    async fn an_invalid_spec_makes_no_call() {
        let (gateway, cluster) = (FakeGateway::default(), FakeCluster::default());
        gateway.fail_with(Some(GatewayError::Unreachable("must not be called".into())));
        let mut d = domain("weebo.internal");
        d.spec.deletion_policy = api::common::DeletionPolicy::Delete;
        let outcome = reconcile_domain(&d, &main(), &gateway, &cluster).await;
        assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
    }

    #[tokio::test]
    async fn failures_map_to_their_reason() {
        let (gateway, cluster) = (FakeGateway::default(), FakeCluster::default());
        for (err, reason) in [
            (
                GatewayError::Unreachable("dns".into()),
                ReasonCode::InstanceUnreachable,
            ),
            (
                GatewayError::Unauthorized("403".into()),
                ReasonCode::InstanceUnauthorized,
            ),
            (
                GatewayError::Invalid("Invalid domain name".into()),
                ReasonCode::InvalidSpec,
            ),
            (
                GatewayError::UnsupportedVersion("schema x".into()),
                ReasonCode::UnsupportedStalwartVersion,
            ),
        ] {
            gateway.fail_with(Some(err));
            let outcome =
                reconcile_domain(&domain("weebo.internal"), &main(), &gateway, &cluster).await;
            assert_eq!(outcome.reason(), reason);
        }
        gateway.fail_with(None);
        cluster.fail_with("apiserver down");
        let outcome =
            reconcile_domain(&domain("weebo.internal"), &main(), &gateway, &cluster).await;
        assert_eq!(outcome.reason(), ReasonCode::KubernetesApiError);
    }
}
