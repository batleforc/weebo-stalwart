//! The admission checks shared by the admission webhook and the
//! reconcilers — same rules, same `ReasonCode` whichever side refuses (a
//! policy may change after admission, and a CR may predate the webhook):
//!
//! - the spec's own rules (`InvalidSpec`): names and aliases that are
//!   hostnames or local-parts, `deletionPolicy: Orphan` on a
//!   `StalwartDomain` (D18), a quota that is a quantity, recipients that
//!   are addresses, a `StalwartServiceAccount`'s Vault target named `smtp`
//!   without `path`, the implicit target in `kubernetes` only (D15);
//! - the allow-list, for the namespaced kinds bound to a
//!   `StalwartInstance` ([`enforce`]): the domains a CR lives in and the
//!   local-parts it claims — its name and every alias — against the
//!   `StalwartNamespacePolicy` rules (`NamespaceNotAllowed`).
//!
//! The uniqueness of a name between CRs is not checked here: the
//! reconcilers check it before creating ([`crate::ports::ClusterReader`]).

use api::common::{DeletionPolicy, Quantity, SecretStoreBackend, SecretTarget};
use api::namespace_policy::NamespaceRule;
use api::{Account, Domain, Group, MailingList, ServiceAccount};
use domain::Failure;
use domain::allow_list::{self, Decision, Kind};
use domain::error::ReasonCode;
use domain::mail;

use crate::ports::{BoundInstance, ClusterError, PolicySource};

fn invalid(message: String) -> Failure {
    Failure::new(ReasonCode::InvalidSpec, message)
}

/// A `StalwartDomain`'s own rules: what Stalwart would refuse, refused
/// before any call with a message naming the field.
pub fn check_domain(domain: &Domain) -> Result<(), Failure> {
    let spec = &domain.spec;
    if spec.deletion_policy != DeletionPolicy::Orphan {
        return Err(invalid(
            "spec.deletionPolicy: a StalwartDomain is never deleted by the operator, only Orphan is accepted"
                .into(),
        ));
    }
    mail::check_domain_name(&domain.domain_name())
        .map_err(|e| invalid(format!("spec.name: {e}")))?;
    for alias in &spec.aliases {
        mail::check_domain_name(alias).map_err(|e| invalid(format!("spec.aliases: {e}")))?;
        if mail::normalize_domain(alias) == domain.domain_name() {
            return Err(invalid(format!(
                "spec.aliases: {alias:?} is the domain's own name"
            )));
        }
    }
    if let Some(local) = &spec.catch_all {
        mail::check_local_part(local).map_err(|e| invalid(format!("spec.catchAll: {e}")))?;
    }
    Ok(())
}

/// A namespaced CR's local-parts: its name and aliases (the aliases live in
/// the CR's domain: they are local-parts, never addresses).
pub fn check_names(name: &str, aliases: &[String]) -> Result<(), Failure> {
    mail::check_local_part(name).map_err(|e| invalid(format!("spec.name: {e}")))?;
    for alias in aliases {
        mail::check_local_part(alias).map_err(|e| {
            invalid(format!(
                "spec.aliases: {e} — an alias is a local-part, in the domain of spec.domainRef"
            ))
        })?;
        if mail::normalize_local_part(alias) == mail::normalize_local_part(name) {
            return Err(invalid(format!(
                "spec.aliases: {alias:?} is the object's own name"
            )));
        }
    }
    Ok(())
}

fn check_quota(quota: Option<&Quantity>) -> Result<Option<u64>, Failure> {
    quota
        .map(|q| domain::quantity::bytes(&q.0).map_err(|e| invalid(format!("spec.quota: {e}"))))
        .transpose()
}

/// The Vault target name D15 allows: the operator's Vault role may only
/// write `<pathPrefix>/<namespace>/smtp`.
pub const SMTP_TARGET: &str = "smtp";

/// D15: a `StalwartServiceAccount`'s Vault target is named `smtp`, without
/// `path`; the implicit target (no `secretTargets`) is only admitted when
/// the instance's default backend (`default_backend`, `None`: unknown yet)
/// is `kubernetes`.
pub fn check_smtp_targets(
    targets: &[SecretTarget],
    default_backend: Option<SecretStoreBackend>,
) -> Result<(), Failure> {
    for target in targets
        .iter()
        .filter(|t| t.backend == SecretStoreBackend::Vault)
    {
        if target.name != SMTP_TARGET || target.path.is_some() {
            return Err(invalid(format!(
                "spec.secretTargets: the Vault target {:?} must be named {SMTP_TARGET:?},                  without path: the operator's Vault role only writes <pathPrefix>/<namespace>/smtp",
                target.name
            )));
        }
    }
    if targets.is_empty() && default_backend == Some(SecretStoreBackend::Vault) {
        return Err(invalid(format!(
            "spec.secretTargets: the instance writes to Vault by default, where the implicit              target (named after the CR) is out of the operator's Vault role: list a Vault              target named {SMTP_TARGET:?}, or a kubernetes one"
        )));
    }
    Ok(())
}

/// A `StalwartServiceAccount`'s own rules (the implicit target's backend
/// is checked once known: [`check_smtp_targets`]).
pub fn check_service_account(sa: &ServiceAccount) -> Result<(), Failure> {
    check_names(&sa.local_part(), &sa.spec.aliases)?;
    check_smtp_targets(&sa.spec.secret_targets, None)
}

/// A `StalwartAccount`'s own rules: its quota in bytes.
pub fn check_account(account: &Account) -> Result<Option<u64>, Failure> {
    check_names(&account.local_part(), &account.spec.aliases)?;
    for (field, value) in [
        ("spec.locale", &account.spec.locale),
        ("spec.timeZone", &account.spec.time_zone),
    ] {
        if value.as_deref().is_some_and(|v| v.trim().is_empty()) {
            return Err(invalid(format!(
                "{field}: empty; leave it unset for no opinion"
            )));
        }
    }
    check_quota(account.spec.quota.as_ref())
}

/// A `StalwartGroup`'s own rules: its quota in bytes.
pub fn check_group(group: &Group) -> Result<Option<u64>, Failure> {
    check_names(&group.local_part(), &group.spec.aliases)?;
    check_quota(group.spec.quota.as_ref())
}

/// A `StalwartMailingList`'s own rules: each recipient an address or an
/// `accountRef`, an address being `local@domain`.
pub fn check_mailing_list(list: &MailingList) -> Result<(), Failure> {
    check_names(&list.local_part(), &list.spec.aliases)?;
    for (i, recipient) in list.spec.recipients.iter().enumerate() {
        match (&recipient.address, &recipient.account_ref) {
            (Some(address), None) => {
                let (local, domain) = address.trim().rsplit_once('@').ok_or_else(|| {
                    invalid(format!(
                        "spec.recipients[{i}].address: {address:?} is not a mail address"
                    ))
                })?;
                if local.is_empty() || local.contains(char::is_whitespace) {
                    return Err(invalid(format!(
                        "spec.recipients[{i}].address: {address:?} is not a mail address"
                    )));
                }
                mail::check_domain_name(domain)
                    .map_err(|e| invalid(format!("spec.recipients[{i}].address: {e}")))?;
            }
            (None, Some(_)) => {}
            _ => {
                return Err(invalid(format!(
                    "spec.recipients[{i}]: either an address or an accountRef"
                )));
            }
        }
    }
    Ok(())
}

/// The allow-list verdict on a namespaced CR of `kind` in `namespace`,
/// living in `domains` (`StalwartDomain` names) and claiming `names`
/// (local-parts, lowercased) — for a CR bound to `instance`: one bound to
/// a `StalwartLocalInstance` isn't governed by the policies.
/// `Err`: the policies couldn't be read.
pub async fn enforce(
    policies: &dyn PolicySource<NamespaceRule>,
    instance: Option<&BoundInstance>,
    namespace: &str,
    kind: Kind,
    domains: &[String],
    names: &[String],
) -> Result<Result<(), Failure>, ClusterError> {
    if instance.is_some_and(|i| !i.governed_by_policy()) {
        return Ok(Ok(()));
    }
    let rules: Vec<Vec<allow_list::Rule>> = policies
        .policies()
        .await?
        .iter()
        .map(|policy| policy.iter().map(NamespaceRule::to_domain).collect())
        .collect();
    let request = allow_list::request(namespace, kind, domains, names);
    Ok(match allow_list::evaluate(&request, &rules) {
        Decision::Allowed => Ok(()),
        Decision::Denied(why) => Err(Failure::new(ReasonCode::NamespaceNotAllowed, why)),
    })
}

#[cfg(test)]
mod tests {
    use api::namespace_policy::{Effect, NamespacedKind};

    use super::*;
    use crate::test_support::FakeCluster;

    fn domain(spec: serde_json::Value) -> Domain {
        Domain::new("weebo.internal", serde_json::from_value(spec).unwrap())
    }

    #[test]
    fn a_domain_spec_is_checked_field_by_field() {
        assert_eq!(
            check_domain(&domain(
                serde_json::json!({"aliases": ["Weebo.Lan"], "catchAll": "all"})
            )),
            Ok(())
        );
        for (spec, field) in [
            (
                serde_json::json!({"deletionPolicy": "Delete"}),
                "deletionPolicy",
            ),
            (serde_json::json!({"name": "localhost"}), "spec.name"),
            (
                serde_json::json!({"aliases": ["bad_label.example"]}),
                "spec.aliases",
            ),
            (
                serde_json::json!({"aliases": ["WEEBO.internal"]}),
                "own name",
            ),
            (serde_json::json!({"catchAll": "a+b"}), "spec.catchAll"),
        ] {
            let err = check_domain(&domain(spec)).unwrap_err();
            assert_eq!(err.reason, ReasonCode::InvalidSpec);
            assert!(err.message.contains(field), "{}", err.message);
        }
    }

    fn rules() -> Vec<NamespaceRule> {
        vec![NamespaceRule {
            namespaces: vec!["forgejo".into()],
            allowed_kinds: vec![NamespacedKind::StalwartServiceAccount],
            allowed_domains: Some(vec!["weebo.internal".into()]),
            allowed_names: Some(vec!["forgejo".into(), "noreply".into()]),
            effect: Effect::Allow,
        }]
    }

    #[tokio::test]
    async fn the_policies_decide_for_a_cluster_instance_only() {
        let cluster = FakeCluster::default();
        cluster.set_policies(vec![rules()]);
        let domains = ["weebo.internal".to_string()];
        let names = ["forgejo".to_string(), "admin".to_string()];
        let cluster_instance = BoundInstance::cluster("main");
        let verdict = enforce(
            &cluster,
            Some(&cluster_instance),
            "forgejo",
            Kind::ServiceAccount,
            &domains,
            &names,
        )
        .await
        .unwrap();
        assert_eq!(verdict.unwrap_err().reason, ReasonCode::NamespaceNotAllowed);
        let local = BoundInstance::local("forgejo", "own");
        let verdict = enforce(
            &cluster,
            Some(&local),
            "forgejo",
            Kind::ServiceAccount,
            &domains,
            &names,
        )
        .await
        .unwrap();
        assert_eq!(verdict, Ok(()));
        let verdict = enforce(
            &cluster,
            None,
            "forgejo",
            Kind::ServiceAccount,
            &domains,
            &names[..1],
        )
        .await
        .unwrap();
        assert_eq!(verdict, Ok(()));
    }

    #[tokio::test]
    async fn unreadable_policies_are_an_error() {
        let cluster = FakeCluster::default();
        cluster.fail_with("connection refused");
        assert!(
            enforce(&cluster, None, "x", Kind::Account, &[], &[])
                .await
                .is_err()
        );
    }
}
