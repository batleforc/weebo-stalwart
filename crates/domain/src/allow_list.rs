//! `StalwartNamespacePolicy` rules — shared by the admission webhook and
//! the reconcilers' own re-check. The engine is the kit's
//! (`weebo_kit_domain::allow_list`); this module binds it to the governed
//! kinds and to the two dimensions a request is scoped by: the
//! `StalwartDomain`s it lives in ([`DOMAINS`]) and the local-parts it
//! claims, its name and every alias ([`NAMES`]).

use std::collections::BTreeMap;

pub use weebo_kit_domain::allow_list::{Decision, Effect};

/// Named in denial messages.
pub const POLICY_KIND: &str = "StalwartNamespacePolicy";
/// Scope dimension: `StalwartDomain` names (`metadata.name`).
pub const DOMAINS: &str = "domains";
/// Scope dimension: Stalwart local-parts — the object's name and each of
/// its aliases.
pub const NAMES: &str = "names";

/// The namespaced kinds the allow-list governs. `StalwartDomain`, the
/// instances and the policy itself are cluster-scoped: governed by RBAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    ServiceAccount,
    Account,
    Group,
    MailingList,
}

impl Kind {
    pub fn from_kind_name(kind: &str) -> Option<Self> {
        Some(match kind {
            "StalwartServiceAccount" => Kind::ServiceAccount,
            "StalwartAccount" => Kind::Account,
            "StalwartGroup" => Kind::Group,
            "StalwartMailingList" => Kind::MailingList,
            _ => return None,
        })
    }
}

pub type Rule = weebo_kit_domain::allow_list::Rule<Kind>;
pub type Request<'a> = weebo_kit_domain::allow_list::Request<'a, Kind>;

/// A rule from its `StalwartNamespacePolicy` fields (`None` = any).
/// Names are compared lowercased, the form Stalwart stores.
pub fn rule(
    namespaces: Vec<String>,
    kinds: Vec<Kind>,
    domains: Option<Vec<String>>,
    names: Option<Vec<String>>,
    effect: Effect,
) -> Rule {
    let names = names.map(|n| n.iter().map(|n| n.to_ascii_lowercase()).collect());
    let scopes = [(DOMAINS, domains), (NAMES, names)]
        .into_iter()
        .filter_map(|(dimension, listed)| Some((dimension.to_string(), listed?)))
        .collect();
    Rule {
        namespaces,
        kinds,
        scopes,
        effect,
    }
}

/// What a namespaced CR in `namespace` asks for: the domains it lives in,
/// the local-parts it claims (already lowercased: [`crate::mail`]).
pub fn request<'a>(
    namespace: &'a str,
    kind: Kind,
    domains: &'a [String],
    names: &'a [String],
) -> Request<'a> {
    Request {
        namespace,
        kind,
        references: BTreeMap::from([(DOMAINS, domains), (NAMES, names)]),
    }
}

/// See `weebo_kit_domain::allow_list::evaluate_policies`: allow everything
/// while no `StalwartNamespacePolicy` exists, default-deny as soon as one
/// does; a `Deny` always wins, and one scoped by `names` hits a request
/// whose name **or** any alias it lists.
pub fn evaluate(request: &Request<'_>, policies: &[Vec<Rule>]) -> Decision {
    weebo_kit_domain::allow_list::evaluate_policies(POLICY_KIND, request, policies)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// The RFC's example policy.
    fn weebo_allow() -> Vec<Vec<Rule>> {
        let accounts = vec![
            Kind::ServiceAccount,
            Kind::Account,
            Kind::Group,
            Kind::MailingList,
        ];
        vec![vec![
            rule(
                s(&["mail"]),
                vec![Kind::Account, Kind::Group, Kind::MailingList],
                Some(s(&["weebo.poc"])),
                None,
                Effect::Allow,
            ),
            rule(
                s(&["forgejo"]),
                vec![Kind::ServiceAccount],
                Some(s(&["weebo.poc"])),
                Some(s(&["forgejo", "NoReply"])),
                Effect::Allow,
            ),
            rule(
                s(&["*"]),
                accounts,
                None,
                Some(s(&[
                    "postmaster",
                    "abuse",
                    "admin",
                    "root",
                    "weebo-stalwart",
                ])),
                Effect::Deny,
            ),
        ]]
    }

    #[test]
    fn names_and_aliases_are_both_covered() {
        let policies = weebo_allow();
        let domain = s(&["weebo.poc"]);
        let ask =
            |ns, kind, names: &[&str]| evaluate(&request(ns, kind, &domain, &s(names)), &policies);
        assert_eq!(
            ask("forgejo", Kind::ServiceAccount, &["forgejo", "noreply"]),
            Decision::Allowed
        );
        assert!(matches!(
            ask("forgejo", Kind::ServiceAccount, &["forgejo", "admin2"]),
            Decision::Denied(_)
        ));
        assert!(matches!(
            ask("forgejo", Kind::Account, &["forgejo"]),
            Decision::Denied(_)
        ));
        // `mail` doesn't bound names.
        assert_eq!(ask("mail", Kind::Account, &["alice"]), Decision::Allowed);
    }

    #[test]
    fn a_reserved_name_is_denied_everywhere_even_as_an_alias() {
        let policies = weebo_allow();
        let domain = s(&["weebo.poc"]);
        for names in [&["postmaster"][..], &["alice", "abuse"]] {
            let decision = evaluate(
                &request("mail", Kind::Account, &domain, &s(names)),
                &policies,
            );
            assert!(matches!(decision, Decision::Denied(_)), "{names:?}");
        }
    }

    #[test]
    fn domains_scope_the_rules() {
        let policies = weebo_allow();
        let other = s(&["other.example"]);
        let decision = evaluate(
            &request("mail", Kind::Account, &other, &s(&["alice"])),
            &policies,
        );
        assert!(matches!(decision, Decision::Denied(m) if m.contains("other.example")));
    }

    #[test]
    fn no_policy_allows_everything() {
        let decision = evaluate(&request("x", Kind::Group, &[], &[]), &[]);
        assert_eq!(decision, Decision::Allowed);
    }

    #[test]
    fn kind_names_round_trip() {
        for k in [
            "StalwartServiceAccount",
            "StalwartAccount",
            "StalwartGroup",
            "StalwartMailingList",
        ] {
            assert!(Kind::from_kind_name(k).is_some(), "{k}");
        }
        assert_eq!(Kind::from_kind_name("StalwartDomain"), None);
    }
}
