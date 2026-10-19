//! A `StalwartNamespacePolicy` has no remote object: it is ready once its
//! rules are usable. A rule with no namespace or no kind can never match,
//! which is almost certainly a mistake worth surfacing.

use api::namespace_policy::StalwartNamespacePolicySpec;
use domain::Failure;
use domain::error::ReasonCode;

use crate::use_cases::Outcome;

pub fn reconcile_namespace_policy(spec: &StalwartNamespacePolicySpec) -> Outcome {
    for (i, rule) in spec.rules.iter().enumerate() {
        if rule.namespaces.is_empty() || rule.allowed_kinds.is_empty() {
            return Outcome::failed(Failure::new(
                ReasonCode::InvalidSpec,
                format!("spec.rules[{i}] has no namespaces or no allowedKinds and can never match"),
            ));
        }
    }
    Outcome::synced(None, format!("{} rule(s) in force", spec.rules.len()))
}

#[cfg(test)]
mod tests {
    use api::namespace_policy::{Effect, NamespaceRule, NamespacedKind};

    use super::*;

    fn rule(namespaces: &[&str], kinds: &[NamespacedKind]) -> NamespaceRule {
        NamespaceRule {
            namespaces: namespaces.iter().map(|n| n.to_string()).collect(),
            allowed_kinds: kinds.to_vec(),
            allowed_domains: None,
            allowed_names: None,
            effect: Effect::Allow,
        }
    }

    #[test]
    fn usable_rules_are_ready() {
        let spec = StalwartNamespacePolicySpec {
            rules: vec![rule(&["mail"], &[NamespacedKind::StalwartAccount])],
        };
        assert_eq!(
            reconcile_namespace_policy(&spec).ready,
            Ok("1 rule(s) in force".to_string())
        );
    }

    #[test]
    fn a_rule_that_can_never_match_is_invalid() {
        for bad in [
            rule(&[], &[NamespacedKind::StalwartGroup]),
            rule(&["mail"], &[]),
        ] {
            let spec = StalwartNamespacePolicySpec {
                rules: vec![rule(&["x"], &[NamespacedKind::StalwartAccount]), bad],
            };
            let outcome = reconcile_namespace_policy(&spec);
            assert_eq!(outcome.reason(), ReasonCode::InvalidSpec);
            assert!(outcome.ready.unwrap_err().message.contains("rules[1]"));
        }
    }
}
