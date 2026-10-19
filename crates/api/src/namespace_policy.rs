use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::status::Status;

/// Namespace allow-list for the namespaced account kinds, enforced by the
/// admission webhook (CREATE/UPDATE) and re-checked by every reconciler
/// before any Stalwart call. It governs the CRs bound to a
/// `StalwartInstance` (shared by every namespace); a CR bound to a
/// `StalwartLocalInstance` is bounded by its namespace's own token instead.
///
/// While no `StalwartNamespacePolicy` exists, everything is allowed. As
/// soon as one exists, a namespaced CR is only accepted if some `Allow`
/// rule matches its namespace and kind and covers the domains and names
/// it asks for — and no `Deny` rule matches. Rules of every policy are
/// pooled; a `Deny` always wins.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "stalwart.weebo.io",
    version = "v1alpha1",
    kind = "StalwartNamespacePolicy",
    plural = "stalwartnamespacepolicies",
    status = "Status",
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct StalwartNamespacePolicySpec {
    pub rules: Vec<NamespaceRule>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceRule {
    /// Namespace names, `*` for all, or a prefix glob like `team-*`.
    pub namespaces: Vec<String>,
    pub allowed_kinds: Vec<NamespacedKind>,
    /// `StalwartDomain`s (by `metadata.name`) the objects may live in.
    /// Unset: any. On a `Deny` rule: only deny requests in one of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    /// Local-parts the objects may claim: an object's name **and** each of
    /// its aliases must be listed. Unset: any. On a `Deny` rule: deny
    /// requests whose name or any alias is listed — the way to reserve
    /// names (`postmaster`, `admin`…) for every namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_names: Option<Vec<String>>,
    #[serde(default)]
    pub effect: Effect,
}

/// The namespaced kinds a rule may allow.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
pub enum NamespacedKind {
    StalwartServiceAccount,
    StalwartAccount,
    StalwartGroup,
    StalwartMailingList,
}

impl NamespacedKind {
    pub fn to_domain(self) -> domain::allow_list::Kind {
        use domain::allow_list::Kind;
        match self {
            NamespacedKind::StalwartServiceAccount => Kind::ServiceAccount,
            NamespacedKind::StalwartAccount => Kind::Account,
            NamespacedKind::StalwartGroup => Kind::Group,
            NamespacedKind::StalwartMailingList => Kind::MailingList,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum Effect {
    #[default]
    Allow,
    Deny,
}

impl NamespaceRule {
    /// The rule as the kit's allow-list engine reads it.
    pub fn to_domain(&self) -> domain::allow_list::Rule {
        let effect = match self.effect {
            Effect::Allow => domain::allow_list::Effect::Allow,
            Effect::Deny => domain::allow_list::Effect::Deny,
        };
        domain::allow_list::rule(
            self.namespaces.clone(),
            self.allowed_kinds.iter().map(|k| k.to_domain()).collect(),
            self.allowed_domains.clone(),
            self.allowed_names.clone(),
            effect,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rfc_example_parses() {
        let spec: StalwartNamespacePolicySpec = serde_json::from_value(serde_json::json!({
            "rules": [
                {"namespaces": ["forgejo"], "allowedKinds": ["StalwartServiceAccount"],
                 "allowedDomains": ["weebo.poc"], "allowedNames": ["forgejo", "noreply"]},
                {"effect": "Deny", "namespaces": ["*"],
                 "allowedKinds": ["StalwartServiceAccount", "StalwartAccount", "StalwartGroup", "StalwartMailingList"],
                 "allowedNames": ["postmaster"]},
            ]
        }))
        .unwrap();
        assert_eq!(spec.rules[0].effect, Effect::Allow);
        let deny = spec.rules[1].to_domain();
        assert_eq!(deny.effect, domain::allow_list::Effect::Deny);
        assert_eq!(deny.kinds.len(), 4);
        assert_eq!(deny.scopes.keys().collect::<Vec<_>>(), ["names"]);
    }
}
