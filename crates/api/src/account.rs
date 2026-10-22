use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use crate::common::{DeletionPolicy, InstanceRef, ObjectRef};
use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::StalwartAccount as Account;
pub use self::StalwartAccountSpec as AccountSpec;

/// A person's mailbox (`x:Account` of type `User`), without any
/// credential: its owner logs in through the instance's OpenID Connect
/// provider, which finds the account by local-part and domain, and creates
/// App Passwords in the web interface. The name, aliases, quota, locale and
/// time zone are the operator's; the description and the group memberships
/// are left to the OpenID Connect login.
///
/// `state: Locked` keeps the mailbox, its address and its App Passwords,
/// but refuses every login (App Passwords included), sending and delivery;
/// `Active` gives them back. A locked account that reached that state is
/// `Ready: True`.
///
/// The account is read by `status.remoteId`, never adopted by name: an
/// address already taken in Stalwart (an account the OpenID Connect login
/// created first) fails (`StalwartObjectAlreadyExists`) until
/// `weebo-stalwart-importer` links it to this CR.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "stalwart.weebo.io",
    version = "v1alpha1",
    kind = "StalwartAccount",
    plural = "stalwartaccounts",
    namespaced,
    status = "Status",
    printcolumn = r#"{"name":"Instance","type":"string","jsonPath":".status.instance.name"}"#,
    printcolumn = r#"{"name":"Address","type":"string","jsonPath":".status.address"}"#,
    printcolumn = r#"{"name":"State","type":"string","jsonPath":".spec.state"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct StalwartAccountSpec {
    /// The `StalwartInstance` (or `StalwartLocalInstance`) the account
    /// lives on. Unset: the only `StalwartInstance`, else the only
    /// `StalwartLocalInstance` of the namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<InstanceRef>,
    /// The `StalwartDomain` (cluster-scoped, by `metadata.name`) the
    /// account's address and aliases are in. It must be `Ready` on the
    /// same instance.
    #[schemars(extend("x-weebo-link" = { "to": [{ "group": "stalwart.weebo.io", "kind": "StalwartDomain" }] }))]
    pub domain_ref: ObjectRef,
    /// The local-part of the account's address (`<name>@<domain>`),
    /// lowercased: the user's login name at the OpenID Connect provider.
    /// Defaults to the CR's `metadata.name`. Changing it moves the address:
    /// only applied with the annotation
    /// `stalwart.weebo.io/allow-disruptive-update: "true"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Other local-parts delivering to this mailbox, in the same domain.
    /// Compared as a set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 32))]
    pub aliases: Vec<String>,
    /// Disk quota of the mailbox (`2Gi`). Unset: no opinion, the server's
    /// value is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quantity>,
    /// Locale of the account (`fr-FR`). Unset: no opinion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Time zone of the account (`Europe/Paris`). Unset: no opinion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    /// `Active`, or `Locked`: logins (App Passwords included), sending and
    /// delivery refused, the mailbox, its address and its App Passwords
    /// kept.
    #[serde(default)]
    pub state: AccountState,
    /// `Orphan` (default): deleting the CR leaves the mailbox in Stalwart.
    /// `Delete`: deleting the CR deletes the mailbox and its mail.
    #[serde(default = "DeletionPolicy::orphan")]
    pub deletion_policy: DeletionPolicy,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum AccountState {
    #[default]
    Active,
    Locked,
}

impl AccountState {
    pub const fn as_str(self) -> &'static str {
        match self {
            AccountState::Active => "Active",
            AccountState::Locked => "Locked",
        }
    }
}

impl Account {
    /// The account's local-part: `spec.name`, or the CR's own name —
    /// normalized.
    pub fn local_part(&self) -> String {
        domain::mail::normalize_local_part(
            &self.spec.name.clone().unwrap_or_else(|| self.name_any()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rfc_example_parses_with_its_defaults() {
        let spec: AccountSpec = serde_json::from_value(serde_json::json!({
            "domainRef": {"name": "weebo.internal"},
            "name": "alice",
            "quota": "2Gi",
        }))
        .unwrap();
        assert_eq!(spec.state, AccountState::Active);
        assert_eq!(spec.deletion_policy, DeletionPolicy::Orphan);
        assert_eq!(spec.quota, Some(Quantity("2Gi".into())));
    }
}
