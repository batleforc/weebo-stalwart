use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use crate::common::{DeletionPolicy, InstanceRef, ObjectRef, SecretTarget};
use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::StalwartServiceAccount as ServiceAccount;
pub use self::StalwartServiceAccountSpec as ServiceAccountSpec;

/// A sending account of an application (`x:Account` of type `User`,
/// authenticating with an App Password): the operator creates the account
/// without any password, has Stalwart generate an App Password for it
/// (granting `authenticate` and `emailSend` only) with the instance's
/// `appPasswordTokenSecretRef` key, and writes the SMTP submission settings
/// to `secretTargets` (`host`, `port`, `security`, `username` — the
/// address —, `password` — the App Password —, `from`). It logs in over
/// SMTP submission only: IMAP, POP3 and ManageSieve logins are disabled,
/// and so is delivery unless `receive` is set. An instance without
/// `appPasswordTokenSecretRef` fails with `TokenSecretMissing`.
///
/// A new App Password replaces the previous one (revoked in the same call;
/// the account's other App Passwords are left alone) when the annotation
/// `stalwart.weebo.io/rotate-secret` takes a new value, or when a target
/// lost it. The account is read by `status.remoteId`, never adopted by
/// name: an address already taken in Stalwart fails
/// (`StalwartObjectAlreadyExists`) until `weebo-stalwart-importer` links
/// it to this CR.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "stalwart.weebo.io",
    version = "v1alpha1",
    kind = "StalwartServiceAccount",
    plural = "stalwartserviceaccounts",
    namespaced,
    status = "Status",
    printcolumn = r#"{"name":"Instance","type":"string","jsonPath":".status.instance.name"}"#,
    printcolumn = r#"{"name":"Address","type":"string","jsonPath":".status.address"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct StalwartServiceAccountSpec {
    /// The `StalwartInstance` (or `StalwartLocalInstance`) the account
    /// lives on. Unset: the only `StalwartInstance`, else the only
    /// `StalwartLocalInstance` of the namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<InstanceRef>,
    /// The `StalwartDomain` (cluster-scoped, by `metadata.name`) the
    /// account's address and aliases are in. It must be `Ready` on the
    /// same instance.
    pub domain_ref: ObjectRef,
    /// The local-part of the account's address (`<name>@<domain>`),
    /// lowercased. Defaults to the CR's `metadata.name`. Changing it moves
    /// the address: only applied with the annotation
    /// `stalwart.weebo.io/allow-disruptive-update: "true"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Other local-parts of the account, in the same domain, usable as
    /// sender (`from` is the first one). Compared as a set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 32))]
    pub aliases: Vec<String>,
    /// Whether mail sent to the account is delivered. `false`: delivery is
    /// disabled (a no-reply sender).
    #[serde(default)]
    pub receive: bool,
    /// Where the SMTP settings and the App Password are written.
    /// Empty: one Kubernetes `Secret` named after the CR, in its namespace
    /// (only when the instance's default backend is `kubernetes`). A Vault
    /// target must be named `smtp`, without `path`: it is written to
    /// `<pathPrefix>/<namespace>/smtp`, the only path the operator's Vault
    /// role may write.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 8))]
    // The keys each target holds, for the docs' CRD IDE (as `reconcile_service_account::credentials` writes them).
    #[schemars(extend("x-weebo-keys" = ["host", "port", "security", "username", "password", "from"]))]
    pub secret_targets: Vec<SecretTarget>,
    /// `Delete` (default): deleting the CR deletes the account and the
    /// secrets it wrote. `Orphan`: both are left in place.
    #[serde(default = "DeletionPolicy::delete")]
    pub deletion_policy: DeletionPolicy,
}

impl ServiceAccount {
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
        let spec: ServiceAccountSpec = serde_json::from_value(serde_json::json!({
            "domainRef": {"name": "weebo.internal"},
            "name": "Forgejo",
            "aliases": ["noreply"],
            "secretTargets": [{"backend": "vault", "name": "smtp"}],
        }))
        .unwrap();
        assert!(!spec.receive);
        assert_eq!(spec.deletion_policy, DeletionPolicy::Delete);
        let sa = ServiceAccount::new("forgejo", spec);
        assert_eq!(sa.local_part(), "forgejo");
    }
}
