use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use crate::common::{DeletionPolicy, InstanceRef, ObjectRef};
use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::StalwartGroup as Group;
pub use self::StalwartGroupSpec as GroupSpec;

/// A group (`x:Account` of type `Group`): a shared address delivering to
/// its members. Its members are not managed here: the OpenID Connect login
/// sets them from the provider's `groups` claim, where `name` must appear.
///
/// The OpenID Connect login also creates a group for every name of the
/// claim the first time a member logs in: a `StalwartGroup` declared after
/// that fails (`StalwartObjectAlreadyExists`) until
/// `weebo-stalwart-importer` links it to the existing group — declare it
/// before the group is published in the claim.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "stalwart.weebo.io",
    version = "v1alpha1",
    kind = "StalwartGroup",
    plural = "stalwartgroups",
    namespaced,
    status = "Status",
    printcolumn = r#"{"name":"Instance","type":"string","jsonPath":".status.instance.name"}"#,
    printcolumn = r#"{"name":"Address","type":"string","jsonPath":".status.address"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct StalwartGroupSpec {
    /// The `StalwartInstance` (or `StalwartLocalInstance`) the group lives
    /// on. Unset: the only `StalwartInstance`, else the only
    /// `StalwartLocalInstance` of the namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<InstanceRef>,
    /// The `StalwartDomain` (cluster-scoped, by `metadata.name`) the
    /// group's address and aliases are in. It must be `Ready` on the same
    /// instance.
    #[schemars(extend("x-weebo-link" = { "to": [{ "group": "stalwart.weebo.io", "kind": "StalwartDomain" }] }))]
    pub domain_ref: ObjectRef,
    /// The local-part of the group's address, lowercased: the group's name
    /// in the OpenID Connect provider's `groups` claim. Defaults to the
    /// CR's `metadata.name`. Changing it moves the address: only applied
    /// with the annotation `stalwart.weebo.io/allow-disruptive-update:
    /// "true"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Other local-parts delivering to the group, in the same domain.
    /// Compared as a set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 32))]
    pub aliases: Vec<String>,
    /// Disk quota of the group's shared mailbox (`10Gi`). Unset: no
    /// opinion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quantity>,
    /// `Orphan` (default): deleting the CR leaves the group in Stalwart.
    /// `Delete`: deleting the CR deletes the group (refused by Stalwart, and
    /// retried, while accounts are still members).
    #[serde(default = "DeletionPolicy::orphan")]
    pub deletion_policy: DeletionPolicy,
}

impl Group {
    /// The group's local-part: `spec.name`, or the CR's own name —
    /// normalized.
    pub fn local_part(&self) -> String {
        domain::mail::normalize_local_part(
            &self.spec.name.clone().unwrap_or_else(|| self.name_any()),
        )
    }
}
