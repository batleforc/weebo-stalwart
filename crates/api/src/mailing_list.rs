use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use crate::common::{DeletionPolicy, InstanceRef, ObjectRef};
use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::StalwartMailingList as MailingList;
pub use self::StalwartMailingListSpec as MailingListSpec;

/// A mailing list (`x:MailingList`): an address relaying every message to
/// its recipients — addresses, or the `StalwartAccount`s of this
/// namespace. Compared on every reconcile, recipients as a set, and
/// written only when it drifted.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "stalwart.weebo.io",
    version = "v1alpha1",
    kind = "StalwartMailingList",
    plural = "stalwartmailinglists",
    namespaced,
    status = "Status",
    printcolumn = r#"{"name":"Instance","type":"string","jsonPath":".status.instance.name"}"#,
    printcolumn = r#"{"name":"Address","type":"string","jsonPath":".status.address"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct StalwartMailingListSpec {
    /// The `StalwartInstance` (or `StalwartLocalInstance`) the list lives
    /// on. Unset: the only `StalwartInstance`, else the only
    /// `StalwartLocalInstance` of the namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<InstanceRef>,
    /// The `StalwartDomain` (cluster-scoped, by `metadata.name`) the list's
    /// address and aliases are in. It must be `Ready` on the same instance.
    pub domain_ref: ObjectRef,
    /// The local-part of the list's address, lowercased. Defaults to the
    /// CR's `metadata.name`. Changing it moves the address: only applied
    /// with the annotation `stalwart.weebo.io/allow-disruptive-update:
    /// "true"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Other local-parts of the list, in the same domain. Compared as a
    /// set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 32))]
    pub aliases: Vec<String>,
    /// Who receives the list's messages. Compared as a set of addresses,
    /// whatever their case.
    #[serde(default)]
    #[schemars(length(max = 1000))]
    pub recipients: Vec<Recipient>,
    // RFC 0001 Q19: the RFC gives no default for a list; a list holds no
    // mail, so deleting it with its CR loses nothing: `Delete`, as the
    // service account.
    /// `Delete` (default): deleting the CR deletes the list. `Orphan`: the
    /// list is left in Stalwart.
    #[serde(default = "DeletionPolicy::delete")]
    pub deletion_policy: DeletionPolicy,
}

/// One recipient: an `address`, or an `accountRef`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "has(self.address) != has(self.accountRef)",
     "message": "a recipient is either an address or an accountRef"}
]))]
pub struct Recipient {
    /// A mail address, inside or outside the instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// A `StalwartAccount` of this namespace: its confirmed address
    /// (`status.address`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<ObjectRef>,
}

impl MailingList {
    /// The list's local-part: `spec.name`, or the CR's own name —
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
    fn recipients_are_addresses_or_account_refs() {
        let spec: MailingListSpec = serde_json::from_value(serde_json::json!({
            "domainRef": {"name": "weebo.internal"},
            "recipients": [{"address": "a@example.com"}, {"accountRef": {"name": "alice"}}],
        }))
        .unwrap();
        assert_eq!(spec.deletion_policy, DeletionPolicy::Delete);
        assert_eq!(
            spec.recipients[1].account_ref.as_ref().unwrap().name,
            "alice"
        );
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(MailingList::crd()).unwrap();
        let recipient = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
            ["properties"]["recipients"]["items"];
        assert_eq!(
            recipient["x-kubernetes-validations"][0]["rule"],
            "has(self.address) != has(self.accountRef)"
        );
    }
}
