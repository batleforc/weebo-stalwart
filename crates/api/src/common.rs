//! Field types shared across CRDs. Those every weebo operator shares
//! (secret refs and targets, CR refs, TLS) come from the kit.

/// A size (`2Gi`): a quota.
pub use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
/// The metadata of every CR (annotations are read through
/// [`crate::ANNOTATIONS`]).
pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub use weebo_kit_api::{
    BoundInstance, InstanceKind, InstanceRef, LocalSecretKeyRef, LocalTlsOptions, ObjectRef,
    SecretKeyRef, SecretStoreBackend, SecretTarget, SharedWith, TlsOptions, VaultPathGrant,
};

/// What happens to the Stalwart object when its CR is deleted.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
pub enum DeletionPolicy {
    /// Delete the Stalwart object (and the secrets the CR emitted).
    Delete,
    /// Leave the Stalwart object in place, only drop the CR.
    Orphan,
}

impl DeletionPolicy {
    /// Default of the kinds whose deletion destroys mail (domains,
    /// mailboxes, groups).
    pub fn orphan() -> Self {
        DeletionPolicy::Orphan
    }

    /// Default of every other kind.
    pub fn delete() -> Self {
        DeletionPolicy::Delete
    }
}

/// Default destination of the secrets the instance's CRs emit. Not a Rust
/// sum type (`enum { Kubernetes, Vault(..) }`): kube-core's CRD schema
/// generation can't merge an internally-tagged enum whose variants carry
/// different discriminator schemas. "`vault` set iff `backend: vault`" is
/// checked by the secret store factory.
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretStoreSpec {
    /// Backend of a CR's implicit target (one named after the CR, when it
    /// lists no `secretTargets`).
    #[serde(default)]
    pub backend: SecretStoreBackend,
    /// The Vault connection a `vault` target writes through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultSecretStoreSpec>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "!has(self.pathGrants) || self.pathGrants.all(g, !has(g.clusterScoped) || !g.clusterScoped)",
     "message": "pathGrants name namespaces: every object writing credentials is namespaced, clusterScoped grants never apply"}
]))]
pub struct VaultSecretStoreSpec {
    /// Vault server address, e.g. `https://vault.example.com:8200`.
    // Drawn by the docs' CRD IDE (the kit's shared schematic kinds).
    #[schemars(extend("x-weebo-produces" = { "kind": { "group": "schematic.weebo.io", "kind": "VaultServer" }, "name": ["."] }))]
    pub address: String,
    /// KV v2 secrets engine mount (e.g. `secret`) credentials are written
    /// under.
    pub mount: String,
    /// Path prefix under `mount`: the default KV path of a target is
    /// `<pathPrefix>/<namespace>/<name>`, one secret per target. Empty:
    /// `<namespace>/<name>`. An explicit `path` must stay under
    /// `<pathPrefix>/<namespace>/` unless `pathGrants` opens it.
    ///
    /// With an empty prefix, a path holding a value no CR owns (written by
    /// another tool) is taken over by the first CR writing it: only the
    /// Vault policy of the operator's role then keeps a CR away from such
    /// values. Keep a prefix unless that policy is narrowed to the paths
    /// the CRs may write.
    #[serde(default = "default_vault_path_prefix")]
    pub path_prefix: String,
    /// Vault paths this instance's CRs may write to outside their
    /// namespace's subtree `<pathPrefix>/<namespace>/`, per namespace
    /// (`clusterScoped` is refused: every object writing credentials is
    /// namespaced). The Vault policy of the operator's role stays the hard
    /// bound.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 32))]
    pub path_grants: Vec<VaultPathGrant>,
    /// Vault Kubernetes-auth role the operator authenticates as: its own
    /// ServiceAccount token is exchanged for a Vault token through
    /// `auth/<kubernetesAuthMount>/login`.
    pub kubernetes_auth_role: String,
    /// Mount path of Vault's Kubernetes auth backend.
    #[serde(default = "default_kubernetes_auth_mount")]
    pub kubernetes_auth_mount: String,
    /// A private CA to verify Vault's TLS with: a PEM bundle under `key`
    /// of a `Secret`, read through the API. Unset: the system trust store.
    /// Only consulted for `https://` addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_secret_ref: Option<SecretKeyRef>,
}

fn default_vault_path_prefix() -> String {
    "weebo-stalwart".to_string()
}

fn default_kubernetes_auth_mount() -> String {
    "kubernetes".to_string()
}

/// How a mail client reaches the instance's submission service: what the
/// credentials the CRs emit announce (`host`, `port`, `security`). Nothing
/// is connected to by the operator itself.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Submission {
    /// Host name of the submission service.
    #[serde(default = "default_submission_host")]
    // Drawn by the docs' CRD IDE (the kit's shared schematic kinds).
    #[schemars(extend("x-weebo-produces" = { "kind": { "group": "schematic.weebo.io", "kind": "DnsName" }, "name": ["."] }))]
    pub host: String,
    /// Port of the submission service.
    #[serde(default = "default_submission_port")]
    #[schemars(range(min = 1, max = 65535))]
    pub port: u16,
    /// Transport security a client must use.
    #[serde(default)]
    pub security: SubmissionSecurity,
}

impl Default for Submission {
    fn default() -> Self {
        Self {
            host: default_submission_host(),
            port: default_submission_port(),
            security: SubmissionSecurity::default(),
        }
    }
}

fn default_submission_host() -> String {
    "stalwart.mail.svc.cluster.local".to_string()
}

fn default_submission_port() -> u16 {
    587
}

/// Transport security of the submission service.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SubmissionSecurity {
    /// Plain connection upgraded with `STARTTLS` (port 587).
    #[default]
    Starttls,
    /// TLS from the first byte (port 465).
    Tls,
    /// No transport security: in-cluster tests only.
    None,
}

impl SubmissionSecurity {
    pub const fn as_str(self) -> &'static str {
        match self {
            SubmissionSecurity::Starttls => "starttls",
            SubmissionSecurity::Tls => "tls",
            SubmissionSecurity::None => "none",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submission_defaults_to_the_in_cluster_service() {
        let s: Submission = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(s, Submission::default());
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            serde_json::json!({"host": "stalwart.mail.svc.cluster.local", "port": 587, "security": "starttls"})
        );
    }

    #[test]
    fn the_vault_prefix_defaults_to_the_operators_name() {
        let v: VaultSecretStoreSpec = serde_json::from_value(serde_json::json!({
            "address": "https://vault:8200", "mount": "mv", "kubernetesAuthRole": "stalwart-operator",
        }))
        .unwrap();
        assert_eq!(v.path_prefix, "weebo-stalwart");
        assert_eq!(v.kubernetes_auth_mount, "kubernetes");
    }
}
