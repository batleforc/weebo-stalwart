use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use crate::common::{LocalSecretKeyRef, LocalTlsOptions, SharedWith, Submission};
use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::StalwartLocalInstance as LocalInstance;
pub use self::StalwartLocalInstanceSpec as LocalInstanceSpec;

/// Connection to one Stalwart server (v0.16), owned by a namespace: its
/// token is that namespace's, and only its objects use it unless
/// `sharedWith` says otherwise. What an operator limited to one namespace
/// uses. Objects bound to it are not governed by `StalwartNamespacePolicy`
/// (the namespace's own token bounds them) and write their secrets as
/// Kubernetes `Secret`s only: the operator's Vault identity is shared by
/// every namespace. `Ready` tells whether the server answers with the
/// token below and speaks a supported management schema.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "stalwart.weebo.io",
    version = "v1alpha1",
    kind = "StalwartLocalInstance",
    plural = "stalwartlocalinstances",
    namespaced,
    status = "Status",
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".spec.url"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
// RFC 0001 Q16: no `secretStore` on the local instance (weebo-forgejo's
// choice): its CRs write Kubernetes Secrets only, the operator's Vault
// identity being shared by every namespace.
#[serde(rename_all = "camelCase")]
pub struct StalwartLocalInstanceSpec {
    /// Base URL of the Stalwart HTTP listener, e.g.
    /// `http://stalwart.mail.svc:8080` (JMAP at `<url>/jmap`).
    pub url: String,
    /// An API key of Stalwart (sent as `Authorization: Bearer`), in a
    /// `Secret` of this namespace labelled
    /// `stalwart.weebo.io/instance-token: "true"` (without the label the
    /// operator doesn't read it). Read on every reconcile: rotating it
    /// needs no restart.
    pub token_secret_ref: LocalSecretKeyRef,
    /// A second API key of Stalwart, on the same account as the one above,
    /// in a `Secret` of this namespace with the same label: the one that
    /// creates, rotates and revokes the App Passwords of the
    /// `StalwartServiceAccount`s (permissions `authenticate`,
    /// `impersonate`, `emailSend` and `sysAppPassword*` only). Read on
    /// every reconcile of a `StalwartServiceAccount`; unset, those fail
    /// with `TokenSecretMissing` (the other kinds don't use it).
    // RFC 0001 D24: see `StalwartInstanceSpec::app_password_token_secret_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_password_token_secret_ref: Option<LocalSecretKeyRef>,
    /// TLS verification of the connection above; the CA `Secret` lives in
    /// this namespace.
    #[serde(default)]
    pub tls: LocalTlsOptions,
    /// Other namespaces (or cluster-scoped objects) allowed to use this
    /// instance — and its token. Unset: this namespace only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<SharedWith>,
    /// The submission service the emitted credentials announce.
    #[serde(default)]
    pub submission: Submission,
}

impl weebo_kit_api::SharesItself for LocalInstance {
    fn shared_with(&self) -> Option<&SharedWith> {
        self.spec.shared_with.as_ref()
    }
}
