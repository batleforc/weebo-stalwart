use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use crate::common::{SecretKeyRef, SecretStoreSpec, Submission, TlsOptions};
use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::StalwartInstance as Instance;
pub use self::StalwartInstanceSpec as InstanceSpec;

/// Connection to one Stalwart server (v0.16). Cluster-scoped: an org-wide
/// piece of infrastructure, not owned by a namespace (a namespace's own
/// server is a `StalwartLocalInstance`). `Ready` tells whether the server
/// answers with the token below and speaks a management schema this
/// operator release supports.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "stalwart.weebo.io",
    version = "v1alpha1",
    kind = "StalwartInstance",
    plural = "stalwartinstances",
    status = "Status",
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".spec.url"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct StalwartInstanceSpec {
    /// Base URL of the Stalwart HTTP listener, e.g.
    /// `http://stalwart.mail.svc:8080`. Management goes through JMAP,
    /// `POST <url>/jmap` (session `GET <url>/jmap/session`); `<url>/api`
    /// only serves the schema, whose hash identifies the server's version.
    pub url: String,
    /// An API key of Stalwart, sent as `Authorization: Bearer`. Read on
    /// every reconcile: rotating it needs no restart.
    pub token_secret_ref: SecretKeyRef,
    /// A second API key of Stalwart, on the same account as the one above:
    /// the one that creates, rotates and revokes the App Passwords of the
    /// `StalwartServiceAccount`s (permissions `authenticate`,
    /// `impersonate`, `emailSend` and `sysAppPassword*` only). Read on
    /// every reconcile of a `StalwartServiceAccount`; unset, those fail
    /// with `TokenSecretMissing` (the other kinds don't use it).
    // RFC 0001 D24: a separate key, because `impersonate` — needed to
    // create an App Password on another account — must never sit next to
    // the main key's `jmap*` permissions (it would read every mailbox).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_password_token_secret_ref: Option<SecretKeyRef>,
    /// TLS verification of the connection above: a private CA to trust
    /// (`tls.caSecretRef`), or `tls.insecureSkipVerify`. Default: the
    /// platform trust store.
    #[serde(default)]
    pub tls: TlsOptions,
    /// Default destination of the secrets the CRs bound to this instance
    /// emit, when they list no `secretTargets`. Default: a Kubernetes
    /// `Secret`.
    #[serde(default)]
    pub secret_store: SecretStoreSpec,
    /// The submission service the emitted credentials announce.
    #[serde(default)]
    pub submission: Submission,
}
