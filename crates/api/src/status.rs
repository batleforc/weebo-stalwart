//! The status every CRD of this operator shares.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub use weebo_kit_api::{BoundInstance, Condition};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// The `metadata.generation` the last successful reconcile applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// Identifier of the remote object, as Stalwart returned it. Its
    /// presence means this CR created (and owns) that object: the remote
    /// object is read by this id, never looked up by name, and the
    /// finalizer only deletes what is recorded here. Set once at creation,
    /// or by `weebo-stalwart-importer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,
    /// The address (or, for a domain, the name) Stalwart confirmed at the
    /// last reconcile. A read by `remoteId` answering another one is taken
    /// as the object being gone — its id reused by another object after a
    /// reset — never patched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Value of the `stalwart.weebo.io/rotate-secret` annotation the last
    /// emitted secret was issued for: the same nonce never rotates twice.
    /// Only on kinds that emit a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rotation: Option<String>,
    /// The instance this object was resolved to and stays bound to: a
    /// `spec.instanceRef` by name only never silently moves to another
    /// instance created later under the same name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<BoundInstance>,
    /// `Ready`, carrying one of the operator's reason codes.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}
