//! The CRDs of the operator. Pure types: `serde`/`schemars` derives and
//! the kit's shared field types, no client code. Doc comments become the
//! CRD schema descriptions (`crdgen` → `deploy/crd/`).
//!
//! The kinds' Rust types carry their kind's name (`StalwartInstance`,
//! the CRD's title); the workspace uses them through short re-exports
//! ([`Instance`], [`LocalInstance`], [`Domain`], [`ServiceAccount`],
//! [`Account`], [`Group`], [`MailingList`]…).

pub mod account;
pub mod common;
pub mod domain;
pub mod group;
pub mod instance;
pub mod local_instance;
pub mod mailing_list;
pub mod namespace_policy;
pub mod service_account;
pub mod status;

/// API group shared by every CRD of this operator.
pub const GROUP: &str = "stalwart.weebo.io";

/// The kit's common annotations under [`GROUP`]:
/// `stalwart.weebo.io/force-orphan` (release a CR without
/// cleanup), `allow-disruptive-update`, `rotate-secret`, `import-pending`,
/// `previous-owner`; the label `instance-token` of a local instance's
/// token `Secret`.
pub const ANNOTATIONS: weebo_kit_api::Annotations = weebo_kit_api::Annotations::new(GROUP);

/// Finalizer set on every CR whose deletion has a Stalwart-side effect.
pub const FINALIZER: &str = "stalwart.weebo.io/finalizer";

/// On every `Secret` the operator emits: the emitting CR, as
/// `<Kind>/<namespace>/<name>`. A `Secret` without it (and without the
/// `managed-by` label) or naming another CR is never overwritten nor
/// deleted.
pub const SECRET_OWNER_ANNOTATION: &str = "stalwart.weebo.io/owner";

pub use account::Account;
pub use domain::Domain;
pub use group::Group;
pub use instance::Instance;
pub use local_instance::LocalInstance;
pub use mailing_list::MailingList;
pub use namespace_policy::StalwartNamespacePolicy as NamespacePolicy;
pub use service_account::ServiceAccount;
pub use status::Status;
