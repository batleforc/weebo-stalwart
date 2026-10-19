//! Pure domain of the operator: no Kubernetes, no HTTP — only the kit's
//! building blocks. Whatever the operator decides without I/O (naming
//! rules, the allow-list, diffing a desired state against the remote
//! one…) lives here.

pub mod account;
pub mod allow_list;
pub mod error;
pub mod mail;
pub mod mail_domain;
pub mod mailing_list;
pub mod quantity;

/// Comparing the desired state with the remote one before writing: only
/// what drifted is sent, nothing when nothing did.
pub use weebo_kit_domain::drift::{self, Drift, RemoteWrite};

/// A `Ready: False` cause, carrying one of this operator's reason codes.
pub type Failure = weebo_kit_domain::Failure<error::ReasonCode>;
/// A non-blocking condition shown next to `Ready: True`.
pub type Advisory = weebo_kit_domain::Advisory<error::ReasonCode>;
