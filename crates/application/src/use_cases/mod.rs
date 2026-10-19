//! One `reconcile_*` use-case per CRD. Each returns an [`Outcome`] the
//! controller turns into a status patch and Events — always through a
//! `ReasonCode`, never a free string.

pub mod accounts;
pub mod admission;
pub mod emit;
pub mod import;
pub mod reconcile_account;
pub mod reconcile_domain;
pub mod reconcile_group;
pub mod reconcile_instance;
pub mod reconcile_mailing_list;
pub mod reconcile_namespace_policy;
pub mod reconcile_service_account;

use domain::error::ReasonCode;
use domain::{Drift, Failure, RemoteWrite};

use crate::ports::{
    BoundInstance, ClusterError, GatewayError, GatewayFactoryError, InstanceError, instance_reason,
};

impl From<GatewayError> for Failure {
    fn from(err: GatewayError) -> Self {
        Failure::new(err.reason(), err.to_string())
    }
}

impl From<GatewayFactoryError> for Failure {
    fn from(err: GatewayFactoryError) -> Self {
        Failure::new(err.reason(), err.to_string())
    }
}

/// A Kubernetes read made for the use-case failed: retried like any
/// failure.
pub fn cluster_failure(err: ClusterError) -> Failure {
    Failure::new(ReasonCode::KubernetesApiError, err.to_string())
}

/// An instance that couldn't be resolved, as a failure (`Failure` and
/// `InstanceError` both being the kit's, no `From` between them).
pub fn instance_failure(err: InstanceError) -> Failure {
    Failure::new(instance_reason(&err), err.to_string())
}

/// What a reconcile ended on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The remote object this CR now owns, to record in its status.
    pub remote_id: Option<String>,
    /// The address (a domain's name) Stalwart confirmed, to record in the
    /// status (`status.address`).
    pub address: Option<String>,
    /// The rotation nonce the emitted secret was issued for
    /// (`status.lastRotation`).
    pub last_rotation: Option<String>,
    /// The instance the CR was resolved to, to record in its status.
    pub instance: Option<BoundInstance>,
    /// `Ok(message)` for `Ready: True`.
    pub ready: Result<String, Failure>,
    /// The write this reconcile made to Stalwart, if any — counted in
    /// `<prefix>_remote_writes_total`. `None` when everything was in sync.
    pub write: Option<RemoteWrite>,
    /// The fields put back in their desired state (a `DriftCorrected`
    /// Event names them).
    pub drift: Drift,
}

impl Outcome {
    pub fn synced(remote_id: Option<String>, message: impl Into<String>) -> Self {
        Self {
            remote_id,
            address: None,
            last_rotation: None,
            instance: None,
            ready: Ok(message.into()),
            write: None,
            drift: Drift::default(),
        }
    }

    pub fn failed(failure: impl Into<Failure>) -> Self {
        Self {
            remote_id: None,
            address: None,
            last_rotation: None,
            instance: None,
            ready: Err(failure.into()),
            write: None,
            drift: Drift::default(),
        }
    }

    /// Records a write to Stalwart.
    pub fn wrote(mut self, write: RemoteWrite) -> Self {
        self.write = Some(write);
        self
    }

    /// Records the fields a drift correction wrote.
    pub fn corrected(mut self, drift: Drift) -> Self {
        self.write = Some(RemoteWrite::Drift);
        self.drift = drift;
        self
    }

    /// Records the address Stalwart confirmed.
    pub fn at(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    /// Records the instance the CR is bound to.
    pub fn on(mut self, instance: BoundInstance) -> Self {
        self.instance = Some(instance);
        self
    }

    /// A failure on an object still owned: its id and confirmed address
    /// stay recorded.
    pub fn with_id(mut self, id: impl Into<String>, address: impl Into<String>) -> Self {
        self.remote_id = Some(id.into());
        self.address = Some(address.into());
        self
    }

    /// Records the rotation nonce the emitted secret was issued for.
    pub fn rotated(mut self, nonce: Option<String>) -> Self {
        self.last_rotation = nonce;
        self
    }

    /// The reason `Ready` ends on — what metrics and Events are keyed by.
    pub fn reason(&self) -> ReasonCode {
        match &self.ready {
            Ok(_) => ReasonCode::Reconciled,
            Err(f) => f.reason,
        }
    }
}
