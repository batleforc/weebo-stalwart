//! Port traits: what the use-cases need from the outside world. One
//! [`RemoteGateway`] per instance (`StalwartInstance` or
//! `StalwartLocalInstance`), produced on demand by the
//! [`GatewayFactory`]; which instance a CR lives on is the kit's
//! [`InstanceDirectory`]; the other CRs a decision depends on (policies,
//! claims) come through [`ClusterReader`] and [`PolicySource`].
//!
//! The gateway speaks Stalwart's management objects (`x:Domain`,
//! `x:Account`, `x:MailingList`) by **id**: a CR reads the object recorded
//! in its `status.remoteId`, never one looked up by name (only the
//! importer searches by name, to link an existing object to a CR).

use std::sync::Arc;

use api::common::{SecretStoreBackend, Submission, VaultPathGrant};
pub use domain::account::{AccountPatch, DesiredAccount, RemoteAccount};
use domain::error::ReasonCode;
pub use domain::mail_domain::{DesiredDomain, DomainPatch, RemoteDomain};
pub use domain::mailing_list::{DesiredMailingList, MailingListPatch, RemoteMailingList};
pub use weebo_kit_application::instances::{
    BoundInstance, InstanceDirectory, InstanceError, ResolveError,
};
pub use weebo_kit_application::ports::{
    ClusterError, PolicySource, SecretOwner, SecretStore, SecretStoreError, SecretStoreFactory,
};

/// A failed call to Stalwart.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatewayError {
    /// No answer: network error, timeout, gateway errors.
    #[error("Stalwart unreachable: {0}")]
    Unreachable(String),
    /// The token was refused, or lacks a permission the call needs.
    #[error("Stalwart refused the token: {0}")]
    Unauthorized(String),
    #[error("not found in Stalwart: {0}")]
    NotFound(String),
    /// A unique name or address is taken (`primaryKeyViolation`): by an
    /// object no CR of this one created — never adopted.
    #[error("already exists in Stalwart: {0}")]
    AlreadyExists(String),
    /// Other objects still use it (`objectIsLinked`).
    #[error("still in use in Stalwart: {0}")]
    Linked(String),
    /// Stalwart refused a value (`invalidPatch`, `validationFailed`,
    /// `invalidProperties`, `invalidForeignKey`): only a change of the CR
    /// clears it.
    #[error("refused by Stalwart: {0}")]
    Invalid(String),
    /// The server's management schema is not one this release supports.
    #[error("{0}")]
    UnsupportedVersion(String),
    /// Any other unexpected answer.
    #[error("Stalwart API error: {0}")]
    Api(String),
    /// The instance's second key — the one that creates the service
    /// accounts' App Passwords (`appPasswordTokenSecretRef`) — is unset, or
    /// its `Secret` can't be read: what the factory would have said of the
    /// main token.
    // RFC 0001 D24: the gateway is built without that key (the other kinds
    // don't need it); only the calls needing it fail, with the reason the
    // factory gives a missing main token.
    #[error("{0}")]
    AppPasswordKey(Box<GatewayFactoryError>),
}

impl GatewayError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            GatewayError::Unreachable(_) => ReasonCode::InstanceUnreachable,
            GatewayError::Unauthorized(_) => ReasonCode::InstanceUnauthorized,
            GatewayError::AlreadyExists(_) => ReasonCode::StalwartObjectAlreadyExists,
            GatewayError::Linked(_) => ReasonCode::ObjectIsLinked,
            GatewayError::Invalid(_) => ReasonCode::InvalidSpec,
            GatewayError::UnsupportedVersion(_) => ReasonCode::UnsupportedStalwartVersion,
            GatewayError::NotFound(_) | GatewayError::Api(_) => ReasonCode::RemoteError,
            GatewayError::AppPasswordKey(e) => e.reason(),
        }
    }
}

/// Talks to one Stalwart instance.
///
/// `#[async_trait]` rather than native `async fn` in trait: it is used as
/// `dyn RemoteGateway`, and native async-fn-in-traits are not
/// `dyn`-compatible.
#[async_trait::async_trait]
pub trait RemoteGateway: Send + Sync {
    /// Whether the instance answers, accepts the token and serves a
    /// supported management schema (`UnsupportedVersion` otherwise).
    async fn ping(&self) -> Result<(), GatewayError>;

    /// The domain `id`, `None` when there is none.
    async fn get_domain(&self, id: &str) -> Result<Option<RemoteDomain>, GatewayError>;
    /// The id of the domain named exactly `name` (lowercased), `None` when
    /// there is none. For the importer: a reconcile never looks a domain up
    /// by name.
    async fn find_domain(&self, name: &str) -> Result<Option<String>, GatewayError>;
    /// Creates the domain; returns its id. `AlreadyExists` when the name
    /// (or an alias) is taken.
    async fn create_domain(&self, domain: &DesiredDomain) -> Result<String, GatewayError>;
    /// Sends the fields of `patch` (only those) to the domain `id`.
    async fn update_domain(&self, id: &str, patch: &DomainPatch) -> Result<(), GatewayError>;

    /// The account (user or group) `id`, `None` when there is none.
    async fn get_account(&self, id: &str) -> Result<Option<RemoteAccount>, GatewayError>;
    /// The id of the account named `name` (lowercased) in the domain
    /// `domain_id`, `None` when there is none. For the importer only.
    async fn find_account(
        &self,
        domain_id: &str,
        name: &str,
    ) -> Result<Option<String>, GatewayError>;
    /// Creates the account, without any credential; returns its id.
    /// `AlreadyExists` when its address or an alias is taken (by any
    /// account, group or list).
    async fn create_account(&self, account: &DesiredAccount) -> Result<String, GatewayError>;
    /// Sends the fields of `patch` (only those) to the account `id`.
    async fn update_account(&self, id: &str, patch: &AccountPatch) -> Result<(), GatewayError>;
    /// Whether the instance's App Password key is set and readable:
    /// `AppPasswordKey` otherwise. No call to Stalwart.
    async fn app_password_key(&self) -> Result<(), GatewayError>;
    /// Gives the account `id` a new App Password of the operator's
    /// ([`APP_PASSWORD_DESCRIPTION`], granting `authenticate` and
    /// `emailSend` only) and revokes the earlier ones of the operator's, in
    /// one call; the account's other App Passwords (its user's) are left
    /// alone. Returns the new secret — the only time Stalwart shows it.
    /// Needs the instance's App Password key: `AppPasswordKey` without it.
    // RFC 0001 D24: a service account authenticates with an App Password,
    // never a `Password` credential — an OIDC default directory refuses
    // both the login and the write of a password, and only `x:AppPassword`
    // (with `impersonate`) creates an App Password on another account.
    async fn rotate_app_password(&self, id: &str) -> Result<String, GatewayError>;
    /// Deletes the account: `true`, or `false` when it was already gone.
    /// `Linked` while other objects use it (a group with members).
    async fn delete_account(&self, id: &str) -> Result<bool, GatewayError>;

    /// The mailing list `id`, `None` when there is none.
    async fn get_mailing_list(&self, id: &str) -> Result<Option<RemoteMailingList>, GatewayError>;
    /// The id of the list named `name` in the domain `domain_id`. For the
    /// importer only.
    async fn find_mailing_list(
        &self,
        domain_id: &str,
        name: &str,
    ) -> Result<Option<String>, GatewayError>;
    async fn create_mailing_list(&self, list: &DesiredMailingList) -> Result<String, GatewayError>;
    async fn update_mailing_list(
        &self,
        id: &str,
        patch: &MailingListPatch,
    ) -> Result<(), GatewayError>;
    /// Deletes the list: `true`, or `false` when it was already gone.
    async fn delete_mailing_list(&self, id: &str) -> Result<bool, GatewayError>;
}

/// The `description` of the App Passwords the operator creates: a rotation
/// revokes these, and only these.
pub const APP_PASSWORD_DESCRIPTION: &str = "weebo-stalwart";

/// Why no gateway could be built for an instance.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatewayFactoryError {
    /// The instance is gone since it was resolved.
    #[error("{0} not found")]
    InstanceNotFound(BoundInstance),
    /// The token `Secret` or its key is missing / not UTF-8.
    #[error("token secret: {0}")]
    TokenSecret(String),
    /// A local instance's token `Secret` doesn't carry the consent label.
    #[error("{0}")]
    TokenNotAllowed(String),
    /// A Kubernetes API read failed — usually transient.
    #[error("Kubernetes API error: {0}")]
    Kubernetes(String),
    /// The instance's spec can't produce a client (its `url`, its TLS CA).
    #[error("invalid instance: {0}")]
    InvalidSpec(String),
}

impl GatewayFactoryError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            GatewayFactoryError::InstanceNotFound(_) => ReasonCode::InstanceNotFound,
            GatewayFactoryError::TokenSecret(_) => ReasonCode::TokenSecretMissing,
            GatewayFactoryError::TokenNotAllowed(_) => ReasonCode::TokenSecretNotAllowed,
            GatewayFactoryError::Kubernetes(_) => ReasonCode::KubernetesApiError,
            GatewayFactoryError::InvalidSpec(_) => ReasonCode::InvalidSpec,
        }
    }
}

/// The gateway of a resolved instance. Implementations re-read the token
/// `Secret` on every call: rotating it needs no restart.
#[async_trait::async_trait]
pub trait GatewayFactory: Send + Sync {
    async fn gateway_for(
        &self,
        instance: &BoundInstance,
    ) -> Result<Arc<dyn RemoteGateway>, GatewayFactoryError>;
}

/// What a claim is about: the unique keys of Stalwart a CR may own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    /// A domain name (`StalwartDomain`'s `status.address`).
    Domain,
    /// A mail address: unique across the accounts, groups, lists and their
    /// aliases of a server — claimed by a `StalwartServiceAccount`,
    /// `StalwartAccount`, `StalwartGroup` or `StalwartMailingList` through
    /// its `status.address`, or one of its aliases in the same domain.
    Address,
}

impl ClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimKind::Domain => "domain",
            ClaimKind::Address => "address",
        }
    }
}

/// A `StalwartDomain` as the account kinds see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainState {
    /// `status.remoteId`: the domain's id in Stalwart.
    pub remote_id: Option<String>,
    /// `status.address`: the domain name Stalwart confirmed.
    pub name: Option<String>,
    /// `status.instance`.
    pub instance: Option<BoundInstance>,
    /// `Ready: True` (the last reconcile succeeded).
    pub ready: bool,
}

/// What a CR's instance says about the secrets it emits.
#[derive(Debug, Clone, PartialEq)]
pub struct InstanceSettings {
    /// What the emitted SMTP settings announce.
    pub submission: Submission,
    /// Backend of an implicit target (`secretStore.backend`; a
    /// `StalwartLocalInstance`: `kubernetes`).
    pub default_backend: SecretStoreBackend,
    /// The Vault connection's path rules, `None` without one.
    pub vault: Option<VaultSettings>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VaultSettings {
    pub path_prefix: String,
    pub path_grants: Vec<VaultPathGrant>,
}

/// The CRs the reconcilers decide on, besides the reconciled one.
#[async_trait::async_trait]
pub trait ClusterReader: Send + Sync {
    /// The CRs (`Kind/name`, `Kind/namespace/name` when namespaced) owning
    /// the Stalwart object `name` of `kind` — the name their status
    /// confirmed — on the server `instance` points at, whatever instance
    /// CR they are bound to as long as it points at the same server. The
    /// unique claim: a name owned by a CR is never taken by another one.
    async fn claimants(
        &self,
        kind: ClaimKind,
        name: &str,
        instance: &BoundInstance,
    ) -> Result<Vec<String>, ClusterError>;

    /// [`Self::claimants`] of every one of `names`, as `(name, claimant)`
    /// in the order of `names`. An adapter reading the cluster overrides it
    /// to read the claiming CRs once for all the names — an object's
    /// address and each of its aliases — rather than once per name.
    async fn claimants_of_any(
        &self,
        kind: ClaimKind,
        names: &[String],
        instance: &BoundInstance,
    ) -> Result<Vec<(String, String)>, ClusterError> {
        let mut all = Vec::new();
        for name in names {
            for claimant in self.claimants(kind, name, instance).await? {
                all.push((name.clone(), claimant));
            }
        }
        Ok(all)
    }

    /// The `StalwartDomain` named `name` (`metadata.name`), `None` when
    /// there is none the operator sees.
    async fn domain(&self, name: &str) -> Result<Option<DomainState>, ClusterError>;

    /// The confirmed address (`status.address`, with a `remoteId`) of the
    /// `StalwartAccount` `namespace/name`: `None` when there is no such CR,
    /// or it has none yet.
    async fn account_address(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<String>, ClusterError>;

    /// The settings of `instance`, `None` when it is gone.
    async fn instance_settings(
        &self,
        instance: &BoundInstance,
    ) -> Result<Option<InstanceSettings>, ClusterError>;
}

/// The reason code of an instance that couldn't be resolved.
pub fn instance_reason(err: &InstanceError) -> ReasonCode {
    match err {
        InstanceError::Kubernetes(_) => ReasonCode::KubernetesApiError,
        InstanceError::Resolve(e) => match e {
            ResolveError::NotFound { .. } | ResolveError::NoInstance => {
                ReasonCode::InstanceNotFound
            }
            ResolveError::Ambiguous { .. } => ReasonCode::InstanceAmbiguous,
            ResolveError::InvalidRef(_) => ReasonCode::InvalidSpec,
            ResolveError::OutsideScope(_) | ResolveError::NotShared { .. } => {
                ReasonCode::InstanceNotAllowed
            }
            ResolveError::BindingChanged { .. } => ReasonCode::InstanceBindingChanged,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_gateway_error_has_the_reason_code_the_cr_shows() {
        let e = |f: fn(String) -> GatewayError| f("why".into()).reason();
        assert_eq!(
            e(GatewayError::Unreachable),
            ReasonCode::InstanceUnreachable
        );
        assert_eq!(
            e(GatewayError::Unauthorized),
            ReasonCode::InstanceUnauthorized
        );
        assert_eq!(
            e(GatewayError::AlreadyExists),
            ReasonCode::StalwartObjectAlreadyExists
        );
        assert_eq!(e(GatewayError::Linked), ReasonCode::ObjectIsLinked);
        assert_eq!(e(GatewayError::Invalid), ReasonCode::InvalidSpec);
        assert_eq!(
            e(GatewayError::UnsupportedVersion),
            ReasonCode::UnsupportedStalwartVersion
        );
        assert_eq!(e(GatewayError::NotFound), ReasonCode::RemoteError);
        assert_eq!(e(GatewayError::Api), ReasonCode::RemoteError);
        let key = |f: GatewayFactoryError| GatewayError::AppPasswordKey(Box::new(f)).reason();
        assert_eq!(
            key(GatewayFactoryError::TokenSecret("unset".into())),
            ReasonCode::TokenSecretMissing
        );
        assert_eq!(
            key(GatewayFactoryError::TokenNotAllowed("label".into())),
            ReasonCode::TokenSecretNotAllowed
        );
    }

    #[test]
    fn every_factory_error_has_the_reason_code_the_cr_shows() {
        let e = |f: fn(String) -> GatewayFactoryError| f("why".into()).reason();
        assert_eq!(
            GatewayFactoryError::InstanceNotFound(BoundInstance::cluster("main")).reason(),
            ReasonCode::InstanceNotFound
        );
        assert_eq!(
            e(GatewayFactoryError::TokenSecret),
            ReasonCode::TokenSecretMissing
        );
        assert_eq!(
            e(GatewayFactoryError::TokenNotAllowed),
            ReasonCode::TokenSecretNotAllowed
        );
        assert_eq!(
            e(GatewayFactoryError::Kubernetes),
            ReasonCode::KubernetesApiError
        );
        assert_eq!(e(GatewayFactoryError::InvalidSpec), ReasonCode::InvalidSpec);
    }

    #[test]
    fn every_unresolved_instance_has_the_reason_code_the_cr_shows() {
        let r = |e: ResolveError| instance_reason(&InstanceError::Resolve(e));
        assert_eq!(
            instance_reason(&InstanceError::Kubernetes("down".into())),
            ReasonCode::KubernetesApiError
        );
        assert_eq!(r(ResolveError::NoInstance), ReasonCode::InstanceNotFound);
        assert_eq!(
            r(ResolveError::NotFound {
                kind: "StalwartInstance".into(),
                name: "main".into()
            }),
            ReasonCode::InstanceNotFound
        );
        assert_eq!(
            r(ResolveError::Ambiguous {
                kind: "StalwartInstance".into(),
                count: 2
            }),
            ReasonCode::InstanceAmbiguous
        );
        assert_eq!(
            r(ResolveError::InvalidRef("kind".into())),
            ReasonCode::InvalidSpec
        );
        assert_eq!(
            r(ResolveError::OutsideScope("ns".into())),
            ReasonCode::InstanceNotAllowed
        );
        assert_eq!(
            r(ResolveError::NotShared {
                instance: "a/b".into(),
                with: "c".into()
            }),
            ReasonCode::InstanceNotAllowed
        );
        assert_eq!(
            r(ResolveError::BindingChanged {
                name: "main".into(),
                recorded: Box::new(BoundInstance::cluster("main")),
                now: Box::new(BoundInstance::local("ns", "main")),
            }),
            ReasonCode::InstanceBindingChanged
        );
    }

    #[test]
    fn claim_kinds_name_what_is_claimed() {
        assert_eq!(ClaimKind::Domain.as_str(), "domain");
        assert_eq!(ClaimKind::Address.as_str(), "address");
    }
}
