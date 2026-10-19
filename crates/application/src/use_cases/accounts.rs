//! What the namespaced kinds share — `StalwartServiceAccount`,
//! `StalwartAccount`, `StalwartGroup` (`x:Account`) and
//! `StalwartMailingList` (`x:MailingList`): an address `name@domain` in a
//! `StalwartDomain`, aliases in the same domain, the allow-list, the unique
//! claim on every address, the read by id with its identity guard, the
//! creation that never adopts, the PATCH of what drifted only, and the
//! deletion.
//!
//! RFC 0001, "Architecture", the reconciliation of an account:
//!
//! 1. the instance is resolved by the controller; the domain must be a
//!    `Ready` `StalwartDomain` of the same instance (`DomainNotFound`,
//!    `DomainNotReady`);
//! 2. the policy (the webhook's verdict, re-checked);
//! 3. the read: by `status.remoteId`, trusted only when the object answers
//!    the address `status.address` confirmed, with the right type (D19) —
//!    otherwise taken as gone;
//! 4. gone: no other CR may claim the address or an alias
//!    (`RemoteObjectClaimed`), then a creation — a name taken in Stalwart
//!    is `StalwartObjectAlreadyExists`, never adopted;
//! 5. present: compared on the owned fields, only the drifted ones sent,
//!    nothing when in sync. A change of name or domain moves the address:
//!    it needs `allow-disruptive-update`.

use api::Status;
use api::common::{DeletionPolicy, ObjectMeta};
use api::namespace_policy::NamespaceRule;
use domain::account::{AccountType, account_patch};
use domain::allow_list::Kind;
use domain::error::ReasonCode;
use domain::mail;
use domain::mailing_list::{mailing_list_patch, normalize_address};
use domain::{Drift, Failure, RemoteWrite};

use crate::ports::{
    AccountPatch, BoundInstance, ClaimKind, ClusterReader, DesiredAccount, DesiredMailingList,
    GatewayError, MailingListPatch, PolicySource, RemoteAccount, RemoteGateway, RemoteMailingList,
};
use crate::use_cases::admission::enforce;
use crate::use_cases::{Outcome, cluster_failure};

/// A failure, boxed: the early return of the reconcilers.
pub(crate) fn fail(failure: impl Into<Failure>) -> Box<Outcome> {
    Box::new(Outcome::failed(failure))
}

/// The ports a namespaced kind's reconcile reads and writes through.
#[derive(Clone, Copy)]
pub struct Ports<'a> {
    pub gateway: &'a dyn RemoteGateway,
    pub cluster: &'a dyn ClusterReader,
    pub policies: &'a dyn PolicySource<NamespaceRule>,
}

/// What a namespaced CR asks for, whatever its kind.
#[derive(Debug, Clone)]
pub struct Subject<'a> {
    /// `StalwartAccount`…: how claims and secrets name the CR.
    pub cr_kind: &'static str,
    /// The allow-list's kind.
    pub kind: Kind,
    pub namespace: &'a str,
    pub cr_name: &'a str,
    pub meta: &'a ObjectMeta,
    pub status: Option<&'a Status>,
    /// The `StalwartDomain` (`metadata.name`).
    pub domain_ref: &'a str,
    /// The local-part, normalized.
    pub name: String,
    /// The aliases' local-parts, normalized, deduplicated, in spec order.
    pub aliases: Vec<String>,
}

impl<'a> Subject<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cr_kind: &'static str,
        kind: Kind,
        namespace: &'a str,
        cr_name: &'a str,
        meta: &'a ObjectMeta,
        status: Option<&'a Status>,
        domain_ref: &'a str,
        name: String,
        aliases: &[String],
    ) -> Self {
        let mut normalized: Vec<String> = Vec::new();
        for alias in aliases.iter().map(|a| mail::normalize_local_part(a)) {
            if !normalized.contains(&alias) {
                normalized.push(alias);
            }
        }
        Self {
            cr_kind,
            kind,
            namespace,
            cr_name,
            meta,
            status,
            domain_ref,
            name: mail::normalize_local_part(&name),
            aliases: normalized,
        }
    }

    /// `Kind/namespace/name`: how claims name the CR.
    pub fn claim_id(&self) -> String {
        format!("{}/{}/{}", self.cr_kind, self.namespace, self.cr_name)
    }

    /// The local-parts the allow-list's `names` dimension sees: the name
    /// and every alias.
    pub fn names(&self) -> Vec<String> {
        std::iter::once(self.name.clone())
            .chain(self.aliases.iter().cloned())
            .collect()
    }

    /// Every address the CR claims in `domain`: its own, then its aliases'.
    pub fn addresses(&self, domain: &str) -> Vec<String> {
        self.names()
            .iter()
            .map(|n| mail::address(n, domain))
            .collect()
    }

    /// The address the last reconcile confirmed, with the id it was
    /// confirmed for. RFC 0001 Q15: an id without an address proves
    /// nothing.
    fn recorded(&self) -> Option<(&'a str, &'a str)> {
        let status = self.status?;
        status.remote_id.as_deref().zip(status.address.as_deref())
    }

    /// The rotation nonce the last emitted secret was issued for.
    pub fn last_rotation(&self) -> Option<String> {
        self.status.and_then(|s| s.last_rotation.clone())
    }

    /// The previous reconcile ended on `reason`.
    pub fn last_failed_on(&self, reason: ReasonCode) -> bool {
        self.status
            .and_then(|s| weebo_kit_api::status::ready(&s.conditions))
            .is_some_and(|c| c.status == "False" && c.reason == reason.as_str())
    }
}

/// The `StalwartDomain` a CR lives in, once checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDomain {
    pub id: String,
    pub name: String,
}

/// Steps 1 and 2: the allow-list verdict, then the domain.
// RFC 0001 Q23: the RFC's order is the domain, then the policy; the policy
// goes first here, so that a namespace it refuses learns nothing of the
// domains (`DomainNotFound`/`DomainNotReady` answer only allowed requests).
pub async fn admit(
    subject: &Subject<'_>,
    instance: &BoundInstance,
    cluster: &dyn ClusterReader,
    policies: &dyn PolicySource<NamespaceRule>,
) -> Result<ResolvedDomain, Failure> {
    enforce(
        policies,
        Some(instance),
        subject.namespace,
        subject.kind,
        &[subject.domain_ref.to_string()],
        &subject.names(),
    )
    .await
    .map_err(cluster_failure)??;
    let domain_ref = subject.domain_ref;
    let Some(domain) = cluster.domain(domain_ref).await.map_err(cluster_failure)? else {
        return Err(Failure::new(
            ReasonCode::DomainNotFound,
            format!("spec.domainRef: no StalwartDomain {domain_ref:?}"),
        ));
    };
    let not_ready = |why: String| {
        Failure::new(
            ReasonCode::DomainNotReady,
            format!("StalwartDomain {domain_ref:?} {why}"),
        )
    };
    if domain.instance.as_ref().is_some_and(|i| i != instance) {
        return Err(not_ready(format!(
            "lives on {}, not on {instance}",
            domain
                .instance
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default()
        )));
    }
    match (domain.ready, domain.remote_id, domain.name) {
        (true, Some(id), Some(name)) if domain.instance.is_some() => {
            Ok(ResolvedDomain { id, name })
        }
        _ => Err(not_ready("is not Ready yet".into())),
    }
}

/// The unique claim: none of `addresses` may be owned by another CR on the
/// same server.
async fn claimed_elsewhere(
    cluster: &dyn ClusterReader,
    addresses: &[String],
    instance: &BoundInstance,
    me: &str,
) -> Result<(), Failure> {
    let claimants = cluster
        .claimants_of_any(ClaimKind::Address, addresses, instance)
        .await
        .map_err(cluster_failure)?;
    match claimants.into_iter().find(|(_, c)| c != me) {
        Some((address, other)) => Err(Failure::new(
            ReasonCode::RemoteObjectClaimed,
            format!("address {address:?} on this server is already owned by {other}"),
        )),
        None => Ok(()),
    }
}

/// One kind of remote object the namespaced CRs own: its reads and writes,
/// and how it compares.
#[async_trait::async_trait]
pub trait RemoteObject: Send + Sync {
    type Desired: Send + Sync;
    type Read: Send + Sync;
    type Patch: Send + Sync;

    /// Named in messages: `account`, `group`, `mailing list`.
    fn what(&self) -> &'static str;
    async fn get(
        &self,
        gateway: &dyn RemoteGateway,
        id: &str,
    ) -> Result<Option<Self::Read>, GatewayError>;
    /// The address the server answers for, if the object is of this kind
    /// (a `Group` read for a user's id is not the user).
    fn address_of<'r>(&self, read: &'r Self::Read) -> Option<&'r str>;
    async fn create(
        &self,
        gateway: &dyn RemoteGateway,
        desired: &Self::Desired,
    ) -> Result<String, GatewayError>;
    fn diff(&self, desired: &Self::Desired, read: &Self::Read) -> (Self::Patch, Drift);
    fn renames(&self, patch: &Self::Patch) -> bool;
    fn moves_aliases(&self, patch: &Self::Patch) -> bool;
    async fn update(
        &self,
        gateway: &dyn RemoteGateway,
        id: &str,
        patch: &Self::Patch,
    ) -> Result<(), GatewayError>;
    async fn delete(&self, gateway: &dyn RemoteGateway, id: &str) -> Result<bool, GatewayError>;
}

/// An `x:Account` of `kind`, created without any credential.
// RFC 0001 D24: no path sends `credentials` (an OIDC default directory
// refuses a `Password`; App Passwords go through `x:AppPassword`).
pub struct AccountObject {
    pub kind: AccountType,
}

#[async_trait::async_trait]
impl RemoteObject for AccountObject {
    type Desired = DesiredAccount;
    type Read = RemoteAccount;
    type Patch = AccountPatch;

    fn what(&self) -> &'static str {
        match self.kind {
            AccountType::User => "account",
            AccountType::Group => "group",
        }
    }

    async fn get(
        &self,
        gateway: &dyn RemoteGateway,
        id: &str,
    ) -> Result<Option<RemoteAccount>, GatewayError> {
        gateway.get_account(id).await
    }

    fn address_of<'r>(&self, read: &'r RemoteAccount) -> Option<&'r str> {
        (read.kind == self.kind.as_str()).then_some(read.email_address.as_str())
    }

    async fn create(
        &self,
        gateway: &dyn RemoteGateway,
        desired: &DesiredAccount,
    ) -> Result<String, GatewayError> {
        gateway.create_account(desired).await
    }

    fn diff(&self, desired: &DesiredAccount, read: &RemoteAccount) -> (AccountPatch, Drift) {
        account_patch(desired, read)
    }

    fn renames(&self, patch: &AccountPatch) -> bool {
        patch.renames()
    }

    fn moves_aliases(&self, patch: &AccountPatch) -> bool {
        patch.moves_aliases()
    }

    async fn update(
        &self,
        gateway: &dyn RemoteGateway,
        id: &str,
        patch: &AccountPatch,
    ) -> Result<(), GatewayError> {
        gateway.update_account(id, patch).await
    }

    async fn delete(&self, gateway: &dyn RemoteGateway, id: &str) -> Result<bool, GatewayError> {
        gateway.delete_account(id).await
    }
}

/// An `x:MailingList`.
pub struct MailingListObject;

#[async_trait::async_trait]
impl RemoteObject for MailingListObject {
    type Desired = DesiredMailingList;
    type Read = RemoteMailingList;
    type Patch = MailingListPatch;

    fn what(&self) -> &'static str {
        "mailing list"
    }

    async fn get(
        &self,
        gateway: &dyn RemoteGateway,
        id: &str,
    ) -> Result<Option<RemoteMailingList>, GatewayError> {
        gateway.get_mailing_list(id).await
    }

    fn address_of<'r>(&self, read: &'r RemoteMailingList) -> Option<&'r str> {
        Some(read.email_address.as_str())
    }

    async fn create(
        &self,
        gateway: &dyn RemoteGateway,
        desired: &DesiredMailingList,
    ) -> Result<String, GatewayError> {
        gateway.create_mailing_list(desired).await
    }

    fn diff(
        &self,
        desired: &DesiredMailingList,
        read: &RemoteMailingList,
    ) -> (MailingListPatch, Drift) {
        mailing_list_patch(desired, read)
    }

    fn renames(&self, patch: &MailingListPatch) -> bool {
        patch.renames()
    }

    fn moves_aliases(&self, patch: &MailingListPatch) -> bool {
        patch.moves_aliases()
    }

    async fn update(
        &self,
        gateway: &dyn RemoteGateway,
        id: &str,
        patch: &MailingListPatch,
    ) -> Result<(), GatewayError> {
        gateway.update_mailing_list(id, patch).await
    }

    async fn delete(&self, gateway: &dyn RemoteGateway, id: &str) -> Result<bool, GatewayError> {
        gateway.delete_mailing_list(id).await
    }
}

/// What [`sync`] ended on: the object owned, at its address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Synced {
    pub id: String,
    pub address: String,
    pub created: bool,
    /// The fields put back (a spec change applied, or a drift corrected).
    pub drift: Drift,
}

impl Synced {
    /// `Ready: True` with `message`, the write it made recorded.
    pub fn outcome(self, message: impl Into<String>) -> Outcome {
        let outcome = Outcome::synced(Some(self.id), message).at(self.address);
        if self.created {
            outcome.wrote(RemoteWrite::Created)
        } else if self.drift.is_empty() {
            outcome
        } else {
            outcome.corrected(self.drift)
        }
    }

    /// `created`, `synced` or `in sync`: for messages.
    pub fn verb(&self) -> &'static str {
        if self.created {
            "created"
        } else if self.drift.is_empty() {
            "in sync"
        } else {
            "synced"
        }
    }
}

/// The object `subject` recorded, if the server still answers for it with
/// the confirmed address (D19): its id, its address and the object.
pub async fn locate<R: RemoteObject>(
    object: &R,
    subject: &Subject<'_>,
    gateway: &dyn RemoteGateway,
) -> Result<Option<(String, String, R::Read)>, GatewayError> {
    let Some((id, confirmed)) = subject.recorded() else {
        return Ok(None);
    };
    Ok(object.get(gateway, id).await?.and_then(|read| {
        let ours = object
            .address_of(&read)
            .is_some_and(|a| normalize_address(a) == normalize_address(confirmed));
        ours.then(|| (id.to_string(), confirmed.to_string(), read))
    }))
}

/// Steps 3 to 5: the object `subject` owns brought to `desired`, in
/// `domain`, on `instance`.
pub async fn sync<R: RemoteObject>(
    object: &R,
    subject: &Subject<'_>,
    domain: &ResolvedDomain,
    desired: &R::Desired,
    instance: &BoundInstance,
    gateway: &dyn RemoteGateway,
    cluster: &dyn ClusterReader,
) -> Result<Synced, Box<Outcome>> {
    let address = mail::address(&subject.name, &domain.name);
    let addresses = subject.addresses(&domain.name);
    let me = subject.claim_id();
    let what = object.what();

    let Some((id, current, read)) = locate(object, subject, gateway).await.map_err(fail)? else {
        claimed_elsewhere(cluster, &addresses, instance, &me)
            .await
            .map_err(fail)?;
        return match object.create(gateway, desired).await {
            Ok(id) => Ok(Synced {
                id,
                address,
                created: true,
                drift: Drift::default(),
            }),
            Err(GatewayError::AlreadyExists(why)) => Err(fail(Failure::new(
                ReasonCode::StalwartObjectAlreadyExists,
                format!(
                    "{why}: the operator never adopts an existing {what} — link it to this CR \
                     with weebo-stalwart-importer, or choose another name"
                ),
            ))),
            Err(e) => Err(fail(e)),
        };
    };

    let (patch, drift) = object.diff(desired, &read);
    if drift.is_empty() {
        return Ok(Synced {
            id,
            address: current,
            created: false,
            drift,
        });
    }
    let owned = |failure: Failure| Box::new(Outcome::failed(failure).with_id(&id, &current));
    // RFC 0001 Q14: a refused move reports `InvalidSpec`, as a domain's.
    if object.renames(&patch) && !api::ANNOTATIONS.allows_disruptive_update(subject.meta) {
        return Err(owned(Failure::new(
            ReasonCode::InvalidSpec,
            format!(
                "moving {what} {current:?} to {address:?} changes its address: annotate the CR \
                 with {}=\"true\" to apply it",
                api::ANNOTATIONS.key(weebo_kit_api::annotations::ALLOW_DISRUPTIVE_UPDATE)
            ),
        )));
    }
    if object.renames(&patch) || object.moves_aliases(&patch) {
        claimed_elsewhere(cluster, &addresses, instance, &me)
            .await
            .map_err(owned)?;
    }
    match object.update(gateway, &id, &patch).await {
        Ok(()) => Ok(Synced {
            id,
            address,
            created: false,
            drift,
        }),
        Err(GatewayError::AlreadyExists(why)) => Err(owned(Failure::new(
            ReasonCode::StalwartObjectAlreadyExists,
            why,
        ))),
        Err(e) => Err(owned(e.into())),
    }
}

/// The finalizer's cleanup: with `deletionPolicy: Delete`, the object the
/// CR recorded — only if the server still answers for it with the
/// confirmed address (D19: never another's) — is deleted. `Linked`
/// (`objectIsLinked`) is `ObjectIsLinked`: retried, never forced.
pub async fn cleanup<R: RemoteObject>(
    object: &R,
    subject: &Subject<'_>,
    policy: DeletionPolicy,
    gateway: &dyn RemoteGateway,
) -> Result<Option<RemoteWrite>, Failure> {
    if policy == DeletionPolicy::Orphan {
        return Ok(None);
    }
    let Some((id, address, _)) = locate(object, subject, gateway).await? else {
        return Ok(None);
    };
    match object.delete(gateway, &id).await {
        Ok(true) => Ok(Some(RemoteWrite::Deleted)),
        Ok(false) => Ok(None),
        Err(GatewayError::Linked(why)) => Err(Failure::new(
            ReasonCode::ObjectIsLinked,
            format!(
                "{why}: {address:?} is still used by other objects; retried until it is not \
                 (or annotate the CR with {}=\"true\" to leave it in Stalwart)",
                api::ANNOTATIONS.key(weebo_kit_api::annotations::FORCE_ORPHAN)
            ),
        )),
        Err(e) => Err(e.into()),
    }
}
