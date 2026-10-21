//! One `kube::runtime::Controller` per CRD, on the kit's skeleton
//! (triggers, concurrency, requeue, finalizer, Events, metrics). The
//! reconcile bodies delegate to `application::use_cases`.

use std::fmt::Debug;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use api::Status;
use api::namespace_policy::NamespaceRule;
use api::status::Condition;
use application::ports::{
    BoundInstance, ClusterReader, GatewayFactory, InstanceDirectory, PolicySource,
    SecretStoreFactory,
};
use application::use_cases::Outcome;
use domain::Failure;
use domain::error::ReasonCode;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::events::Recorder;
use kube::{Client, Resource};
use serde::Serialize;
use serde::de::DeserializeOwned;
use weebo_kit_runtime::events;
use weebo_kit_runtime::metrics::ReconcileMetrics;
use weebo_kit_runtime::shared::SharedWatches;
use weebo_kit_runtime::status::StatusUpdate;
use weebo_kit_runtime::{Health, WatchScope};

/// Resolves once the process is asked to stop: every controller then stops
/// taking new work, lets its in-flight reconciles finish, and its `run`
/// returns.
pub use weebo_kit_runtime::Shutdown;
/// The kit's controller skeleton: a watch filtered to what reconciling
/// acts on (never the CR's own status patches), bounded concurrency
/// (`WEEBO_RECONCILE_CONCURRENCY`), the result stream drained into the
/// liveness.
pub use weebo_kit_runtime::controller::{controller, drive};

pub mod instance;
pub mod local_instance;
pub mod namespace_policy;
pub mod namespaced;
pub mod stalwart_account;
pub mod stalwart_domain;
pub mod stalwart_group;
pub mod stalwart_mailing_list;
pub mod stalwart_service_account;

/// Field manager of the status patches, meter and Event reporter name.
pub const FIELD_MANAGER: &str = "weebo-stalwart-operator";
pub use api::FINALIZER;
/// Prefix of every metric: `<prefix>_reconcile_total`, `<prefix>_leader`…
pub const METRIC_PREFIX: &str = "weebo_stalwart";

/// Shared across every controller. Concrete adapters are built and
/// injected once, in `operator::main` (tests inject fakes).
pub struct Ctx {
    pub client: Client,
    pub gateways: Arc<dyn GatewayFactory>,
    /// The secret store of an instance, for the kinds that emit a secret
    /// (`secretTargets`).
    pub secrets: Arc<dyn SecretStoreFactory>,
    /// The other CRs a decision depends on (the unique claims).
    pub cluster: Arc<dyn ClusterReader>,
    /// The `StalwartNamespacePolicy` rules, re-checked before any Stalwart
    /// call.
    pub policies: Arc<dyn PolicySource<NamespaceRule>>,
    /// Which instance a CR lives on (the kit's `Instances`, on the watch
    /// scope).
    pub instances: Arc<dyn InstanceDirectory>,
    /// One recorder for the whole process: the kit folds repeated Events
    /// into a series only within a recorder.
    pub recorder: Recorder,
    pub shutdown: Shutdown,
    /// Liveness: controllers report their watch errors here.
    pub health: Arc<Health>,
    /// What the controllers watch (`WEEBO_WATCH_NAMESPACE`,
    /// `WEEBO_WATCH_LABEL_SELECTOR`): every watch goes through it.
    pub scope: WatchScope,
    /// The binary's shared watches ([`spawn_watches`]): one per kind for
    /// every controller and every store read (`SharedWatches::default()`:
    /// each controller watches on its own).
    pub watches: SharedWatches,
}

/// One watch per kind, on `scope`, for every controller, the instance
/// stores and the claim and policy reads (the cluster-scoped kinds only
/// when the scope watches them). Spawned before the lease is campaigned
/// for: a standby keeps them warm.
pub fn spawn_watches(client: &Client, scope: &WatchScope, health: &Arc<Health>) -> SharedWatches {
    let mut w = SharedWatches::default();
    let (c, s, h) = (client, scope, health);
    if scope.cluster_kinds() {
        w.spawn(
            s.api::<api::Instance>(c.clone()),
            s,
            h,
            "StalwartInstance watch",
        );
        w.spawn(
            s.api::<api::Domain>(c.clone()),
            s,
            h,
            "StalwartDomain watch",
        );
        w.spawn(
            s.api::<api::NamespacePolicy>(c.clone()),
            s,
            h,
            "StalwartNamespacePolicy watch",
        );
    }
    w.spawn(
        s.api::<api::LocalInstance>(c.clone()),
        s,
        h,
        "StalwartLocalInstance watch",
    );
    w.spawn(
        s.api::<api::ServiceAccount>(c.clone()),
        s,
        h,
        "StalwartServiceAccount watch",
    );
    w.spawn(
        s.api::<api::Account>(c.clone()),
        s,
        h,
        "StalwartAccount watch",
    );
    w.spawn(s.api::<api::Group>(c.clone()), s, h, "StalwartGroup watch");
    w.spawn(
        s.api::<api::MailingList>(c.clone()),
        s,
        h,
        "StalwartMailingList watch",
    );
    w
}

/// What stopped a reconcile before (or instead of) its status.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    /// Anything the finalizer helper reports: the reconcile's own error
    /// (`ApplyFailed`/`CleanupFailed`) or adding/removing the finalizer.
    #[error("{0}")]
    Finalizer(Box<kube::runtime::finalizer::Error<Error>>),
    /// A cleanup that couldn't delete the remote object: the finalizer
    /// stays until it can (or the CR is force-orphaned).
    #[error("{0}")]
    Cleanup(Failure),
}

impl Error {
    /// The reason code of the Event announcing this error, and whether it
    /// happened reconciling or cleaning up (the Event's `action`).
    pub fn reason(&self) -> (ReasonCode, &'static str) {
        use kube::runtime::finalizer::Error as Finalizer;
        match self {
            Error::Kube(_) => (ReasonCode::KubernetesApiError, events::RECONCILE),
            Error::Cleanup(failure) => (failure.reason, events::CLEANUP),
            Error::Finalizer(err) => match err.as_ref() {
                Finalizer::ApplyFailed(inner) => inner.reason(),
                Finalizer::CleanupFailed(inner) => (inner.reason().0, events::CLEANUP),
                _ => (ReasonCode::KubernetesApiError, events::RECONCILE),
            },
        }
    }
}

/// Every reconcile that errors out is announced by a `Warning` Event on
/// its CR, then retried in ~30s (the kit's).
pub fn error_policy<K>(obj: Arc<K>, err: &Error, ctx: Arc<Ctx>) -> Action
where
    K: Resource<DynamicType = ()>,
{
    let (reason, action) = err.reason();
    weebo_kit_runtime::controller::retry_after_error(
        &ctx.recorder,
        obj.object_ref(&()),
        reason,
        action,
        err,
    )
}

/// Steady-state drift check after a success, a quick retry after a
/// failure (both jittered — the kit's).
pub fn requeue_after<K: Resource>(obj: &K, outcome: &Outcome) -> Action {
    weebo_kit_runtime::controller::requeue_after(obj, outcome.ready.is_ok(), None)
}

/// The kit's `ReconcileMetrics`. A no-op until the telemetry installs a
/// real `MeterProvider`.
pub fn metrics() -> &'static ReconcileMetrics {
    static METRICS: OnceLock<ReconcileMetrics> = OnceLock::new();
    METRICS.get_or_init(|| ReconcileMetrics::new(FIELD_MANAGER, METRIC_PREFIX))
}

/// `<prefix>_reconcile_total` / `_duration_seconds`, and
/// `<prefix>_remote_writes_total` when the reconcile wrote to Stalwart.
pub fn record_reconcile(kind: &'static str, started: Instant, outcome: &Outcome) {
    metrics().record(kind, outcome.reason(), started.elapsed());
    if let Some(write) = outcome.write {
        metrics().record_write(kind, write);
    }
}

/// The `status` of every CRD here is a [`Status`].
pub trait HasStatus {
    fn status(&self) -> Option<&Status>;

    fn remote_id(&self) -> Option<&str> {
        self.status()?.remote_id.as_deref()
    }

    /// The instance recorded at the last resolution.
    fn bound_instance(&self) -> Option<&BoundInstance> {
        self.status()?.instance.as_ref()
    }
}

impl HasStatus for api::Instance {
    fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }
}

impl HasStatus for api::LocalInstance {
    fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }
}

impl HasStatus for api::Domain {
    fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }
}

impl HasStatus for api::NamespacePolicy {
    fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }
}

impl HasStatus for api::ServiceAccount {
    fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }
}

impl HasStatus for api::Account {
    fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }
}

impl HasStatus for api::Group {
    fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }
}

impl HasStatus for api::MailingList {
    fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }
}

/// Publishes `outcome` on `obj` (read fresh from the API server: its
/// conditions are the previous ones). The kit's: one merge patch
/// (conditions, `observedGeneration` on success, `remoteId`), retried while
/// the apiserver is unavailable, then a `Warning` on every failed reconcile
/// and a `Normal` for every condition change. One more Event when the
/// remote object was just created, or put back after a drift (naming the
/// fields).
pub async fn publish<K>(
    api: &Api<K>,
    recorder: &Recorder,
    obj: &K,
    outcome: &Outcome,
) -> Result<(), kube::Error>
where
    K: Resource<DynamicType = ()> + HasStatus + Clone + Debug + DeserializeOwned + Serialize,
{
    let previous: &[Condition] = obj
        .status()
        .map(|s| s.conditions.as_slice())
        .unwrap_or_default();
    let mut fields = serde_json::Map::new();
    if let Some(id) = &outcome.remote_id {
        fields.insert("remoteId".into(), id.clone().into());
    }
    if let Some(address) = &outcome.address {
        fields.insert("address".into(), address.clone().into());
    }
    if let Some(nonce) = &outcome.last_rotation {
        fields.insert("lastRotation".into(), nonce.clone().into());
    }
    if let Some(instance) = &outcome.instance {
        #[expect(
            clippy::expect_used,
            reason = "a BoundInstance is strings and an enum: serializing it to a Value cannot fail"
        )]
        let instance = serde_json::to_value(instance).expect("a BoundInstance serializes");
        fields.insert("instance".into(), instance);
    }
    weebo_kit_runtime::status::publish(
        api,
        recorder,
        FIELD_MANAGER,
        obj,
        previous,
        StatusUpdate {
            ready: &outcome.ready,
            advisories: &[],
            fields,
        },
    )
    .await?;
    if let Some(id) = &outcome.remote_id
        && obj.remote_id().is_none()
    {
        events::announce_change(
            recorder,
            &obj.object_ref(&()),
            ReasonCode::Created,
            events::RECONCILE,
            &format!("created in Stalwart as {id}"),
        )
        .await;
    }
    // A spec change being applied is not a drift: only a remote object
    // that moved on its own is announced.
    let spec_changed = obj.meta().generation != obj.status().and_then(|s| s.observed_generation);
    if !spec_changed {
        events::announce_drift(
            recorder,
            &obj.object_ref(&()),
            ReasonCode::DriftCorrected,
            &outcome.drift,
        )
        .await;
    }
    Ok(())
}

/// The importer is still seeding the CR's status
/// (`stalwart.weebo.io/import-pending`): the controller leaves it alone —
/// it must not create the object the CR is about to be linked to.
pub fn import_pending<K: Resource<DynamicType = ()>>(obj: &K) -> bool {
    api::ANNOTATIONS
        .get(obj.meta(), weebo_kit_api::annotations::IMPORT_PENDING)
        .is_some()
}

/// A finalizer's cleanup — unless the CR carries
/// `stalwart.weebo.io/force-orphan: "true"`, the way out for
/// a CR whose cleanup can't succeed any more (its instance gone) — then a
/// `Released` Event (the kit's).
pub async fn finalize<K>(
    obj: &K,
    ctx: &Ctx,
    cleanup: impl Future<Output = Result<(), Error>>,
) -> Result<Action, Error>
where
    K: Resource<DynamicType = ()>,
{
    weebo_kit_runtime::controller::finalize(
        obj,
        &ctx.recorder,
        &api::ANNOTATIONS,
        ReasonCode::Released,
        cleanup,
    )
    .await
}

#[cfg(test)]
mod tests {
    use kube::runtime::finalizer::Error as Finalizer;

    use super::*;

    #[test]
    fn errors_map_to_a_reason_and_an_action() {
        let unreachable = || Error::Cleanup(Failure::new(ReasonCode::InstanceUnreachable, "x"));
        assert_eq!(
            unreachable().reason(),
            (ReasonCode::InstanceUnreachable, events::CLEANUP)
        );
        assert_eq!(
            Error::Finalizer(Box::new(Finalizer::CleanupFailed(unreachable()))).reason(),
            (ReasonCode::InstanceUnreachable, events::CLEANUP)
        );
        assert_eq!(
            Error::Finalizer(Box::new(Finalizer::UnnamedObject)).reason(),
            (ReasonCode::KubernetesApiError, events::RECONCILE)
        );
    }
}
