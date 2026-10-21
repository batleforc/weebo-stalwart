//! The controller of every namespaced kind (`StalwartServiceAccount`,
//! `StalwartAccount`, `StalwartGroup`, `StalwartMailingList`), on the
//! `StalwartDomain` one's model: the finalizer, `import-pending` honoured,
//! the CR re-read before reconciling, its instance resolved in its
//! namespace and kept to what its status recorded, the use-case, the
//! status, the Events, the metrics. What varies is the [`NamespacedKind`].
//!
//! Deleting a CR follows its `deletionPolicy`: `Orphan` releases it at once;
//! `Delete` deletes the remote object it recorded (through the instance it
//! is bound to) — a deletion Stalwart refuses (`ObjectIsLinked`, a group
//! with members) keeps the finalizer and is retried, never forced; the
//! `force-orphan` annotation releases it without cleanup.

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Instant;

use api::common::{DeletionPolicy, InstanceRef};
use application::ports::{BoundInstance, InstanceError, RemoteGateway};
use application::use_cases::{Outcome, instance_failure};
use domain::{Failure, RemoteWrite};
use kube::api::Api;
use kube::core::NamespaceResourceScope;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::{Client, Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{Ctx, Error, FINALIZER, HasStatus, error_policy};

/// One namespaced kind, as its controller drives it.
#[async_trait::async_trait]
pub trait NamespacedKind:
    Resource<DynamicType = (), Scope = NamespaceResourceScope>
    + HasStatus
    + Clone
    + Debug
    + Serialize
    + DeserializeOwned
    + Send
    + Sync
    + 'static
{
    /// The kind, as metrics and logs name it.
    const KIND: &'static str;

    fn instance_ref(&self) -> Option<&InstanceRef>;
    fn deletion_policy(&self) -> DeletionPolicy;

    /// The use-case, on the instance the CR is bound to.
    async fn reconcile(
        &self,
        bound: &BoundInstance,
        gateway: &dyn RemoteGateway,
        ctx: &Ctx,
    ) -> Outcome;

    /// The finalizer's cleanup (`deletionPolicy: Delete` only).
    async fn cleanup(
        &self,
        bound: &BoundInstance,
        gateway: &dyn RemoteGateway,
        ctx: &Ctx,
    ) -> Result<Option<RemoteWrite>, Failure>;

    /// After every reconcile, its outcome published (the account gauge).
    fn reconciled(&self, _outcome: &Outcome) {}

    /// Once released by the finalizer.
    fn released(&self) {}
}

pub async fn run<K: NamespacedKind>(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = ctx
        .watches
        .controller(ctx.scope.api::<K>(client), &ctx.scope)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile::<K>, error_policy, ctx);
    super::drive(K::KIND, health, results).await;
}

async fn reconcile<K: NamespacedKind>(obj: Arc<K>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let namespace = obj.namespace().unwrap_or_default();
    let api: Api<K> = Api::namespaced(ctx.client.clone(), &namespace);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(cr) => apply(&api, &cr, &ctx).await,
            FinalizerEvent::Cleanup(cr) => {
                let action = super::finalize(cr.as_ref(), &ctx, cleanup(cr.as_ref(), &ctx)).await?;
                cr.released();
                Ok(action)
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

async fn apply<K: NamespacedKind>(api: &Api<K>, cr: &K, ctx: &Ctx) -> Result<Action, Error> {
    if super::import_pending(cr) {
        return Ok(Action::await_change());
    }
    // Re-read from the API server rather than trusted from the watch
    // cache: the status patch of the previous reconcile may not have
    // reached it yet, and a stale `remoteId` would recreate the object.
    let current = api.get(&cr.name_any()).await?;
    let started = Instant::now();
    // A refused resolution leaves `status.instance` as it was.
    let outcome = match resolve(&current, ctx).await {
        Err(e) => Outcome::failed(instance_failure(e)),
        Ok(bound) => match ctx.gateways.gateway_for(&bound).await {
            Ok(gateway) => current.reconcile(&bound, gateway.as_ref(), ctx).await,
            Err(e) => Outcome::failed(e),
        }
        .on(bound),
    };
    super::record_reconcile(K::KIND, started, &outcome);
    super::publish(api, &ctx.recorder, &current, &outcome).await?;
    current.reconciled(&outcome);
    Ok(super::requeue_after(cr, &outcome))
}

async fn cleanup<K: NamespacedKind>(cr: &K, ctx: &Ctx) -> Result<(), Error> {
    if cr.deletion_policy() == DeletionPolicy::Orphan {
        return Ok(());
    }
    // Never resolved, or nothing created: nothing to delete.
    let (Some(bound), Some(_)) = (cr.bound_instance(), cr.remote_id()) else {
        return Ok(());
    };
    let gateway = ctx
        .gateways
        .gateway_for(bound)
        .await
        .map_err(|e| Error::Cleanup(e.into()))?;
    if let Some(write) = cr
        .cleanup(bound, gateway.as_ref(), ctx)
        .await
        .map_err(Error::Cleanup)?
    {
        super::metrics().record_write(K::KIND, write);
    }
    Ok(())
}

/// The instance `cr` lives on: its `instanceRef` resolved in its
/// namespace (the kit's rules), and kept to what its status recorded.
async fn resolve<K: NamespacedKind>(cr: &K, ctx: &Ctx) -> Result<BoundInstance, InstanceError> {
    ctx.instances
        .resolve(
            cr.namespace().as_deref(),
            cr.instance_ref(),
            cr.bound_instance(),
        )
        .await
}
