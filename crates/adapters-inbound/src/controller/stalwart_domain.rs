//! `StalwartDomain` (cluster-scoped): the domain is compared with the spec
//! on every reconcile and written only when it differs. Never deleted
//! remotely: the finalizer only releases the CR (`deletionPolicy: Orphan`).

use std::sync::Arc;
use std::time::Instant;

use api::Domain;
use application::ports::BoundInstance;
use application::use_cases::reconcile_domain::reconcile_domain;
use application::use_cases::{Outcome, instance_failure};
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::{Client, ResourceExt};

use super::{Ctx, Error, FINALIZER, HasStatus, error_policy};

const KIND: &str = "StalwartDomain";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = ctx
        .watches
        .controller(ctx.scope.api::<Domain>(client), &ctx.scope)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<Domain>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let api: Api<Domain> = Api::all(ctx.client.clone());
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(domain) => apply(&api, &domain, &ctx).await,
            // `Orphan` only: nothing to clean up in Stalwart.
            FinalizerEvent::Cleanup(domain) => {
                super::finalize(domain.as_ref(), &ctx, async { Ok(()) }).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

async fn apply(api: &Api<Domain>, domain: &Domain, ctx: &Ctx) -> Result<Action, Error> {
    if super::import_pending(domain) {
        return Ok(Action::await_change());
    }
    // Re-read from the API server rather than trusted from the watch
    // cache: the status patch of the previous reconcile may not have
    // reached it yet, and a stale `remoteId` would recreate the domain.
    let current = api.get(&domain.name_any()).await?;
    let started = Instant::now();
    // A refused resolution leaves `status.instance` as it was.
    let outcome = match resolve(&current, ctx).await {
        Err(e) => Outcome::failed(instance_failure(e)),
        Ok(bound) => match ctx.gateways.gateway_for(&bound).await {
            Ok(gateway) => {
                reconcile_domain(&current, &bound, gateway.as_ref(), ctx.cluster.as_ref()).await
            }
            Err(e) => Outcome::failed(e),
        }
        .on(bound),
    };
    super::record_reconcile(KIND, started, &outcome);
    super::publish(api, &ctx.recorder, &current, &outcome).await?;
    Ok(super::requeue_after(domain, &outcome))
}

/// The instance `domain` lives on: its `instanceRef` resolved (the kit's
/// rules), and kept to what its status recorded.
async fn resolve(
    domain: &Domain,
    ctx: &Ctx,
) -> Result<BoundInstance, application::ports::InstanceError> {
    ctx.instances
        .resolve(
            None,
            domain.spec.instance_ref.as_ref(),
            domain.bound_instance(),
        )
        .await
}
