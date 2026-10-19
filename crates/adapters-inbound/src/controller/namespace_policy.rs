//! `StalwartNamespacePolicy` (cluster-scoped): no remote object, `Ready`
//! once its rules are usable. Its rules are read live by the webhook and
//! the reconcilers (`PolicySource`), not through this controller.

use std::sync::Arc;
use std::time::Instant;

use api::NamespacePolicy;
use application::use_cases::reconcile_namespace_policy::reconcile_namespace_policy;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::{Client, Resource};

use super::{Ctx, Error, error_policy};

const KIND: &str = "StalwartNamespacePolicy";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = ctx
        .watches
        .controller(ctx.scope.api::<NamespacePolicy>(client), &ctx.scope)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<NamespacePolicy>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if obj.meta().deletion_timestamp.is_some() {
        return Ok(Action::await_change());
    }
    let api: Api<NamespacePolicy> = Api::all(ctx.client.clone());
    let started = Instant::now();
    let outcome = reconcile_namespace_policy(&obj.spec);
    super::record_reconcile(KIND, started, &outcome);
    super::publish(&api, &ctx.recorder, obj.as_ref(), &outcome).await?;
    Ok(super::requeue_after(&outcome))
}
