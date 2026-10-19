//! `StalwartGroup` (namespaced). `deletionPolicy: Orphan` by default; a
//! `Delete` Stalwart refuses while accounts are members is retried.

use std::sync::Arc;

use api::Group;
use api::common::{DeletionPolicy, InstanceRef};
use application::ports::{BoundInstance, RemoteGateway};
use application::use_cases::Outcome;
use application::use_cases::accounts::Ports;
use application::use_cases::reconcile_group::{KIND, cleanup_group, reconcile_group};
use domain::{Failure, RemoteWrite};
use kube::Client;

use super::Ctx;
use super::namespaced::{self, NamespacedKind};

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    namespaced::run::<Group>(client, ctx).await;
}

#[async_trait::async_trait]
impl NamespacedKind for Group {
    const KIND: &'static str = KIND;

    fn instance_ref(&self) -> Option<&InstanceRef> {
        self.spec.instance_ref.as_ref()
    }

    fn deletion_policy(&self) -> DeletionPolicy {
        self.spec.deletion_policy
    }

    async fn reconcile(
        &self,
        bound: &BoundInstance,
        gateway: &dyn RemoteGateway,
        ctx: &Ctx,
    ) -> Outcome {
        let ports = Ports {
            gateway,
            cluster: ctx.cluster.as_ref(),
            policies: ctx.policies.as_ref(),
        };
        reconcile_group(self, bound, ports).await
    }

    async fn cleanup(
        &self,
        _bound: &BoundInstance,
        gateway: &dyn RemoteGateway,
        _ctx: &Ctx,
    ) -> Result<Option<RemoteWrite>, Failure> {
        cleanup_group(self, gateway).await
    }
}
