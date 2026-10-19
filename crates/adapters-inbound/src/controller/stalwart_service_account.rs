//! `StalwartServiceAccount` (namespaced): the account and its App Password,
//! written to the CR's `secretTargets` through its instance's secret
//! store. `deletionPolicy: Delete` (the default) deletes both.

use std::sync::Arc;

use api::ServiceAccount;
use api::common::{DeletionPolicy, InstanceRef};
use application::ports::{BoundInstance, RemoteGateway};
use application::use_cases::Outcome;
use application::use_cases::accounts::Ports;
use application::use_cases::reconcile_service_account::{
    KIND, cleanup_service_account, reconcile_service_account,
};
use domain::error::ReasonCode;
use domain::{Failure, RemoteWrite};
use kube::Client;

use super::Ctx;
use super::namespaced::{self, NamespacedKind};

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    namespaced::run::<ServiceAccount>(client, ctx).await;
}

fn store_failure(e: application::ports::SecretStoreError) -> Failure {
    Failure::new(ReasonCode::SecretTargetFailed, e.to_string())
}

#[async_trait::async_trait]
impl NamespacedKind for ServiceAccount {
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
        let secrets = match ctx.secrets.store_for(bound).await {
            Ok(store) => store,
            Err(e) => return Outcome::failed(store_failure(e)),
        };
        let ports = Ports {
            gateway,
            cluster: ctx.cluster.as_ref(),
            policies: ctx.policies.as_ref(),
        };
        reconcile_service_account(self, bound, ports, secrets.as_ref()).await
    }

    async fn cleanup(
        &self,
        bound: &BoundInstance,
        gateway: &dyn RemoteGateway,
        ctx: &Ctx,
    ) -> Result<Option<RemoteWrite>, Failure> {
        let secrets = ctx.secrets.store_for(bound).await.map_err(store_failure)?;
        cleanup_service_account(self, gateway, secrets.as_ref()).await
    }
}
