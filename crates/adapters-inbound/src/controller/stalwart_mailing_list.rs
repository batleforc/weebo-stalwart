//! `StalwartMailingList` (namespaced). Its `accountRef` recipients are the
//! `StalwartAccount`s of the namespace; one without an address yet is
//! retried (`AccountNotFound`).

use std::sync::Arc;

use api::MailingList;
use api::common::{DeletionPolicy, InstanceRef};
use application::ports::{BoundInstance, RemoteGateway};
use application::use_cases::Outcome;
use application::use_cases::accounts::Ports;
use application::use_cases::reconcile_mailing_list::{
    KIND, cleanup_mailing_list, reconcile_mailing_list,
};
use domain::{Failure, RemoteWrite};
use kube::Client;

use super::Ctx;
use super::namespaced::{self, NamespacedKind};

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    namespaced::run::<MailingList>(client, ctx).await;
}

#[async_trait::async_trait]
impl NamespacedKind for MailingList {
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
        reconcile_mailing_list(self, bound, ports).await
    }

    async fn cleanup(
        &self,
        _bound: &BoundInstance,
        gateway: &dyn RemoteGateway,
        _ctx: &Ctx,
    ) -> Result<Option<RemoteWrite>, Failure> {
        cleanup_mailing_list(self, gateway).await
    }
}
