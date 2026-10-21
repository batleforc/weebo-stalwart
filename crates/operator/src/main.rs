//! The `weebo-stalwart-operator` binary: wires the adapters into the
//! controllers, then runs them on the kit's runtime (telemetry, health,
//! graceful shutdown, leader election, HTTPS probes).

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_inbound::webhook;
use adapters_outbound::cluster_reader::ClaimStores;
use adapters_outbound::{
    JmapGatewayFactory, KubeClusterReader, OperatorInstances, StalwartSecretStoreFactory,
};
use api::{
    Account, Domain, Group, Instance, LocalInstance, MailingList, NamespacePolicy, ServiceAccount,
};
use kube::Client;
use kube::api::ApiResource;
use kube::runtime::events::{Recorder, Reporter};
use weebo_kit_runtime::shared::{LISTED_TIMEOUT, SharedWatch};
use weebo_kit_runtime::{Health, WatchScope, leader, telemetry, webhook_server};

/// Default `LEASE_NAME`. Keep it across releases: old and new pods of a
/// rollout must compete for the same lease.
const DEFAULT_LEASE_NAME: &str = "weebo-stalwart-operator-leader";

/// The kit's runtime: `WEEBO_WORKER_THREADS` workers (4 by default), not
/// tokio's one per core (`weebo_kit_runtime::runtime`).
fn main() -> anyhow::Result<()> {
    weebo_kit_runtime::runtime::build()?.block_on(operator())
}

async fn operator() -> anyhow::Result<()> {
    let telemetry = telemetry::init(controller::FIELD_MANAGER)?;
    let result = match std::env::args().nth(1).as_deref() {
        // What the image's smoke run calls: no cluster needed.
        Some("--version") => {
            println!(
                "{} {}",
                controller::FIELD_MANAGER,
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Some("migrate-instance-ref") => migrate_instance_ref().await,
        Some(other) => Err(anyhow::anyhow!("unknown command {other:?}")),
        None => run(&telemetry).await,
    };
    if let Err(err) = &result {
        tracing::error!(error = %err, "operator failed");
    }
    telemetry.shutdown();
    result
}

/// `migrate-instance-ref [--dry-run]`: rewrites the CRs written when
/// `spec.instanceRef` was a bare name (`main` → `{name: main}`). Offline:
/// operator stopped, new CRDs applied, then this, then the operator.
async fn migrate_instance_ref() -> anyhow::Result<()> {
    let dry_run = std::env::args().any(|a| a == "--dry-run");
    install_crypto_provider();
    let client = Client::try_default().await?;
    let kinds = [
        ApiResource::erase::<Domain>(&()),
        ApiResource::erase::<ServiceAccount>(&()),
        ApiResource::erase::<Account>(&()),
        ApiResource::erase::<Group>(&()),
        ApiResource::erase::<MailingList>(&()),
    ];
    let migration = weebo_kit_adapters::migrate::migrate_instance_refs(
        &client,
        &kinds,
        controller::FIELD_MANAGER,
        dry_run,
    )
    .await
    .map_err(|e| anyhow::anyhow!(e))?;
    let verb = if dry_run { "to migrate" } else { "migrated" };
    for id in &migration.migrated {
        println!("{verb}: {id}");
    }
    println!(
        "{} {verb}, {} unchanged",
        migration.migrated.len(),
        migration.unchanged
    );
    Ok(())
}

/// `ring` and `aws-lc-rs` are both linked transitively (`kube`'s rustls
/// vs. reqwest's); rustls refuses to pick a default provider when more
/// than one is present. `Err`: one is installed already, which is as good.
fn install_crypto_provider() {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a rustls crypto provider was already installed");
    }
}

async fn run(telemetry: &telemetry::Telemetry) -> anyhow::Result<()> {
    install_crypto_provider();

    telemetry.serve_metrics().await?;
    // `<prefix>_leader`: 1 on the replica holding the lease.
    leader::register_leader_gauge(controller::FIELD_MANAGER, controller::METRIC_PREFIX);

    let client = Client::try_default().await?;
    // The whole cluster, or one namespace (with or without the
    // cluster-scoped kinds) and/or a label selector (the chart's
    // `watch.*`): an invalid value stops the start here, as does a kind
    // the scope can't watch.
    let scope = WatchScope::from_env()?;
    scope.ensure::<LocalInstance>()?;
    scope.ensure::<ServiceAccount>()?;
    scope.ensure::<Account>()?;
    scope.ensure::<Group>()?;
    scope.ensure::<MailingList>()?;
    if scope.cluster_kinds() {
        scope.ensure::<Instance>()?;
        scope.ensure::<Domain>()?;
        scope.ensure::<NamespacePolicy>()?;
    }
    tracing::info!(
        namespace = ?scope.watched_namespace(),
        selector = ?scope.selector(),
        cluster_kinds = scope.cluster_kinds(),
        "watch scope"
    );

    // The binary is PID 1 in its container: without a handler, SIGTERM
    // would be ignored and every rollout would wait for the SIGKILL.
    let shutdown = Shutdown::on_termination()?;
    let health = Arc::new(Health::default());

    // One watch per kind, shared by every controller and by the instance,
    // claim and policy reads (every resolution reads the instances, every
    // creation the claims: from memory, not a LIST per reconcile). Started
    // before campaigning for the lease: a standby keeps them warm, and the
    // controllers start from stores that already listed.
    let watches = controller::spawn_watches(&client, &scope, &health);
    let cluster_store = watches.get::<Instance>().map(SharedWatch::store);
    let local_store = watches.get::<LocalInstance>().map(SharedWatch::store);
    let instances = Arc::new(
        OperatorInstances::new(client.clone())
            .with_scope(
                scope.watched_namespace().map(String::from),
                scope.selector().cloned(),
                scope.cluster_kinds(),
            )
            .with_stores(cluster_store, local_store),
    );

    // The claims (every CR of the four namespaced kinds, the instances'
    // servers and the domains, read on each creation) and the policies
    // (read on every reconcile) come from the same stores: from the API, a
    // burst of N creations listed N² objects.
    let claim_stores = ClaimStores {
        policies: watches.get::<NamespacePolicy>().map(SharedWatch::store),
        service_accounts: watches.get::<ServiceAccount>().map(SharedWatch::store),
        accounts: watches.get::<Account>().map(SharedWatch::store),
        groups: watches.get::<Group>().map(SharedWatch::store),
        mailing_lists: watches.get::<MailingList>().map(SharedWatch::store),
        instances: watches.get::<Instance>().map(SharedWatch::store),
        local_instances: watches.get::<LocalInstance>().map(SharedWatch::store),
        domains: watches.get::<Domain>().map(SharedWatch::store),
    };
    let cluster = Arc::new(
        KubeClusterReader::new(client.clone())
            .with_scope(
                scope.watched_namespace().map(String::from),
                scope.selector().cloned(),
                scope.cluster_kinds(),
            )
            .with_stores(claim_stores),
    );

    let holder_id = std::env::var("HOSTNAME").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(JmapGatewayFactory::new(client.clone(), instances.clone())),
        secrets: Arc::new(StalwartSecretStoreFactory::new(
            client.clone(),
            instances.clone(),
        )),
        cluster: cluster.clone(),
        policies: cluster.clone(),
        instances: instances.clone(),
        recorder: Recorder::new(
            client.clone(),
            Reporter {
                controller: controller::FIELD_MANAGER.into(),
                instance: Some(holder_id.clone()),
            },
        ),
        shutdown: shutdown.clone(),
        health: health.clone(),
        scope: scope.clone(),
        watches,
    });

    // The HTTPS server (probes, the admission webhook, the scope guard) runs on every replica, before and regardless of leadership: a
    // standby must stay ready, and a leader-only webhook would turn every
    // failover into an outage. On shutdown it keeps answering while
    // endpoints drain.
    let server = webhook_server::spawn(
        webhook::router(
            webhook::WebhookState {
                policies: cluster.clone(),
                instances: Some(instances),
                cluster: Some(cluster),
            },
            health.clone(),
            scope,
        ),
        health,
        shutdown.clone(),
    )
    .await?;

    // The controllers, in contrast, run on one replica at a time: two
    // active reconcilers could both create the same remote object. The
    // replica campaigns once its shared watches listed (their LISTs done
    // before the lease, not in the leader's first minute), or after
    // LISTED_TIMEOUT: a watch that can't list is reported by /livez, not
    // waited for.
    let campaign = async {
        ctx.watches.wait_listed(LISTED_TIMEOUT).await;
        leader::acquire_leadership(&client, holder_id, DEFAULT_LEASE_NAME).await
    };
    let leadership = tokio::select! {
        leadership = campaign => leadership,
        () = shutdown.wait() => {
            server.stopped().await;
            return Ok(());
        }
    };

    tracing::info!("starting controllers");
    // The cluster-scoped kinds, only when the scope watches them.
    let cluster_kinds = async {
        if ctx.scope.cluster_kinds() {
            tokio::join!(
                controller::instance::run(client.clone(), ctx.clone()),
                controller::stalwart_domain::run(client.clone(), ctx.clone()),
                controller::namespace_policy::run(client.clone(), ctx.clone()),
            );
        }
    };
    tokio::join!(
        cluster_kinds,
        controller::local_instance::run(client.clone(), ctx.clone()),
        controller::stalwart_service_account::run(client.clone(), ctx.clone()),
        controller::stalwart_account::run(client.clone(), ctx.clone()),
        controller::stalwart_group::run(client.clone(), ctx.clone()),
        controller::stalwart_mailing_list::run(client.clone(), ctx.clone()),
    );
    // Every controller returns once the shutdown signal arrived and its
    // in-flight reconciles finished: hand the lease over right away
    // instead of making the next leader wait out the TTL.
    leadership.release().await;
    // Bounded: the drain started with the signal, long before.
    if tokio::time::timeout(Duration::from_secs(30), server.stopped())
        .await
        .is_err()
    {
        tracing::warn!("the HTTP server did not stop within 30s; exiting anyway");
    }
    Ok(())
}
