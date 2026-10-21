//! The HTTPS router the kit's `webhook_server` serves on every replica
//! (`WEBHOOK_PORT`, default 8443): the probes — `/readyz`, `/livez`,
//! `/healthz` —, `POST /validate` (the kit's admission endpoint, deciding
//! through [`WebhookState`]) and `/scope`, the kit's `ScopeGuard`.
//!
//! `/validate` runs the reconcilers' own checks
//! (`application::use_cases::admission`), so a refused CR is refused with
//! the same reason code either side: a `StalwartDomain`'s spec rules
//! (`deletionPolicy: Orphan` only, D18; names and aliases), and — for the
//! namespaced account kinds bound to a `StalwartInstance` — the
//! `StalwartNamespacePolicy` allow-list (dimensions `domains`, `names`).
//! Anything it doesn't understand fails closed. Served on every replica,
//! not only the leader: with `failurePolicy: Fail`, a leader-only webhook
//! would turn every failover into an outage of these kinds.
//!
//! For the namespaced kinds, it also checks what the reconcilers check:
//! names and aliases are local-parts (the aliases stay in the domain of
//! `domainRef`), a quota is a quantity, a recipient an address; and for a
//! `StalwartServiceAccount`, its Vault targets — named `smtp`, without
//! `path`, the implicit target only on a `kubernetes` default backend (D15)
//! — and the instance's Vault path rules (`check_vault_targets`). The
//! unique claim on an address is the reconcile's (D16).

use std::sync::Arc;

use api::common::{InstanceRef, SecretTarget};
use api::namespace_policy::NamespaceRule;
use api::{Account, Group, MailingList, ServiceAccount, Status};
use application::ports::{BoundInstance, ClusterReader, InstanceDirectory, PolicySource};
use application::use_cases::admission::{
    check_account, check_domain, check_group, check_mailing_list, check_service_account,
    check_smtp_targets, enforce,
};
use axum::Router;
use domain::Failure;
use domain::allow_list::Kind;
use domain::error::ReasonCode;
use kube::core::DynamicObject;
use weebo_kit_runtime::admission::{
    Admission, Denial, ScopeGuard, VaultPaths, check_vault_targets, scope_router, typed,
};
use weebo_kit_runtime::{Health, WatchScope};

use crate::controller::{FIELD_MANAGER, FINALIZER, METRIC_PREFIX};

#[derive(Clone)]
pub struct WebhookState {
    /// The `StalwartNamespacePolicy` rules of the namespaced kinds.
    pub policies: Arc<dyn PolicySource<NamespaceRule>>,
    /// Resolves the reviewed CR's instance; `None`, or an instance that
    /// can't be resolved: the CR is governed by the policies (the
    /// reconcile reports why it can't be resolved).
    pub instances: Option<Arc<dyn InstanceDirectory>>,
    /// The resolved instance's settings (default backend, Vault paths);
    /// `None`: only the reconcilers check them.
    pub cluster: Option<Arc<dyn ClusterReader>>,
}

/// What the namespaced kinds' checks read of a reviewed CR.
struct Reviewed<'a> {
    kind: Kind,
    instance_ref: Option<&'a InstanceRef>,
    status: Option<&'a Status>,
    domain_ref: &'a str,
    name: String,
    aliases: &'a [String],
    /// A `StalwartServiceAccount`'s targets.
    targets: Option<&'a [SecretTarget]>,
}

fn denied(failure: Failure) -> Denial<ReasonCode> {
    Denial::new(failure.reason, failure.message)
}

pub fn router(state: WebhookState, health: Arc<Health>, scope: WatchScope) -> Router {
    let guard = ScopeGuard {
        scope,
        finalizer: FINALIZER,
        annotations: api::ANNOTATIONS,
        reason: ReasonCode::LeavesWatchScope,
    };
    weebo_kit_runtime::admission::router(Arc::new(state), health, FIELD_MANAGER, METRIC_PREFIX)
        .merge(scope_router(Arc::new(guard)))
}

#[async_trait::async_trait]
impl Admission for WebhookState {
    type Reason = ReasonCode;

    async fn admit(
        &self,
        kind: &str,
        namespace: &str,
        object: &DynamicObject,
    ) -> Result<(), Denial<ReasonCode>> {
        match kind {
            "StalwartDomain" => {
                let domain: api::Domain = typed(object)
                    .map_err(|m| Denial::new(ReasonCode::InvalidSpec, m.to_string()))?;
                check_domain(&domain).map_err(|f| Denial::new(f.reason, f.message))
            }
            "StalwartServiceAccount" => {
                let sa: ServiceAccount = parse(object)?;
                check_service_account(&sa).map_err(denied)?;
                self.check(
                    namespace,
                    Reviewed {
                        kind: Kind::ServiceAccount,
                        instance_ref: sa.spec.instance_ref.as_ref(),
                        status: sa.status.as_ref(),
                        domain_ref: &sa.spec.domain_ref.name,
                        name: sa.local_part(),
                        aliases: &sa.spec.aliases,
                        targets: Some(&sa.spec.secret_targets),
                    },
                )
                .await
            }
            "StalwartAccount" => {
                let account: Account = parse(object)?;
                check_account(&account).map_err(denied)?;
                self.check(
                    namespace,
                    Reviewed {
                        kind: Kind::Account,
                        instance_ref: account.spec.instance_ref.as_ref(),
                        status: account.status.as_ref(),
                        domain_ref: &account.spec.domain_ref.name,
                        name: account.local_part(),
                        aliases: &account.spec.aliases,
                        targets: None,
                    },
                )
                .await
            }
            "StalwartGroup" => {
                let group: Group = parse(object)?;
                check_group(&group).map_err(denied)?;
                self.check(
                    namespace,
                    Reviewed {
                        kind: Kind::Group,
                        instance_ref: group.spec.instance_ref.as_ref(),
                        status: group.status.as_ref(),
                        domain_ref: &group.spec.domain_ref.name,
                        name: group.local_part(),
                        aliases: &group.spec.aliases,
                        targets: None,
                    },
                )
                .await
            }
            "StalwartMailingList" => {
                let list: MailingList = parse(object)?;
                check_mailing_list(&list).map_err(denied)?;
                self.check(
                    namespace,
                    Reviewed {
                        kind: Kind::MailingList,
                        instance_ref: list.spec.instance_ref.as_ref(),
                        status: list.status.as_ref(),
                        domain_ref: &list.spec.domain_ref.name,
                        name: list.local_part(),
                        aliases: &list.spec.aliases,
                        targets: None,
                    },
                )
                .await
            }
            other => Err(Denial::new(
                ReasonCode::NamespaceNotAllowed,
                format!("kind {other} is not handled by this webhook"),
            )),
        }
    }

    fn undecidable(&self) -> ReasonCode {
        ReasonCode::NamespaceNotAllowed
    }
}

/// The typed CR, or a denial: an object that doesn't match its CRD.
fn parse<K: serde::de::DeserializeOwned>(object: &DynamicObject) -> Result<K, Denial<ReasonCode>> {
    typed(object).map_err(|m| Denial::new(ReasonCode::InvalidSpec, m.to_string()))
}

impl WebhookState {
    /// The reconcilers' checks of a namespaced CR in `namespace`, bound to
    /// its instance.
    async fn check(&self, namespace: &str, cr: Reviewed<'_>) -> Result<(), Denial<ReasonCode>> {
        let instance = self.resolve(namespace, &cr).await;
        let names: Vec<String> = std::iter::once(cr.name.clone())
            .chain(
                cr.aliases
                    .iter()
                    .map(|a| domain::mail::normalize_local_part(a)),
            )
            .collect();
        let verdict = enforce(
            self.policies.as_ref(),
            instance.as_ref(),
            namespace,
            cr.kind,
            &[cr.domain_ref.to_string()],
            &names,
        )
        .await;
        match verdict {
            Ok(decision) => decision.map_err(denied)?,
            Err(e) => {
                tracing::error!(error = %e, "admission lookup failed");
                return Err(Denial::new(
                    ReasonCode::NamespaceNotAllowed,
                    "StalwartNamespacePolicy lookup failed",
                ));
            }
        }
        match (cr.targets, &instance) {
            (Some(targets), Some(instance)) => {
                self.check_targets(namespace, targets, instance).await
            }
            _ => Ok(()),
        }
    }

    async fn resolve(&self, namespace: &str, cr: &Reviewed<'_>) -> Option<BoundInstance> {
        let directory = self.instances.as_ref()?;
        let recorded = cr.status.and_then(|s| s.instance.as_ref());
        directory
            .resolve(Some(namespace), cr.instance_ref, recorded)
            .await
            .ok()
    }

    /// D15 against the instance's default backend, then the stores' Vault
    /// path rules. An instance gone or unreadable is left to the reconcile.
    async fn check_targets(
        &self,
        namespace: &str,
        targets: &[SecretTarget],
        instance: &BoundInstance,
    ) -> Result<(), Denial<ReasonCode>> {
        let Some(cluster) = &self.cluster else {
            return Ok(());
        };
        let settings = match cluster.instance_settings(instance).await {
            Ok(Some(settings)) => settings,
            Ok(None) => return Ok(()),
            Err(e) => {
                tracing::warn!(error = %e, "reading the instance's settings failed");
                return Ok(());
            }
        };
        check_smtp_targets(targets, Some(settings.default_backend)).map_err(denied)?;
        let paths = settings.vault.as_ref().map(|v| VaultPaths {
            path_prefix: &v.path_prefix,
            path_grants: &v.path_grants,
        });
        check_vault_targets(targets, Some(namespace), paths)
            .map_err(|m| Denial::new(ReasonCode::SecretTargetFailed, m))
    }
}

#[cfg(test)]
mod tests {
    use application::test_support::FakeCluster;
    use kube::core::admission::{AdmissionResponse, AdmissionReview};

    use super::*;

    fn review(kind: &str, object: serde_json::Value) -> AdmissionReview<DynamicObject> {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "11111111-1111-1111-1111-111111111111",
                "kind": {"group": "stalwart.weebo.io", "version": "v1alpha1", "kind": kind},
                "resource": {"group": "stalwart.weebo.io", "version": "v1alpha1", "resource": "x"},
                "operation": "CREATE",
                "userInfo": {},
                "object": object,
            }
        }))
        .unwrap()
    }

    async fn run(review: AdmissionReview<DynamicObject>) -> AdmissionResponse {
        let state = WebhookState {
            policies: Arc::new(FakeCluster::default()),
            instances: None,
            cluster: None,
        };
        weebo_kit_runtime::admission::handle(&state, review)
            .await
            .response
            .unwrap()
    }

    fn domain(spec: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": "StalwartDomain",
            "metadata": {"name": "weebo.internal"}, "spec": spec,
        })
    }

    #[tokio::test]
    async fn a_valid_domain_is_admitted() {
        let response = run(review(
            "StalwartDomain",
            domain(serde_json::json!({"catchAll": "all"})),
        ))
        .await;
        assert!(response.allowed, "{:?}", response.result);
    }

    #[tokio::test]
    async fn a_domain_to_delete_is_refused() {
        let response = run(review(
            "StalwartDomain",
            domain(serde_json::json!({"deletionPolicy": "Delete"})),
        ))
        .await;
        assert!(!response.allowed);
        assert_eq!(response.result.reason, "InvalidSpec");
        assert!(response.result.message.contains("Orphan"));
    }

    #[tokio::test]
    async fn a_malformed_domain_is_refused() {
        let response = run(review(
            "StalwartDomain",
            domain(serde_json::json!({"aliases": "not-a-list"})),
        ))
        .await;
        assert!(!response.allowed);
    }

    #[tokio::test]
    async fn unknown_kinds_fail_closed() {
        let response = run(review(
            "StalwartInstance",
            serde_json::json!({"metadata": {"name": "x"}}),
        ))
        .await;
        assert!(!response.allowed);
        assert_eq!(response.result.reason, "NamespaceNotAllowed");
    }

    fn namespaced(kind: &str, spec: serde_json::Value) -> serde_json::Value {
        let mut spec = spec;
        spec["domainRef"] = serde_json::json!({"name": "weebo.internal"});
        spec["instanceRef"] = serde_json::json!({"name": "main"});
        serde_json::json!({
            "apiVersion": "stalwart.weebo.io/v1alpha1", "kind": kind,
            "metadata": {"name": "forgejo", "namespace": "forgejo"}, "spec": spec,
        })
    }

    /// A webhook resolving every instance, whose settings and policies
    /// `cluster` gives.
    async fn decide(
        cluster: FakeCluster,
        kind: &str,
        spec: serde_json::Value,
    ) -> AdmissionResponse {
        let cluster = Arc::new(cluster);
        let gateway = Arc::new(testkit::FakeGateway::default());
        let state = WebhookState {
            policies: cluster.clone(),
            instances: Some(Arc::new(testkit::StaticGatewayFactory::new(gateway))),
            cluster: Some(cluster),
        };
        let mut review = review(kind, namespaced(kind, spec));
        review.request.as_mut().unwrap().namespace = Some("forgejo".into());
        weebo_kit_runtime::admission::handle(&state, review)
            .await
            .response
            .unwrap()
    }

    fn forgejo_rule() -> api::namespace_policy::NamespaceRule {
        serde_json::from_value(serde_json::json!({
            "namespaces": ["forgejo"], "allowedKinds": ["StalwartServiceAccount"],
            "allowedDomains": ["weebo.internal"], "allowedNames": ["forgejo", "noreply"],
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn a_service_account_is_bounded_by_the_policy_on_its_name_and_aliases() {
        let allowed = || {
            let c = FakeCluster::default();
            c.set_policies(vec![vec![forgejo_rule()]]);
            c
        };
        let ok = decide(
            allowed(),
            "StalwartServiceAccount",
            serde_json::json!({"aliases": ["NoReply"]}),
        )
        .await;
        assert!(ok.allowed, "{:?}", ok.result);
        let alias = decide(
            allowed(),
            "StalwartServiceAccount",
            serde_json::json!({"aliases": ["postmaster"]}),
        )
        .await;
        assert!(!alias.allowed);
        assert_eq!(alias.result.reason, "NamespaceNotAllowed");
        let kind = decide(allowed(), "StalwartAccount", serde_json::json!({})).await;
        assert_eq!(kind.result.reason, "NamespaceNotAllowed");
    }

    #[tokio::test]
    async fn d15_vault_targets_are_named_smtp_and_need_a_vault() {
        let bad = decide(
            FakeCluster::default(),
            "StalwartServiceAccount",
            serde_json::json!({"secretTargets": [{"backend": "vault", "name": "forgejo"}]}),
        )
        .await;
        assert_eq!(bad.result.reason, "InvalidSpec");
        // Named right, but the instance has no Vault connection.
        let no_vault = decide(
            FakeCluster::default(),
            "StalwartServiceAccount",
            serde_json::json!({"secretTargets": [{"backend": "vault", "name": "smtp"}]}),
        )
        .await;
        assert_eq!(no_vault.result.reason, "SecretTargetFailed");
        let with_vault = || {
            let c = FakeCluster::default();
            c.set_settings(Some(application::ports::InstanceSettings {
                submission: Default::default(),
                default_backend: api::common::SecretStoreBackend::Vault,
                vault: Some(application::ports::VaultSettings {
                    path_prefix: String::new(),
                    path_grants: vec![],
                }),
            }));
            c
        };
        let ok = decide(
            with_vault(),
            "StalwartServiceAccount",
            serde_json::json!({"secretTargets": [{"backend": "vault", "name": "smtp"}]}),
        )
        .await;
        assert!(ok.allowed, "{:?}", ok.result);
        // The implicit target would go to Vault, under the CR's name.
        let implicit = decide(
            with_vault(),
            "StalwartServiceAccount",
            serde_json::json!({}),
        )
        .await;
        assert_eq!(implicit.result.reason, "InvalidSpec");
    }

    #[tokio::test]
    async fn the_namespaced_kinds_specs_are_checked() {
        for (kind, spec) in [
            ("StalwartAccount", serde_json::json!({"quota": "lots"})),
            (
                "StalwartAccount",
                serde_json::json!({"aliases": ["max@other.example"]}),
            ),
            ("StalwartGroup", serde_json::json!({"name": "a b"})),
            (
                "StalwartMailingList",
                serde_json::json!({"recipients": [{"address": "x@example.com", "accountRef": {"name": "a"}}]}),
            ),
            (
                "StalwartMailingList",
                serde_json::json!({"recipients": [{"address": "not-an-address"}]}),
            ),
        ] {
            let response = decide(FakeCluster::default(), kind, spec.clone()).await;
            assert!(!response.allowed, "{kind} {spec}");
            assert_eq!(response.result.reason, "InvalidSpec", "{kind} {spec}");
        }
        for (kind, spec) in [
            (
                "StalwartAccount",
                serde_json::json!({"quota": "2Gi", "state": "Locked"}),
            ),
            ("StalwartGroup", serde_json::json!({"aliases": ["all"]})),
            (
                "StalwartMailingList",
                serde_json::json!({"recipients": [{"address": "x@example.com"}, {"accountRef": {"name": "a"}}]}),
            ),
        ] {
            let response = decide(FakeCluster::default(), kind, spec.clone()).await;
            assert!(response.allowed, "{kind} {spec}: {:?}", response.result);
        }
    }
}
