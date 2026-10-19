//! Writing a value Stalwart shows only once (a generated password) to
//! every target of a CR, and detecting a target that lost it — the kit's
//! helpers, with failures mapped to `SecretTargetFailed` (a target out of
//! its CR's namespace: `InvalidSpec`). Used by the kinds that emit a
//! secret, through the `SecretStore` of their instance
//! (`SecretStoreFactory`).

use std::collections::BTreeMap;

use api::common::SecretTarget;
use domain::Failure;
use domain::error::ReasonCode;

use crate::ports::{SecretOwner, SecretStore, SecretStoreError};

use weebo_kit_application::emit as kit;
pub use weebo_kit_application::emit::{TargetViolation, rotation_requested, targets};

fn failed(e: SecretStoreError) -> Failure {
    Failure::new(ReasonCode::SecretTargetFailed, e.to_string())
}

/// A namespaced CR's targets stay in its namespace; a cluster-scoped CR's
/// targets name one. Checked before any Stalwart call, by the reconcilers
/// and the admission webhook alike.
pub fn check_targets(targets: &[SecretTarget], owner: &SecretOwner<'_>) -> Result<(), Failure> {
    kit::check_targets(targets, owner)
        .map_err(|v| Failure::new(ReasonCode::InvalidSpec, v.to_string()))
}

pub async fn any_missing(
    targets: &[SecretTarget],
    owner: &SecretOwner<'_>,
    store: &dyn SecretStore,
) -> Result<bool, Failure> {
    kit::any_missing(targets, owner, store)
        .await
        .map_err(failed)
}

pub async fn write_all(
    targets: &[SecretTarget],
    owner: &SecretOwner<'_>,
    data: &BTreeMap<String, String>,
    store: &dyn SecretStore,
) -> Result<(), Failure> {
    kit::write_all(targets, owner, data, store)
        .await
        .map_err(failed)
}

pub async fn delete_all(
    targets: &[SecretTarget],
    owner: &SecretOwner<'_>,
    store: &dyn SecretStore,
) -> Result<(), Failure> {
    kit::delete_all(targets, owner, store).await.map_err(failed)
}

#[cfg(test)]
mod tests {
    use weebo_kit_application::test_support::FakeSecretStore;

    use super::*;

    fn target(name: &str, namespace: Option<&str>) -> SecretTarget {
        SecretTarget {
            backend: Default::default(),
            name: name.into(),
            namespace: namespace.map(String::from),
            path: None,
        }
    }

    #[tokio::test]
    async fn a_lost_value_is_detected_then_written_back() {
        let store = FakeSecretStore::default();
        let owner = SecretOwner::namespaced("StalwartServiceAccount", "forgejo", "forgejo");
        let targets = targets(&[], "forgejo", &store);
        assert_eq!(any_missing(&targets, &owner, &store).await, Ok(true));
        let data = BTreeMap::from([("password".to_string(), "x".to_string())]);
        write_all(&targets, &owner, &data, &store).await.unwrap();
        assert_eq!(any_missing(&targets, &owner, &store).await, Ok(false));
        delete_all(&targets, &owner, &store).await.unwrap();
        assert_eq!(any_missing(&targets, &owner, &store).await, Ok(true));
    }

    #[tokio::test]
    async fn a_failing_store_is_a_secret_target_failure() {
        let store = FakeSecretStore::default();
        store.fail_writes(true);
        let owner = SecretOwner::namespaced("StalwartServiceAccount", "forgejo", "forgejo");
        let err = write_all(&[target("smtp", None)], &owner, &BTreeMap::new(), &store)
            .await
            .unwrap_err();
        assert_eq!(err.reason, ReasonCode::SecretTargetFailed);
    }

    #[test]
    fn targets_stay_in_the_crs_namespace() {
        let owner = SecretOwner::namespaced("StalwartServiceAccount", "forgejo", "forgejo");
        let err = check_targets(&[target("smtp", Some("mail"))], &owner).unwrap_err();
        assert_eq!(err.reason, ReasonCode::InvalidSpec);
        assert_eq!(
            check_targets(&[target("smtp", Some("forgejo"))], &owner),
            Ok(())
        );
    }
}
