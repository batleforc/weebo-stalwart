//! `StalwartAccount` (namespaced): a mailbox, `Active` or `Locked`.
//! `deletionPolicy: Orphan` by default — a mailbox is only deleted
//! explicitly. Every reconcile updates `weebo_stalwart_accounts{state}`.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use api::Account;
use api::common::{DeletionPolicy, InstanceRef};
use application::ports::{BoundInstance, RemoteGateway};
use application::use_cases::Outcome;
use application::use_cases::accounts::Ports;
use application::use_cases::reconcile_account::{KIND, cleanup_account, reconcile_account};
use domain::{Failure, RemoteWrite};
use kube::{Client, ResourceExt};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Gauge;

use super::Ctx;
use super::namespaced::{self, NamespacedKind};

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    namespaced::run::<Account>(client, ctx).await;
}

// RFC 0001 Q20: `weebo_stalwart_accounts{state}` counts the
// `StalwartAccount`s by the state their last reconcile reached: `Active`
// or `Locked` when `Ready`, `NotReady` otherwise (a lock not applied is not
// counted as one) — the gauge an alert "an account not Ready for 10 min"
// reads. Counted by the leader, over the CRs it reconciled since it took
// the lease.
/// The `state` label values.
pub const STATES: [&str; 3] = ["Active", "Locked", "NotReady"];

/// The state each account (`namespace/name`) last reached.
static ACCOUNTS: LazyLock<Mutex<Tally>> = LazyLock::new(Mutex::default);

/// The state of each account, and how many are in each of [`STATES`]:
/// kept up to date one account at a time, never recounted.
#[derive(Default)]
pub struct Tally {
    states: BTreeMap<String, &'static str>,
    counts: [u64; 3],
}

impl Tally {
    /// Records `state` for `key` (`None`: gone).
    pub fn set(&mut self, key: String, state: Option<&'static str>) {
        let previous = match state {
            Some(state) => {
                self.bump(state, true);
                self.states.insert(key, state)
            }
            None => self.states.remove(&key),
        };
        if let Some(previous) = previous {
            self.bump(previous, false);
        }
    }

    fn bump(&mut self, state: &str, up: bool) {
        if let Some(count) = STATES
            .iter()
            .position(|s| *s == state)
            .and_then(|i| self.counts.get_mut(i))
        {
            *count = if up {
                count.saturating_add(1)
            } else {
                count.saturating_sub(1)
            };
        }
    }

    /// How many accounts are in each state.
    pub fn counts(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        STATES.into_iter().zip(self.counts)
    }
}

static GAUGE: LazyLock<Gauge<u64>> = LazyLock::new(|| {
    opentelemetry::global::meter(super::FIELD_MANAGER)
        .u64_gauge(format!("{}_accounts", super::METRIC_PREFIX))
        .with_description(
            "StalwartAccounts by the state their last reconcile reached (Active, Locked, NotReady)",
        )
        .build()
});

/// The state label of an account whose last reconcile ended on `outcome`.
pub fn state_of(account: &Account, outcome: &Outcome) -> &'static str {
    match outcome.ready {
        Ok(_) => account.spec.state.as_str(),
        Err(_) => "NotReady",
    }
}

fn key(account: &Account) -> String {
    format!(
        "{}/{}",
        account.namespace().unwrap_or_default(),
        account.name_any()
    )
}

/// Records `state` for `account` (`None`: gone), then the gauge.
fn record(account: &Account, state: Option<&'static str>) {
    // A map of plain values: a panic mid-insert leaves it consistent.
    let mut accounts = ACCOUNTS.lock().unwrap_or_else(PoisonError::into_inner);
    accounts.set(key(account), state);
    for (state, count) in accounts.counts() {
        GAUGE.record(count, &[KeyValue::new("state", state)]);
    }
}

#[async_trait::async_trait]
impl NamespacedKind for Account {
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
        reconcile_account(self, bound, ports).await
    }

    async fn cleanup(
        &self,
        _bound: &BoundInstance,
        gateway: &dyn RemoteGateway,
        _ctx: &Ctx,
    ) -> Result<Option<RemoteWrite>, Failure> {
        cleanup_account(self, gateway).await
    }

    fn reconciled(&self, outcome: &Outcome) {
        record(self, Some(state_of(self, outcome)));
    }

    fn released(&self) {
        record(self, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_are_counted_by_the_state_they_reached() {
        let mut account = Account::new(
            "alice",
            serde_json::from_value(serde_json::json!({"domainRef": {"name": "d"}})).unwrap(),
        );
        assert_eq!(state_of(&account, &Outcome::synced(None, "ok")), "Active");
        account.spec.state = api::account::AccountState::Locked;
        assert_eq!(state_of(&account, &Outcome::synced(None, "ok")), "Locked");
        let failed = Outcome::failed(Failure::new(domain::error::ReasonCode::RemoteError, "x"));
        assert_eq!(state_of(&account, &failed), "NotReady");
        let mut accounts = Tally::default();
        accounts.set("mail/a".into(), Some("Active"));
        accounts.set("mail/b".into(), Some("Active"));
        accounts.set("mail/c".into(), Some("Active"));
        // A change of state moves the account, a deletion drops it.
        accounts.set("mail/b".into(), Some("Locked"));
        accounts.set("mail/c".into(), None);
        accounts.set("mail/d".into(), None);
        accounts.set("mail/e".into(), Some("NotReady"));
        accounts.set("mail/e".into(), Some("Active"));
        assert_eq!(
            accounts.counts().collect::<Vec<_>>(),
            [("Active", 2), ("Locked", 1), ("NotReady", 0)]
        );
    }
}
