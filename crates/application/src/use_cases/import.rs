//! What `weebo-stalwart-importer` links: the Stalwart object a CR
//! describes, found **by name** — the only place the operator's code does
//! so (D9) — and checked to be what the CR says it is (a `Group` is not an
//! account, an address must be `name@domain`). The importer then seeds the
//! CR's `status.remoteId`/`status.address` with it, after the unique claim
//! (`RemoteObjectClaimed`), and the reconciles take over from there: they
//! read by id, compare, and write what differs.
//!
//! D21: a `StalwartServiceAccount` linked to an existing account always
//! gets a password of the operator's — the importer sets a rotation nonce
//! on it ([`IMPORT_ROTATION_PREFIX`]): the password another tool wrote has
//! two sources otherwise.

use domain::account::AccountType;
use domain::mail;

use crate::ports::{GatewayError, RemoteGateway};

/// The prefix of the `rotate-secret` nonce the importer sets on a
/// `StalwartServiceAccount` it links (D21), followed by a timestamp.
pub const IMPORT_ROTATION_PREFIX: &str = "import-";

/// What a CR describes in Stalwart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// A `StalwartDomain`: the domain named `name`.
    Domain { name: String },
    /// A `StalwartServiceAccount`/`StalwartAccount` (`User`) or
    /// `StalwartGroup` (`Group`): the account `name` of the domain `domain`
    /// (its id and name in Stalwart).
    Account {
        kind: AccountType,
        domain_id: String,
        domain: String,
        name: String,
    },
    /// A `StalwartMailingList`: the list `name` of the domain.
    MailingList {
        domain_id: String,
        domain: String,
        name: String,
    },
}

/// The object found: what the CR's status is seeded with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub remote_id: String,
    /// The domain's name, or the object's address.
    pub address: String,
}

/// Why nothing can be linked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    /// Nothing of that name: the operator will create it — nothing to
    /// import.
    #[error("{0} does not exist in Stalwart: nothing to import (the operator creates it)")]
    NotFound(String),
    /// Something of that name, but not what the CR describes.
    #[error("{0}")]
    Mismatch(String),
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

/// The object `wanted` describes.
pub async fn locate(gateway: &dyn RemoteGateway, wanted: &Wanted) -> Result<Found, ImportError> {
    match wanted {
        Wanted::Domain { name } => {
            let name = mail::normalize_domain(name);
            let id = gateway
                .find_domain(&name)
                .await?
                .ok_or_else(|| ImportError::NotFound(format!("domain {name:?}")))?;
            let read = gateway
                .get_domain(&id)
                .await?
                .ok_or_else(|| ImportError::NotFound(format!("domain {name:?}")))?;
            if mail::normalize_domain(&read.name) != name {
                return Err(ImportError::Mismatch(format!(
                    "domain {id} answers {:?}, not {name:?}",
                    read.name
                )));
            }
            Ok(Found {
                remote_id: id,
                address: name,
            })
        }
        Wanted::Account {
            kind,
            domain_id,
            domain,
            name,
        } => {
            let address = mail::address(name, domain);
            let what = || format!("account {address:?}");
            let id = gateway
                .find_account(domain_id, name)
                .await?
                .ok_or_else(|| ImportError::NotFound(what()))?;
            let read = gateway
                .get_account(&id)
                .await?
                .ok_or_else(|| ImportError::NotFound(what()))?;
            if read.kind != kind.as_str() {
                return Err(ImportError::Mismatch(format!(
                    "{address:?} is a {} in Stalwart, not a {}",
                    read.kind,
                    kind.as_str()
                )));
            }
            if !read.email_address.eq_ignore_ascii_case(&address) {
                return Err(ImportError::Mismatch(format!(
                    "account {id} answers {:?}, not {address:?}",
                    read.email_address
                )));
            }
            Ok(Found {
                remote_id: id,
                address,
            })
        }
        Wanted::MailingList {
            domain_id,
            domain,
            name,
        } => {
            let address = mail::address(name, domain);
            let id = gateway
                .find_mailing_list(domain_id, name)
                .await?
                .ok_or_else(|| ImportError::NotFound(format!("mailing list {address:?}")))?;
            let read = gateway
                .get_mailing_list(&id)
                .await?
                .ok_or_else(|| ImportError::NotFound(format!("mailing list {address:?}")))?;
            if !read.email_address.eq_ignore_ascii_case(&address) {
                return Err(ImportError::Mismatch(format!(
                    "mailing list {id} answers {:?}, not {address:?}",
                    read.email_address
                )));
            }
            Ok(Found {
                remote_id: id,
                address,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::DesiredMailingList;
    use crate::test_support::FakeGateway;

    fn account(kind: AccountType, domain_id: &str, name: &str) -> Wanted {
        Wanted::Account {
            kind,
            domain_id: domain_id.into(),
            domain: "weebo.internal".into(),
            name: name.into(),
        }
    }

    #[tokio::test]
    async fn existing_objects_are_found_by_name() {
        let gateway = FakeGateway::default();
        let domain = gateway.seed_domain("weebo.internal");
        let wanted = Wanted::Domain {
            name: "Weebo.Internal".into(),
        };
        assert_eq!(
            locate(&gateway, &wanted).await,
            Ok(Found {
                remote_id: domain.clone(),
                address: "weebo.internal".into()
            })
        );
        let alice = gateway.seed_account(AccountType::User, "alice", &domain);
        assert_eq!(
            locate(&gateway, &account(AccountType::User, &domain, "Alice")).await,
            Ok(Found {
                remote_id: alice,
                address: "alice@weebo.internal".into()
            })
        );
        use crate::ports::RemoteGateway as _;
        let list = gateway
            .create_mailing_list(&DesiredMailingList::new("team", &domain, &[], &[]))
            .await
            .unwrap();
        let wanted = Wanted::MailingList {
            domain_id: domain.clone(),
            domain: "weebo.internal".into(),
            name: "team".into(),
        };
        assert_eq!(locate(&gateway, &wanted).await.unwrap().remote_id, list);
    }

    #[tokio::test]
    async fn a_group_is_not_an_account_and_nothing_is_not_importable() {
        let gateway = FakeGateway::default();
        let domain = gateway.seed_domain("weebo.internal");
        gateway.seed_account(AccountType::Group, "team", &domain);
        assert!(matches!(
            locate(&gateway, &account(AccountType::User, &domain, "team")).await,
            Err(ImportError::Mismatch(m)) if m.contains("Group")
        ));
        assert!(matches!(
            locate(&gateway, &account(AccountType::User, &domain, "ghost")).await,
            Err(ImportError::NotFound(_))
        ));
    }
}
