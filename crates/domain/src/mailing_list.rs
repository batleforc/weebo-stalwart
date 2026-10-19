//! A Stalwart `x:MailingList`: the state the operator wants, the one it
//! reads back, and the PATCH between them (RFC 0001, "Champs comparés et
//! normalisation"):
//!
//! | Field | Comparison |
//! | --- | --- |
//! | `name`, `domainId` | equality, the name lowercased (a change moves the address: disruptive) |
//! | `aliases` | set of `(name, domainId)`, as an account's |
//! | `recipients` | set of addresses, lowercased (Stalwart keeps them as sent) |
//!
//! `emailAddress` is never written; `description` is not owned.

use crate::account::{Alias, RemoteAlias, aliases, same_aliases};
use crate::drift::{Drift, same_set};
use crate::mail::normalize_local_part;

/// An address as compared: trimmed, lowercased. Mail addresses are
/// case-insensitive in practice, and Stalwart stores a recipient as sent.
pub fn normalize_address(address: &str) -> String {
    address.trim().to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredMailingList {
    /// Normalized.
    pub name: String,
    pub domain_id: String,
    pub aliases: Vec<Alias>,
    /// Normalized ([`normalize_address`]), deduplicated, sorted.
    pub recipients: Vec<String>,
}

impl DesiredMailingList {
    pub fn new(name: &str, domain_id: &str, local_parts: &[String], recipients: &[String]) -> Self {
        let mut recipients: Vec<String> = recipients.iter().map(|r| normalize_address(r)).collect();
        recipients.sort();
        recipients.dedup();
        Self {
            name: normalize_local_part(name),
            domain_id: domain_id.to_string(),
            aliases: aliases(local_parts, domain_id),
            recipients,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMailingList {
    pub name: String,
    pub domain_id: String,
    /// Set by the server: `name@domain`.
    pub email_address: String,
    pub aliases: Vec<RemoteAlias>,
    pub recipients: Vec<String>,
}

/// The fields of an `x:MailingList/set update`: `None` is not sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailingListPatch {
    pub name: Option<String>,
    pub domain_id: Option<String>,
    pub aliases: Option<Vec<Alias>>,
    pub recipients: Option<Vec<String>>,
}

impl MailingListPatch {
    /// Changing the name or the domain moves the list's address.
    pub fn renames(&self) -> bool {
        self.name.is_some() || self.domain_id.is_some()
    }

    pub fn moves_aliases(&self) -> bool {
        self.aliases.is_some()
    }
}

pub fn mailing_list_patch(
    desired: &DesiredMailingList,
    remote: &RemoteMailingList,
) -> (MailingListPatch, Drift) {
    let mut patch = MailingListPatch {
        name: Some(desired.name.clone()),
        domain_id: Some(desired.domain_id.clone()),
        aliases: Some(desired.aliases.clone()),
        recipients: Some(desired.recipients.clone()),
    };
    let mut drift = Drift::default();
    drift.keep_with("name", &mut patch.name, &remote.name, |d, r| {
        *d == normalize_local_part(r)
    });
    drift.keep("domainId", &mut patch.domain_id, &remote.domain_id);
    drift.keep_with("aliases", &mut patch.aliases, &remote.aliases, |d, r| {
        same_aliases(d, r)
    });
    let recipients: Vec<String> = remote
        .recipients
        .iter()
        .map(|r| normalize_address(r))
        .collect();
    drift.keep_with("recipients", &mut patch.recipients, &recipients, |d, r| {
        same_set(d, r)
    });
    (patch, drift)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn desired() -> DesiredMailingList {
        DesiredMailingList::new(
            "Team",
            "c",
            &s(&["all"]),
            &s(&[
                "Alice@Weebo.Internal",
                "bob@weebo.internal",
                "alice@weebo.internal",
            ]),
        )
    }

    fn stored() -> RemoteMailingList {
        RemoteMailingList {
            name: "team".into(),
            domain_id: "c".into(),
            email_address: "team@weebo.internal".into(),
            aliases: vec![RemoteAlias {
                name: "all".into(),
                domain_id: "c".into(),
                enabled: true,
            }],
            recipients: s(&["bob@weebo.internal", "Alice@Weebo.Internal"]),
        }
    }

    #[test]
    fn recipients_are_a_set_whatever_their_case() {
        assert_eq!(
            desired().recipients,
            ["alice@weebo.internal", "bob@weebo.internal"]
        );
        let (patch, drift) = mailing_list_patch(&desired(), &stored());
        assert!(drift.is_empty(), "{drift:?}");
        assert_eq!(patch, MailingListPatch::default());
        let mut remote = stored();
        remote.recipients.push("eve@weebo.internal".into());
        let (patch, drift) = mailing_list_patch(&desired(), &remote);
        assert_eq!(drift.fields(), ["recipients"]);
        assert_eq!(patch.recipients.unwrap().len(), 2);
    }

    #[test]
    fn a_rename_is_disruptive() {
        let mut d = desired();
        d.name = "crew".into();
        let (patch, drift) = mailing_list_patch(&d, &stored());
        assert_eq!(drift.fields(), ["name"]);
        assert!(patch.renames());
    }
}
