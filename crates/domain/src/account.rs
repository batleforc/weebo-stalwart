//! A Stalwart `x:Account` — a `User` (`StalwartServiceAccount`,
//! `StalwartAccount`) or a `Group` (`StalwartGroup`): the state the
//! operator wants, the one it reads back, and the PATCH between them —
//! only the fields it owns, compared in the form Stalwart stores them (RFC
//! 0001, "Champs comparés et normalisation"):
//!
//! | Field | Comparison |
//! | --- | --- |
//! | `name`, `domainId` | equality, the name lowercased (a change moves the address: disruptive) |
//! | `aliases` | set of `(name, domainId)`, lowercased, each `enabled: true`; an alias `description` is ignored |
//! | `roles` | variant (`@type`): `User`, or `Default` for a group |
//! | `permissions` | subset: only the permissions the operator disables, present or absent from `disabledPermissions`; the other entries are left as they are, a remote `Inherit` disables nothing |
//! | `quotas` | subset of the map, key `maxDiskQuota` (bytes) |
//! | `locale`, `timeZone` | equality when set (schema enums, case-sensitive), `None`: no opinion |
//!
//! `emailAddress` is never written (the server sets it, `name@domain`): it
//! is read for `status.address` and the identity guard (D19).
//! `encryptionAtRest` is set to `Disabled` at creation of a `User` and
//! never compared; `description` and `memberGroupIds` belong to the OIDC
//! JIT (D5, D6); `credentials` is never written nor read (a service
//! account's App Password goes through `x:AppPassword`, D24).

use std::collections::BTreeMap;

use crate::drift::{Drift, same_set};
use crate::mail::normalize_local_part;

/// The permissions the operator disables, as Stalwart names them.
pub mod permission {
    pub const AUTHENTICATE: &str = "authenticate";
    pub const EMAIL_SEND: &str = "emailSend";
    pub const EMAIL_RECEIVE: &str = "emailReceive";
    pub const IMAP_AUTHENTICATE: &str = "imapAuthenticate";
    pub const POP3_AUTHENTICATE: &str = "pop3Authenticate";
    pub const SIEVE_AUTHENTICATE: &str = "sieveAuthenticate";
}

/// `@type` of an `x:Account`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountType {
    User,
    Group,
}

impl AccountType {
    pub const fn as_str(self) -> &'static str {
        match self {
            AccountType::User => "User",
            AccountType::Group => "Group",
        }
    }
}

/// `roles` of an `x:Account` (its `@type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The role of a mailbox owner.
    User,
    /// The role of a group.
    Default,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::User => "User",
            Role::Default => "Default",
        }
    }
}

/// An alias of an account or a list, as Stalwart stores it: a lowercased
/// local-part in a domain (by id).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Alias {
    pub name: String,
    pub domain_id: String,
}

/// An alias as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAlias {
    pub name: String,
    pub domain_id: String,
    pub enabled: bool,
}

/// `local_parts`, normalized, deduplicated, sorted, in `domain_id`.
pub fn aliases(local_parts: &[String], domain_id: &str) -> Vec<Alias> {
    let mut aliases: Vec<Alias> = local_parts
        .iter()
        .map(|a| Alias {
            name: normalize_local_part(a),
            domain_id: domain_id.to_string(),
        })
        .collect();
    aliases.sort();
    aliases.dedup();
    aliases
}

/// The desired aliases match the remote ones as a set of `(name,
/// domainId)`, every remote one enabled.
pub fn same_aliases(desired: &[Alias], remote: &[RemoteAlias]) -> bool {
    let remote: Vec<Option<Alias>> = remote
        .iter()
        .map(|r| {
            r.enabled.then(|| Alias {
                name: normalize_local_part(&r.name),
                domain_id: r.domain_id.clone(),
            })
        })
        .collect();
    let desired: Vec<Option<Alias>> = desired.iter().cloned().map(Some).collect();
    same_set(&desired, &remote)
}

/// The permissions the operator owns on an account: those it may disable
/// (`owned`), and those of them disabled in the desired state. Any other
/// entry of the account's `permissions` is someone else's, left alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedPermissions {
    pub owned: &'static [&'static str],
    pub disabled: Vec<&'static str>,
}

impl OwnedPermissions {
    const SERVICE_ACCOUNT: &'static [&'static str] = &[
        permission::IMAP_AUTHENTICATE,
        permission::POP3_AUTHENTICATE,
        permission::SIEVE_AUTHENTICATE,
        permission::EMAIL_RECEIVE,
    ];
    const ACCOUNT: &'static [&'static str] = &[
        permission::AUTHENTICATE,
        permission::EMAIL_SEND,
        permission::EMAIL_RECEIVE,
    ];

    /// A sending account: no IMAP, POP3 nor ManageSieve login, and no
    /// delivery unless it `receive`s.
    pub fn service_account(receive: bool) -> Self {
        let mut disabled = vec![
            permission::IMAP_AUTHENTICATE,
            permission::POP3_AUTHENTICATE,
            permission::SIEVE_AUTHENTICATE,
        ];
        if !receive {
            disabled.push(permission::EMAIL_RECEIVE);
        }
        Self {
            owned: Self::SERVICE_ACCOUNT,
            disabled,
        }
    }

    /// A mailbox: `Locked` disables every authentication (App Passwords
    /// included: they pass through the same `Authenticate` check), sending
    /// and delivery; `Active` none of them — only the operator's own
    /// entries are removed, App Passwords work again.
    pub fn account(locked: bool) -> Self {
        Self {
            owned: Self::ACCOUNT,
            disabled: if locked {
                Self::ACCOUNT.to_vec()
            } else {
                Vec::new()
            },
        }
    }

    fn disables(&self, permission: &str) -> bool {
        self.disabled.contains(&permission)
    }
}

/// `permissions` of an account as read: the variant and its sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemotePermissions {
    /// The role's permissions, nothing disabled.
    Inherit,
    /// The role's, plus `enabled`, minus `disabled` (which win).
    Merge {
        enabled: Vec<String>,
        disabled: Vec<String>,
    },
    /// Exactly `granted`, the role ignored.
    Replace { granted: Vec<String> },
    /// A variant this release doesn't know.
    Other(String),
}

/// The `permissions` an update sends: always the whole value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionsUpdate {
    Merge {
        enabled: Vec<String>,
        disabled: Vec<String>,
    },
    Replace {
        granted: Vec<String>,
    },
}

// RFC 0001 Q18: the RFC only speaks of `Merge` and `Inherit`. A remote
// `Replace` (set by hand) is someone's explicit choice: the operator then
// only checks that the permissions it disables are absent from `granted`,
// has no opinion on those it wants enabled (it can't tell them from the
// role's), and on drift sends the same `Replace` without them.
fn permissions_update(
    desired: &OwnedPermissions,
    remote: &RemotePermissions,
) -> Option<PermissionsUpdate> {
    let owned = |p: &String| desired.owned.contains(&p.as_str());
    let wanted = || desired.disabled.iter().map(|p| p.to_string());
    match remote {
        RemotePermissions::Inherit if desired.disabled.is_empty() => None,
        RemotePermissions::Inherit | RemotePermissions::Other(_) => {
            Some(PermissionsUpdate::Merge {
                enabled: Vec::new(),
                disabled: wanted().collect(),
            })
        }
        RemotePermissions::Merge { enabled, disabled } => {
            let in_sync = desired
                .owned
                .iter()
                .all(|p| desired.disables(p) == disabled.iter().any(|d| d == p));
            (!in_sync).then(|| PermissionsUpdate::Merge {
                enabled: enabled.clone(),
                disabled: disabled
                    .iter()
                    .filter(|p| !owned(p))
                    .cloned()
                    .chain(wanted())
                    .collect(),
            })
        }
        RemotePermissions::Replace { granted } => {
            let in_sync = !granted.iter().any(|p| desired.disables(p));
            (!in_sync).then(|| PermissionsUpdate::Replace {
                granted: granted
                    .iter()
                    .filter(|p| !desired.disables(p))
                    .cloned()
                    .collect(),
            })
        }
    }
}

/// The account the operator wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredAccount {
    pub kind: AccountType,
    /// Normalized ([`normalize_local_part`]).
    pub name: String,
    pub domain_id: String,
    /// Normalized, deduplicated, sorted: in the account's domain.
    pub aliases: Vec<Alias>,
    pub role: Role,
    /// `None`: not compared (a group's).
    pub permissions: Option<OwnedPermissions>,
    /// `quotas.maxDiskQuota` in bytes, `None`: no opinion.
    pub quota: Option<u64>,
    pub locale: Option<String>,
    pub time_zone: Option<String>,
}

impl DesiredAccount {
    /// A user or group named `name` in `domain_id`, with `aliases`
    /// (local-parts) in the same domain, nothing else owned yet.
    pub fn new(kind: AccountType, name: &str, domain_id: &str, aliases: &[String]) -> Self {
        Self {
            kind,
            name: normalize_local_part(name),
            domain_id: domain_id.to_string(),
            aliases: self::aliases(aliases, domain_id),
            role: match kind {
                AccountType::User => Role::User,
                AccountType::Group => Role::Default,
            },
            permissions: None,
            quota: None,
            locale: None,
            time_zone: None,
        }
    }

    // RFC 0001 Q24: the RFC sets `encryptionAtRest: Disabled` on every
    // account kind; v0.16.27 refuses the property on a `Group`
    // (`invalidPatch: Invalid property`): only users get it.
    /// `encryptionAtRest: Disabled`, sent at the creation of a `User`
    /// only (a `Group` has no such property).
    pub const ENCRYPTION_AT_REST: &'static str = "Disabled";
}

/// An account as Stalwart returns it (the owned fields, and what the
/// identity guard reads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAccount {
    /// `@type`: `User`, `Group`.
    pub kind: String,
    pub name: String,
    pub domain_id: String,
    /// Set by the server: `name@domain`.
    pub email_address: String,
    pub aliases: Vec<RemoteAlias>,
    /// `roles`' `@type`.
    pub role: String,
    pub permissions: RemotePermissions,
    pub quotas: BTreeMap<String, u64>,
    pub locale: Option<String>,
    pub time_zone: Option<String>,
}

impl RemoteAccount {
    /// What [`account_patch`] compares the quota with.
    pub const DISK_QUOTA: &'static str = "maxDiskQuota";
}

/// The fields of an `x:Account/set update`: `None` is not sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountPatch {
    pub name: Option<String>,
    pub domain_id: Option<String>,
    pub aliases: Option<Vec<Alias>>,
    pub role: Option<Role>,
    pub permissions: Option<PermissionsUpdate>,
    /// Sent as `quotas/maxDiskQuota`: the other quotas are left alone.
    pub quota: Option<u64>,
    pub locale: Option<String>,
    pub time_zone: Option<String>,
}

impl AccountPatch {
    /// Changing the name or the domain moves the account's address: a
    /// disruptive update.
    pub fn renames(&self) -> bool {
        self.name.is_some() || self.domain_id.is_some()
    }

    /// Whether the aliases change: they claim addresses.
    pub fn moves_aliases(&self) -> bool {
        self.aliases.is_some()
    }
}

/// The update `remote` needs to reach `desired`: the fields already in
/// their desired state left out, the drifted ones named.
pub fn account_patch(desired: &DesiredAccount, remote: &RemoteAccount) -> (AccountPatch, Drift) {
    let mut patch = AccountPatch {
        name: Some(desired.name.clone()),
        domain_id: Some(desired.domain_id.clone()),
        aliases: Some(desired.aliases.clone()),
        role: Some(desired.role),
        permissions: None,
        quota: desired.quota,
        locale: desired.locale.clone(),
        time_zone: desired.time_zone.clone(),
    };
    let mut drift = Drift::default();
    drift.keep_with("name", &mut patch.name, &remote.name, |d, r| {
        *d == normalize_local_part(r)
    });
    drift.keep("domainId", &mut patch.domain_id, &remote.domain_id);
    drift.keep_with("aliases", &mut patch.aliases, &remote.aliases, |d, r| {
        same_aliases(d, r)
    });
    drift.keep_with("roles", &mut patch.role, &remote.role, |d, r| {
        d.as_str() == r
    });
    if let Some(owned) = &desired.permissions {
        patch.permissions = permissions_update(owned, &remote.permissions);
        drift.note("permissions", patch.permissions.is_some());
    }
    drift.keep_with("quotas", &mut patch.quota, &remote.quotas, |d, r| {
        r.get(RemoteAccount::DISK_QUOTA) == Some(d)
    });
    // Both are enums of the schema, case included (`fr-FR`,
    // `Europe/Paris`): another case is refused, never stored.
    drift.keep_opt("locale", &mut patch.locale, &remote.locale);
    drift.keep_opt("timeZone", &mut patch.time_zone, &remote.time_zone);
    (patch, drift)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn desired() -> DesiredAccount {
        let mut d = DesiredAccount::new(AccountType::User, "Forgejo", "c", &s(&["NoReply"]));
        d.permissions = Some(OwnedPermissions::service_account(false));
        d
    }

    /// What Stalwart stores once `desired()` is created.
    fn stored() -> RemoteAccount {
        RemoteAccount {
            kind: "User".into(),
            name: "forgejo".into(),
            domain_id: "c".into(),
            email_address: "forgejo@weebo.internal".into(),
            aliases: vec![RemoteAlias {
                name: "noreply".into(),
                domain_id: "c".into(),
                enabled: true,
            }],
            role: "User".into(),
            permissions: RemotePermissions::Merge {
                enabled: Vec::new(),
                disabled: s(&[
                    "imapAuthenticate",
                    "pop3Authenticate",
                    "sieveAuthenticate",
                    "emailReceive",
                ]),
            },
            quotas: BTreeMap::new(),
            locale: Some("en-US".into()),
            time_zone: None,
        }
    }

    #[test]
    fn the_stored_form_is_in_sync() {
        let (patch, drift) = account_patch(&desired(), &stored());
        assert!(drift.is_empty(), "{drift:?}");
        assert_eq!(patch, AccountPatch::default());
    }

    #[test]
    fn aliases_compare_as_a_set_of_enabled_names_in_a_domain() {
        let mut remote = stored();
        remote.aliases[0].name = "NOREPLY".into();
        assert!(account_patch(&desired(), &remote).1.is_empty());
        remote.aliases[0].enabled = false;
        assert_eq!(account_patch(&desired(), &remote).1.fields(), ["aliases"]);
        remote.aliases[0].enabled = true;
        remote.aliases[0].domain_id = "b".into();
        let (patch, drift) = account_patch(&desired(), &remote);
        assert_eq!(drift.fields(), ["aliases"]);
        assert_eq!(patch.aliases.unwrap()[0].domain_id, "c");
    }

    #[test]
    fn an_admin_role_is_put_back() {
        let mut remote = stored();
        remote.role = "Admin".into();
        let (patch, drift) = account_patch(&desired(), &remote);
        assert_eq!(drift.fields(), ["roles"]);
        assert_eq!(patch.role, Some(Role::User));
    }

    #[test]
    fn only_the_owned_permissions_are_compared() {
        let mut remote = stored();
        // Someone else's entries: left alone.
        remote.permissions = RemotePermissions::Merge {
            enabled: s(&["impersonate"]),
            disabled: s(&[
                "imapAuthenticate",
                "pop3Authenticate",
                "sieveAuthenticate",
                "emailReceive",
                "jmapEmailGet",
            ]),
        };
        assert!(account_patch(&desired(), &remote).1.is_empty());
        // `receive: true`: delivery comes back, the rest is kept.
        let mut receiving = desired();
        receiving.permissions = Some(OwnedPermissions::service_account(true));
        let (patch, drift) = account_patch(&receiving, &remote);
        assert_eq!(drift.fields(), ["permissions"]);
        assert_eq!(
            patch.permissions,
            Some(PermissionsUpdate::Merge {
                enabled: s(&["impersonate"]),
                disabled: s(&[
                    "jmapEmailGet",
                    "imapAuthenticate",
                    "pop3Authenticate",
                    "sieveAuthenticate"
                ]),
            })
        );
    }

    #[test]
    fn a_remote_inherit_disables_nothing() {
        let mut remote = stored();
        remote.permissions = RemotePermissions::Inherit;
        let active = OwnedPermissions::account(false);
        let mut d = desired();
        d.permissions = Some(active);
        assert!(account_patch(&d, &remote).1.is_empty());
        d.permissions = Some(OwnedPermissions::account(true));
        let (patch, drift) = account_patch(&d, &remote);
        assert_eq!(drift.fields(), ["permissions"]);
        assert_eq!(
            patch.permissions,
            Some(PermissionsUpdate::Merge {
                enabled: vec![],
                disabled: s(&["authenticate", "emailSend", "emailReceive"]),
            })
        );
    }

    #[test]
    fn locking_then_unlocking_touches_the_owned_entries_only() {
        let mut d = desired();
        d.permissions = Some(OwnedPermissions::account(true));
        let mut remote = stored();
        remote.permissions = RemotePermissions::Merge {
            enabled: vec![],
            disabled: s(&[
                "authenticate",
                "emailSend",
                "emailReceive",
                "imapAuthenticate",
            ]),
        };
        assert!(account_patch(&d, &remote).1.is_empty(), "locked in sync");
        d.permissions = Some(OwnedPermissions::account(false));
        let (patch, _) = account_patch(&d, &remote);
        assert_eq!(
            patch.permissions,
            Some(PermissionsUpdate::Merge {
                enabled: vec![],
                disabled: s(&["imapAuthenticate"]),
            })
        );
    }

    #[test]
    fn a_remote_replace_only_loses_what_the_operator_disables() {
        let mut d = desired();
        d.permissions = Some(OwnedPermissions::account(true));
        let mut remote = stored();
        remote.permissions = RemotePermissions::Replace {
            granted: s(&["authenticate", "jmapEmailGet"]),
        };
        let (patch, _) = account_patch(&d, &remote);
        assert_eq!(
            patch.permissions,
            Some(PermissionsUpdate::Replace {
                granted: s(&["jmapEmailGet"])
            })
        );
        d.permissions = Some(OwnedPermissions::account(false));
        assert!(account_patch(&d, &remote).1.is_empty());
    }

    #[test]
    fn quotas_compare_on_the_disk_quota_only() {
        let mut d = desired();
        d.quota = Some(2_147_483_648);
        let mut remote = stored();
        remote.quotas = BTreeMap::from([
            ("maxDiskQuota".to_string(), 2_147_483_648),
            ("maxApiKeys".to_string(), 5),
        ]);
        assert!(account_patch(&d, &remote).1.is_empty());
        remote.quotas.insert("maxDiskQuota".into(), 1);
        let (patch, drift) = account_patch(&d, &remote);
        assert_eq!(drift.fields(), ["quotas"]);
        assert_eq!(patch.quota, Some(2_147_483_648));
        // No quota in the spec: no opinion.
        assert!(account_patch(&desired(), &remote).1.is_empty());
    }

    #[test]
    fn locale_and_time_zone_are_compared_when_set() {
        let mut d = desired();
        d.locale = Some("fr-FR".into());
        d.time_zone = Some("Europe/Paris".into());
        let mut remote = stored();
        remote.locale = Some("fr-FR".into());
        let (patch, drift) = account_patch(&d, &remote);
        assert_eq!(drift.fields(), ["timeZone"]);
        assert_eq!(patch.time_zone.as_deref(), Some("Europe/Paris"));
        // `en-US`, the server's default, is no drift without an opinion.
        assert!(account_patch(&desired(), &stored()).1.is_empty());
    }

    #[test]
    fn a_rename_is_disruptive() {
        let d = DesiredAccount {
            name: "gitea".into(),
            ..desired()
        };
        let (patch, drift) = account_patch(&d, &stored());
        assert_eq!(drift.fields(), ["name"]);
        assert!(patch.renames());
        let d = DesiredAccount {
            domain_id: "z".into(),
            aliases: aliases(&s(&["noreply"]), "z"),
            ..desired()
        };
        let (patch, drift) = account_patch(&d, &stored());
        assert_eq!(drift.fields(), ["domainId", "aliases"]);
        assert!(patch.renames() && patch.moves_aliases());
    }

    #[test]
    fn a_group_has_the_default_role_and_no_permission_opinion() {
        let g = DesiredAccount::new(AccountType::Group, "Team", "c", &[]);
        assert_eq!((g.role, g.permissions.as_ref()), (Role::Default, None));
        let remote = RemoteAccount {
            kind: "Group".into(),
            name: "team".into(),
            email_address: "team@weebo.internal".into(),
            aliases: vec![],
            role: "Default".into(),
            permissions: RemotePermissions::Merge {
                enabled: vec![],
                disabled: s(&["authenticate"]),
            },
            ..stored()
        };
        assert!(account_patch(&g, &remote).1.is_empty());
    }
}
