//! `x:Account` (`User`, `Group`) on the wire, as v0.16.27 speaks it:
//!
//! - `aliases` is an object list, `{"0": {"name", "domainId", "enabled",
//!   "description"}}`, sent whole;
//! - `roles`, `permissions`, `encryptionAtRest` are variants (`@type`);
//!   `permissions: Merge` carries `enabledPermissions`/`disabledPermissions`
//!   sets, `Replace` a `permissions` set; a `Group` has no
//!   `encryptionAtRest`;
//! - `quotas` is a map, patched by key (`quotas/maxDiskQuota`): the other
//!   quotas are left alone;
//! - `credentials` (the `Password`, App Passwords and API keys) is never
//!   sent nor read: an OIDC default directory refuses a `Password`, and App
//!   Passwords are created through `x:AppPassword` (D24).

use std::collections::BTreeMap;

use ::domain::account::{AccountType, Alias, PermissionsUpdate, RemoteAlias, RemotePermissions};
use application::ports::{AccountPatch, DesiredAccount, GatewayError, RemoteAccount};
use serde_json::{Map, Value, json};

/// What a read asks for: the fields compared and the identity, nothing
/// else (not the credentials).
pub const PROPERTIES: &[&str] = &[
    "id",
    "@type",
    "name",
    "domainId",
    "emailAddress",
    "aliases",
    "roles",
    "permissions",
    "quotas",
    "locale",
    "timeZone",
];

/// A set, as JMAP spells it.
pub fn set<'a>(values: impl IntoIterator<Item = &'a String>) -> Value {
    Value::Object(
        values
            .into_iter()
            .map(|v| (v.clone(), Value::Bool(true)))
            .collect(),
    )
}

/// An object list of aliases, `{"0": {...}, "1": {...}}`.
pub fn aliases(aliases: &[Alias]) -> Value {
    Value::Object(
        aliases
            .iter()
            .enumerate()
            .map(|(i, a)| {
                (
                    i.to_string(),
                    json!({"name": a.name, "domainId": a.domain_id, "enabled": true}),
                )
            })
            .collect(),
    )
}

fn permissions(update: &PermissionsUpdate) -> Value {
    match update {
        PermissionsUpdate::Merge { enabled, disabled } => json!({
            "@type": "Merge",
            "enabledPermissions": set(enabled),
            "disabledPermissions": set(disabled),
        }),
        PermissionsUpdate::Replace { granted } => json!({
            "@type": "Replace",
            "permissions": set(granted),
        }),
    }
}

/// The creation of `desired`: every owned field; `encryptionAtRest:
/// Disabled` for a `User`; no credential.
pub fn create(desired: &DesiredAccount) -> Value {
    let mut object = Map::new();
    object.insert("@type".into(), desired.kind.as_str().into());
    object.insert("name".into(), desired.name.clone().into());
    object.insert("domainId".into(), desired.domain_id.clone().into());
    object.insert("roles".into(), json!({"@type": desired.role.as_str()}));
    if desired.kind == AccountType::User {
        object.insert(
            "encryptionAtRest".into(),
            json!({"@type": DesiredAccount::ENCRYPTION_AT_REST}),
        );
    }
    object.insert("aliases".into(), aliases(&desired.aliases));
    if let Some(owned) = &desired.permissions {
        let value = if owned.disabled.is_empty() {
            json!({"@type": "Inherit"})
        } else {
            let disabled: Vec<String> = owned.disabled.iter().map(|p| p.to_string()).collect();
            json!({"@type": "Merge", "disabledPermissions": set(&disabled)})
        };
        object.insert("permissions".into(), value);
    }
    if let Some(quota) = desired.quota {
        object.insert("quotas".into(), json!({ RemoteAccount::DISK_QUOTA: quota }));
    }
    if let Some(locale) = &desired.locale {
        object.insert("locale".into(), locale.clone().into());
    }
    if let Some(tz) = &desired.time_zone {
        object.insert("timeZone".into(), tz.clone().into());
    }
    Value::Object(object)
}

/// The fields of `patch`, and only those.
pub fn patch(patch: &AccountPatch) -> Value {
    let mut object = Map::new();
    if let Some(name) = &patch.name {
        object.insert("name".into(), name.clone().into());
    }
    if let Some(domain_id) = &patch.domain_id {
        object.insert("domainId".into(), domain_id.clone().into());
    }
    if let Some(list) = &patch.aliases {
        object.insert("aliases".into(), aliases(list));
    }
    if let Some(role) = patch.role {
        object.insert("roles".into(), json!({"@type": role.as_str()}));
    }
    if let Some(update) = &patch.permissions {
        object.insert("permissions".into(), permissions(update));
    }
    if let Some(quota) = patch.quota {
        object.insert(
            format!("quotas/{}", RemoteAccount::DISK_QUOTA),
            quota.into(),
        );
    }
    if let Some(locale) = &patch.locale {
        object.insert("locale".into(), locale.clone().into());
    }
    if let Some(tz) = &patch.time_zone {
        object.insert("timeZone".into(), tz.clone().into());
    }
    Value::Object(object)
}

fn unexpected(method: &str, field: &str, object: &Value) -> GatewayError {
    GatewayError::Api(format!("{method}: unexpected {field} in {object}"))
}

/// The keys of a set whose value is `true`.
pub fn set_keys(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Object(set)) => set
            .iter()
            .filter(|(_, v)| v.as_bool() == Some(true))
            .map(|(k, _)| k.clone())
            .collect(),
        _ => Vec::new(),
    }
}

/// An object list of aliases as read, in index order.
pub fn aliases_from_wire(method: &str, object: &Value) -> Result<Vec<RemoteAlias>, GatewayError> {
    let list = match object.get("aliases") {
        Some(Value::Object(list)) => list,
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(_) => return Err(unexpected(method, "aliases", object)),
    };
    let mut indexed: Vec<(usize, RemoteAlias)> = Vec::new();
    for (key, alias) in list {
        let name = alias.get("name").and_then(Value::as_str);
        let domain_id = alias.get("domainId").and_then(Value::as_str);
        let (Some(name), Some(domain_id)) = (name, domain_id) else {
            return Err(unexpected(method, "aliases", object));
        };
        indexed.push((
            key.parse().unwrap_or(usize::MAX),
            RemoteAlias {
                name: name.to_string(),
                domain_id: domain_id.to_string(),
                // Unset: enabled, Stalwart's default.
                enabled: alias
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
            },
        ));
    }
    indexed.sort_by_key(|(i, _)| *i);
    Ok(indexed.into_iter().map(|(_, a)| a).collect())
}

fn string(method: &str, object: &Value, field: &str) -> Result<String, GatewayError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| unexpected(method, field, object))
}

fn optional(object: &Value, field: &str) -> Option<String> {
    object.get(field).and_then(Value::as_str).map(String::from)
}

const GET: &str = "x:Account/get";

pub fn from_wire(object: &Value) -> Result<RemoteAccount, GatewayError> {
    let permissions = match object.get("permissions") {
        None | Some(Value::Null) => RemotePermissions::Inherit,
        Some(p) => match p.get("@type").and_then(Value::as_str) {
            Some("Inherit") => RemotePermissions::Inherit,
            Some("Merge") => RemotePermissions::Merge {
                enabled: set_keys(p.get("enabledPermissions")),
                disabled: set_keys(p.get("disabledPermissions")),
            },
            Some("Replace") => RemotePermissions::Replace {
                granted: set_keys(p.get("permissions")),
            },
            Some(other) => RemotePermissions::Other(other.to_string()),
            None => return Err(unexpected(GET, "permissions", object)),
        },
    };
    let quotas = match object.get("quotas") {
        Some(Value::Object(map)) => map
            .iter()
            .filter_map(|(k, v)| v.as_u64().map(|v| (k.clone(), v)))
            .collect(),
        None | Some(Value::Null) => BTreeMap::new(),
        Some(_) => return Err(unexpected(GET, "quotas", object)),
    };
    Ok(RemoteAccount {
        kind: string(GET, object, "@type")?,
        name: string(GET, object, "name")?,
        domain_id: string(GET, object, "domainId")?,
        email_address: string(GET, object, "emailAddress")?,
        aliases: aliases_from_wire(GET, object)?,
        role: object
            .get("roles")
            .and_then(|r| r.get("@type"))
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| unexpected(GET, "roles", object))?,
        permissions,
        quotas,
        locale: optional(object, "locale"),
        time_zone: optional(object, "timeZone"),
    })
}
