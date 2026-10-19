//! `x:Domain` on the wire.

use application::ports::{DesiredDomain, DomainPatch, GatewayError, RemoteDomain};
use serde_json::{Map, Value, json};

/// What a read asks for: the fields compared, nothing else (a full get
/// also computes the domain's DNS zone file).
pub const PROPERTIES: &[&str] = &[
    "id",
    "name",
    "aliases",
    "catchAllAddress",
    "allowRelaying",
    "subAddressing",
    "dkimManagement",
    "dnsManagement",
    "certificateManagement",
];

/// A set, as JMAP spells it.
fn set(values: &[String]) -> Value {
    Value::Object(
        values
            .iter()
            .map(|v| (v.clone(), Value::Bool(true)))
            .collect(),
    )
}

fn variant(name: &str) -> Value {
    json!({"@type": name})
}

/// The creation of `desired`: every owned field, the server's defaults for
/// the rest (`Automatic` DKIM with its default parameters).
pub fn create(desired: &DesiredDomain) -> Value {
    let mut object = Map::new();
    object.insert("name".into(), desired.name.clone().into());
    object.insert("aliases".into(), set(&desired.aliases));
    if let Some(catch_all) = &desired.catch_all {
        object.insert("catchAllAddress".into(), catch_all.clone().into());
    }
    object.insert("allowRelaying".into(), DesiredDomain::ALLOW_RELAYING.into());
    object.insert(
        "subAddressing".into(),
        variant(desired.sub_addressing.as_str()),
    );
    object.insert("dkimManagement".into(), variant(desired.dkim.as_str()));
    object.insert(
        "dnsManagement".into(),
        variant(DesiredDomain::DNS_MANAGEMENT),
    );
    object.insert(
        "certificateManagement".into(),
        variant(DesiredDomain::CERTIFICATE_MANAGEMENT),
    );
    Value::Object(object)
}

/// The fields of `patch`, and only those.
pub fn patch(patch: &DomainPatch) -> Value {
    let mut object = Map::new();
    if let Some(name) = &patch.name {
        object.insert("name".into(), name.clone().into());
    }
    if let Some(aliases) = &patch.aliases {
        object.insert("aliases".into(), set(aliases));
    }
    if let Some(catch_all) = &patch.catch_all {
        object.insert(
            "catchAllAddress".into(),
            catch_all.clone().map_or(Value::Null, Value::from),
        );
    }
    if let Some(relay) = patch.allow_relaying {
        object.insert("allowRelaying".into(), relay.into());
    }
    if let Some(sub) = patch.sub_addressing {
        object.insert("subAddressing".into(), variant(sub.as_str()));
    }
    if let Some(dkim) = patch.dkim {
        object.insert("dkimManagement".into(), variant(dkim.as_str()));
    }
    if let Some(dns) = patch.dns {
        object.insert("dnsManagement".into(), variant(dns));
    }
    if let Some(certificate) = patch.certificate {
        object.insert("certificateManagement".into(), variant(certificate));
    }
    Value::Object(object)
}

fn unexpected(field: &str, object: &Value) -> GatewayError {
    GatewayError::Api(format!("x:Domain/get: unexpected {field} in {object}"))
}

fn type_of(object: &Value, field: &str) -> Result<String, GatewayError> {
    object
        .get(field)
        .and_then(|v| v.get("@type"))
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| unexpected(field, object))
}

/// A domain as read: the set's keys whose value is `true`.
pub fn from_wire(object: &Value) -> Result<RemoteDomain, GatewayError> {
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| unexpected("name", object))?;
    let aliases = match object.get("aliases") {
        Some(Value::Object(set)) => set
            .iter()
            .filter(|(_, v)| v.as_bool() == Some(true))
            .map(|(k, _)| k.clone())
            .collect(),
        None | Some(Value::Null) => Vec::new(),
        Some(_) => return Err(unexpected("aliases", object)),
    };
    let catch_all = match object.get("catchAllAddress") {
        Some(Value::String(s)) => Some(s.clone()),
        None | Some(Value::Null) => None,
        Some(_) => return Err(unexpected("catchAllAddress", object)),
    };
    Ok(RemoteDomain {
        name: name.to_string(),
        aliases,
        catch_all,
        allow_relaying: object
            .get("allowRelaying")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        sub_addressing: type_of(object, "subAddressing")?,
        dkim: type_of(object, "dkimManagement")?,
        dns: type_of(object, "dnsManagement")?,
        certificate: type_of(object, "certificateManagement")?,
    })
}
