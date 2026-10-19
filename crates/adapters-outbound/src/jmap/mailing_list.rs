//! `x:MailingList` on the wire: `aliases` an object list as an account's,
//! `recipients` a set of addresses (kept in the case sent).

use application::ports::{DesiredMailingList, GatewayError, MailingListPatch, RemoteMailingList};
use serde_json::{Map, Value};

use super::account::{aliases, aliases_from_wire, set, set_keys};

pub const PROPERTIES: &[&str] = &[
    "id",
    "name",
    "domainId",
    "emailAddress",
    "aliases",
    "recipients",
];

/// What [`find`](super::JmapGateway) reads of each candidate: the query
/// only filters by `text`.
pub const IDENTITY: &[&str] = &["id", "name", "domainId"];

pub fn create(desired: &DesiredMailingList) -> Value {
    let mut object = Map::new();
    object.insert("name".into(), desired.name.clone().into());
    object.insert("domainId".into(), desired.domain_id.clone().into());
    object.insert("aliases".into(), aliases(&desired.aliases));
    object.insert("recipients".into(), set(&desired.recipients));
    Value::Object(object)
}

pub fn patch(patch: &MailingListPatch) -> Value {
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
    if let Some(recipients) = &patch.recipients {
        object.insert("recipients".into(), set(recipients));
    }
    Value::Object(object)
}

const GET: &str = "x:MailingList/get";

fn string(object: &Value, field: &str) -> Result<String, GatewayError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| GatewayError::Api(format!("{GET}: unexpected {field} in {object}")))
}

pub fn from_wire(object: &Value) -> Result<RemoteMailingList, GatewayError> {
    Ok(RemoteMailingList {
        name: string(object, "name")?,
        domain_id: string(object, "domainId")?,
        email_address: string(object, "emailAddress")?,
        aliases: aliases_from_wire(GET, object)?,
        recipients: set_keys(object.get("recipients")),
    })
}
