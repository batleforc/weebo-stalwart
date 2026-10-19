//! `x:AppPassword` on the wire, as v0.16.27 speaks it (RFC 0001 D24): the
//! App Passwords of the account `accountId` names — another account than
//! the key's own, which needs `impersonate`.
//!
//! - `x:AppPassword/get` without `ids` lists them all; the secret reads
//!   back masked, so only `id` and `description` are asked for;
//! - Stalwart generates the secret (`app_…`) and returns it once, in
//!   `created.<key>.secret`; a client-chosen secret and an update of one
//!   are refused (`invalidPatch`): a rotation is a create and a destroy in
//!   the same `x:AppPassword/set`;
//! - `permissions: Inherit` would be the creator's own (the key's account),
//!   refused to a key that doesn't hold them all: `Replace` with
//!   `authenticate` and `emailSend`.

use application::ports::{APP_PASSWORD_DESCRIPTION, GatewayError};
use serde_json::{Value, json};

pub const GET: &str = "x:AppPassword/get";
pub const SET: &str = "x:AppPassword/set";

/// The creation key of the new App Password in the `/set` call.
const NEW: &str = "p";

/// What a list asks for: never the secret.
pub fn list(account: &str) -> Value {
    json!({"accountId": account, "properties": ["id", "description"]})
}

/// The ids of the operator's App Passwords in a `/get` answer: those
/// described [`APP_PASSWORD_DESCRIPTION`], and only those.
pub fn ours(answer: &Value) -> Vec<String> {
    answer
        .get("list")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| p.get("description").and_then(Value::as_str) == Some(APP_PASSWORD_DESCRIPTION))
        .filter_map(|p| p.get("id").and_then(Value::as_str).map(String::from))
        .collect()
}

// RFC 0001 Q25: `Replace` with `authenticate` and `emailSend` — `Inherit`
// is refused to the App Password key (it holds less than its account).
/// The `/set` creating a new App Password of the operator's on `account`
/// and destroying `previous`.
pub fn rotation(account: &str, previous: &[String]) -> Value {
    let mut args = json!({
        "accountId": account,
        "create": {NEW: {
            "description": APP_PASSWORD_DESCRIPTION,
            "permissions": {
                "@type": "Replace",
                "permissions": {"authenticate": true, "emailSend": true},
            },
        }},
    });
    if !previous.is_empty() {
        args["destroy"] = json!(previous);
    }
    args
}

/// The secret a rotation's answer carries. Errors never quote the answer:
/// it holds the secret.
pub fn secret(answer: &Value) -> Result<String, GatewayError> {
    if let Some(error) = answer.get("notCreated").and_then(|n| n.get(NEW)) {
        return Err(super::client::set_error(SET, error));
    }
    answer
        .pointer(&format!("/created/{NEW}/secret"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .ok_or_else(|| GatewayError::Api(format!("{SET}: no secret in the answer")))
}

/// The previous App Passwords the answer says were not destroyed.
pub fn not_destroyed(answer: &Value) -> Vec<String> {
    answer
        .get("notDestroyed")
        .and_then(Value::as_object)
        .map(|n| n.keys().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_operators_app_passwords_are_ours() {
        let answer = json!({"list": [
            {"id": "a", "description": "weebo-stalwart"},
            {"id": "b", "description": "thunderbird"},
            {"id": "c"},
            {"id": "d", "description": "weebo-stalwart"},
        ]});
        assert_eq!(ours(&answer), ["a", "d"]);
        assert!(ours(&json!({})).is_empty());
    }

    #[test]
    fn a_rotation_creates_and_destroys_in_one_call() {
        let first = rotation("x", &[]);
        assert!(first.get("destroy").is_none());
        assert_eq!(
            first["create"]["p"]["permissions"],
            json!({"@type": "Replace", "permissions": {"authenticate": true, "emailSend": true}})
        );
        assert_eq!(rotation("x", &["a".into()])["destroy"], json!(["a"]));
    }

    #[test]
    fn the_secret_is_read_and_never_quoted() {
        assert_eq!(
            secret(&json!({"created": {"p": {"id": "e", "secret": "app_s"}}})).unwrap(),
            "app_s"
        );
        let err = secret(&json!({"created": {"p": {"id": "e", "secret": ""}}})).unwrap_err();
        assert!(!err.to_string().contains("\"id\""), "{err}");
        let refused =
            secret(&json!({"notCreated": {"p": {"type": "forbidden", "description": "no"}}}));
        assert!(
            matches!(refused, Err(GatewayError::Unauthorized(_))),
            "{refused:?}"
        );
        assert_eq!(not_destroyed(&json!({"notDestroyed": {"a": {}}})), ["a"]);
        assert!(not_destroyed(&json!({})).is_empty());
    }
}
