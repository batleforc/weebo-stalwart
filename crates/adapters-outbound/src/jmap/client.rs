//! The JMAP transport of Stalwart's management API: `GET <url>/jmap/session`
//! (the account the `x:` methods act in), `GET <url>/api/schema` (its
//! hash, read from the redirect's `Location`), and one method call per
//! `POST <url>/jmap`, authenticated by `Authorization: Bearer <API key>`
//! (marked sensitive: never logged nor traced).
//!
//! Every failure maps onto a [`GatewayError`]: it decides the reason code
//! the CR shows. Every call is counted in
//! `weebo_stalwart_api_requests_total{method, outcome}`.

use std::sync::LazyLock;
use std::time::Duration;

use application::ports::GatewayError;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use reqwest::{Client, RequestBuilder, Response, StatusCode, Url, header};
use serde::Deserialize;
use serde_json::{Value, json};

/// Per-request timeout: a hung server must not hold a reconcile forever.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The largest JSON answer read: generous for any session or method
/// response (thousands of objects), but `spec.url` is the tenant's, and a
/// server streaming an endless body must not exhaust the operator's memory.
pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
/// How much of an error answer is read: its start is all the message keeps.
const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;

/// What the `x:` methods need in `using` (the official CLI's).
const USING: [&str; 2] = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"];
/// The capability whose primary account the `x:` methods act in.
const MANAGEMENT_CAPABILITY: &str = "urn:stalwart:jmap";

static REQUESTS: LazyLock<Counter<u64>> = LazyLock::new(|| {
    opentelemetry::global::meter("weebo-stalwart-operator")
        // The Prometheus exporter appends `_total` to counters.
        .u64_counter("weebo_stalwart_api_requests")
        .with_description("Stalwart API calls, by JMAP method (or endpoint) and outcome")
        .build()
});

/// The `outcome` label: bounded, unlike error messages.
fn outcome_of<T>(result: &Result<T, GatewayError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(GatewayError::Unreachable(_)) => "unreachable",
        Err(GatewayError::Unauthorized(_)) => "unauthorized",
        Err(GatewayError::NotFound(_)) => "not_found",
        Err(GatewayError::AlreadyExists(_)) => "already_exists",
        Err(GatewayError::Linked(_)) => "linked",
        Err(GatewayError::Invalid(_)) => "invalid",
        Err(GatewayError::UnsupportedVersion(_)) => "unsupported_version",
        Err(GatewayError::Api(_)) => "error",
        // Not a call's: the factory's, before any.
        Err(GatewayError::AppPasswordKey(_)) => "token_secret",
    }
}

pub struct JmapClient {
    base: Url,
    token: String,
    http: Client,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Session {
    #[serde(default)]
    primary_accounts: std::collections::BTreeMap<String, String>,
}

impl JmapClient {
    /// `url`: the instance's `spec.url`. `Err` when it can't serve as a
    /// base URL. `http` must not follow redirects ([`Self::client_builder`]).
    pub fn new(url: &str, token: impl Into<String>, http: Client) -> Result<Self, String> {
        let base = Url::parse(url).map_err(|e| format!("url {url:?}: {e}"))?;
        if base.cannot_be_a_base() || !matches!(base.scheme(), "http" | "https") {
            return Err(format!("url {url:?}: not an http(s) base URL"));
        }
        Ok(Self {
            base,
            token: token.into(),
            http,
        })
    }

    /// The HTTP client settings the gateway needs: a timeout, and no
    /// redirect followed (the schema's hash is the redirect's target).
    pub fn client_builder() -> reqwest::ClientBuilder {
        Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
    }

    /// `{url}/<segments…>`, each segment percent-encoded.
    pub(crate) fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        url.path_segments_mut()
            // Checked in `new`.
            .expect("an http(s) URL is a base")
            .pop_if_empty()
            .extend(segments);
        url
    }

    async fn send(&self, request: RequestBuilder) -> Result<Response, GatewayError> {
        let response = request
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| GatewayError::Unreachable(e.without_url().to_string()))?;
        let status = response.status();
        if status.is_success() || status.is_redirection() {
            return Ok(response);
        }
        // Only the message's start: a broken body still reports the status.
        let body = read_body(response, MAX_ERROR_BODY_BYTES)
            .await
            .unwrap_or_else(|(head, _)| head);
        let body = String::from_utf8_lossy(&body);
        let why = format!("{status}: {}", body.chars().take(200).collect::<String>());
        Err(match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => GatewayError::Unauthorized(why),
            StatusCode::NOT_FOUND => GatewayError::NotFound(why),
            StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT => GatewayError::Unreachable(why),
            _ => GatewayError::Api(why),
        })
    }

    /// The account the `x:` methods act in: the token's own, the primary
    /// account of `urn:stalwart:jmap`.
    pub async fn account_id(&self) -> Result<String, GatewayError> {
        let result = async {
            let response = self
                .send(self.http.get(self.url(&["jmap", "session"])))
                .await?;
            let session: Session = json_body(response)
                .await
                .map_err(|e| GatewayError::Api(format!("unexpected session: {e}")))?;
            session
                .primary_accounts
                .get(MANAGEMENT_CAPABILITY)
                .cloned()
                .ok_or_else(|| {
                    GatewayError::Api(format!(
                        "the session has no {MANAGEMENT_CAPABILITY} account: not a Stalwart v0.16 \
                         management endpoint"
                    ))
                })
        }
        .await;
        REQUESTS.add(
            1,
            &[
                KeyValue::new("method", "session"),
                KeyValue::new("outcome", outcome_of(&result)),
            ],
        );
        result
    }

    /// The hash of the management schema the server serves: the last path
    /// segment of `GET /api/schema`'s redirect.
    pub async fn schema_hash(&self) -> Result<String, GatewayError> {
        let result = async {
            let response = self
                .send(self.http.get(self.url(&["api", "schema"])))
                .await?;
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .filter(|_| response.status().is_redirection())
                .ok_or_else(|| {
                    GatewayError::UnsupportedVersion(format!(
                        "GET /api/schema answered {} without a redirect to the schema's hash: not \
                         a Stalwart v0.16 server",
                        response.status()
                    ))
                })?;
            let hash = location
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or_default();
            Ok(hash.to_string())
        }
        .await;
        REQUESTS.add(
            1,
            &[
                KeyValue::new("method", "schema"),
                KeyValue::new("outcome", outcome_of(&result)),
            ],
        );
        result
    }

    /// One method call: its response arguments, or the method-level error
    /// mapped. `SetError`s stay in the answer (see [`set_error`]).
    pub async fn call(&self, method: &'static str, args: Value) -> Result<Value, GatewayError> {
        let result = async {
            let body = json!({"using": USING, "methodCalls": [[method, args, "0"]]});
            let response = self
                .send(self.http.post(self.url(&["jmap"])).json(&body))
                .await?;
            let mut answer: Value = json_body(response)
                .await
                .map_err(|e| GatewayError::Api(format!("unexpected answer to {method}: {e}")))?;
            let reply = answer
                .get_mut("methodResponses")
                .and_then(|r| r.get_mut(0))
                .map(Value::take)
                .ok_or_else(|| GatewayError::Api(format!("{method}: no method response")))?;
            match (reply.get(0).and_then(Value::as_str), reply.get(1)) {
                (Some("error"), Some(error)) => Err(method_error(method, error)),
                (Some(name), Some(args)) if name == method => Ok(args.clone()),
                _ => Err(GatewayError::Api(format!(
                    "{method}: unexpected response {reply}"
                ))),
            }
        }
        .await;
        REQUESTS.add(
            1,
            &[
                KeyValue::new("method", method),
                KeyValue::new("outcome", outcome_of(&result)),
            ],
        );
        result
    }
}

/// The body, read chunk by chunk up to `limit` bytes. `Err` carries what
/// was read before the transport failed or the limit was crossed.
async fn read_body(mut response: Response, limit: usize) -> Result<Vec<u8>, (Vec<u8>, String)> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(None) => return Ok(body),
            Ok(Some(chunk)) => {
                if chunk.len() > limit.saturating_sub(body.len()) {
                    let room = limit.saturating_sub(body.len());
                    body.extend_from_slice(chunk.get(..room).unwrap_or_default());
                    return Err((body, format!("body larger than {limit} bytes")));
                }
                body.extend_from_slice(&chunk);
            }
            Err(e) => return Err((body, e.without_url().to_string())),
        }
    }
}

/// The body as JSON, read up to [`MAX_BODY_BYTES`].
async fn json_body<T: serde::de::DeserializeOwned>(response: Response) -> Result<T, String> {
    let body = read_body(response, MAX_BODY_BYTES)
        .await
        .map_err(|(_, why)| why)?;
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}

fn describe(error: &Value) -> String {
    let kind = error.get("type").and_then(Value::as_str).unwrap_or("error");
    let mut why = kind.to_string();
    if let Some(d) = error.get("description").and_then(Value::as_str) {
        why.push_str(&format!(": {d}"));
    }
    if let Some(p) = error
        .get("properties")
        .and_then(Value::as_array)
        .filter(|p| !p.is_empty())
    {
        let props: Vec<&str> = p.iter().filter_map(Value::as_str).collect();
        why.push_str(&format!(" ({})", props.join(", ")));
    }
    if let Some(v) = error.get("validationErrors").and_then(Value::as_array) {
        for e in v {
            let (t, p) = (
                e.get("type").and_then(Value::as_str),
                e.get("property").and_then(Value::as_str),
            );
            why.push_str(&format!("; {}: {}", p.unwrap_or("?"), t.unwrap_or("?")));
        }
    }
    if let Some(o) = error.get("objectId") {
        let (object, id) = (
            o.get("object").and_then(Value::as_str),
            o.get("id").and_then(Value::as_str),
        );
        why.push_str(&format!(
            " [{} {}]",
            object.unwrap_or("?"),
            id.unwrap_or("?")
        ));
    }
    why
}

/// A method-level error (`["error", {...}]`).
fn method_error(method: &str, error: &Value) -> GatewayError {
    let why = format!("{method}: {}", describe(error));
    match error.get("type").and_then(Value::as_str) {
        // A token without the permission the method needs.
        Some("forbidden") | Some("accountNotFound") => GatewayError::Unauthorized(why),
        Some("unknownMethod") => GatewayError::UnsupportedVersion(why),
        _ => GatewayError::Api(why),
    }
}

/// A `SetError` of `notCreated`/`notUpdated`/`notDestroyed`.
pub fn set_error(method: &str, error: &Value) -> GatewayError {
    let why = format!("{method}: {}", describe(error));
    match error.get("type").and_then(Value::as_str) {
        Some("primaryKeyViolation") => GatewayError::AlreadyExists(why),
        Some("objectIsLinked") => GatewayError::Linked(why),
        Some("notFound") => GatewayError::NotFound(why),
        Some("forbidden") => GatewayError::Unauthorized(why),
        Some("invalidPatch" | "invalidProperties" | "validationFailed" | "invalidForeignKey") => {
            GatewayError::Invalid(why)
        }
        _ => GatewayError::Api(why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(url: &str) -> Result<JmapClient, String> {
        JmapClient::new(url, "t", Client::new())
    }

    #[test]
    fn paths_hang_off_the_base_url() {
        let c = client("https://mail.example.com/sub/").unwrap();
        assert_eq!(
            c.url(&["jmap", "session"]).as_str(),
            "https://mail.example.com/sub/jmap/session"
        );
        let c = client("http://stalwart:8080").unwrap();
        assert_eq!(
            c.url(&["api", "schema"]).as_str(),
            "http://stalwart:8080/api/schema"
        );
    }

    #[test]
    fn only_http_base_urls_are_accepted() {
        assert!(client("not a url").is_err());
        assert!(client("mailto:someone@example.com").is_err());
        assert!(client("ftp://example.com").is_err());
    }

    #[test]
    fn set_errors_map_to_their_cause() {
        let e = |v: Value| set_error("x:Domain/set", &v);
        assert!(matches!(
            e(json!({"type": "primaryKeyViolation", "properties": ["name"], "objectId": {"object": "Domain", "id": "b"}})),
            GatewayError::AlreadyExists(m) if m.contains("(name) [Domain b]")
        ));
        assert!(matches!(
            e(json!({"type": "objectIsLinked"})),
            GatewayError::Linked(_)
        ));
        assert!(matches!(
            e(json!({"type": "invalidPatch", "description": "Invalid domain name", "properties": ["name"]})),
            GatewayError::Invalid(m) if m.contains("Invalid domain name")
        ));
        assert!(matches!(
            e(json!({"type": "validationFailed", "validationErrors": [{"type": "Required", "property": "else"}]})),
            GatewayError::Invalid(m) if m.contains("else: Required")
        ));
        assert!(matches!(
            e(json!({"type": "notFound"})),
            GatewayError::NotFound(_)
        ));
        assert!(matches!(
            e(json!({"type": "surprise"})),
            GatewayError::Api(_)
        ));
    }
}
