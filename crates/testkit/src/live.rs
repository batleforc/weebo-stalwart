//! The live suites' Stalwart: a real server (v0.16.27, `task
//! stalwart:container:start`), reached through `STALWART_URL` with the
//! operator's API key `STALWART_TOKEN` and its App Password key
//! `STALWART_APP_PASSWORD_TOKEN` (RFC 0001 D24) — exported, or read from
//! `.stalwart-test.env` at the workspace root. `STALWART_ADMIN` (the
//! recovery admin, `user:password`) lets a suite do what the operator's key
//! may not, such as deleting the domains it created. `STALWART_SUBMISSION`
//! and `STALWART_SMTP` (`host:port`) are its submission (587, STARTTLS)
//! and MX (25) listeners, for the SMTP-level tests.

use std::collections::BTreeMap;
use std::path::Path;

/// `STALWART_URL`, `STALWART_TOKEN`, `STALWART_APP_PASSWORD_TOKEN`,
/// `STALWART_ADMIN`, `STALWART_SUBMISSION`, `STALWART_SMTP`.
#[derive(Debug, Clone)]
pub struct LiveStalwart {
    pub url: String,
    pub token: String,
    /// The second key of the operator's account, the one that creates the
    /// service accounts' App Passwords.
    pub app_password_token: String,
    pub admin: Option<(String, String)>,
    pub submission: Option<String>,
    pub smtp: Option<String>,
}

impl LiveStalwart {
    /// From the environment, then `.stalwart-test.env`; panics with the
    /// way to get one when neither has `STALWART_URL`/`STALWART_TOKEN`/
    /// `STALWART_APP_PASSWORD_TOKEN`.
    pub fn from_env() -> Self {
        let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.stalwart-test.env");
        let mut vars: BTreeMap<String, String> = std::fs::read_to_string(file)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();
        for key in [
            "STALWART_URL",
            "STALWART_TOKEN",
            "STALWART_APP_PASSWORD_TOKEN",
            "STALWART_ADMIN",
            "STALWART_SUBMISSION",
            "STALWART_SMTP",
        ] {
            if let Ok(v) = std::env::var(key) {
                vars.insert(key.to_string(), v);
            }
        }
        let need = |k: &str| {
            vars.get(k).cloned().unwrap_or_else(|| {
                panic!("{k} unset: run `task stalwart:container:start ENGINE=podman` first")
            })
        };
        Self {
            url: need("STALWART_URL"),
            token: need("STALWART_TOKEN"),
            app_password_token: need("STALWART_APP_PASSWORD_TOKEN"),
            admin: vars
                .get("STALWART_ADMIN")
                .and_then(|a| a.split_once(':'))
                .map(|(u, p)| (u.to_string(), p.to_string())),
            submission: vars.get("STALWART_SUBMISSION").cloned(),
            smtp: vars.get("STALWART_SMTP").cloned(),
        }
    }

    /// A name no earlier run used: `<prefix>-<unique>.internal`.
    pub fn unique_domain(prefix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{prefix}-{:x}.internal", nanos % 0xffff_ffff)
    }
}

impl LiveStalwart {
    /// One JMAP method call as the recovery admin (what the operator's key
    /// may not do: destroying a domain, editing behind its back): the
    /// method's response arguments.
    pub async fn admin_call(&self, method: &str, args: serde_json::Value) -> serde_json::Value {
        let (user, password) = self.admin.as_ref().expect("STALWART_ADMIN unset");
        self.call_as(Some((user, password)), None, method, args)
            .await
    }

    /// One JMAP method call with the operator's own key, unchecked: for
    /// the spike tests probing what that key may do.
    pub async fn token_call(&self, method: &str, args: serde_json::Value) -> serde_json::Value {
        self.call_as(None, Some(&self.token), method, args).await
    }

    async fn call_as(
        &self,
        basic: Option<(&String, &String)>,
        bearer: Option<&str>,
        method: &str,
        args: serde_json::Value,
    ) -> serde_json::Value {
        let body = serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
            "methodCalls": [[method, args, "0"]],
        });
        let mut request = reqwest::Client::new()
            .post(format!("{}/jmap", self.url))
            .json(&body);
        if let Some((user, password)) = basic {
            request = request.basic_auth(user, Some(password));
        }
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        let answer: serde_json::Value = request
            .send()
            .await
            .expect("Stalwart answers")
            .error_for_status()
            .expect("a JMAP answer")
            .json()
            .await
            .expect("JSON");
        answer["methodResponses"][0][1].clone()
    }

    /// The HTTP status of `GET /jmap/session` logging in as `user` with
    /// `password` (Basic): `200` logged in, `401` refused, `403` an account
    /// whose `Authenticate` permission is disabled.
    pub async fn login(&self, user: &str, password: &str) -> u16 {
        reqwest::Client::new()
            .get(format!("{}/jmap/session", self.url))
            .basic_auth(user, Some(password))
            .send()
            .await
            .expect("Stalwart answers")
            .status()
            .as_u16()
    }

    /// One JMAP method call as `user` (Basic): what a user does in the web
    /// interface, such as creating an App Password.
    pub async fn user_call(
        &self,
        user: &str,
        password: &str,
        method: &str,
        args: serde_json::Value,
    ) -> serde_json::Value {
        let (user, password) = (user.to_string(), password.to_string());
        self.call_as(Some((&user, &password)), None, method, args)
            .await
    }

    /// Destroys the domain named `name` and everything in it, as the
    /// recovery admin (the operator's key can't): its mailing lists, its
    /// users, then its groups (a group with members is `objectIsLinked`),
    /// then its DKIM keys (`Automatic` DKIM generates `x:DkimSignature`s
    /// that keep a domain from being destroyed), then the domain.
    pub async fn destroy_domain(&self, name: &str) {
        let ids = self
            .admin_call(
                "x:Domain/query",
                serde_json::json!({"filter": {"name": name}}),
            )
            .await["ids"]
            .clone();
        for id in ids.as_array().into_iter().flatten() {
            // `x:MailingList/query` doesn't filter by domain.
            let lists = self
                .admin_call("x:MailingList/query", serde_json::json!({}))
                .await["ids"]
                .clone();
            let lists = self
                .admin_call(
                    "x:MailingList/get",
                    serde_json::json!({"ids": lists, "properties": ["id", "domainId"]}),
                )
                .await["list"]
                .clone();
            let in_domain: Vec<serde_json::Value> = lists
                .as_array()
                .into_iter()
                .flatten()
                .filter(|l| l["domainId"] == *id)
                .map(|l| l["id"].clone())
                .collect();
            self.admin_call(
                "x:MailingList/set",
                serde_json::json!({"destroy": in_domain}),
            )
            .await;
            for filter in [
                serde_json::json!({"domainId": id, "@type": "User"}),
                serde_json::json!({"domainId": id}),
            ] {
                let accounts = self
                    .admin_call("x:Account/query", serde_json::json!({"filter": filter}))
                    .await["ids"]
                    .clone();
                self.admin_call("x:Account/set", serde_json::json!({"destroy": accounts}))
                    .await;
            }
            let keys = self
                .admin_call(
                    "x:DkimSignature/query",
                    serde_json::json!({"filter": {"domainId": id}}),
                )
                .await["ids"]
                .clone();
            self.admin_call("x:DkimSignature/set", serde_json::json!({"destroy": keys}))
                .await;
            self.admin_call("x:Domain/set", serde_json::json!({"destroy": [id]}))
                .await;
        }
    }
}
