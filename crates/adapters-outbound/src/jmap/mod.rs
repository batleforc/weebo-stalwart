//! [`JmapGateway`]: the [`RemoteGateway`] over Stalwart v0.16's
//! management API, JMAP `x:` objects (`POST <url>/jmap`). Wire rules the
//! mapping follows (checked against v0.16.27, contract and live tests):
//!
//! - a set (`Set<…>`: a domain's `aliases`) is a map `{"value": true}`;
//! - an object list (an account's `aliases`, `credentials`) is a map keyed
//!   by a decimal index, `{"0": {...}}`;
//! - a variant object carries `@type`; sending a variant of another type
//!   rebuilds it from the server's defaults (`dkimManagement: Automatic`
//!   gets Stalwart's default algorithms and schedule);
//! - an update is a patch: only the properties sent change, a top-level
//!   value replaces the whole property;
//! - a patch may also address one entry (`quotas/maxDiskQuota`,
//!   `credentials/0/secret`): only that entry changes;
//! - ids are short strings (`"b"`, `"c"`…), one sequence per object type,
//!   restarting with the store;
//! - an address — an account's, a group's, a list's, or one of their
//!   aliases — is unique across all of them (`primaryKeyViolation` on
//!   `email`).
//!
//! Before its first call, a gateway reads the session (the account the
//! `x:` methods act in) and the schema's hash: an unknown hash fails every
//! call with `UnsupportedVersion` — no write is attempted against a
//! management schema this release wasn't tested with (D13).
//!
//! The service accounts' App Passwords go through a second client, with
//! the instance's second key (`appPasswordTokenSecretRef`, D24), loaded
//! the first time a call needs it: the other kinds never read that key.

mod account;
mod app_password;
mod client;
mod domain;
mod mailing_list;

use application::ports::{
    AccountPatch, DesiredAccount, DesiredDomain, DesiredMailingList, DomainPatch, GatewayError,
    GatewayFactoryError, MailingListPatch, RemoteAccount, RemoteDomain, RemoteGateway,
    RemoteMailingList,
};
use futures::future::BoxFuture;
use serde_json::{Value, json};
use tokio::sync::OnceCell;

pub use client::{InvalidUrl, JmapClient, MAX_BODY_BYTES, REQUEST_TIMEOUT};

/// The hashes of the management schemas this release speaks (base64url
/// SHA-256, the last segment of `GET /api/schema`'s redirect), with the
/// Stalwart releases observed serving each. The hash only moves when the
/// schema does: v0.16.25 to v0.16.27 serve the same one, v0.16.0 another.
// RFC 0001 Q10: observed on the images, the hash is the schema's, not the
// release's (v0.16.25, .26, .27 identical, v0.16.0 different): D13 costs a
// release only when the schema moves. Kept as a constant, not a field.
pub const SUPPORTED_SCHEMAS: &[(&str, &str)] = &[(
    "Pzykh-dZ4p6qVJ7wVulQvyF7-1aRB8fI6GcjdJMWK2Q",
    "v0.16.25 – v0.16.27",
)];

/// Reads the App Password key and builds its client: called once, the
/// first time a gateway needs it.
pub type AppPasswordKeyLoader =
    Box<dyn Fn() -> BoxFuture<'static, Result<JmapClient, GatewayFactoryError>> + Send + Sync>;

pub struct JmapGateway {
    client: JmapClient,
    /// The `urn:stalwart:jmap` account, once the session and the schema
    /// were checked.
    account: OnceCell<String>,
    /// Where the App Password key comes from: `None` when the instance
    /// sets none.
    app_password_key: Option<AppPasswordKeyLoader>,
    /// The client of the App Password key, once loaded.
    app_passwords: OnceCell<JmapClient>,
}

impl JmapGateway {
    /// A gateway without the App Password key: `rotate_app_password`
    /// fails with `AppPasswordKey`.
    pub fn new(client: JmapClient) -> Self {
        Self {
            client,
            account: OnceCell::new(),
            app_password_key: None,
            app_passwords: OnceCell::new(),
        }
    }

    /// The App Password key, read by `load` when first needed.
    pub fn with_app_password_key(mut self, load: AppPasswordKeyLoader) -> Self {
        self.app_password_key = Some(load);
        self
    }

    /// The App Password key's client, already built.
    pub fn with_app_password_client(mut self, client: JmapClient) -> Self {
        self.app_passwords = OnceCell::new_with(Some(client));
        self
    }

    /// The App Password key's client, loaded on first use.
    async fn app_password_client(&self) -> Result<&JmapClient, GatewayError> {
        if let Some(client) = self.app_passwords.get() {
            return Ok(client);
        }
        let Some(load) = &self.app_password_key else {
            return Err(GatewayError::AppPasswordKey(Box::new(
                GatewayFactoryError::TokenSecret(
                    "the instance sets no appPasswordTokenSecretRef: the API key that creates \
                     the service accounts' App Passwords"
                        .into(),
                ),
            )));
        };
        self.app_passwords
            .get_or_try_init(load)
            .await
            .map_err(|e| GatewayError::AppPasswordKey(Box::new(e)))
    }

    // RFC 0001 Q12: the session and the schema are read once per gateway,
    // that is once per reconcile (a gateway is built per call to the
    // factory): two GETs before the first method call, no cache across
    // reconciles. `accountId` is the session's `urn:stalwart:jmap` primary
    // account rather than left out (Stalwart would default it).
    /// The session's account, after the schema check (once per gateway).
    async fn account(&self) -> Result<&str, GatewayError> {
        self.account
            .get_or_try_init(|| async {
                let (account, hash) =
                    tokio::try_join!(self.client.account_id(), self.client.schema_hash())?;
                if !SUPPORTED_SCHEMAS.iter().any(|(h, _)| *h == hash) {
                    let supported: Vec<&str> = SUPPORTED_SCHEMAS.iter().map(|(_, v)| *v).collect();
                    return Err(GatewayError::UnsupportedVersion(format!(
                        "Stalwart serves management schema {hash:?}, which this operator release \
                         was not tested against (supported: Stalwart {})",
                        supported.join(", ")
                    )));
                }
                Ok(account)
            })
            .await
            .map(String::as_str)
    }

    /// `<object>/get` of one id, restricted to `properties`: the object, or
    /// `None` when Stalwart doesn't know the id.
    async fn get(
        &self,
        method: &'static str,
        id: &str,
        properties: &[&str],
    ) -> Result<Option<Value>, GatewayError> {
        let account = self.account().await?;
        let mut answer = self
            .client
            .call(
                method,
                json!({"accountId": account, "ids": [id], "properties": properties}),
            )
            .await?;
        Ok(answer
            .get_mut("list")
            .and_then(Value::as_array_mut)
            .and_then(|list| {
                list.iter_mut()
                    .find(|o| o.get("id").and_then(Value::as_str) == Some(id))
            })
            .map(Value::take))
    }

    /// `<object>/set` creating `object`: its id.
    async fn create(&self, method: &'static str, object: Value) -> Result<String, GatewayError> {
        let account = self.account().await?;
        let answer = self
            .client
            .call(
                method,
                json!({"accountId": account, "create": {"new": object}}),
            )
            .await?;
        if let Some(error) = answer.pointer("/notCreated/new") {
            return Err(client::set_error(method, error));
        }
        answer
            .pointer("/created/new/id")
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| GatewayError::Api(format!("{method}: no id created in {answer}")))
    }

    /// `<object>/set` updating `id` with `patch`.
    async fn update(
        &self,
        method: &'static str,
        id: &str,
        patch: Value,
    ) -> Result<(), GatewayError> {
        let account = self.account().await?;
        let answer = self
            .client
            .call(method, json!({"accountId": account, "update": {id: patch}}))
            .await?;
        if let Some(error) = answer.get("notUpdated").and_then(|n| n.get(id)) {
            return Err(client::set_error(method, error));
        }
        match answer.get("updated").and_then(|u| u.get(id)) {
            Some(_) => Ok(()),
            None => Err(GatewayError::Api(format!(
                "{method}: {id} not updated in {answer}"
            ))),
        }
    }

    /// `<object>/set` destroying `id`: `true`, or `false` when it was
    /// already gone.
    async fn destroy(&self, method: &'static str, id: &str) -> Result<bool, GatewayError> {
        let account = self.account().await?;
        let answer = self
            .client
            .call(method, json!({"accountId": account, "destroy": [id]}))
            .await?;
        if let Some(error) = answer.get("notDestroyed").and_then(|n| n.get(id)) {
            return match client::set_error(method, error) {
                GatewayError::NotFound(_) => Ok(false),
                e => Err(e),
            };
        }
        let destroyed = answer
            .get("destroyed")
            .and_then(Value::as_array)
            .is_some_and(|d| d.iter().any(|x| x.as_str() == Some(id)));
        if destroyed {
            Ok(true)
        } else {
            Err(GatewayError::Api(format!(
                "{method}: {id} not destroyed in {answer}"
            )))
        }
    }

    /// `<object>/query` with `filter`: the ids found.
    async fn query(
        &self,
        method: &'static str,
        filter: Value,
    ) -> Result<Vec<String>, GatewayError> {
        let account = self.account().await?;
        let answer = self
            .client
            .call(method, json!({"accountId": account, "filter": filter}))
            .await?;
        Ok(answer
            .get("ids")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default())
    }
}

#[async_trait::async_trait]
impl RemoteGateway for JmapGateway {
    async fn ping(&self) -> Result<(), GatewayError> {
        self.account().await.map(|_| ())
    }

    async fn get_domain(&self, id: &str) -> Result<Option<RemoteDomain>, GatewayError> {
        match self.get("x:Domain/get", id, domain::PROPERTIES).await? {
            Some(object) => domain::from_wire(&object).map(Some),
            None => Ok(None),
        }
    }

    async fn find_domain(&self, name: &str) -> Result<Option<String>, GatewayError> {
        let name = ::domain::mail::normalize_domain(name);
        Ok(self
            .query("x:Domain/query", json!({"name": name}))
            .await?
            .into_iter()
            .next())
    }

    async fn create_domain(&self, desired: &DesiredDomain) -> Result<String, GatewayError> {
        self.create("x:Domain/set", domain::create(desired)).await
    }

    async fn update_domain(&self, id: &str, patch: &DomainPatch) -> Result<(), GatewayError> {
        self.update("x:Domain/set", id, domain::patch(patch)).await
    }

    async fn get_account(&self, id: &str) -> Result<Option<RemoteAccount>, GatewayError> {
        match self.get("x:Account/get", id, account::PROPERTIES).await? {
            Some(object) => account::from_wire(&object).map(Some),
            None => Ok(None),
        }
    }

    async fn find_account(
        &self,
        domain_id: &str,
        name: &str,
    ) -> Result<Option<String>, GatewayError> {
        // The filter is exact: Stalwart stores names lowercased.
        let name = ::domain::mail::normalize_local_part(name);
        Ok(self
            .query(
                "x:Account/query",
                json!({"name": name, "domainId": domain_id}),
            )
            .await?
            .into_iter()
            .next())
    }

    async fn create_account(&self, desired: &DesiredAccount) -> Result<String, GatewayError> {
        self.create("x:Account/set", account::create(desired)).await
    }

    async fn update_account(&self, id: &str, patch: &AccountPatch) -> Result<(), GatewayError> {
        self.update("x:Account/set", id, account::patch(patch))
            .await
    }

    async fn app_password_key(&self) -> Result<(), GatewayError> {
        self.app_password_client().await.map(|_| ())
    }

    async fn rotate_app_password(&self, id: &str) -> Result<String, GatewayError> {
        let key = self.app_password_client().await?;
        // The schema is checked (D13) before a write, with the main key.
        self.account().await?;
        let listed = key.call(app_password::GET, app_password::list(id)).await?;
        let previous = app_password::ours(&listed);
        let answer = key
            .call(app_password::SET, app_password::rotation(id, &previous))
            .await?;
        let secret = app_password::secret(&answer)?;
        let kept = app_password::not_destroyed(&answer);
        if !kept.is_empty() {
            // The new one works: the next rotation revokes these.
            tracing::warn!(account = id, ?kept, "previous App Passwords not revoked");
        }
        Ok(secret)
    }

    async fn delete_account(&self, id: &str) -> Result<bool, GatewayError> {
        self.destroy("x:Account/set", id).await
    }

    async fn get_mailing_list(&self, id: &str) -> Result<Option<RemoteMailingList>, GatewayError> {
        match self
            .get("x:MailingList/get", id, mailing_list::PROPERTIES)
            .await?
        {
            Some(object) => mailing_list::from_wire(&object).map(Some),
            None => Ok(None),
        }
    }

    async fn find_mailing_list(
        &self,
        domain_id: &str,
        name: &str,
    ) -> Result<Option<String>, GatewayError> {
        // `x:MailingList/query` only filters by `text`: each candidate is
        // read and matched on its name and domain.
        let name = ::domain::mail::normalize_local_part(name);
        for id in self
            .query("x:MailingList/query", json!({"text": name}))
            .await?
        {
            let Some(found) = self
                .get("x:MailingList/get", &id, mailing_list::IDENTITY)
                .await?
            else {
                continue;
            };
            let same_name = found.get("name").and_then(Value::as_str) == Some(name.as_str());
            let same_domain = found.get("domainId").and_then(Value::as_str) == Some(domain_id);
            if same_name && same_domain {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    async fn create_mailing_list(&self, list: &DesiredMailingList) -> Result<String, GatewayError> {
        self.create("x:MailingList/set", mailing_list::create(list))
            .await
    }

    async fn update_mailing_list(
        &self,
        id: &str,
        patch: &MailingListPatch,
    ) -> Result<(), GatewayError> {
        self.update("x:MailingList/set", id, mailing_list::patch(patch))
            .await
    }

    async fn delete_mailing_list(&self, id: &str) -> Result<bool, GatewayError> {
        self.destroy("x:MailingList/set", id).await
    }
}
