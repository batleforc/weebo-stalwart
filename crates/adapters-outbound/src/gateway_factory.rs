//! One [`JmapGateway`] per instance — a `StalwartInstance` or a
//! `StalwartLocalInstance` — built on every call: the instance comes from
//! the kit's [`Instances`] (live reflector `Store`s when `operator::main`
//! wires them in, the API otherwise), its token is read fresh from
//! `tokenSecretRef` and its CA from `tls.caSecretRef` — a rotated token, an
//! edited `url` or a new CA takes effect on the next reconcile. The second
//! key, `appPasswordTokenSecretRef` (D24), is read the same way, by the
//! gateway, the first time a call needs it (a `StalwartServiceAccount`'s).
//! The HTTP client (its connection pool) is kept per URL, TLS options and
//! CA: only a change to one of them builds a new one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use api::common::TlsOptions;
use api::{Instance, LocalInstance};
use application::ports::{BoundInstance, GatewayFactory, GatewayFactoryError, RemoteGateway};
use kube::{Client, ResourceExt};
use weebo_kit_adapters::{
    Instances, Resolved, TokenSecretError, read_local_instance_token, read_secret_key,
};
use weebo_kit_api::SecretKeyRef;

use crate::jmap::{InvalidUrl, JmapClient, JmapGateway};

/// The operator's instances, both kinds: also its `InstanceDirectory`.
pub type OperatorInstances = Instances<Instance, LocalInstance>;

/// How many HTTP clients are kept: one per instance, with room for the
/// ones a rotated CA or an edited URL leaves behind.
const MAX_HTTP_CLIENTS: usize = 256;

/// What an HTTP client depends on: the server, `insecureSkipVerify`, the
/// CA's PEM.
type HttpKey = (String, bool, Option<Vec<u8>>);

pub struct JmapGatewayFactory {
    client: Client,
    instances: Arc<OperatorInstances>,
    http: Mutex<HashMap<HttpKey, reqwest::Client>>,
}

impl JmapGatewayFactory {
    pub fn new(client: Client, instances: Arc<OperatorInstances>) -> Self {
        Self {
            client,
            instances,
            http: Mutex::default(),
        }
    }

    /// The HTTP client for `url` with these TLS settings: the one kept, or
    /// a new one (an entry evicted when full).
    fn http(
        &self,
        url: &str,
        tls: &TlsOptions,
        ca: Option<Vec<u8>>,
    ) -> Result<reqwest::Client, GatewayFactoryError> {
        let key = (url.to_string(), tls.insecure_skip_verify, ca);
        // Plain values: a panic mid-insert leaves the map usable.
        let mut clients = self.http.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(http) = clients.get(&key) {
            return Ok(http.clone());
        }
        let http = http_client(tls, key.2.as_deref())?;
        if clients.len() >= MAX_HTTP_CLIENTS
            && let Some(old) = clients.keys().next().cloned()
        {
            clients.remove(&old);
        }
        clients.insert(key, http.clone());
        Ok(http)
    }

    async fn ca(&self, tls: &TlsOptions) -> Result<Option<Vec<u8>>, GatewayFactoryError> {
        let Some(r) = &tls.ca_secret_ref else {
            return Ok(None);
        };
        read_secret_key(&self.client, r)
            .await
            .map_err(GatewayFactoryError::Kubernetes)?
            .map(Some)
            .ok_or_else(|| {
                GatewayFactoryError::InvalidSpec(format!(
                    "tls.caSecretRef {}/{} has no key {:?}",
                    r.namespace, r.name, r.key
                ))
            })
    }
}

/// A token Secret's value. A local instance's token is only read from a
/// Secret labelled for it (`<group>/instance-token: "true"`): the operator
/// reads with its own rights, and the CR names the URL the token is sent
/// to. `field` names the reference in the errors.
async fn read_token(
    client: &Client,
    field: &str,
    secret_ref: &SecretKeyRef,
    local: bool,
) -> Result<String, GatewayFactoryError> {
    let where_ = || {
        format!(
            "{field}: secret {}/{} key {:?}",
            secret_ref.namespace, secret_ref.name, secret_ref.key
        )
    };
    let bytes = if local {
        read_local_instance_token(client, secret_ref, &api::ANNOTATIONS)
            .await
            .map_err(|e| match e {
                TokenSecretError::NotAllowed { .. } => {
                    GatewayFactoryError::TokenNotAllowed(format!("{field}: {e}"))
                }
                TokenSecretError::Kubernetes(e) => GatewayFactoryError::Kubernetes(e),
            })?
    } else {
        read_secret_key(client, secret_ref)
            .await
            .map_err(GatewayFactoryError::Kubernetes)?
    }
    .ok_or_else(|| GatewayFactoryError::TokenSecret(format!("{} not found", where_())))?;
    let token = String::from_utf8(bytes)
        .map_err(|_| GatewayFactoryError::TokenSecret(format!("{} is not UTF-8", where_())))?;
    // A token written with `echo` carries a trailing newline.
    Ok(token.trim().to_string())
}

/// The HTTP client of an instance: its timeout, no redirect followed, its
/// TLS options.
pub fn http_client(
    tls: &TlsOptions,
    ca_pem: Option<&[u8]>,
) -> Result<reqwest::Client, GatewayFactoryError> {
    let mut builder = JmapClient::client_builder();
    if let Some(pem) = ca_pem {
        let certs = reqwest::Certificate::from_pem_bundle(pem).map_err(|e| {
            GatewayFactoryError::InvalidSpec(format!("parsing tls.caSecretRef: {e}"))
        })?;
        if certs.is_empty() {
            return Err(GatewayFactoryError::InvalidSpec(
                "tls.caSecretRef contains no PEM certificate".into(),
            ));
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    if tls.insecure_skip_verify {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder
        .build()
        .map_err(|e| GatewayFactoryError::InvalidSpec(format!("building the HTTP client: {e}")))
}

fn invalid_url(e: InvalidUrl) -> GatewayFactoryError {
    GatewayFactoryError::InvalidSpec(e.to_string())
}

#[async_trait::async_trait]
impl GatewayFactory for JmapGatewayFactory {
    async fn gateway_for(
        &self,
        bound: &BoundInstance,
    ) -> Result<Arc<dyn RemoteGateway>, GatewayFactoryError> {
        let instance = self
            .instances
            .get(bound)
            .await
            .map_err(|e| GatewayFactoryError::Kubernetes(e.to_string()))?
            .ok_or_else(|| GatewayFactoryError::InstanceNotFound(bound.clone()))?;
        // A local instance's token and CA live in its own namespace.
        let (url, secret_ref, app_password_ref, tls, local) = match &instance {
            Resolved::Cluster(i) => (
                &i.spec.url,
                i.spec.token_secret_ref.clone(),
                i.spec.app_password_token_secret_ref.clone(),
                i.spec.tls.clone(),
                false,
            ),
            Resolved::Local(l) => {
                let namespace = l.namespace().unwrap_or_default();
                (
                    &l.spec.url,
                    l.spec.token_secret_ref.in_namespace(&namespace),
                    l.spec
                        .app_password_token_secret_ref
                        .as_ref()
                        .map(|r| r.in_namespace(&namespace)),
                    l.spec.tls.in_namespace(&namespace),
                    true,
                )
            }
        };
        let token = read_token(&self.client, "tokenSecretRef", &secret_ref, local).await?;
        let ca = self.ca(&tls).await?;
        let http = self.http(url, &tls, ca)?;
        let client = JmapClient::new(url, token, http.clone()).map_err(invalid_url)?;
        let mut gateway = JmapGateway::new(client);
        // RFC 0001 D24: the second key is read like the first, but only
        // when a call needs it — a `StalwartServiceAccount`'s.
        if let Some(secret_ref) = app_password_ref {
            let (kube, url) = (self.client.clone(), url.clone());
            gateway = gateway.with_app_password_key(Box::new(move || {
                let (kube, url, http, secret_ref) =
                    (kube.clone(), url.clone(), http.clone(), secret_ref.clone());
                Box::pin(async move {
                    let token =
                        read_token(&kube, "appPasswordTokenSecretRef", &secret_ref, local).await?;
                    JmapClient::new(&url, token, http).map_err(invalid_url)
                })
            }));
        }
        Ok(Arc::new(gateway))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_ca_is_refused() {
        assert!(http_client(&TlsOptions::default(), Some(b"nope")).is_err());
        assert!(http_client(&TlsOptions::default(), None).is_ok());
    }
}
