//! In-memory ports for use-case and controller tests (exposed to other
//! crates by the `test-support` feature): a Stalwart ([`FakeGateway`]) and
//! the cluster reads ([`FakeCluster`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use api::namespace_policy::NamespaceRule;
use domain::account::{AccountType, PermissionsUpdate, RemoteAlias, RemotePermissions};
use domain::mail::{normalize_domain, normalize_local_part};

use crate::ports::{
    APP_PASSWORD_DESCRIPTION, AccountPatch, BoundInstance, ClaimKind, ClusterError, ClusterReader,
    DesiredAccount, DesiredDomain, DesiredMailingList, DomainPatch, DomainState, GatewayError,
    InstanceSettings, MailingListPatch, PolicySource, RemoteAccount, RemoteDomain, RemoteGateway,
    RemoteMailingList,
};

pub use weebo_kit_application::test_support::FakeSecretStore;

/// Domains keyed by id. Ids are handed out in creation order (`"1"`,
/// `"2"`…) and kept across updates, like a real server's; names are
/// unique and stored lowercased, as Stalwart does. Every write is recorded
/// ([`FakeGateway::writes`]): a reconcile with nothing to change must leave
/// it empty.
///
/// Accounts and lists follow Stalwart's rules too: an address — an
/// account's, a list's, or one of their aliases — is unique across all of
/// them (`AlreadyExists`), `emailAddress` is `name@domain`, a `User` gets
/// `locale: en-US` when created without one. App Passwords are kept apart
/// ([`FakeGateway::app_passwords`]), never in the account read back; a
/// rotation revokes the operator's ([`APP_PASSWORD_DESCRIPTION`]) only.
#[derive(Default)]
pub struct FakeGateway {
    domains: Mutex<BTreeMap<String, RemoteDomain>>,
    accounts: Mutex<BTreeMap<String, RemoteAccount>>,
    lists: Mutex<BTreeMap<String, RemoteMailingList>>,
    /// Per account: `(description, secret)`, oldest first.
    app_passwords: Mutex<BTreeMap<String, Vec<(String, String)>>>,
    /// Why the App Password key is unusable, `None` when it is.
    app_password_key: Mutex<Option<GatewayError>>,
    /// Objects other objects still use: their deletion is `Linked`.
    linked: Mutex<BTreeSet<String>>,
    next_id: Mutex<u64>,
    failure: Mutex<Option<GatewayError>>,
    writes: Mutex<Vec<String>>,
}

impl FakeGateway {
    /// Every call fails with `failure` until it is set back to `None`.
    pub fn fail_with(&self, failure: Option<GatewayError>) {
        *self.failure.lock().unwrap() = failure;
    }

    pub fn domain(&self, id: &str) -> Option<RemoteDomain> {
        self.domains.lock().unwrap().get(id).cloned()
    }

    /// The domain named `name`, with its id.
    pub fn domain_named(&self, name: &str) -> Option<(String, RemoteDomain)> {
        self.domains
            .lock()
            .unwrap()
            .iter()
            .find(|(_, d)| d.name == name)
            .map(|(id, d)| (id.clone(), d.clone()))
    }

    /// A domain created behind the operator's back (by hand, by the
    /// bootstrap plan); returns its id. Not recorded as a write.
    pub fn seed_domain(&self, name: &str) -> String {
        let id = self.next_id();
        self.domains.lock().unwrap().insert(
            id.clone(),
            stored(&DesiredDomain::new(
                name,
                &[],
                None,
                domain::mail_domain::SubAddressing::Enabled,
                domain::mail_domain::DkimManagement::Automatic,
            )),
        );
        id
    }

    /// Changes the domain `id` behind the operator's back (a drift).
    pub fn edit_domain(&self, id: &str, edit: impl FnOnce(&mut RemoteDomain)) {
        if let Some(domain) = self.domains.lock().unwrap().get_mut(id) {
            edit(domain);
        }
    }

    /// The writes received, oldest first: `create weebo.internal`,
    /// `update 1 [aliases, subAddressing]`.
    pub fn writes(&self) -> Vec<String> {
        self.writes.lock().unwrap().clone()
    }

    pub fn clear_writes(&self) {
        self.writes.lock().unwrap().clear();
    }

    pub fn account(&self, id: &str) -> Option<RemoteAccount> {
        self.accounts.lock().unwrap().get(id).cloned()
    }

    /// The account (or group) whose address is `address`, with its id.
    pub fn account_at(&self, address: &str) -> Option<(String, RemoteAccount)> {
        self.accounts
            .lock()
            .unwrap()
            .iter()
            .find(|(_, a)| a.email_address == address)
            .map(|(id, a)| (id.clone(), a.clone()))
    }

    /// The App Password of the operator's on the account `id` (the last
    /// one created: a rotation revokes the others).
    pub fn app_password(&self, id: &str) -> Option<String> {
        self.app_passwords(id)
            .into_iter()
            .rev()
            .find(|(d, _)| d == APP_PASSWORD_DESCRIPTION)
            .map(|(_, s)| s)
    }

    /// Every App Password of the account `id`: `(description, secret)`,
    /// oldest first.
    pub fn app_passwords(&self, id: &str) -> Vec<(String, String)> {
        self.app_passwords
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    /// An App Password created behind the operator's back (by the
    /// account's user): returns its secret. Not recorded as a write.
    pub fn seed_app_password(&self, id: &str, description: &str) -> String {
        let secret = format!("app_{}", self.next_id());
        self.app_passwords
            .lock()
            .unwrap()
            .entry(id.to_string())
            .or_default()
            .push((description.to_string(), secret.clone()));
        secret
    }

    /// The App Password key fails with `failure` until set back to `None`
    /// (an instance without `appPasswordTokenSecretRef`).
    pub fn fail_app_password_key(&self, failure: Option<GatewayError>) {
        *self.app_password_key.lock().unwrap() = failure;
    }

    /// An account created behind the operator's back (the OpenID Connect
    /// login, by hand); returns its id. Not recorded as a write.
    pub fn seed_account(&self, kind: AccountType, name: &str, domain_id: &str) -> String {
        let id = self.next_id();
        let desired = DesiredAccount::new(kind, name, domain_id, &[]);
        let account = self.stored_account(&desired).expect("a known domain");
        self.accounts.lock().unwrap().insert(id.clone(), account);
        id
    }

    /// Changes the account `id` behind the operator's back (a drift).
    pub fn edit_account(&self, id: &str, edit: impl FnOnce(&mut RemoteAccount)) {
        if let Some(account) = self.accounts.lock().unwrap().get_mut(id) {
            edit(account);
        }
    }

    pub fn mailing_list(&self, id: &str) -> Option<RemoteMailingList> {
        self.lists.lock().unwrap().get(id).cloned()
    }

    /// Changes the list `id` behind the operator's back (a drift).
    pub fn edit_mailing_list(&self, id: &str, edit: impl FnOnce(&mut RemoteMailingList)) {
        if let Some(list) = self.lists.lock().unwrap().get_mut(id) {
            edit(list);
        }
    }

    /// The object `id` is in use (a group with members): deleting it is
    /// `Linked` until [`FakeGateway::unlink`].
    pub fn link(&self, id: &str) {
        self.linked.lock().unwrap().insert(id.to_string());
    }

    pub fn unlink(&self, id: &str) {
        self.linked.lock().unwrap().remove(id);
    }

    fn domain_name(&self, domain_id: &str) -> Result<String, GatewayError> {
        self.domain(domain_id).map(|d| d.name).ok_or_else(|| {
            GatewayError::Invalid(format!("invalidForeignKey: no domain {domain_id}"))
        })
    }

    /// Every address in use but `except`'s: accounts', lists', aliases'.
    fn addresses(&self, except: Option<&str>) -> Vec<String> {
        let domains = self.domains.lock().unwrap().clone();
        let alias_address = |a: &RemoteAlias| {
            domains
                .get(&a.domain_id)
                .map(|d| format!("{}@{}", a.name, d.name))
        };
        let mut taken = Vec::new();
        for (id, a) in self.accounts.lock().unwrap().iter() {
            if Some(id.as_str()) != except {
                taken.push(a.email_address.clone());
                taken.extend(a.aliases.iter().filter_map(alias_address));
            }
        }
        for (id, l) in self.lists.lock().unwrap().iter() {
            if Some(id.as_str()) != except {
                taken.push(l.email_address.clone());
                taken.extend(l.aliases.iter().filter_map(alias_address));
            }
        }
        taken
    }

    fn check_free(
        &self,
        name: &str,
        domain_id: &str,
        aliases: &[domain::account::Alias],
        except: Option<&str>,
    ) -> Result<String, GatewayError> {
        let domain = self.domain_name(domain_id)?;
        let address = format!("{name}@{domain}");
        let taken = self.addresses(except);
        let mut wanted = vec![address.clone()];
        for alias in aliases {
            wanted.push(format!(
                "{}@{}",
                alias.name,
                self.domain_name(&alias.domain_id)?
            ));
        }
        if let Some(clash) = wanted.iter().find(|a| taken.contains(a)) {
            return Err(GatewayError::AlreadyExists(format!(
                "primaryKeyViolation: {clash:?} is taken"
            )));
        }
        Ok(address)
    }

    /// What Stalwart stores for `desired`.
    fn stored_account(&self, desired: &DesiredAccount) -> Result<RemoteAccount, GatewayError> {
        let email_address = self.domain_name(&desired.domain_id)?;
        let disabled: Vec<String> = desired
            .permissions
            .iter()
            .flat_map(|p| p.disabled.iter().map(|d| d.to_string()))
            .collect();
        Ok(RemoteAccount {
            kind: desired.kind.as_str().into(),
            name: desired.name.clone(),
            domain_id: desired.domain_id.clone(),
            email_address: format!("{}@{email_address}", desired.name),
            aliases: remote_aliases(&desired.aliases),
            role: desired.role.as_str().into(),
            permissions: if disabled.is_empty() {
                RemotePermissions::Inherit
            } else {
                RemotePermissions::Merge {
                    enabled: Vec::new(),
                    disabled,
                }
            },
            quotas: desired
                .quota
                .map(|q| BTreeMap::from([(RemoteAccount::DISK_QUOTA.to_string(), q)]))
                .unwrap_or_default(),
            locale: Some(
                desired
                    .locale
                    .clone()
                    .unwrap_or_else(|| "en-US".to_string()),
            ),
            time_zone: desired.time_zone.clone(),
        })
    }

    fn check(&self) -> Result<(), GatewayError> {
        match self.failure.lock().unwrap().clone() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn wrote(&self, write: String) {
        self.writes.lock().unwrap().push(write);
    }

    fn next_id(&self) -> String {
        let mut next = self.next_id.lock().unwrap();
        *next += 1;
        next.to_string()
    }

    fn taken(&self, name: &str, except: Option<&str>) -> bool {
        self.domains
            .lock()
            .unwrap()
            .iter()
            .any(|(id, d)| Some(id.as_str()) != except && d.name == name)
    }
}

/// What Stalwart stores for `desired`: the server's own normalization
/// (lowercased name and catch-all, aliases as sent).
fn stored(desired: &DesiredDomain) -> RemoteDomain {
    RemoteDomain {
        name: desired.name.clone(),
        aliases: desired.aliases.clone(),
        catch_all: desired.catch_all.clone(),
        allow_relaying: DesiredDomain::ALLOW_RELAYING,
        sub_addressing: desired.sub_addressing.as_str().into(),
        dkim: desired.dkim.as_str().into(),
        dns: DesiredDomain::DNS_MANAGEMENT.into(),
        certificate: DesiredDomain::CERTIFICATE_MANAGEMENT.into(),
    }
}

fn remote_aliases(aliases: &[domain::account::Alias]) -> Vec<RemoteAlias> {
    aliases
        .iter()
        .map(|a| RemoteAlias {
            name: a.name.clone(),
            domain_id: a.domain_id.clone(),
            enabled: true,
        })
        .collect()
}

/// The JMAP field names of an account patch, in its order.
fn account_fields(patch: &AccountPatch) -> Vec<&'static str> {
    [
        ("name", patch.name.is_some()),
        ("domainId", patch.domain_id.is_some()),
        ("aliases", patch.aliases.is_some()),
        ("roles", patch.role.is_some()),
        ("permissions", patch.permissions.is_some()),
        ("quotas", patch.quota.is_some()),
        ("locale", patch.locale.is_some()),
        ("timeZone", patch.time_zone.is_some()),
    ]
    .into_iter()
    .filter_map(|(f, set)| set.then_some(f))
    .collect()
}

fn list_fields(patch: &MailingListPatch) -> Vec<&'static str> {
    [
        ("name", patch.name.is_some()),
        ("domainId", patch.domain_id.is_some()),
        ("aliases", patch.aliases.is_some()),
        ("recipients", patch.recipients.is_some()),
    ]
    .into_iter()
    .filter_map(|(f, set)| set.then_some(f))
    .collect()
}

/// The JMAP field names of a patch, in its order.
fn fields(patch: &DomainPatch) -> Vec<&'static str> {
    [
        ("name", patch.name.is_some()),
        ("aliases", patch.aliases.is_some()),
        ("catchAllAddress", patch.catch_all.is_some()),
        ("allowRelaying", patch.allow_relaying.is_some()),
        ("subAddressing", patch.sub_addressing.is_some()),
        ("dkimManagement", patch.dkim.is_some()),
        ("dnsManagement", patch.dns.is_some()),
        ("certificateManagement", patch.certificate.is_some()),
    ]
    .into_iter()
    .filter_map(|(f, set)| set.then_some(f))
    .collect()
}

#[async_trait::async_trait]
impl RemoteGateway for FakeGateway {
    async fn ping(&self) -> Result<(), GatewayError> {
        self.check()
    }

    async fn get_domain(&self, id: &str) -> Result<Option<RemoteDomain>, GatewayError> {
        self.check()?;
        Ok(self.domain(id))
    }

    async fn find_domain(&self, name: &str) -> Result<Option<String>, GatewayError> {
        self.check()?;
        Ok(self.domain_named(&normalize_domain(name)).map(|(id, _)| id))
    }

    async fn create_domain(&self, domain: &DesiredDomain) -> Result<String, GatewayError> {
        self.check()?;
        if self.taken(&domain.name, None) {
            return Err(GatewayError::AlreadyExists(format!(
                "domain {:?} exists",
                domain.name
            )));
        }
        let id = self.next_id();
        self.domains
            .lock()
            .unwrap()
            .insert(id.clone(), stored(domain));
        self.wrote(format!("create {}", domain.name));
        Ok(id)
    }

    async fn update_domain(&self, id: &str, patch: &DomainPatch) -> Result<(), GatewayError> {
        self.check()?;
        if let Some(name) = &patch.name
            && self.taken(name, Some(id))
        {
            return Err(GatewayError::AlreadyExists(format!(
                "domain {name:?} exists"
            )));
        }
        let mut domains = self.domains.lock().unwrap();
        let domain = domains
            .get_mut(id)
            .ok_or_else(|| GatewayError::NotFound(format!("domain {id}")))?;
        if let Some(name) = &patch.name {
            domain.name = name.clone();
        }
        if let Some(aliases) = &patch.aliases {
            domain.aliases = aliases.clone();
        }
        if let Some(catch_all) = &patch.catch_all {
            domain.catch_all = catch_all.clone();
        }
        if let Some(relay) = patch.allow_relaying {
            domain.allow_relaying = relay;
        }
        if let Some(sub) = patch.sub_addressing {
            domain.sub_addressing = sub.as_str().into();
        }
        if let Some(dkim) = patch.dkim {
            domain.dkim = dkim.as_str().into();
        }
        if let Some(dns) = patch.dns {
            domain.dns = dns.into();
        }
        if let Some(certificate) = patch.certificate {
            domain.certificate = certificate.into();
        }
        drop(domains);
        self.wrote(format!("update {id} [{}]", fields(patch).join(", ")));
        Ok(())
    }

    async fn get_account(&self, id: &str) -> Result<Option<RemoteAccount>, GatewayError> {
        self.check()?;
        Ok(self.account(id))
    }

    async fn find_account(
        &self,
        domain_id: &str,
        name: &str,
    ) -> Result<Option<String>, GatewayError> {
        self.check()?;
        let name = normalize_local_part(name);
        Ok(self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .find(|(_, a)| a.name == name && a.domain_id == domain_id)
            .map(|(id, _)| id.clone()))
    }

    async fn create_account(&self, account: &DesiredAccount) -> Result<String, GatewayError> {
        self.check()?;
        let address = self.check_free(&account.name, &account.domain_id, &account.aliases, None)?;
        let stored = self.stored_account(account)?;
        let id = self.next_id();
        self.accounts.lock().unwrap().insert(id.clone(), stored);
        self.wrote(format!("create account {address}"));
        Ok(id)
    }

    async fn update_account(&self, id: &str, patch: &AccountPatch) -> Result<(), GatewayError> {
        self.check()?;
        let current = self
            .account(id)
            .ok_or_else(|| GatewayError::NotFound(format!("account {id}")))?;
        let name = patch.name.clone().unwrap_or(current.name.clone());
        let domain_id = patch.domain_id.clone().unwrap_or(current.domain_id.clone());
        let aliases = patch.aliases.clone().unwrap_or_else(|| {
            current
                .aliases
                .iter()
                .map(|a| domain::account::Alias {
                    name: a.name.clone(),
                    domain_id: a.domain_id.clone(),
                })
                .collect()
        });
        let address = self.check_free(&name, &domain_id, &aliases, Some(id))?;
        let mut accounts = self.accounts.lock().unwrap();
        let account = accounts.get_mut(id).expect("read above");
        account.name = name;
        account.domain_id = domain_id;
        account.email_address = address;
        if let Some(aliases) = &patch.aliases {
            account.aliases = remote_aliases(aliases);
        }
        if let Some(role) = patch.role {
            account.role = role.as_str().into();
        }
        if let Some(permissions) = &patch.permissions {
            account.permissions = match permissions.clone() {
                PermissionsUpdate::Merge { enabled, disabled } => {
                    RemotePermissions::Merge { enabled, disabled }
                }
                PermissionsUpdate::Replace { granted } => RemotePermissions::Replace { granted },
            };
        }
        if let Some(quota) = patch.quota {
            account
                .quotas
                .insert(RemoteAccount::DISK_QUOTA.to_string(), quota);
        }
        if let Some(locale) = &patch.locale {
            account.locale = Some(locale.clone());
        }
        if let Some(tz) = &patch.time_zone {
            account.time_zone = Some(tz.clone());
        }
        drop(accounts);
        self.wrote(format!(
            "update account {id} [{}]",
            account_fields(patch).join(", ")
        ));
        Ok(())
    }

    async fn app_password_key(&self) -> Result<(), GatewayError> {
        match self.app_password_key.lock().unwrap().clone() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    async fn rotate_app_password(&self, id: &str) -> Result<String, GatewayError> {
        self.check()?;
        self.app_password_key().await?;
        if self.account(id).is_none() {
            return Err(GatewayError::NotFound(format!("account {id}")));
        }
        let secret = format!("app_{}", self.next_id());
        let mut all = self.app_passwords.lock().unwrap();
        let list = all.entry(id.to_string()).or_default();
        list.retain(|(d, _)| d != APP_PASSWORD_DESCRIPTION);
        list.push((APP_PASSWORD_DESCRIPTION.to_string(), secret.clone()));
        drop(all);
        self.wrote(format!("app password {id}"));
        Ok(secret)
    }

    async fn delete_account(&self, id: &str) -> Result<bool, GatewayError> {
        self.check()?;
        if self.linked.lock().unwrap().contains(id) {
            return Err(GatewayError::Linked(format!("objectIsLinked: {id}")));
        }
        let gone = self.accounts.lock().unwrap().remove(id).is_some();
        self.app_passwords.lock().unwrap().remove(id);
        if gone {
            self.wrote(format!("delete account {id}"));
        }
        Ok(gone)
    }

    async fn get_mailing_list(&self, id: &str) -> Result<Option<RemoteMailingList>, GatewayError> {
        self.check()?;
        Ok(self.mailing_list(id))
    }

    async fn find_mailing_list(
        &self,
        domain_id: &str,
        name: &str,
    ) -> Result<Option<String>, GatewayError> {
        self.check()?;
        let name = normalize_local_part(name);
        Ok(self
            .lists
            .lock()
            .unwrap()
            .iter()
            .find(|(_, l)| l.name == name && l.domain_id == domain_id)
            .map(|(id, _)| id.clone()))
    }

    async fn create_mailing_list(&self, list: &DesiredMailingList) -> Result<String, GatewayError> {
        self.check()?;
        let address = self.check_free(&list.name, &list.domain_id, &list.aliases, None)?;
        let id = self.next_id();
        self.lists.lock().unwrap().insert(
            id.clone(),
            RemoteMailingList {
                name: list.name.clone(),
                domain_id: list.domain_id.clone(),
                email_address: address.clone(),
                aliases: remote_aliases(&list.aliases),
                recipients: list.recipients.clone(),
            },
        );
        self.wrote(format!("create list {address}"));
        Ok(id)
    }

    async fn update_mailing_list(
        &self,
        id: &str,
        patch: &MailingListPatch,
    ) -> Result<(), GatewayError> {
        self.check()?;
        let current = self
            .mailing_list(id)
            .ok_or_else(|| GatewayError::NotFound(format!("list {id}")))?;
        let name = patch.name.clone().unwrap_or(current.name.clone());
        let domain_id = patch.domain_id.clone().unwrap_or(current.domain_id.clone());
        let aliases = patch.aliases.clone().unwrap_or_else(|| {
            current
                .aliases
                .iter()
                .map(|a| domain::account::Alias {
                    name: a.name.clone(),
                    domain_id: a.domain_id.clone(),
                })
                .collect()
        });
        let address = self.check_free(&name, &domain_id, &aliases, Some(id))?;
        let mut lists = self.lists.lock().unwrap();
        let list = lists.get_mut(id).expect("read above");
        list.name = name;
        list.domain_id = domain_id;
        list.email_address = address;
        if let Some(aliases) = &patch.aliases {
            list.aliases = remote_aliases(aliases);
        }
        if let Some(recipients) = &patch.recipients {
            list.recipients = recipients.clone();
        }
        drop(lists);
        self.wrote(format!(
            "update list {id} [{}]",
            list_fields(patch).join(", ")
        ));
        Ok(())
    }

    async fn delete_mailing_list(&self, id: &str) -> Result<bool, GatewayError> {
        self.check()?;
        let gone = self.lists.lock().unwrap().remove(id).is_some();
        if gone {
            self.wrote(format!("delete list {id}"));
        }
        Ok(gone)
    }
}

/// The cluster reads: the namespace policies and the claims, as set by the
/// test. Every read fails while [`FakeCluster::fail_with`] is set.
pub struct FakeCluster {
    policies: Mutex<Vec<Vec<NamespaceRule>>>,
    claimants: Mutex<Vec<String>>,
    domains: Mutex<BTreeMap<String, DomainState>>,
    account_addresses: Mutex<BTreeMap<String, String>>,
    settings: Mutex<Option<InstanceSettings>>,
    failure: Mutex<Option<String>>,
}

impl Default for FakeCluster {
    /// No policy, no claim, no domain; every instance has the default
    /// settings (submission on the in-cluster service, Kubernetes
    /// secrets, no Vault).
    fn default() -> Self {
        Self {
            policies: Mutex::default(),
            claimants: Mutex::default(),
            domains: Mutex::default(),
            account_addresses: Mutex::default(),
            settings: Mutex::new(Some(InstanceSettings {
                submission: Default::default(),
                default_backend: Default::default(),
                vault: None,
            })),
            failure: Mutex::default(),
        }
    }
}

impl FakeCluster {
    /// A `Ready` `StalwartDomain` `name` of `instance`, as Stalwart's
    /// domain `remote_id` (named `name`).
    pub fn set_domain(&self, name: &str, remote_id: &str, instance: &BoundInstance) {
        self.set_domain_state(
            name,
            DomainState {
                remote_id: Some(remote_id.to_string()),
                name: Some(normalize_domain(name)),
                instance: Some(instance.clone()),
                ready: true,
            },
        );
    }

    pub fn set_domain_state(&self, name: &str, state: DomainState) {
        self.domains.lock().unwrap().insert(name.to_string(), state);
    }

    /// The confirmed address of the `StalwartAccount` `namespace/name`.
    pub fn set_account_address(&self, namespace: &str, name: &str, address: &str) {
        self.account_addresses
            .lock()
            .unwrap()
            .insert(format!("{namespace}/{name}"), address.to_string());
    }

    /// What `instance_settings` answers, whatever the instance (`None`:
    /// gone).
    pub fn set_settings(&self, settings: Option<InstanceSettings>) {
        *self.settings.lock().unwrap() = settings;
    }

    pub fn set_policies(&self, policies: Vec<Vec<NamespaceRule>>) {
        *self.policies.lock().unwrap() = policies;
    }

    /// What `claimants` answers, whatever the object.
    pub fn set_claimants(&self, claimants: Vec<String>) {
        *self.claimants.lock().unwrap() = claimants;
    }

    pub fn fail_with(&self, error: &str) {
        *self.failure.lock().unwrap() = Some(error.to_string());
    }

    fn check(&self) -> Result<(), ClusterError> {
        match self.failure.lock().unwrap().clone() {
            Some(e) => Err(ClusterError(e)),
            None => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl PolicySource<NamespaceRule> for FakeCluster {
    async fn policies(&self) -> Result<Vec<Vec<NamespaceRule>>, ClusterError> {
        self.check()?;
        Ok(self.policies.lock().unwrap().clone())
    }
}

#[async_trait::async_trait]
impl ClusterReader for FakeCluster {
    async fn claimants(
        &self,
        _kind: ClaimKind,
        _name: &str,
        _instance: &BoundInstance,
    ) -> Result<Vec<String>, ClusterError> {
        self.check()?;
        Ok(self.claimants.lock().unwrap().clone())
    }

    async fn domain(&self, name: &str) -> Result<Option<DomainState>, ClusterError> {
        self.check()?;
        Ok(self.domains.lock().unwrap().get(name).cloned())
    }

    async fn account_address(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<String>, ClusterError> {
        self.check()?;
        Ok(self
            .account_addresses
            .lock()
            .unwrap()
            .get(&format!("{namespace}/{name}"))
            .cloned())
    }

    async fn instance_settings(
        &self,
        _instance: &BoundInstance,
    ) -> Result<Option<InstanceSettings>, ClusterError> {
        self.check()?;
        Ok(self.settings.lock().unwrap().clone())
    }
}

/// Records `outcome` in `status` as the controller publishes it: the id,
/// address and rotation nonce when set, and the `Ready` condition with its
/// reason.
pub fn record(status: &mut Option<api::Status>, outcome: &crate::use_cases::Outcome) {
    let status = status.get_or_insert_with(api::Status::default);
    if outcome.remote_id.is_some() {
        status.remote_id = outcome.remote_id.clone();
    }
    if outcome.address.is_some() {
        status.address = outcome.address.clone();
    }
    if outcome.last_rotation.is_some() {
        status.last_rotation = outcome.last_rotation.clone();
    }
    if outcome.instance.is_some() {
        status.instance = outcome.instance.clone();
    }
    status.conditions = vec![api::status::Condition {
        type_: api::status::Condition::READY.into(),
        status: if outcome.ready.is_ok() {
            "True"
        } else {
            "False"
        }
        .into(),
        reason: outcome.reason().as_str().into(),
        message: match &outcome.ready {
            Ok(m) => m.clone(),
            Err(f) => f.message.clone(),
        },
        ..Default::default()
    }];
}

/// A secret store whose implicit targets go to Vault (the instance's
/// `secretStore.backend: vault`), otherwise the [`FakeSecretStore`] it
/// wraps.
#[derive(Default)]
pub struct VaultDefaultStore(pub FakeSecretStore);

#[async_trait::async_trait]
impl crate::ports::SecretStore for VaultDefaultStore {
    fn default_backend(&self) -> api::common::SecretStoreBackend {
        api::common::SecretStoreBackend::Vault
    }

    async fn write(
        &self,
        target: &api::common::SecretTarget,
        owner: &crate::ports::SecretOwner<'_>,
        data: &BTreeMap<String, String>,
    ) -> Result<(), crate::ports::SecretStoreError> {
        self.0.write(target, owner, data).await
    }

    async fn exists(
        &self,
        target: &api::common::SecretTarget,
        owner: &crate::ports::SecretOwner<'_>,
    ) -> Result<bool, crate::ports::SecretStoreError> {
        self.0.exists(target, owner).await
    }

    async fn delete(
        &self,
        target: &api::common::SecretTarget,
        owner: &crate::ports::SecretOwner<'_>,
    ) -> Result<(), crate::ports::SecretStoreError> {
        self.0.delete(target, owner).await
    }
}
