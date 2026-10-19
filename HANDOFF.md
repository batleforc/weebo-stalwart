# weebo-stalwart — handoff (RFC 0001, Phase 1 + Phase 2 done)

State on 2026-10-19. Nothing is committed: the repository is local (`git init`
by cargo-generate, no remote — the repos move to a GitHub organisation).
Design: weebo-operator-kit `docs/rfc-0001-stalwart.md`.

## What exists

Generated with
`cargo generate --git https://github.com/batleforc/weebo-operator-kit --tag v0.18.0 templates/operator --name weebo-stalwart --define product=Stalwart`
(outside the kit tree), then `task init`.

| CRD | Scope | State |
| --- | --- | --- |
| `StalwartInstance` | cluster | `url`, `tokenSecretRef` (Bearer API key), `appPasswordTokenSecretRef` (optional, the second key — D24), `tls`, `secretStore` (`pathPrefix: weebo-stalwart`), `submission` (defaults `stalwart.mail.svc.cluster.local:587 starttls`) |
| `StalwartLocalInstance` | namespaced | same, minus `secretStore` (Kubernetes Secrets only), `instance-token` label (on both token Secrets) |
| `StalwartNamespacePolicy` | cluster | rules `namespaces` × `allowedKinds` × `allowedDomains` × `allowedNames`, `effect` |
| `StalwartDomain` | cluster | `x:Domain`; `deletionPolicy: Orphan` only (CEL + webhook + reconcile) |
| `StalwartServiceAccount` | namespaced | `x:Account` `User`, no credential, + an App Password (D24): `domainRef`, `name`, `aliases`, `receive`, `secretTargets` (keys `host`, `port`, `security`, `username` = address, `password` = `app_…`, `from`), `deletionPolicy` (`Delete`) |
| `StalwartAccount` | namespaced | `x:Account` `User`, no credential: `domainRef`, `name`, `aliases`, `quota` (Quantity), `locale`, `timeZone`, `state` (`Active`/`Locked`), `deletionPolicy` (`Orphan`) |
| `StalwartGroup` | namespaced | `x:Account` `Group` (`roles: Default`): `domainRef`, `name`, `aliases`, `quota`, `deletionPolicy` (`Orphan`) |
| `StalwartMailingList` | namespaced | `x:MailingList`: `domainRef`, `name`, `aliases`, `recipients` (`{address}` \| `{accountRef}`, CEL "exactly one"), `deletionPolicy` (`Delete`) |

`Status` (all kinds): `observedGeneration`, `remoteId`, `address`,
`lastRotation`, `instance`, `conditions`. Every reason code of the RFC is used
(`DomainNotFound`, `DomainNotReady`, `AccountNotFound`, `ObjectIsLinked`
included).

### Crates

- `domain`: `allow_list`, `mail`, `mail_domain`, **`account`** (`DesiredAccount`,
  `RemoteAccount`, `AccountPatch`, `account_patch()`, `OwnedPermissions`
  `service_account(receive)`/`account(locked)`, `RemotePermissions`
  Inherit/Merge/Replace), **`mailing_list`** (`mailing_list_patch()`,
  recipients lowercased as a set), **`quantity`** (`2Gi` → bytes).
- `api`: the eight CRDs; `common` re-exports `ObjectMeta`, `Quantity`.
- `application`:
  - `ports`: `RemoteGateway` + `get/find/create/update/delete_account`,
    `app_password_key`, `rotate_app_password` (D24, `APP_PASSWORD_DESCRIPTION`
    = `weebo-stalwart`; `GatewayError::AppPasswordKey` carries the factory
    error of the second key), `get/find/create/update/delete_mailing_list`;
    `ClaimKind::Address`; `ClusterReader::{domain, account_address,
    instance_settings}` (`DomainState`, `InstanceSettings`).
  - `use_cases::accounts`: the shared machinery — `Subject` (what a
    namespaced CR asks for), `admit` (policy, then the domain), the
    `RemoteObject` trait (`AccountObject`, `MailingListObject`), `sync`
    (read by id + D19 guard incl. the `@type`, claims on the address and
    every alias, create never adopting, PATCH of the drift only, rename =
    `allow-disruptive-update`), `cleanup` (D19-guarded delete, `Linked` →
    `ObjectIsLinked`).
  - `reconcile_service_account` (checks the App Password key before
    creating anything, account created without credential, App Password
    created at creation and rotated — created + earlier ones of ours
    destroyed in one call — on a new nonce / `any_missing` / after
    `SecretTargetFailed`; `lastRotation`; D15 on targets), `reconcile_account` (lock/unlock, D20),
    `reconcile_group`, `reconcile_mailing_list` (`accountRef` →
    `status.address`), `import` (lookup by name for the importer),
    `admission` (`check_names`, `check_smtp_targets`, `check_*` per kind).
  - `test_support`: `FakeGateway` (accounts/lists, cross-kind address
    uniqueness, App Passwords per account — a rotation drops only ours —,
    `seed_app_password`, `fail_app_password_key`, `link`/`unlink`), `FakeCluster`
    (domains, account addresses, settings), `record()`, `VaultDefaultStore`.
- `adapters-outbound`: `jmap/account.rs` (never sends nor reads
  `credentials`), `jmap/app_password.rs` (`x:AppPassword/get` with `id`,
  `description` only, `/set` create + destroy, secret never quoted in
  errors), `jmap/mailing_list.rs`, `destroy` helper; `JmapGateway` holds a
  second `JmapClient` for the App Password key, loaded lazily
  (`with_app_password_key(loader)` from the factory, so only service
  accounts read that Secret; `with_app_password_client` for tests); `KubeClusterReader` claims across the four namespaced kinds
  (address or alias), `domain`, `account_address`, `instance_settings`.
- `adapters-inbound`: `controller::namespaced` (generic controller:
  finalizer, `import-pending`, re-read, resolve in the namespace, Orphan
  releases at once, Delete via the recorded instance), one file per kind;
  `stalwart_account` holds the `weebo_stalwart_accounts{state}` gauge;
  `webhook` arms for the four kinds (`WebhookState { policies, instances,
  cluster }`: spec checks, `enforce`, D15, `check_vault_targets`).
- `importer` (new): `weebo-stalwart-importer` (`--url`, `--token`, `-f`,
  `--namespace`, `--apply`, `--force`, `--ca-file`): parses CRs, finds each
  object by name, seeds `remoteId`/`address`/`instance` via the kit's
  `Adopter`, `RemoteObjectClaimed` guard, D21 nonce `import-<unix secs>` on
  service accounts. Shipped in both images.
- `operator/main.rs`: the four controllers run in every scope (namespaced),
  `migrate-instance-ref` covers the new kinds.

### Tests (all green)

| Suite | Count |
| --- | --- |
| unit (`task test`) | domain 31, api 9, application 54, adapters-outbound 7, adapters-inbound 9, importer 3 |
| contract (wiremock) | `jmap_contract` 20, `jmap_contract_accounts` 20 (one per normalization; App Password rotation, filtering by description, no second key) |
| envtest | `account_controllers` 2, `domain_controller` 2, `namespace_policy_controller` 1, `watch_scope` 2, `instance_ref_migration` 1, adapters-outbound `factories` 3, importer `adopt` 1 |
| binaries | crdgen `in_sync` 1 (CRDs vs `deploy/crd/`), importer `cli` 3, operator `binary` 3 (`--version`, `migrate-instance-ref`, lease loss) |
| perf (`task perf`, ignored) | operator `perf` 1: 200 `StalwartMailingList`s against a fake JMAP store |
| live (`task test:live-stalwart`) | adapters-outbound 11 + `live_smtp` 9 (3 OIDC spikes, 2 end-to-end service accounts: with and without an OIDC default directory), adapters-inbound 2, importer 1 |

Gates: `task recu`, `task lint`, `task lint:helm`, `task test:all`,
`task audit` green; live suite green against podman Stalwart v0.16.27
(container torn down afterwards).

## Findings on the image (v0.16.27), beyond the first half's

- Permission names are camelCase on the wire (`imapAuthenticate`,
  `emailReceive`, `authenticate`).
- **A `Group` refuses `encryptionAtRest`** (`invalidPatch: Invalid property`):
  only users get it (Q24).
- `credentials` lists the `Password`, App Passwords and API keys together:
  sending `credentials` whole would wipe App Passwords; a second `Password`
  is refused ("Only one password credential"). Since D24 the operator never
  sends it.
- Patch paths work on maps/sets (`quotas/maxDiskQuota`,
  `permissions/disabledPermissions/x`), but not on an `Inherit` variant
  (`Invalid JSON Pointer path`): `permissions` is always sent whole.
- **Locking works as the RFC says**: with `authenticate` disabled, both the
  password and an App Password get `403` on `/jmap/session`; removing the
  entry gives both back (`200`). App Passwords are kept.
- Addresses are unique across accounts, groups, lists and aliases
  (`primaryKeyViolation` on `email`, with the owner's `objectId`).
- `x:Account/query` `name` filter is exact (stored lowercased);
  `x:MailingList/query` filters only `text` (no `name`, no `domainId`).
- `locale` and `timeZone` are case-sensitive schema enums (`fr-fr` refused).
- List `recipients` are stored in the case sent.
- A group with members can't be destroyed (`objectIsLinked` with
  `linkedObjects`).
- **No listener on 587 by default**: the image listens on 25 (`smtp`) and
  465 (`submissions`, implicit TLS) only. The instance's default
  `submission` (587 `starttls`) needs an `x:NetworkListener`
  (`protocol: smtp`, `tlsImplicit: false`, bind `[::]:587`), bound at the
  next start only (a created listener isn't picked up live). The test
  container's bootstrap creates it and restarts; **weebo-si phase 0 must
  create it too** (or announce 465 `tls`). Its certificate is self-signed
  (`CN=rcgen self signed cert`, SAN `localhost`). Before `STARTTLS`, 587
  offers only `AUTH XOAUTH2 OAUTHBEARER`; after it, `PLAIN LOGIN`.
- **Published credentials work** (`live_smtp`): `host`/`port` with
  `STARTTLS`, `AUTH PLAIN` `username`/`password` (the App Password) →
  `235`, `MAIL FROM` the published `from` (first alias) → `250`, message
  delivered; a wrong password is `535`; same through
  `reconcile_service_account` with and without an OIDC default directory,
  a rotation refusing the old App Password (`535`).
- **Q8** — `mustMatchSender` at its default: an authenticated account may
  use its address and its aliases (any case) as `MAIL FROM`; another
  account's address, a foreign address and a sub-address (`svc+tag@`)
  are `501 5.5.4 You are not allowed to send from this address.` (source:
  `smtp/src/inbound/mail.rs`, the address or one of the token's emails).
- **Q4, delivery** — a recipient without `emailReceive` (locked
  `StalwartAccount`, service account without `receive`) is **accepted at
  `RCPT TO`** (`250`, on 25 and on 587) **then bounced by a DSN**: the
  sender gets "Failed to deliver message" from `MAILER-DAEMON`,
  `550 (5.5.0) This account is not authorized to receive email.`; nothing
  lands in the mailbox. The check is at local delivery
  (`email/src/message/delivery.rs`), not at `RCPT`. An unknown recipient
  is `550 5.1.2` at `RCPT`. So a lock doesn't hide the address from the
  outside, and backscatter is possible for spoofed senders.
- **Q4, App Passwords** — one whose own permissions are `Replace` (incl.
  `authenticate`) **doesn't bypass** a disabled `authenticate`: Stalwart
  intersects a credential's `Replace` with the account's permissions
  (`common/src/auth/access_token.rs`). Locked: `550 5.7.1 Your account is
  not authorized to use this service.` at SMTP `AUTH` on 587 and `403` on
  JMAP, for the password and the App Password; unlocked, both work again.
- Stalwart's default inbound throttle: 5 connections/s per IP
  (`x:MtaInboundThrottle` "Sender IP throttle"); beyond, the connection is
  reset before the greeting — the test client retries.

## D24 — service accounts by App Password (2026-10-19)

Why: users log in through an OIDC default directory, which on the
community edition serves every domain: a Basic password login is refused
(`454` on 587, `401` on JMAP) and every `Password` write is refused ("Cannot
set credentials for accounts in an external directory"), even to the
recovery admin. The main key can't create an App Password on another
account (`impersonate`, which it must never hold: with its `jmap*` it would
read every mailbox).

What changed:

- **No path writes `credentials`.** `create_account` sends none;
  `set_password`, `password_patch`, `generate_password` and the `rand`
  dependency are gone.
- **Second key** on the operator's account, `permissions: Replace` with
  `deploy/stalwart/app-password-key-permissions.json` (`authenticate`,
  `impersonate`, `emailSend`, `sysAppPassword{Create,Get,Update,Destroy,Query}`).
- **Instance contract**: `appPasswordTokenSecretRef` (optional) on
  `StalwartInstance` (`SecretKeyRef`) and `StalwartLocalInstance`
  (`LocalSecretKeyRef`, `instance-token` label required, same rule as
  `tokenSecretRef`). Secret key used in the docs and RFC:
  `appPasswordToken` in `stalwart-operator-token`. Read lazily, only by a
  `StalwartServiceAccount` reconcile (`app_password_key()` before
  creating anything, then `rotate_app_password`). Unset: `TokenSecretMissing`
  ("the instance sets no appPasswordTokenSecretRef…"); an unreadable /
  unlabelled one: `TokenSecretMissing` / `TokenSecretNotAllowed` with the
  field name in the message. Other kinds never read it.
- **Rotation**: `x:AppPassword/get {accountId, properties: [id,
  description]}`, then one `x:AppPassword/set {accountId, create: {p:
  {description: weebo-stalwart, permissions: Replace {authenticate,
  emailSend}}}, destroy: [our earlier ones]}`; returns `created.p.secret`.
  Others' App Passwords are never touched. A `notDestroyed` is a warning
  (the new one works; the next rotation retries).
- **Service account**: same triggers (creation, nonce, `any_missing`,
  previous `SecretTargetFailed`); `password` = `app_…`, `username` = address.
  A failed App Password after creation keeps the id (no second creation):
  the next reconcile finds the targets empty and creates one.
- **Importer (D21)**: still a forced rotation, now an App Password; a
  password Terraform set is left alone (it stops working once the default
  directory is OIDC — the live test checks it still logs in without OIDC).
- **Test container** (`.tasks/stalwart.yaml`): the operator account has no
  password; the recovery admin creates both keys with `accountId`;
  `.stalwart-test.env` gains `STALWART_APP_PASSWORD_TOKEN`
  (`testkit::LiveStalwart::app_password_token`, required; `task coverage`
  requires it too).
- `live_smtp` tests take a shared lock (`SERIAL`): an OIDC default
  directory is server-wide, and `task coverage` runs them in parallel.
- Docs: service accounts (why an App Password, the second key), connect
  instance (*The App Password key*), getting started, security (two keys,
  "send as anyone" accepted, no mailbox read under OIDC), migration,
  operations, concepts, index, README; reason-code hints.

## Decisions on open points (`// RFC 0001 Qn:` in the code)

Q1, Q10, Q12–Q17: see the first half (key permissions, schema hash
constant, session per gateway, catch-all no opinion, refused rename =
`InvalidSpec`, `remoteId` without `address` not trusted, no `secretStore`
on the local instance, D18 three times). New:

- Q18: a remote `permissions: Replace` — only the operator's disabled
  entries must be absent from `granted`; no opinion on the enabled ones.
- Q19: `StalwartMailingList` defaults to `deletionPolicy: Delete` (holds no
  mail).
- Q20: `weebo_stalwart_accounts{state}` = `Active`/`Locked` when the last
  reconcile was `Ready`, `NotReady` otherwise.
- Q21: "password not written everywhere" = previous `Ready` reason
  `SecretTargetFailed` (no `secretPending` field as forgejo).
- Q22: D21 via a fresh `rotate-secret` nonce set by the importer; the
  importer also seeds `status.instance`.
- Q23: the policy is evaluated before the domain lookup.
- Q24: `encryptionAtRest` on users only.
- Q25 (replaced by D24): an App Password's permissions are `Replace`
  `{authenticate, emailSend}` — `Inherit` is refused to the second key.
- Also: account `name`/`domainId` are compared, a change needs
  `allow-disruptive-update` (as a domain rename); aliases are local-parts
  only (an `@` is refused), hence always in the account's domain.

## RFC discrepancies (the RFC is not edited)

- `weebo.poc` is refused by Stalwart (unknown TLD); `.internal`, `.lan`,
  `.test`, `.home.arpa` work (or `weebo.poc` as a domain *alias*).
- The operator key needs the User role's 258 permissions, `sysApiKey*`,
  `sysAppPassword*`, `jmapEmail*` included (a key can't grant what it lacks)
  — contrary to *Sécurité*; and `sysAccountUpdate` sets any account's
  password (blast radius includes reading mailboxes).
- `encryptionAtRest` doesn't exist on a `Group` (*Champs comparés* says "tous
  les comptes").
- Permission names in the RFC are PascalCase (`ImapAuthenticate`); the wire
  is camelCase.
- *Architecture* orders domain before policy; implemented the other way
  (Q23).
- No `deletionPolicy` default given for `StalwartMailingList` (Q19), no label
  values for `weebo_stalwart_accounts{state}` (Q20), nothing on a remote
  `Replace` (Q18).
- *Champs comparés* doesn't list an account's `name`/`domainId`.
- The default submission (587 `starttls`) has no listener in the image:
  the deployment must add it (see the findings).

## What's left

- weebo-si phase 0 (Terraform, `2.argo/helm/mail`, bootstrap Job with the
  258-permission key, the App Password key (D24, both created by the
  recovery admin with `accountId`, the operator account without password,
  Secret keys `token` and `appPasswordToken`), the OIDC default directory
  after the import, and the 587 `submission` listener, domain name other
  than `weebo.poc`), then phase 1/2
  rollout (importer for the plan's objects, forgejo/Authentik/Argo CD
  service accounts, one hand-declared `StalwartAccount`).
- Done: the docs site (`docs/`, `@weebo/operator-docs` 0.18.0, set up as
  weebo-forgejo's: `crd-docs.config.mjs`, generated CRD and reference
  pages by `task recu`, `docs:deps`/`docs`/`docs:build`, `NPM_DIR: docs`
  for `task audit`, `node` in `mise.toml`), `LICENSE.md` (Apache-2.0, as
  forgejo's), CI aligned on forgejo (`regen-and-diff` covers the docs'
  generated pages, `docs` job, `image-build` matrix running
  `weebo-stalwart-importer --version` in both images, publish smoke on the
  importer's `--version`, `docs-pages.yml`). Left: enable GitHub Pages
  (Settings → Pages → Source = GitHub Actions) once the repo is pushed; no
  `perf/weebo-stalwart.json` yet — after `task perf`, copy the report there
  and set `perfReport` (and `perfScheduled` with a `perf.yml` as forgejo's)
  in `docs/crd-docs.config.mjs`; no `coverage` CI job (forgejo has one, needs
  the Stalwart container in CI); the `verify-release`, `high-availability`,
  `troubleshooting` guides forgejo has were not written (their content is
  folded into `operations`/`security`/`install`).
- Done: `task coverage` (lines 89.4% → 95.9%, regions 88.2% → 94.5%;
  threshold 85% as forgejo/authentik; the live suites need
  `.stalwart-test.env`, now required by the task) and `task perf`
  (`Budget::small_cluster()` met: burst 9 API req/object, churn 4, delete
  3, peak RSS 30 MiB, idle RSS growth 7%). Two causes fixed on the way:
  claims and policies are read from reflector stores in the binary
  (`ClaimStores`, `ClusterReader::claimants_of_any`: from the API, every
  creation listed the four namespaced kinds once per address *and* alias —
  a burst of N lists read N² CRs, 14 req/object and +8 MiB RSS), and the
  runtime is capped at 4 tokio workers (on a 16-core host the default one
  per core gave +14% idle RSS per cycle; weebo-forgejo fails the same check
  there, 15.4% — worth fixing in the kit's template too).
  Left: the report is in `target/perf/weebo-stalwart.json` — copy it to
  `docs/perf/` (see the docs item above); a `coverage` CI job.
  `importer`'s live test once timed out (`DomainNotReady` after 30 s) under
  the parallel instrumented run, green alone and on the rerun.
- The link brick (RFC 0002) consumes `spec.state`, `status.conditions` and
  `status.address` of `StalwartAccount` as implemented.
