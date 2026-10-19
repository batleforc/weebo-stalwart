# weebo-stalwart

Kubernetes operator managing Stalwart objects as CRDs, built on
[weebo-operator-kit](https://github.com/batleforc/weebo-operator-kit).

| Kind                | Scope      | What it does                                                       |
| ------------------- | ---------- | ------------------------------------------------------------------ |
| `StalwartInstance` | Cluster    | A Stalwart v0.16 to drive: its URL and API key (`tokenSecretRef`), checked by `ping` and the schema hash, and the second key creating App Passwords (`appPasswordTokenSecretRef`) |
| `StalwartLocalInstance` | Namespaced | The same, owned by a namespace (`sharedWith`) |
| `StalwartNamespacePolicy` | Cluster | Which namespaces may create which account kinds, in which domains, with which names |
| `StalwartDomain` | Cluster | A mail domain (`x:Domain`): created, kept in sync, never deleted (`deletionPolicy: Orphan`) |
| `StalwartServiceAccount` | Namespaced | An application's sending account (`x:Account` `User`, no password): an App Password (second key) and SMTP settings written to `secretTargets`, rotated by `rotate-secret` |
| `StalwartAccount` | Namespaced | A person's mailbox (`x:Account` `User`, no credential): aliases, quota, locale, `state: Active \| Locked` |
| `StalwartGroup` | Namespaced | A group (`x:Account` `Group`): aliases, quota; members are the OpenID Connect login's |
| `StalwartMailingList` | Namespaced | A mailing list (`x:MailingList`): recipients as addresses or `accountRef`s |

`weebo-stalwart-importer` (`crates/importer`, in the image) links an
existing Stalwart object to the CR describing it — the only way one comes
under a CR: `weebo-stalwart-importer --url … --token … -f crs.yaml
[--apply]`.

Design: weebo-operator-kit's `docs/rfc-0001-stalwart.md` (RFC 0001).
Progress and next steps: `HANDOFF.md`.

## Layout

Hexagonal, one crate per layer, same rules as every weebo operator:

| Crate               | Holds                                                                    |
| ------------------- | ------------------------------------------------------------------------ |
| `domain`            | the reason codes (`reason_codes!`), no dependency                        |
| `api`               | the CRD types (`#[derive(CustomResource)]`), the kit's shared field types |
| `application`       | ports (`RemoteGateway`, `GatewayFactory`) and the `reconcile_*` use cases |
| `adapters-outbound` | the JMAP gateway (`JmapGateway`, `POST /jmap`), its factory, the secret store factory, the cluster reads |
| `adapters-inbound`  | the controllers and the webhook router (`/validate`, `/scope`, probes)    |
| `operator`          | the binary: telemetry, leader election, webhook server, controllers      |
| `importer`          | `weebo-stalwart-importer`: links existing objects to their CRs            |
| `crdgen`            | writes `deploy/crd/` from `api`                                           |
| `testkit`           | envtest and fakes for the integration tests                               |

`deploy/charts/weebo-stalwart` is a thin chart on the kit's library
chart: `templates/_params.tpl` holds what is the operator's own (group,
kinds, env, egress), `values.yaml` follows the kit's values contract.

## First steps

Licensed `Apache-2.0` (`LICENSE.md`).

```bash
task init     # toolchain (mise) and mise.lock — commit it, cog.toml from the kit, git hooks
task doctor   # envtest prerequisites
task recu     # CRDs (crdgen), their copies in the chart, the docs' CRD and reference pages
task test:all # unit, contract and envtest tests — creates Cargo.lock: commit it
```

The documentation site (`docs/`, `@weebo/operator-docs`) is published to
GitHub Pages by `.github/workflows/docs-pages.yml`; see `docs/README.md`.

Live tests against a real Stalwart v0.16.27:

```bash
task stalwart:container:start ENGINE=podman  # writes .stalwart-test.env
task test:live-stalwart
task stalwart:container:stop ENGINE=podman
```

## Tasks

```bash
task lint        # fmt --check, clippy -D warnings, actionlint, hadolint
task lint:helm   # helm lint + the kit's smoke renders
task test        # unit + contract tests
task test:all    # + envtest integration tests
task coverage    # cargo llvm-cov, fails under 85%
task audit       # cargo-deny + trivy + npm audit (docs) + trivy config
task docs        # the docs site in dev mode (http://localhost:3000)
task docs:build  # lint + static export of the docs site
task kit:sync TAG=vX.Y.Z  # move to another kit release (crates, tasks, CI, chart, cog.toml)
```

`lint`, `audit`, `coverage`, `doctor` and the chart tasks are the kit's
(`tasks/*.yaml`, included remotely and pinned by checksum); CI calls the
kit's reusable `checks.yml`.
