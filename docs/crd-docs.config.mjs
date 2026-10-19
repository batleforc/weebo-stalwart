// Input of `weebo-crd-docs` (@weebo/operator-docs), run by `task recu` /
// `npm run gen:crds`: what the CRD reference pages say beyond the CRDs
// themselves. Paths default to the expected tree (../deploy/crd →
// content/docs/crds + public/crd-schemas).
import { defineConfig } from "@weebo/operator-docs/crd-docs";

export default defineConfig({
  // `StalwartMailingList` → example named `my-mailinglist`.
  kindPrefix: "Stalwart",
  indexIntro: `Each page lists a kind's \`spec\` fields, shows a minimal example, and has a
form that builds a ready-to-apply manifest. These pages are generated from
the CRDs themselves, so they always match the installed version. For the
ideas behind the fields, start with [Concepts](/docs/concepts).`,
  // Sidebar order follows the order you'd create things in, not the alphabet.
  order: [
    "StalwartInstance",
    "StalwartLocalInstance",
    "StalwartNamespacePolicy",
    "StalwartDomain",
    "StalwartServiceAccount",
    "StalwartAccount",
    "StalwartGroup",
    "StalwartMailingList",
  ],
  // The guide that explains each kind, linked from its reference page.
  guides: {
    StalwartInstance: ["Connect a Stalwart", "/docs/guides/connect-instance"],
    StalwartLocalInstance: [
      "A namespace's own instance",
      "/docs/guides/connect-instance#a-namespaces-own-instance",
    ],
    StalwartNamespacePolicy: ["The allow-list", "/docs/guides/allow-list"],
    StalwartDomain: ["Domains", "/docs/guides/domains"],
    StalwartServiceAccount: ["Service accounts", "/docs/guides/service-accounts"],
    StalwartAccount: ["Mailboxes", "/docs/guides/accounts"],
    StalwartGroup: ["Groups and mailing lists", "/docs/guides/groups-and-lists#groups"],
    StalwartMailingList: ["Groups and mailing lists", "/docs/guides/groups-and-lists#mailing-lists"],
  },
  // A minimal, realistic `spec` per kind, checked against the schema (every
  // required field present, every key a real field): a renamed field fails
  // generation instead of shipping a stale example.
  examples: {
    StalwartInstance: {
      url: "http://stalwart.mail.svc:8080",
      tokenSecretRef: { name: "stalwart-operator-token", namespace: "mail", key: "token" },
      appPasswordTokenSecretRef: { name: "stalwart-operator-token", namespace: "mail", key: "appPasswordToken" },
    },
    StalwartLocalInstance: {
      url: "http://stalwart.mail.svc:8080",
      tokenSecretRef: { name: "stalwart-token", key: "token" },
      appPasswordTokenSecretRef: { name: "stalwart-token", key: "appPasswordToken" },
    },
    StalwartNamespacePolicy: {
      rules: [
        {
          namespaces: ["forgejo"],
          allowedKinds: ["StalwartServiceAccount"],
          allowedDomains: ["example.internal"],
          allowedNames: ["forgejo", "noreply"],
        },
      ],
    },
    StalwartDomain: { name: "example.internal" },
    StalwartServiceAccount: {
      domainRef: { name: "example.internal" },
      name: "forgejo",
      aliases: ["noreply"],
      secretTargets: [{ name: "forgejo-smtp" }],
    },
    StalwartAccount: { domainRef: { name: "example.internal" }, name: "alice", quota: "2Gi" },
    StalwartGroup: { domainRef: { name: "example.internal" }, name: "devs" },
    StalwartMailingList: {
      domainRef: { name: "example.internal" },
      name: "team",
      recipients: [{ accountRef: { name: "alice" } }, { address: "bob@example.com" }],
    },
  },
  // The operator reference pages (content/docs/reference/), generated from
  // the Rust sources: reason codes (crates/domain/src/error.rs), Events,
  // metrics & health, resource budget.
  reference: {
    metricsPrefix: "weebo_stalwart",
    // The operator's own metrics, beyond the kit's.
    extraMetrics: [
      {
        name: "weebo_stalwart_api_requests_total",
        type: "counter",
        labels: "`method` (the JMAP method, e.g. `x:Account/set`, or `session`/`schema`), `outcome` (`ok`, `unreachable`, `unauthorized`, `not_found`, `already_exists`, `linked`, `invalid`, `unsupported_version`, `error`)",
        description: "Stalwart API calls",
      },
      {
        name: "weebo_stalwart_accounts",
        type: "gauge",
        labels: "`state` (`Active`, `Locked` when the last reconcile was `Ready`, `NotReady` otherwise)",
        description: "`StalwartAccount`s by the state their last reconcile reached, counted by the leader",
      },
    ],
    // "What to do" per code; the meaning comes from the Rust doc comments.
    remedies: {
      Reconciled: "Nothing",
      InstanceNotFound: "[Create the instance](/docs/guides/connect-instance), or fix `instanceRef`",
      InstanceAmbiguous: "Set `instanceRef`",
      InstanceNotAllowed:
        "Use an instance of the CR's namespace, or have that `StalwartLocalInstance` list it in `sharedWith`",
      InstanceBindingChanged:
        "Set `instanceRef.kind` to the instance you want (see [A namespace's own instance](/docs/guides/connect-instance#a-namespaces-own-instance))",
      TokenSecretMissing: "Fix `tokenSecretRef` — or, on a `StalwartServiceAccount`, set the instance's `appPasswordTokenSecretRef` (see [The App Password key](/docs/guides/connect-instance#the-app-password-key)) — or create the Secret (the bootstrap Job writes it on its first run)",
      TokenSecretNotAllowed: "Label the Secret (of `tokenSecretRef` or `appPasswordTokenSecretRef`) `stalwart.weebo.io/instance-token: \"true\"`",
      InvalidSpec: "Fix the spec; the message says what's wrong (an alias with an `@`, a Vault target not named `smtp`, `deletionPolicy: Delete` on a domain…)",
      InstanceUnreachable: "Check Stalwart's health and the URL/CA; it's retried automatically",
      InstanceUnauthorized: "The API key was revoked or lacks permissions: issue a new one (see [The API key](/docs/guides/connect-instance#the-api-key))",
      RemoteError: "Read the message; often a value Stalwart's schema refuses (a lowercase `locale`, an unknown top-level domain)",
      KubernetesApiError: "Transient; retried automatically",
      Created: "Nothing",
      DriftCorrected:
        "Nothing, unless it names the same field on every reconcile: then Stalwart stores that field differently than it is sent (a comparison bug, report it)",
      Deleted: "Nothing",
      Released: "Nothing",
      LeavesWatchScope:
        "Set the `force-orphan` annotation first, or move the CR to another release's selector and remove its finalizer",
      NamespaceNotAllowed: "Adjust the [allow-list](/docs/guides/allow-list): kind, domain, and the name and every alias",
      SecretTargetFailed:
        "Check RBAC or Vault access and the target's namespace/name (a Vault target is named `smtp`, without `path`)",
      RemoteObjectClaimed: "Another CR owns that Stalwart object: rename this one, or delete the other",
      StalwartObjectAlreadyExists:
        "The address exists in Stalwart (created by hand or by an OpenID Connect login): link it with the [importer](/docs/guides/migration), or pick another name",
      UnsupportedStalwartVersion: "Run the Stalwart version this operator release supports, or upgrade the operator",
      DomainNotFound: "Create the `StalwartDomain`, or fix `domainRef`",
      DomainNotReady: "Fix the domain first; this one follows on its own",
      AccountNotFound: "Create the `StalwartAccount` in this namespace, or wait for it to be `Ready`",
      ObjectIsLinked: "Remove what still uses the object (a group's members); the deletion is retried",
    },
  },
});
