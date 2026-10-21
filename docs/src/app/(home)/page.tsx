import { OperatorHome } from '@weebo/operator-docs/site';
import { site } from '@/lib/shared';

export default function HomePage() {
  return (
    <OperatorHome
      site={site}
      label="Kubernetes operator · Stalwart v0.16"
      caption="Manage the inside of an existing Stalwart mail server — domains, application sending accounts, mailboxes, groups and mailing lists — as Kubernetes custom resources, with GitOps-friendly status and a namespace allow-list."
      actions={[
        { href: '/docs/getting-started', label: 'Get started', primary: true },
        { href: '/docs', label: 'Read the docs' },
        { href: '/docs/ide', label: 'Access the CRD IDE' },
      ]}
      install={`helm install weebo-stalwart \\
  oci://ghcr.io/batleforc/charts/weebo-stalwart \\
  --namespace weebo-stalwart --create-namespace`}
      example={{
        title: 'Give an app an SMTP account',
        yaml: `apiVersion: stalwart.weebo.io/v1alpha1
kind: StalwartServiceAccount
metadata:
  name: forgejo
  namespace: forgejo
spec:
  domainRef: { name: example.internal }
  aliases: [noreply]
  secretTargets:
    - name: forgejo-smtp`,
      }}
      features={[
        {
          title: 'Declare the mail server',
          body: 'Domains, mailboxes, groups and mailing lists are Kubernetes resources. Apply YAML, and the operator keeps Stalwart in line with it, writing only what differs.',
          href: '/docs/getting-started',
          link: 'Quickstart',
        },
        {
          title: 'Hand out SMTP credentials',
          body: 'An application asks for a sending account; the operator generates its password and writes the submission settings straight into a Secret (or Vault), rotated on request.',
          href: '/docs/guides/service-accounts',
          link: 'Service accounts guide',
        },
        {
          title: 'Fence namespaces',
          body: 'An allow-list says which namespaces may create which kinds, in which domains, under which names. It is enforced by an admission webhook, before anything reaches Stalwart.',
          href: '/docs/guides/allow-list',
          link: 'Allow-list guide',
        },
      ]}
    />
  );
}
