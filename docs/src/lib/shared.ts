import { defineSite } from '@weebo/operator-docs/site';

// What makes this site weebo-stalwart's; everything else comes from
// @weebo/operator-docs.
export const site = defineSite({
  name: 'weebo-stalwart',
  description: 'Manage Stalwart mail domains, accounts, groups and mailing lists as Kubernetes resources.',
  git: {
    user: 'batleforc',
    repo: 'weebo-stalwart',
    branch: 'main',
    contentDir: 'docs/content/docs',
  },
});
