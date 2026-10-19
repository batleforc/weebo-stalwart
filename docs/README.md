# docs

The weebo-stalwart documentation site ([Fumadocs](https://fumadocs.dev) on
Next.js), published at <https://batleforc.github.io/weebo-stalwart>.

```bash
task docs          # dev server on http://localhost:3000
task docs:build    # lint + static export into out/
```

## Content

- `content/docs/{index,getting-started,concepts}.mdx`, `guides/*.mdx`,
  `contributing/*.mdx`: hand-written. Sidebar order lives in each folder's
  `meta.json`.
- `content/docs/crds/*` (pages, `index.mdx`, `meta.json`) and
  `public/crd-schemas/*.json` are **generated** from `deploy/crd/*.yaml` by
  `weebo-crd-docs` (`task recu`, or `npm run gen:crds --prefix docs` for the
  docs alone), configured by `crd-docs.config.mjs`. Never edit them by hand.
  A field without a description means its Rust doc-comment is missing; each
  kind's example spec lives in the config and is checked against the schema.
- `content/docs/reference/*` (reason codes, Events, metrics & health,
  resource budget) are **generated** by the same run, from the operator's
  sources: the `ReasonCode` catalog (`crates/domain/src/error.rs`, its doc
  comments are the "Meaning" column; "What to do" is in the config) and the
  metric names. Once `task perf` has run, copy its report from
  `target/perf/` to `perf/weebo-stalwart.json` and set `perfReport` in the
  config: the budget page then shows the measured values.

## @weebo/operator-docs

What every weebo operator's site shares comes from the kit's
[`packages/operator-docs`](https://github.com/batleforc/weebo-operator-kit/tree/main/packages/operator-docs):
the CRD page generator, the manifest builder, the theme, the layouts, the
docs page and the search/llms/OG routes. This site keeps its content, its
name and repo (`src/lib/shared.ts`), the generator's config and the guided
choices. It is consumed as the kit release's tarball (`package.json`);
`task kit:sync TAG=vX.Y.Z` moves it with the rest of the kit.

## Manifest builder

Every CRD page ends with a form (`<CrdForm>`, from the package) built from
the kind's JSON schema. Kinds with mutually exclusive ways of doing one thing
(a service account's credentials in the default Secret or in explicit
targets; a mailbox active or locked) start with guided choices, declared in
`src/lib/crd-choices.ts`. Keep those field names in sync with the CRDs when
renaming a field.

## Publishing

The site is a static export (`output: 'export'`). `.github/workflows/docs-pages.yml`
builds it on every push to `main` that touches `docs/` or `deploy/crd/`, with
`DOCS_BASE_PATH=/weebo-stalwart` (the project-site sub-path) and
`DOCS_SITE_URL` (absolute OG image URLs), then deploys it to GitHub Pages.
Files fetched at runtime from `public/` must go through `withBasePath()`
(`@weebo/operator-docs/site`); `next/link` handles the prefix by itself.
