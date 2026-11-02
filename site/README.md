# Sekisho site

Static landing page for Sekisho, built with Astro. No client-side framework, no tracking scripts.

Pages: `/`, `/pricing/`, `/security/`.

## Build

Requires Node 22.19 or newer.

```sh
cd site
npm ci
npm run build     # output in dist/
npm run dev       # local dev server
npm run preview   # serve dist/ locally
```

Set `SEKISHO_SITE_URL` to change the canonical site URL (default `https://sekisho.sh`).

## Deploy (Cloudflare Pages)

The Pages project name is a placeholder: `sekisho-dev`.

```sh
cd site
npx wrangler whoami
npm run build
npx wrangler pages deploy dist --project-name=sekisho-dev --branch=main
```

`--branch=main` makes it a production deploy. Without it you get a preview.

## Copy rules

No em dashes, no en dashes, no dashes used as punctuation. Check the built output:

```sh
grep -rl -e '—' -e '–' dist --include='*.html' || echo clean
```
