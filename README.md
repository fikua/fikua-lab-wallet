# Fikua Lab — Wallet (holder)

EUDI-style Wallet PWA for the Fikua Lab. Served at
**<https://wallet.lab.fikua.com>**.

The only frontend in the lab with a real build step (Vite + TypeScript +
`vite-plugin-pwa`). Acts as the OID4VCI client and the OID4VP holder
against the lab backend.

## Stack

- TypeScript + Vite
- `vite-plugin-pwa` (service worker + manifest)
- Vitest (with `jsdom` + `fake-indexeddb`)

## What lives here

```text
.
├── src/                TypeScript source
├── public/             Static assets copied into dist/ verbatim
├── index.html          Vite entry
├── package.json        Scripts: dev / build / preview / test
├── vite.config.ts      Build config + PWA + local backend proxy
├── tsconfig.json
├── vitest.config.ts
└── shared/             Vendored shared assets (consent banner, error pages)
```

## Local development

```bash
npm ci
npm run dev          # http://localhost:3004 — proxies /oid4vci, /oid4vp, /.well-known, /admin to http://localhost:8090
npm test
```

## Build

```bash
npm run build
# Output → dist/
```

## Hosting

- **Production:** Cloudflare Workers Static Assets (project
  `fikua-lab-wallet`), serving the `dist/` directory. Custom domain
  `wallet.lab.fikua.com`.
- **CI build:** the Workers project runs `npm ci && npm run build` and
  publishes `dist/` on every push to `main`.
- **Backend reverse-proxy:** `/.well-known/*`, `/oid4vci/*` and
  `/oid4vp/*` are proxied to the lab backend at the edge.

## Architecture decisions

- ADR 0008 — Fikua Lab frontends on Cloudflare Workers.

## License

Apache-2.0. See [LICENSE](LICENSE).
