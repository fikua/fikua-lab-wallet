# Fikua Lab — Wallet (holder)

EUDI-style Wallet PWA for the Fikua Lab. Served at
**<https://wallet.fikua.com>** — its own domain, matching the convention
`issuer.fikua.com` / `idp.fikua.com` / `attestation-registry.fikua.com`
already follow.

The only frontend in the lab with a real build step (Vite + TypeScript +
`vite-plugin-pwa`). Acts as the OID4VCI client (against
`issuer.fikua.com`) and the OID4VP holder, calling `issuer.fikua.com`
and `idp.fikua.com` directly — there is no single "lab backend" it goes
through anymore since the AS/Issuer split.

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
├── vite.config.ts      Build config + PWA
├── tsconfig.json
├── vitest.config.ts
└── shared/             Vendored shared assets (error pages)
```

## Local development

```bash
npm ci
npm run dev          # http://localhost:3004 — calls issuer.fikua.com / idp.fikua.com directly (CORS-enabled)
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
  `wallet.fikua.com`.
- **CI build:** the Workers project runs `npm ci && npm run build` and
  publishes `dist/` on every push to `main`.
- **No backend proxy:** the wallet calls `issuer.fikua.com` and
  `idp.fikua.com` directly from the browser; both must serve permissive
  CORS headers (see each repo's own `internal/httpapi/cors.go`).

## Architecture decisions

- ADR 0008 — Fikua Lab frontends on Cloudflare Workers.

## License

Apache-2.0. See [LICENSE](LICENSE).
