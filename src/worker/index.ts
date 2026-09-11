/**
 * Cloudflare Worker for wallet.fikua.com.
 *
 * Serves only the static PWA assets, at the domain's own root — no role
 * prefix to strip anymore, now that the wallet has its own custom domain
 * (see wrangler.toml) instead of being mounted under lab.fikua.com/wallet.
 * Since the fikua-lab-idp/fikua-lab-issuer split, the wallet talks
 * directly to https://issuer.fikua.com and https://idp.fikua.com (both
 * DNS-only, no Cloudflare proxy, to satisfy the FAPI 2.0 TLS conformance
 * requirements documented on those services) — there is no single "lab
 * backend" left for this Worker to sit in front of, so it no longer
 * proxies any API path. Those two hosts serve permissive CORS headers
 * for the wallet's own origin; this Worker has no part in that.
 */

export interface Env {
    ASSETS: Fetcher;
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        return env.ASSETS.fetch(request);
    },
};
