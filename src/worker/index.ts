/**
 * Cloudflare Worker for wallet.lab.fikua.com.
 *
 * Proxies API paths to https://api.lab.fikua.com (the Fikua Lab backend on
 * the VPS, fronted by Traefik). Everything else falls through to the
 * static asset binding.
 */

export interface Env {
    ASSETS: Fetcher;
}

const BACKEND_ORIGIN = 'https://api.lab.fikua.com';

const BACKEND_PREFIXES = ["/.well-known/", "/oid4vci/", "/oid4vp/", "/health"];

function isBackendPath(pathname: string): boolean {
    return BACKEND_PREFIXES.some((p) =>
        p.endsWith('/') ? pathname.startsWith(p) : pathname === p || pathname.startsWith(p + '/'),
    );
}

async function proxyToBackend(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const upstream = new URL(BACKEND_ORIGIN + url.pathname + url.search);
    const init: RequestInit = {
        method: request.method,
        headers: request.headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.clone().arrayBuffer(),
        redirect: 'manual',
    };
    return fetch(upstream.toString(), init);
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);
        if (isBackendPath(url.pathname)) {
            return proxyToBackend(request);
        }
        return env.ASSETS.fetch(request);
    },
};
