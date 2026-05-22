/**
 * Cloudflare Worker for lab.fikua.com/wallet/*.
 *
 * Serves the static UI for any non-API path. For API paths the role
 * prefix is stripped and the request is forwarded to the lab backend at
 * https://lab-backend.fikua.com (Cloudflare Tunnel + Access Service
 * Auth), attaching the CF-Access service-token headers so the Access
 * policy lets it through.
 */

export interface Env {
    ASSETS: Fetcher;
    LAB_BACKEND_ORIGIN: string;
    CF_ACCESS_CLIENT_ID: string;
    CF_ACCESS_CLIENT_SECRET: string;
}

const ROLE_PREFIX = '/wallet';

const BACKEND_PREFIXES = [
    '/.well-known/',
    '/oid4vci/',
    '/oid4vp/',
];

function matchesBackend(relativePath: string): boolean {
    return BACKEND_PREFIXES.some((p) =>
        p.endsWith('/')
            ? relativePath.startsWith(p)
            : relativePath === p || relativePath.startsWith(p + '/'),
    );
}

async function proxyToBackend(request: Request, env: Env, relativePath: string): Promise<Response> {
    const url = new URL(request.url);
    const upstream = new URL(relativePath + url.search, env.LAB_BACKEND_ORIGIN);
    const headers = new Headers(request.headers);
    headers.set('CF-Access-Client-Id', env.CF_ACCESS_CLIENT_ID);
    headers.set('CF-Access-Client-Secret', env.CF_ACCESS_CLIENT_SECRET);
    return fetch(upstream.toString(), {
        method: request.method,
        headers,
        body: ['GET', 'HEAD'].includes(request.method)
            ? undefined
            : await request.clone().arrayBuffer(),
        redirect: 'manual',
    });
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);

        // Canonical role URL ends with a slash: redirect /<role> → /<role>/
        // so relative asset references in index.html resolve against the
        // correct base.
        if (url.pathname === ROLE_PREFIX) {
            return Response.redirect(url.origin + ROLE_PREFIX + '/' + url.search, 301);
        }

        const relative = url.pathname.startsWith(ROLE_PREFIX)
            ? url.pathname.slice(ROLE_PREFIX.length) || '/'
            : url.pathname;

        if (matchesBackend(relative)) {
            return proxyToBackend(request, env, relative);
        }
        // Static asset lookup: strip the role prefix so /<role>/foo.css
        // hits dist/foo.css instead of dist/<role>/foo.css.
        const rewritten = new URL(relative + url.search, url.origin);
        return env.ASSETS.fetch(new Request(rewritten, request));
    },
};
