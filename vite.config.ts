import { defineConfig } from 'vite';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
    // The wallet PWA is served at its own domain's root,
    // https://wallet.fikua.com — matching the convention
    // issuer.fikua.com/idp.fikua.com/attestation-registry.fikua.com
    // already follow, replacing the old lab.fikua.com/wallet/* subpath
    // mount. No base path needed anymore.
    base: '/',
    root: '.',
    publicDir: 'public',
    build: {
        outDir: 'dist',
        emptyOutDir: true,
    },
    server: {
        port: 3004,
    },
    plugins: [
        VitePWA({
            registerType: 'autoUpdate',
            scope: '/',
            manifest: {
                name: 'Fikua Lab Wallet',
                short_name: 'Wallet',
                description: 'Digital Identity Wallet for Fikua Lab',
                theme_color: '#1A4C9C',
                background_color: '#1A1A1A',
                display: 'standalone',
                orientation: 'portrait',
                scope: '/',
                start_url: '/',
                icons: [
                    { src: 'icon-192.png', type: 'image/png', sizes: '192x192' },
                    { src: 'icon-512.png', type: 'image/png', sizes: '512x512', purpose: 'any' },
                    { src: 'favicon.svg', type: 'image/svg+xml', sizes: 'any' },
                ],
            },
            workbox: {
                globPatterns: ['**/*.{js,css,html,svg}'],
                navigateFallback: '/index.html',
                // No API paths to deny anymore — the wallet calls
                // issuer.fikua.com / idp.fikua.com directly (different
                // origins), so the service worker's own navigation
                // fallback/precache never sees those requests at all.
            },
        }),
    ],
});
