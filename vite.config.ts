import { defineConfig } from 'vite';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
    // The wallet PWA is served at https://lab.fikua.com/wallet/ in
    // production, so every emitted asset URL must be prefixed with
    // /wallet/ (Vite handles this through `base`).
    base: '/wallet/',
    root: '.',
    publicDir: 'public',
    build: {
        outDir: 'dist',
        emptyOutDir: true,
    },
    server: {
        port: 3004,
        proxy: {
            '/.well-known': 'http://localhost:8090',
            '/oid4vci': 'http://localhost:8090',
            '/oid4vp': 'http://localhost:8090',
            '/admin': 'http://localhost:8090',
        },
    },
    plugins: [
        VitePWA({
            registerType: 'autoUpdate',
            // PWA is mounted under /wallet/ on lab.fikua.com.
            scope: '/wallet/',
            manifest: {
                name: 'Fikua Lab Wallet',
                short_name: 'Wallet',
                description: 'Digital Identity Wallet for Fikua Lab',
                theme_color: '#2A9D8F',
                background_color: '#0f1117',
                display: 'standalone',
                orientation: 'portrait',
                scope: '/wallet/',
                start_url: '/wallet/',
                icons: [
                    { src: 'icon-192.png', type: 'image/png', sizes: '192x192' },
                    { src: 'icon-512.png', type: 'image/png', sizes: '512x512', purpose: 'any' },
                    { src: 'favicon.svg', type: 'image/svg+xml', sizes: 'any' },
                ],
            },
            workbox: {
                globPatterns: ['**/*.{js,css,html,svg}'],
                navigateFallback: '/wallet/index.html',
                navigateFallbackDenylist: [/^\/wallet\/(\.well-known|oid4vci|oid4vp|admin)\//],
                runtimeCaching: [
                    {
                        // Don't cache backend calls — they go through the Worker
                        // proxy which also strips the /wallet prefix.
                        urlPattern: /\/wallet\/(oid4vci|oid4vp|admin|\.well-known)\//,
                        handler: 'NetworkOnly',
                    },
                ],
            },
        }),
    ],
});
