import { defineConfig } from 'vite';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
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
            manifest: {
                name: 'Fikua Lab Wallet',
                short_name: 'Wallet',
                description: 'Digital Identity Wallet for Fikua Lab',
                theme_color: '#2A9D8F',
                background_color: '#0f1117',
                display: 'standalone',
                orientation: 'portrait',
                icons: [
                    { src: 'icon-192.png', type: 'image/png', sizes: '192x192' },
                    { src: 'icon-512.png', type: 'image/png', sizes: '512x512', purpose: 'any' },
                    { src: 'favicon.svg', type: 'image/svg+xml', sizes: 'any' },
                ],
            },
            workbox: {
                globPatterns: ['**/*.{js,css,html,svg}'],
                navigateFallback: 'index.html',
                runtimeCaching: [
                    {
                        urlPattern: /\/(oid4vci|oid4vp|admin|\.well-known)\//,
                        handler: 'NetworkOnly',
                    },
                ],
            },
        }),
    ],
});
