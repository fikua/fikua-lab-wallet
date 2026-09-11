import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'jsdom',
        include: ['src/**/*.test.ts'],
        setupFiles: ['src/test/setup.ts'],
        coverage: {
            provider: 'v8',
            // lcov is what SonarCloud's sonar.javascript.lcov.reportPaths reads.
            reporter: ['text', 'lcov'],
            include: ['src/**/*.ts'],
            exclude: ['src/**/*.test.ts', 'src/test/**', 'src/worker/**'],
        },
    },
});
