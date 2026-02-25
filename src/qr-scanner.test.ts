import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock qr-scanner module — nimiq's QrScanner manages camera & worker internally,
// so we mock at the module boundary to test our wrapper's behaviour.
const startMock = vi.fn().mockResolvedValue(undefined);
const stopMock = vi.fn();
const destroyMock = vi.fn();
let constructorCallback: ((result: { data: string }) => void) | null = null;

vi.mock('qr-scanner', () => {
    return {
        default: class MockQrScanner {
            constructor(_video: HTMLVideoElement, onDecode: (result: { data: string }) => void) {
                constructorCallback = onDecode;
            }
            start = startMock;
            stop = stopMock;
            destroy = destroyMock;
        },
    };
});

describe('startScanning (qr-scanner nimiq wrapper)', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        constructorCallback = null;
    });

    afterEach(() => {
        vi.resetModules();
    });

    it('returns an AbortController', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = document.createElement('video');
        const controller = startScanning(video, { onResult: vi.fn() });
        expect(controller).toBeInstanceOf(AbortController);
        controller.abort();
    });

    it('calls scanner.start() on creation', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = document.createElement('video');
        const controller = startScanning(video, { onResult: vi.fn() });
        expect(startMock).toHaveBeenCalledOnce();
        controller.abort();
    });

    it('calls onResult when QR code is detected', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = document.createElement('video');
        const onResult = vi.fn();
        const controller = startScanning(video, { onResult });

        // Simulate QR detection via the callback captured from the constructor
        constructorCallback!({ data: 'openid-credential-offer://test' });

        expect(onResult).toHaveBeenCalledWith({ data: 'openid-credential-offer://test' });
        expect(stopMock).toHaveBeenCalled();
        expect(destroyMock).toHaveBeenCalled();
        controller.abort();
    });

    it('stops and destroys scanner on abort', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = document.createElement('video');
        const controller = startScanning(video, { onResult: vi.fn() });

        controller.abort();

        expect(stopMock).toHaveBeenCalled();
        expect(destroyMock).toHaveBeenCalled();
    });

    it('calls onStatus with "Scanning..." after start', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = document.createElement('video');
        const onStatus = vi.fn();
        startScanning(video, { onResult: vi.fn(), onStatus });

        // Wait for the start() promise to resolve
        await vi.waitFor(() => expect(onStatus).toHaveBeenCalledWith('Scanning...'));
    });

    it('calls onStatus with "QR detected" before onResult', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = document.createElement('video');
        const calls: string[] = [];
        const controller = startScanning(video, {
            onResult: () => calls.push('result'),
            onStatus: (msg) => calls.push('status:' + msg),
        });

        // Wait for start, then simulate detection
        await vi.waitFor(() => expect(calls).toContain('status:Scanning...'));
        constructorCallback!({ data: 'test' });

        expect(calls).toContain('status:QR detected');
        const qrIdx = calls.indexOf('status:QR detected');
        const resultIdx = calls.indexOf('result');
        expect(qrIdx).toBeLessThan(resultIdx);
        controller.abort();
    });

    // Full integration testing (real camera + QR decode) is done manually on device.
});
