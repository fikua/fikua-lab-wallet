import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

function createMockVideo(readyState = 0, videoWidth = 0, videoHeight = 0): HTMLVideoElement {
    const video = document.createElement('video');
    Object.defineProperty(video, 'readyState', { value: readyState, writable: true });
    Object.defineProperty(video, 'videoWidth', { value: videoWidth, writable: true });
    Object.defineProperty(video, 'videoHeight', { value: videoHeight, writable: true });
    return video;
}

describe('startScanning (worker fallback path)', () => {
    let rafCallbacks: Array<(t: number) => void>;
    let originalRaf: typeof requestAnimationFrame;
    let terminateSpy: ReturnType<typeof vi.fn>;

    beforeEach(() => {
        // Ensure no BarcodeDetector so worker fallback path runs
        delete (globalThis as Record<string, unknown>).BarcodeDetector;

        rafCallbacks = [];
        originalRaf = globalThis.requestAnimationFrame;
        globalThis.requestAnimationFrame = vi.fn((cb: FrameRequestCallback) => {
            rafCallbacks.push(cb);
            return rafCallbacks.length;
        }) as unknown as typeof requestAnimationFrame;

        terminateSpy = vi.fn();
        vi.stubGlobal('Worker', class MockWorker {
            onmessage: ((e: MessageEvent) => void) | null = null;
            postMessage = vi.fn();
            terminate = terminateSpy;
            addEventListener = vi.fn();
        });
    });

    afterEach(() => {
        globalThis.requestAnimationFrame = originalRaf;
        vi.unstubAllGlobals();
        vi.resetModules();
    });

    function flushFrame(timestamp: number): void {
        const pending = [...rafCallbacks];
        rafCallbacks = [];
        pending.forEach(cb => cb(timestamp));
    }

    it('returns an AbortController', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = createMockVideo();
        const controller = startScanning(video, { onResult: vi.fn() });
        expect(controller).toBeInstanceOf(AbortController);
        controller.abort();
    });

    it('schedules a requestAnimationFrame on start', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = createMockVideo();
        const controller = startScanning(video, { onResult: vi.fn() });
        expect(requestAnimationFrame).toHaveBeenCalledOnce();
        controller.abort();
    });

    it('stops scanning when aborted', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = createMockVideo();
        const controller = startScanning(video, { onResult: vi.fn() });
        controller.abort();
        flushFrame(0);
        expect(rafCallbacks).toHaveLength(0);
    });

    it('does not call onResult when video has no data', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = createMockVideo(0, 0, 0);
        const onResult = vi.fn();
        const controller = startScanning(video, { onResult });
        flushFrame(0);
        flushFrame(200);
        expect(onResult).not.toHaveBeenCalled();
        controller.abort();
    });

    it('schedules next frame when video has no data', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = createMockVideo(0, 0, 0);
        const controller = startScanning(video, { onResult: vi.fn() });
        flushFrame(0);
        expect(rafCallbacks.length).toBeGreaterThan(0);
        controller.abort();
    });

    it('terminates worker on abort', async () => {
        const { startScanning } = await import('./qr-scanner');
        const video = createMockVideo();
        const controller = startScanning(video, { onResult: vi.fn() });
        controller.abort();
        expect(terminateSpy).toHaveBeenCalled();
    });

    // Canvas decode and BarcodeDetector tests require a real browser.
    // QR decode accuracy is covered by the 'qr' library's own test suite.
    // Full integration testing is done manually on a real device.
});
