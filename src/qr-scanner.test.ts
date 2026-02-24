import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { startScanning } from './qr-scanner';

function createMockVideo(readyState = 0, videoWidth = 0, videoHeight = 0): HTMLVideoElement {
    const video = document.createElement('video');
    Object.defineProperty(video, 'readyState', { value: readyState, writable: true });
    Object.defineProperty(video, 'videoWidth', { value: videoWidth, writable: true });
    Object.defineProperty(video, 'videoHeight', { value: videoHeight, writable: true });
    return video;
}

describe('startScanning', () => {
    let rafCallbacks: Array<(t: number) => void>;
    let originalRaf: typeof requestAnimationFrame;

    beforeEach(() => {
        rafCallbacks = [];
        originalRaf = globalThis.requestAnimationFrame;
        globalThis.requestAnimationFrame = vi.fn((cb: FrameRequestCallback) => {
            rafCallbacks.push(cb);
            return rafCallbacks.length;
        }) as unknown as typeof requestAnimationFrame;
    });

    afterEach(() => {
        globalThis.requestAnimationFrame = originalRaf;
    });

    function flushFrame(timestamp: number): void {
        const pending = [...rafCallbacks];
        rafCallbacks = [];
        pending.forEach(cb => cb(timestamp));
    }

    it('returns an AbortController', () => {
        const video = createMockVideo();
        const controller = startScanning(video, { onResult: vi.fn() });
        expect(controller).toBeInstanceOf(AbortController);
        controller.abort();
    });

    it('schedules a requestAnimationFrame on start', () => {
        const video = createMockVideo();
        const controller = startScanning(video, { onResult: vi.fn() });
        expect(requestAnimationFrame).toHaveBeenCalledOnce();
        controller.abort();
    });

    it('stops scanning when aborted', () => {
        const video = createMockVideo();
        const controller = startScanning(video, { onResult: vi.fn() });
        controller.abort();

        flushFrame(0);
        // After abort, no new rAF should be scheduled beyond the initial one
        expect(rafCallbacks).toHaveLength(0);
    });

    it('does not call onResult when video has no data', () => {
        const video = createMockVideo(0, 0, 0);
        const onResult = vi.fn();
        const controller = startScanning(video, { onResult });

        // Flush with enough time gap to pass throttle
        flushFrame(0);
        flushFrame(300);

        expect(onResult).not.toHaveBeenCalled();
        controller.abort();
    });

    it('schedules next frame when video has no data', () => {
        const video = createMockVideo(0, 0, 0);
        const controller = startScanning(video, { onResult: vi.fn() });

        flushFrame(0);
        // Should have scheduled another frame
        expect(rafCallbacks.length).toBeGreaterThan(0);
        controller.abort();
    });

    // Canvas decode tests require a real canvas (jsdom does not implement getContext).
    // Actual QR decode accuracy is covered by the 'qr' library's own test suite.
    // Full integration testing is done manually on a real device.
});
