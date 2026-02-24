declare class BarcodeDetector {
    constructor(options: { formats: string[] });
    detect(source: ImageBitmapSource): Promise<Array<{ rawValue: string }>>;
}

const MAX_CANVAS_SIZE = 480;
const WORKER_THROTTLE_MS = 100;

export interface QrScanResult {
    data: string;
}

export interface ScanCallbacks {
    onResult: (result: QrScanResult) => void;
    onStatus?: (msg: string) => void;
}

const nativeDetector: BarcodeDetector | null =
    'BarcodeDetector' in globalThis
        ? new BarcodeDetector({ formats: ['qr_code'] })
        : null;

export function startScanning(
    video: HTMLVideoElement,
    callbacks: ScanCallbacks,
): AbortController {
    const controller = new AbortController();

    if (nativeDetector) {
        runNativeScanLoop(video, callbacks, controller.signal);
    } else {
        runWorkerScanLoop(video, callbacks, controller.signal);
    }

    return controller;
}

// ---------------------------------------------------------------------------
// BarcodeDetector path (Chrome/Edge Android) — native, no throttle
// ---------------------------------------------------------------------------

function runNativeScanLoop(
    video: HTMLVideoElement,
    callbacks: ScanCallbacks,
    signal: AbortSignal,
): void {
    let scanning = false;
    let frameCount = 0;

    function scanFrame(): void {
        if (signal.aborted) return;

        if (!scanning && video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && video.videoWidth > 0) {
            scanning = true;
            frameCount++;

            createImageBitmap(video)
                .then(bitmap => nativeDetector!.detect(bitmap).finally(() => bitmap.close()))
                .then(results => {
                    scanning = false;
                    if (signal.aborted) return;
                    if (results.length > 0) {
                        callbacks.onStatus?.('QR detected');
                        callbacks.onResult({ data: results[0].rawValue });
                        return;
                    }
                    callbacks.onStatus?.('Scanning... (frame ' + frameCount + ')');
                    requestAnimationFrame(scanFrame);
                })
                .catch(() => {
                    scanning = false;
                    if (!signal.aborted) requestAnimationFrame(scanFrame);
                });
        } else {
            requestAnimationFrame(scanFrame);
        }
    }

    requestAnimationFrame(scanFrame);
}

// ---------------------------------------------------------------------------
// Web Worker path (iOS Safari, Firefox) — off main thread
// ---------------------------------------------------------------------------

function runWorkerScanLoop(
    video: HTMLVideoElement,
    callbacks: ScanCallbacks,
    signal: AbortSignal,
): void {
    const worker = new Worker(
        new URL('./qr-decode-worker.ts', import.meta.url),
        { type: 'module' },
    );
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true })!;
    let lastScanTime = 0;
    let workerBusy = false;
    let frameCount = 0;

    signal.addEventListener('abort', () => worker.terminate(), { once: true });

    worker.onmessage = (e: MessageEvent) => {
        workerBusy = false;
        if (signal.aborted) return;

        if (e.data.type === 'result') {
            callbacks.onStatus?.('QR detected');
            callbacks.onResult({ data: e.data.data });
            worker.terminate();
            return;
        }
    };

    function scanFrame(timestamp: number): void {
        if (signal.aborted) return;

        if (!workerBusy && timestamp - lastScanTime >= WORKER_THROTTLE_MS) {
            lastScanTime = timestamp;

            if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && video.videoWidth > 0) {
                const scale = Math.min(1, MAX_CANVAS_SIZE / Math.max(video.videoWidth, video.videoHeight));
                const w = Math.round(video.videoWidth * scale);
                const h = Math.round(video.videoHeight * scale);

                if (canvas.width !== w || canvas.height !== h) {
                    canvas.width = w;
                    canvas.height = h;
                }

                ctx.drawImage(video, 0, 0, w, h);
                const imageData = ctx.getImageData(0, 0, w, h);
                frameCount++;

                workerBusy = true;
                worker.postMessage(
                    { type: 'decode', data: imageData.data, width: w, height: h },
                    [imageData.data.buffer],
                );

                callbacks.onStatus?.('Scanning... (frame ' + frameCount + ')');
            }
        }

        requestAnimationFrame(scanFrame);
    }

    requestAnimationFrame(scanFrame);
}
