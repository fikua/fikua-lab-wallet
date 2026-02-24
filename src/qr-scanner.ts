import decodeQR from 'qr/decode.js';

const SCAN_INTERVAL_MS = 150;
const MAX_CANVAS_SIZE = 480;

export interface QrScanResult {
    data: string;
}

export interface ScanCallbacks {
    onResult: (result: QrScanResult) => void;
    onStatus?: (msg: string) => void;
}

export function startScanning(
    video: HTMLVideoElement,
    callbacks: ScanCallbacks,
): AbortController {
    const controller = new AbortController();
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true })!;
    let lastScanTime = 0;
    let frameCount = 0;

    function scanFrame(timestamp: number): void {
        if (controller.signal.aborted) return;

        if (timestamp - lastScanTime >= SCAN_INTERVAL_MS) {
            lastScanTime = timestamp;

            if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && video.videoWidth > 0) {
                // Scale down to MAX_CANVAS_SIZE for faster decode
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

                try {
                    const result = decodeQR({ data: imageData.data, width: w, height: h });
                    if (result) {
                        callbacks.onStatus?.('QR detected');
                        callbacks.onResult({ data: result });
                        return;
                    }
                } catch {
                    // decode throws on unreadable frames; continue scanning
                }

                if (callbacks.onStatus) {
                    callbacks.onStatus('Scanning... (frame ' + frameCount + ')');
                }
            }
        }

        requestAnimationFrame(scanFrame);
    }

    requestAnimationFrame(scanFrame);
    return controller;
}
