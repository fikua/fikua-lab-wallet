import decodeQR from 'qr/decode.js';

const SCAN_INTERVAL_MS = 200;

export interface QrScanResult {
    data: string;
}

export function startScanning(
    video: HTMLVideoElement,
    onResult: (result: QrScanResult) => void,
): AbortController {
    const controller = new AbortController();
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true })!;
    let lastScanTime = 0;

    function scanFrame(timestamp: number): void {
        if (controller.signal.aborted) return;

        if (timestamp - lastScanTime >= SCAN_INTERVAL_MS) {
            lastScanTime = timestamp;

            if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && video.videoWidth > 0) {
                if (canvas.width !== video.videoWidth || canvas.height !== video.videoHeight) {
                    canvas.width = video.videoWidth;
                    canvas.height = video.videoHeight;
                }

                ctx.drawImage(video, 0, 0);
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

                try {
                    const result = decodeQR({ data: imageData.data, width: canvas.width, height: canvas.height });
                    if (result) {
                        onResult({ data: result });
                        return;
                    }
                } catch {
                    // decode throws on unreadable frames; continue scanning
                }
            }
        }

        requestAnimationFrame(scanFrame);
    }

    requestAnimationFrame(scanFrame);
    return controller;
}
