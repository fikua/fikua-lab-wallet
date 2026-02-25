import QrScanner from 'qr-scanner';

export interface QrScanResult {
    data: string;
}

export interface ScanCallbacks {
    onResult: (result: QrScanResult) => void;
    onStatus?: (msg: string) => void;
}

/**
 * Start scanning for QR codes on the given video element.
 * Uses qr-scanner (nimiq) which handles its own Web Worker,
 * adaptive binarization, and BarcodeDetector fallback internally.
 *
 * Returns an AbortController — call .abort() to stop scanning and
 * release the camera.
 */
export function startScanning(
    video: HTMLVideoElement,
    callbacks: ScanCallbacks,
): AbortController {
    const controller = new AbortController();

    const scanner = new QrScanner(
        video,
        (result: QrScanner.ScanResult) => {
            callbacks.onStatus?.('QR detected');
            callbacks.onResult({ data: result.data });
            scanner.stop();
            scanner.destroy();
        },
        {
            preferredCamera: 'environment',
            highlightScanRegion: true,
            highlightCodeOutline: true,
            returnDetailedScanResult: true,
            maxScansPerSecond: 10,
        },
    );

    controller.signal.addEventListener('abort', () => {
        scanner.stop();
        scanner.destroy();
    }, { once: true });

    scanner.start()
        .then(() => callbacks.onStatus?.('Scanning...'))
        .catch(() => callbacks.onStatus?.('Camera not available'));

    return controller;
}
