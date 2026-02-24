import decodeQR from 'qr/decode.js';

self.onmessage = (e: MessageEvent) => {
    const { data, width, height } = e.data;
    try {
        const result = decodeQR({ data, width, height });
        self.postMessage(result ? { type: 'result', data: result } : { type: 'empty' });
    } catch {
        self.postMessage({ type: 'empty' });
    }
};
