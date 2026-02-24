import jsQR from 'jsqr';

self.onmessage = (e: MessageEvent) => {
    const { data, width, height } = e.data;
    try {
        const result = jsQR(new Uint8ClampedArray(data), width, height);
        self.postMessage(result ? { type: 'result', data: result.data } : { type: 'empty' });
    } catch {
        self.postMessage({ type: 'empty' });
    }
};
