export function base64urlEncode(data: Uint8Array): string {
    let str = '';
    for (let i = 0; i < data.length; i++) str += String.fromCharCode(data[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlDecode(str: string): Uint8Array {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

export function base64urlDecodeJson(str: string): Record<string, unknown> {
    return JSON.parse(new TextDecoder().decode(base64urlDecode(str)));
}

export function base64urlEncodeJson(obj: unknown): string {
    return base64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

export function esc(str: unknown): string {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

export function formatTime(ts: number): string {
    const d = new Date(ts);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function formatDate(ts: number): string {
    return new Date(ts).toISOString().slice(0, 10);
}

export function generateRandomString(length: number): string {
    return base64urlEncode(crypto.getRandomValues(new Uint8Array(length)));
}
