import { base64urlEncode, base64urlEncodeJson, generateRandomString } from './utils';
import type { ExportedKeyPair } from './types';

function padOrTrim(arr: Uint8Array<ArrayBuffer>, len: number): Uint8Array<ArrayBuffer> {
    if (arr.length === len) return arr;
    if (arr.length > len) return arr.slice(arr.length - len) as Uint8Array<ArrayBuffer>;
    const padded = new Uint8Array(len);
    padded.set(arr, len - arr.length);
    return padded;
}

function derToRaw(der: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
    let offset = 2;
    const rLen = der[offset + 1];
    let r = der.slice(offset + 2, offset + 2 + rLen) as Uint8Array<ArrayBuffer>;
    offset = offset + 2 + rLen;
    const sLen = der[offset + 1];
    let s = der.slice(offset + 2, offset + 2 + sLen) as Uint8Array<ArrayBuffer>;
    r = padOrTrim(r, 32);
    s = padOrTrim(s, 32);
    const raw = new Uint8Array(64);
    raw.set(r, 0);
    raw.set(s, 32);
    return raw;
}

/** Generate EC P-256 key pair with non-extractable private key (for holder binding). */
export async function generateHolderKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify'],
    );
}

/** Generate EC P-256 key pair with extractable keys (for DPoP/WIA — needs sessionStorage serialization). */
export async function generateExtractableKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify'],
    );
}

/** Export public key as JWK (public fields only). */
export async function exportPublicJwk(keyPair: CryptoKeyPair): Promise<JsonWebKey> {
    const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

/** Export full key pair as JWK (for sessionStorage persistence during redirect). */
export async function exportKeyPair(keyPair: CryptoKeyPair): Promise<ExportedKeyPair> {
    return {
        privateKey: await crypto.subtle.exportKey('jwk', keyPair.privateKey),
        publicKey: await crypto.subtle.exportKey('jwk', keyPair.publicKey),
    };
}

/** Import key pair from exported JWK. */
export async function importKeyPair(exported: ExportedKeyPair): Promise<CryptoKeyPair> {
    const privateKey = await crypto.subtle.importKey(
        'jwk', exported.privateKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true, ['sign'],
    );
    const publicKey = await crypto.subtle.importKey(
        'jwk', exported.publicKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true, ['verify'],
    );
    return { privateKey, publicKey } as CryptoKeyPair;
}

export async function sha256(data: string | Uint8Array): Promise<Uint8Array> {
    const bytes = (typeof data === 'string') ? new TextEncoder().encode(data) : data;
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
}

async function signES256(privateKey: CryptoKey, data: string | Uint8Array): Promise<Uint8Array> {
    const bytes = (typeof data === 'string') ? new TextEncoder().encode(data) : data;
    const sig = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey,
        bytes as Uint8Array<ArrayBuffer>,
    );
    return derToRaw(new Uint8Array(sig));
}

/** Build and sign a JWT with ES256. */
export async function buildJwt(
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
    privateKey: CryptoKey,
): Promise<string> {
    const headerB64 = base64urlEncodeJson(header);
    const payloadB64 = base64urlEncodeJson(payload);
    const sigInput = headerB64 + '.' + payloadB64;
    const sig = await signES256(privateKey, sigInput);
    return sigInput + '.' + base64urlEncode(sig);
}

/** Generate PKCE code_verifier + code_challenge (S256). */
export async function generatePkce(): Promise<{ code_verifier: string; code_challenge: string }> {
    const verifier = generateRandomString(32);
    const challenge = await sha256(verifier);
    return { code_verifier: verifier, code_challenge: base64urlEncode(challenge) };
}
