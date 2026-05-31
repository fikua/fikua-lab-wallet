// WebAuthn PRF-backed wallet key.
//
// Instead of storing the WIA proof-of-possession private key in IndexedDB,
// we derive it from a passkey via the WebAuthn PRF extension (HMAC-secret).
// The passkey's secret lives in the authenticator (Secure Enclave / TPM /
// security key) and never leaves it; PRF(secret, salt) returns 32 deterministic
// bytes that we expand (HKDF) into a P-256 private scalar. Same passkey + same
// salt => same key, every time, gated by user verification (biometric/PIN).
//
// This is the closest a browser PWA gets to an ARF WSCD: the signing key is
// bound to hardware and every signature requires user presence. It is NOT a
// certified WSCD; document that boundary.
//
// Support is not universal (needs an authenticator + browser with PRF). Callers
// should fall back to the IndexedDB key when isPrfSupported() is false.

import { PRF_SALT_KEY } from './constants';

/** Stable per-wallet salt for PRF evaluation. Created once, kept in storage. */
export function getOrCreatePrfSalt(): Uint8Array {
    const existing = localStorage.getItem(PRF_SALT_KEY);
    if (existing) {
        return Uint8Array.from(atob(existing), c => c.charCodeAt(0));
    }
    const salt = crypto.getRandomValues(new Uint8Array(32));
    localStorage.setItem(PRF_SALT_KEY, btoa(String.fromCharCode(...salt)));
    return salt;
}

/**
 * Evaluate the passkey PRF for our salt, returning 32 bytes — or null if the
 * authenticator/browser did not return a PRF result (unsupported). Triggers a
 * user-verification ceremony.
 */
export async function evaluatePrf(credentialId?: Uint8Array): Promise<Uint8Array | null> {
    if (!window.PublicKeyCredential) return null;
    const salt = getOrCreatePrfSalt();
    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const publicKey: PublicKeyCredentialRequestOptions = {
        challenge,
        rpId: window.location.hostname,
        userVerification: 'required',
        timeout: 60000,
        ...(credentialId ? { allowCredentials: [{ id: credentialId as BufferSource, type: 'public-key' as const }] } : {}),
        extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    };

    const assertion = await navigator.credentials.get({ publicKey }) as PublicKeyCredential | null;
    if (!assertion) return null;
    const ext = assertion.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } };
    const first = ext.prf?.results?.first;
    if (!first) return null; // PRF not supported / not evaluated
    return new Uint8Array(first);
}

/**
 * Derive a deterministic P-256 signing key pair from 32 bytes of PRF output.
 * HKDF-SHA256 expands the PRF bytes into a private scalar; we then build the
 * key via JWK. The derivation is pinned so the same PRF bytes always yield the
 * same key across sessions.
 */
export async function deriveP256FromPrf(prfBytes: Uint8Array): Promise<CryptoKeyPair> {
    // HKDF expand → 32-byte candidate scalar.
    const hkdfKey = await crypto.subtle.importKey('raw', prfBytes as Uint8Array<ArrayBuffer>,
        'HKDF', false, ['deriveBits']);
    const info = new TextEncoder().encode('fikua-wallet-wia-key-v1');
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: info as Uint8Array<ArrayBuffer> },
        hkdfKey, 256);
    const d = new Uint8Array(bits);

    // Build a P-256 private key from the scalar via JWK (d). Derive the public
    // point by importing the private key, then exporting the public JWK.
    const dJwk = {
        kty: 'EC', crv: 'P-256',
        d: base64url(d),
        // x/y are required by importKey for EC private JWKs; compute via a
        // throwaway import of the raw scalar is not directly supported, so we
        // use the well-known trick: import as PKCS8 is complex — instead derive
        // x,y by scalar-mult through SubtleCrypto is unavailable. We therefore
        // generate the public coordinates by importing d into an ECDSA key using
        // the JWK with a placeholder, which browsers reject; so we compute x,y
        // using a minimal EC math fallback.
    } as JsonWebKey;

    const pub = await p256PublicFromScalar(d);
    dJwk.x = pub.x;
    dJwk.y = pub.y;

    const privateKey = await crypto.subtle.importKey('jwk', dJwk,
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const publicKey = await crypto.subtle.importKey('jwk',
        { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y },
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    return { privateKey, publicKey };
}

/** True if a PRF evaluation returns bytes on this device/browser. */
export async function isPrfSupported(credentialId?: Uint8Array): Promise<boolean> {
    try {
        return (await evaluatePrf(credentialId)) !== null;
    } catch {
        return false;
    }
}

/**
 * Derive the WIA proof-of-possession key pair from the passkey via PRF, or
 * return null if PRF is unavailable (caller falls back to its stored key).
 * The private key is non-extractable and re-derived on demand — it is never
 * persisted, only the salt is.
 */
export async function getPrfWiaKeyPair(credentialId?: Uint8Array): Promise<CryptoKeyPair | null> {
    let prfBytes: Uint8Array | null;
    try {
        prfBytes = await evaluatePrf(credentialId);
    } catch {
        return null;
    }
    if (!prfBytes) return null;
    return deriveP256FromPrf(prfBytes);
}

// --- helpers -------------------------------------------------------------

function base64url(b: Uint8Array): string {
    return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Compute the P-256 public point (x, y) for a private scalar d. SubtleCrypto
 * has no scalar-mult primitive, so this does minimal secp256r1 point math.
 */
async function p256PublicFromScalar(d: Uint8Array): Promise<{ x: string; y: string }> {
    const { scalarMultBase } = await import('./p256');
    const { x, y } = scalarMultBase(bytesToBigInt(d));
    return { x: base64url(bigIntTo32(x)), y: base64url(bigIntTo32(y)) };
}

function bytesToBigInt(b: Uint8Array): bigint {
    let n = 0n;
    for (const x of b) n = (n << 8n) | BigInt(x);
    return n;
}

function bigIntTo32(n: bigint): Uint8Array {
    const out = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
    return out;
}
