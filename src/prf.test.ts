import { describe, it, expect, afterEach, vi } from 'vitest';
import { PRF_SALT_KEY } from './constants';
import {
    getOrCreatePrfSalt, evaluatePrf, deriveP256FromPrf,
    isPrfSupported, getPrfWiaKeyPair,
} from './prf';

afterEach(() => {
    localStorage.clear();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
});

describe('getOrCreatePrfSalt', () => {
    it('creates and persists a 32-byte salt on first call', () => {
        const salt = getOrCreatePrfSalt();
        expect(salt).toBeInstanceOf(Uint8Array);
        expect(salt.length).toBe(32);
        expect(localStorage.getItem(PRF_SALT_KEY)).not.toBeNull();
    });

    it('returns the same salt on subsequent calls', () => {
        const first = getOrCreatePrfSalt();
        const second = getOrCreatePrfSalt();
        expect(second).toEqual(first);
    });

    it('reads back an already-stored salt instead of generating a new one', () => {
        const original = getOrCreatePrfSalt();
        // Simulate a fresh page load: same storage, but re-read.
        const reread = getOrCreatePrfSalt();
        expect(reread).toEqual(original);
    });
});

describe('evaluatePrf', () => {
    it('returns null when PublicKeyCredential is unsupported', async () => {
        vi.stubGlobal('PublicKeyCredential', undefined);
        const result = await evaluatePrf();
        expect(result).toBeNull();
    });

    it('returns null when no assertion is returned', async () => {
        vi.stubGlobal('PublicKeyCredential', function () {});
        vi.stubGlobal('navigator', {
            ...navigator,
            credentials: { get: vi.fn().mockResolvedValue(null) },
        });
        const result = await evaluatePrf();
        expect(result).toBeNull();
    });

    it('returns null when the assertion carries no PRF results', async () => {
        vi.stubGlobal('PublicKeyCredential', function () {});
        const assertion = {
            getClientExtensionResults: () => ({}),
        };
        vi.stubGlobal('navigator', {
            ...navigator,
            credentials: { get: vi.fn().mockResolvedValue(assertion) },
        });
        const result = await evaluatePrf();
        expect(result).toBeNull();
    });

    it('returns the PRF bytes when the authenticator supports it', async () => {
        vi.stubGlobal('PublicKeyCredential', function () {});
        const prfOutput = new Uint8Array(32).fill(7).buffer;
        const assertion = {
            getClientExtensionResults: () => ({ prf: { results: { first: prfOutput } } }),
        };
        const getMock = vi.fn().mockResolvedValue(assertion);
        vi.stubGlobal('navigator', { ...navigator, credentials: { get: getMock } });

        const result = await evaluatePrf();
        expect(result).not.toBeNull();
        expect(result).toEqual(new Uint8Array(32).fill(7));

        // Confirms the PRF salt (not some other value) is what gets sent to
        // the authenticator as the evaluation input.
        const salt = getOrCreatePrfSalt();
        const options = getMock.mock.calls[0][0].publicKey;
        expect(new Uint8Array(options.extensions.prf.eval.first)).toEqual(salt);
    });

    it('scopes the request to a specific credential when one is given', async () => {
        vi.stubGlobal('PublicKeyCredential', function () {});
        const getMock = vi.fn().mockResolvedValue(null);
        vi.stubGlobal('navigator', { ...navigator, credentials: { get: getMock } });

        const credentialId = new Uint8Array([1, 2, 3]);
        await evaluatePrf(credentialId);

        const options = getMock.mock.calls[0][0].publicKey;
        expect(options.allowCredentials).toEqual([{ id: credentialId, type: 'public-key' }]);
    });
});

describe('isPrfSupported', () => {
    it('returns true when evaluatePrf resolves with bytes', async () => {
        vi.stubGlobal('PublicKeyCredential', function () {});
        const assertion = {
            getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).buffer } } }),
        };
        vi.stubGlobal('navigator', {
            ...navigator,
            credentials: { get: vi.fn().mockResolvedValue(assertion) },
        });
        expect(await isPrfSupported()).toBe(true);
    });

    it('returns false when PRF is unsupported', async () => {
        vi.stubGlobal('PublicKeyCredential', undefined);
        expect(await isPrfSupported()).toBe(false);
    });

    it('returns false (not throws) when the authenticator call rejects', async () => {
        vi.stubGlobal('PublicKeyCredential', function () {});
        vi.stubGlobal('navigator', {
            ...navigator,
            credentials: { get: vi.fn().mockRejectedValue(new Error('NotAllowedError')) },
        });
        expect(await isPrfSupported()).toBe(false);
    });
});

describe('deriveP256FromPrf', () => {
    it('derives a usable, non-extractable ECDSA P-256 key pair', async () => {
        const prfBytes = crypto.getRandomValues(new Uint8Array(32));
        const kp = await deriveP256FromPrf(prfBytes);

        expect(kp.privateKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
        expect(kp.privateKey.extractable).toBe(false);
        expect(kp.publicKey.extractable).toBe(true);

        // The derived key must actually be usable to sign/verify.
        const data = new TextEncoder().encode('prf key smoke test');
        const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data);
        const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, kp.publicKey, sig, data);
        expect(ok).toBe(true);
    });

    it('is deterministic: the same PRF bytes always derive the same key pair', async () => {
        const prfBytes = new Uint8Array(32).fill(42);
        const kp1 = await deriveP256FromPrf(prfBytes);
        const kp2 = await deriveP256FromPrf(prfBytes);

        const pub1 = await crypto.subtle.exportKey('jwk', kp1.publicKey);
        const pub2 = await crypto.subtle.exportKey('jwk', kp2.publicKey);
        expect(pub1.x).toBe(pub2.x);
        expect(pub1.y).toBe(pub2.y);
    });

    it('different PRF bytes derive different key pairs', async () => {
        const kp1 = await deriveP256FromPrf(new Uint8Array(32).fill(1));
        const kp2 = await deriveP256FromPrf(new Uint8Array(32).fill(2));

        const pub1 = await crypto.subtle.exportKey('jwk', kp1.publicKey);
        const pub2 = await crypto.subtle.exportKey('jwk', kp2.publicKey);
        expect(pub1.x).not.toBe(pub2.x);
    });
});

describe('getPrfWiaKeyPair', () => {
    it('returns null when PRF evaluation is unsupported', async () => {
        vi.stubGlobal('PublicKeyCredential', undefined);
        const result = await getPrfWiaKeyPair();
        expect(result).toBeNull();
    });

    it('returns null (not throws) when the authenticator call rejects', async () => {
        vi.stubGlobal('PublicKeyCredential', function () {});
        vi.stubGlobal('navigator', {
            ...navigator,
            credentials: { get: vi.fn().mockRejectedValue(new Error('NotAllowedError')) },
        });
        const result = await getPrfWiaKeyPair();
        expect(result).toBeNull();
    });

    it('derives a key pair end-to-end when PRF is supported', async () => {
        vi.stubGlobal('PublicKeyCredential', function () {});
        const prfOutput = crypto.getRandomValues(new Uint8Array(32));
        const assertion = {
            getClientExtensionResults: () => ({ prf: { results: { first: prfOutput.buffer } } }),
        };
        vi.stubGlobal('navigator', {
            ...navigator,
            credentials: { get: vi.fn().mockResolvedValue(assertion) },
        });

        const kp = await getPrfWiaKeyPair();
        expect(kp).not.toBeNull();
        expect(kp!.privateKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
    });
});
