import { describe, it, expect } from 'vitest';
import {
    generateHolderKeyPair, generateExtractableKeyPair,
    exportPublicJwk, exportKeyPair, importKeyPair,
    sha256, buildJwt, generatePkce,
} from './crypto';
import { base64urlDecode, base64urlDecodeJson } from './utils';

describe('generateHolderKeyPair', () => {
    it('generates an EC P-256 key pair', async () => {
        const kp = await generateHolderKeyPair();
        expect(kp.publicKey).toBeDefined();
        expect(kp.privateKey).toBeDefined();
        expect(kp.publicKey.algorithm).toMatchObject({ name: 'ECDSA' });
    });

    it('generates non-extractable private key', async () => {
        const kp = await generateHolderKeyPair();
        expect(kp.privateKey.extractable).toBe(false);
    });
});

describe('generateExtractableKeyPair', () => {
    it('generates extractable keys for DPoP/WIA', async () => {
        const kp = await generateExtractableKeyPair();
        expect(kp.privateKey.extractable).toBe(true);
        expect(kp.publicKey.extractable).toBe(true);
    });
});

describe('exportPublicJwk', () => {
    it('exports only public key fields (kty, crv, x, y)', async () => {
        const kp = await generateExtractableKeyPair();
        const jwk = await exportPublicJwk(kp);
        expect(jwk.kty).toBe('EC');
        expect(jwk.crv).toBe('P-256');
        expect(jwk.x).toBeDefined();
        expect(jwk.y).toBeDefined();
        expect(jwk.d).toBeUndefined();
    });
});

describe('exportKeyPair / importKeyPair', () => {
    it('round-trips an extractable key pair', async () => {
        const original = await generateExtractableKeyPair();
        const exported = await exportKeyPair(original);

        expect(exported.privateKey.d).toBeDefined();
        expect(exported.publicKey.d).toBeUndefined();

        const imported = await importKeyPair(exported);
        expect(imported.privateKey.algorithm).toMatchObject({ name: 'ECDSA' });
        expect(imported.publicKey.algorithm).toMatchObject({ name: 'ECDSA' });

        // Verify imported key can sign
        const data = new TextEncoder().encode('test');
        const sig = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            imported.privateKey,
            data,
        );
        expect(sig.byteLength).toBeGreaterThan(0);
    });
});

describe('sha256', () => {
    it('hashes a string correctly', async () => {
        // Known SHA-256 of empty string
        const hash = await sha256('');
        expect(hash.length).toBe(32);
        // SHA-256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        const hex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
        expect(hex).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('hashes Uint8Array input', async () => {
        const data = new TextEncoder().encode('hello');
        const hash = await sha256(data);
        expect(hash.length).toBe(32);
        // SHA-256('hello') = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        const hex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
        expect(hex).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
    });
});

describe('buildJwt', () => {
    it('produces a valid 3-part JWT', async () => {
        const kp = await generateExtractableKeyPair();
        const header = { alg: 'ES256', typ: 'jwt' };
        const payload = { iss: 'test', aud: 'aud', iat: 1000 };

        const jwt = await buildJwt(header, payload, kp.privateKey);
        const parts = jwt.split('.');
        expect(parts).toHaveLength(3);

        const decodedHeader = base64urlDecodeJson(parts[0]);
        expect(decodedHeader).toEqual(header);

        const decodedPayload = base64urlDecodeJson(parts[1]);
        expect(decodedPayload).toEqual(payload);
    });

    it('signature is 64 bytes (raw ES256)', async () => {
        const kp = await generateExtractableKeyPair();
        const jwt = await buildJwt({ alg: 'ES256' }, { test: true }, kp.privateKey);
        const sig = base64urlDecode(jwt.split('.')[2]);
        expect(sig.length).toBe(64);
    });

    it('two JWTs signed by the same key produce different signatures', async () => {
        const kp = await generateExtractableKeyPair();
        const jwt1 = await buildJwt({ alg: 'ES256' }, { nonce: 'a' }, kp.privateKey);
        const jwt2 = await buildJwt({ alg: 'ES256' }, { nonce: 'b' }, kp.privateKey);
        // Different payloads → different signatures (ECDSA is non-deterministic anyway)
        expect(jwt1.split('.')[2]).not.toBe(jwt2.split('.')[2]);
    });
});

describe('generatePkce', () => {
    it('produces code_verifier and code_challenge', async () => {
        const pkce = await generatePkce();
        expect(pkce.code_verifier).toBeDefined();
        expect(pkce.code_challenge).toBeDefined();
        expect(pkce.code_verifier.length).toBeGreaterThan(0);
        expect(pkce.code_challenge.length).toBeGreaterThan(0);
    });

    it('code_challenge is SHA-256 of code_verifier', async () => {
        const pkce = await generatePkce();
        const expectedHash = await sha256(pkce.code_verifier);
        const { base64urlEncode } = await import('./utils');
        expect(pkce.code_challenge).toBe(base64urlEncode(expectedHash));
    });

    it('values are URL-safe', async () => {
        const pkce = await generatePkce();
        expect(pkce.code_verifier).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(pkce.code_challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    });
});
