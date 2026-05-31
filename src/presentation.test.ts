import { describe, it, expect, vi, beforeEach } from 'vitest';
import { filterDisclosuresForPresentation } from './sdjwt';
import { base64urlEncodeJson, base64urlDecodeJson } from './utils';

// Build a minimal SD-JWT for testing
function buildTestSdJwt(disclosures: Array<[string, string, unknown]>): string {
    const header = { alg: 'ES256', typ: 'dc+sd-jwt' };
    const payload = {
        iss: 'https://issuer.example.com',
        iat: 1700000000,
        exp: 1700086400,
        vct: 'eu.europa.ec.eudi.pid.1',
        _sd_alg: 'sha-256',
        _sd: ['hash1', 'hash2', 'hash3'],
        cnf: { jwk: { kty: 'EC', crv: 'P-256', x: 'test-x', y: 'test-y' } },
    };

    const headerB64 = base64urlEncodeJson(header);
    const payloadB64 = base64urlEncodeJson(payload);
    const jwt = `${headerB64}.${payloadB64}.fakesig`;

    const disclosureParts = disclosures.map(d => base64urlEncodeJson(d));
    return jwt + '~' + disclosureParts.join('~') + '~';
}

describe('filterDisclosuresForPresentation', () => {
    const allDisclosures: Array<[string, string, unknown]> = [
        ['salt1', 'given_name', 'Oriol'],
        ['salt2', 'family_name', 'Canadés'],
        ['salt3', 'birth_date', '1992-01-01'],
        ['salt4', 'nationality', 'ES'],
    ];

    it('returns only disclosures matching requested claims', () => {
        const sdJwt = buildTestSdJwt(allDisclosures);
        const result = filterDisclosuresForPresentation(sdJwt, ['given_name', 'family_name']);

        expect(result.disclosures).toHaveLength(2);
        // Verify the disclosure contents
        const names = result.disclosures.map(d => {
            const decoded = base64urlDecodeJson(d) as unknown[];
            return decoded[1];
        });
        expect(names).toContain('given_name');
        expect(names).toContain('family_name');
    });

    it('returns the issuer JWT unchanged', () => {
        const sdJwt = buildTestSdJwt(allDisclosures);
        const result = filterDisclosuresForPresentation(sdJwt, ['given_name']);

        // issuerJwt should be the first part (before ~)
        const expectedJwt = sdJwt.split('~')[0];
        expect(result.issuerJwt).toBe(expectedJwt);
    });

    it('returns empty disclosures when no claims match', () => {
        const sdJwt = buildTestSdJwt(allDisclosures);
        const result = filterDisclosuresForPresentation(sdJwt, ['nonexistent_claim']);

        expect(result.disclosures).toHaveLength(0);
    });

    it('returns all disclosures when all claims are requested', () => {
        const sdJwt = buildTestSdJwt(allDisclosures);
        const result = filterDisclosuresForPresentation(
            sdJwt, ['given_name', 'family_name', 'birth_date', 'nationality'],
        );

        expect(result.disclosures).toHaveLength(4);
    });

    it('skips malformed disclosure segments', () => {
        const header = base64urlEncodeJson({ alg: 'ES256' });
        const payload = base64urlEncodeJson({ iss: 'test' });
        const validDisc = base64urlEncodeJson(['salt1', 'given_name', 'Oriol']);
        const sdJwt = `${header}.${payload}.sig~${validDisc}~not-valid-base64~`;

        const result = filterDisclosuresForPresentation(sdJwt, ['given_name']);
        expect(result.disclosures).toHaveLength(1);
    });
});

describe('buildVpToken', () => {
    beforeEach(() => {
        vi.resetModules();
    });

    it('produces SD-JWT with KB-JWT in correct format', async () => {
        // Generate a real key pair for signing
        const keyPair = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['sign', 'verify'],
        );

        const sdJwt = buildTestSdJwt([
            ['salt1', 'given_name', 'Oriol'],
            ['salt2', 'family_name', 'Canadés'],
            ['salt3', 'birth_date', '1992-01-01'],
        ]);

        const credential = {
            id: 'test-id',
            rawSdJwt: sdJwt,
            format: 'dc+sd-jwt',
            issuer: 'https://issuer.example.com',
            issuerName: 'Test Issuer',
            credentialConfigId: 'pid',
            vct: 'eu.europa.ec.eudi.pid.1',
            claims: { given_name: 'Oriol', family_name: 'Canadés', birth_date: '1992-01-01' },
            metadata: { alg: 'ES256', issuedAt: null, expiresAt: null, notificationId: null, notificationEndpoint: null },
            accessToken: 'token',
            tokenType: 'Bearer',
            holderKey: keyPair,
            issuedAt: Date.now(),
        };

        const { buildVpToken } = await import('./protocol');
        const vpToken = await buildVpToken(
            credential, ['given_name', 'family_name'], 'test-nonce', 'verifier.example.com',
        );

        // VP Token format: issuer-jwt~disc1~disc2~kb-jwt
        const parts = vpToken.split('~');
        expect(parts.length).toBeGreaterThanOrEqual(4); // issuer-jwt, disc1, disc2, kb-jwt

        // First part is the issuer JWT (3 dot-separated segments)
        expect(parts[0].split('.')).toHaveLength(3);

        // Last part is the KB-JWT (also 3 dot-separated segments)
        const kbJwt = parts[parts.length - 1];
        expect(kbJwt.split('.')).toHaveLength(3);

        // KB-JWT header should have typ: kb+jwt
        const kbHeader = base64urlDecodeJson(kbJwt.split('.')[0]);
        expect(kbHeader.typ).toBe('kb+jwt');
        expect(kbHeader.alg).toBe('ES256');

        // KB-JWT payload should have aud, nonce, sd_hash
        const kbPayload = base64urlDecodeJson(kbJwt.split('.')[1]);
        expect(kbPayload.aud).toBe('verifier.example.com');
        expect(kbPayload.nonce).toBe('test-nonce');
        expect(kbPayload.sd_hash).toBeDefined();
        expect(typeof kbPayload.sd_hash).toBe('string');
        expect(kbPayload.iat).toBeDefined();
    });

    it('only includes requested disclosures in VP Token', async () => {
        const keyPair = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['sign', 'verify'],
        );

        const sdJwt = buildTestSdJwt([
            ['salt1', 'given_name', 'Oriol'],
            ['salt2', 'family_name', 'Canadés'],
            ['salt3', 'birth_date', '1992-01-01'],
        ]);

        const credential = {
            id: 'test-id',
            rawSdJwt: sdJwt,
            format: 'dc+sd-jwt',
            issuer: 'https://issuer.example.com',
            issuerName: 'Test Issuer',
            credentialConfigId: 'pid',
            vct: 'eu.europa.ec.eudi.pid.1',
            claims: { given_name: 'Oriol', family_name: 'Canadés', birth_date: '1992-01-01' },
            metadata: { alg: 'ES256', issuedAt: null, expiresAt: null, notificationId: null, notificationEndpoint: null },
            accessToken: 'token',
            tokenType: 'Bearer',
            holderKey: keyPair,
            issuedAt: Date.now(),
        };

        const { buildVpToken } = await import('./protocol');

        // Request only given_name
        const vpToken = await buildVpToken(
            credential, ['given_name'], 'nonce', 'verifier.example.com',
        );

        // Should have: issuer-jwt ~ given_name_disc ~ kb-jwt
        const parts = vpToken.split('~').filter(p => p.length > 0);
        expect(parts).toHaveLength(3); // issuer-jwt, 1 disclosure, kb-jwt

        // The middle part should be the given_name disclosure
        const disc = base64urlDecodeJson(parts[1]) as unknown[];
        expect(disc[1]).toBe('given_name');
        expect(disc[2]).toBe('Oriol');
    });
});

describe('fetchRequestObject', () => {
    // Throwaway self-signed P-256 cert + matching PKCS8 key (not a real key).
    const TEST_PKCS8 = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgv7fMQCbiQdg8P0Ia\nWDl48n//nxpgWzV69/dE6q4xjKahRANCAAQw77Oi+7SEHX70xbUaD5kgyrv9tTyR\nGzjZpcjC5e4fXjTkp3Om/wdug2Lfte+j/WOaF59DcXRIGOLqD15iQVFr\n-----END PRIVATE KEY-----\n';
    const TEST_X5C = 'MIIBhDCCASugAwIBAgIUcf06uF4G5kWF1SsSSlJwUPfhoIswCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNdGVzdC12ZXJpZmllcjAeFw0yNjA1MzExNjU4MzhaFw0zNjA1MjgxNjU4MzhaMBgxFjAUBgNVBAMMDXRlc3QtdmVyaWZpZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQw77Oi+7SEHX70xbUaD5kgyrv9tTyRGzjZpcjC5e4fXjTkp3Om/wdug2Lfte+j/WOaF59DcXRIGOLqD15iQVFro1MwUTAdBgNVHQ4EFgQUsh3g38anbSgXjQlEB5Pr7AryL54wHwYDVR0jBBgwFoAUsh3g38anbSgXjQlEB5Pr7AryL54wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiA+dl3cdSFe8exczXWzJwiIxiT3QjT+FD1jTiySnpggewIgPAG+53ez88cwsoajlvpVftTVW5p/TfB5+DH5rm3bq84=';

    beforeEach(() => { vi.restoreAllMocks(); });

    const signJws = async (key: CryptoKey, claims: object): Promise<string> => {
        const { CompactSign } = await import('jose');
        const payload = Uint8Array.from(new TextEncoder().encode(JSON.stringify(claims)));
        return new CompactSign(payload)
            .setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: [TEST_X5C] })
            .sign(key);
    };

    it('verifies a signed JAR (x5c) and extracts the request parameters', async () => {
        const { importPKCS8 } = await import('jose');
        const key = await importPKCS8(TEST_PKCS8, 'ES256');
        const jws = await signJws(key, {
            response_type: 'vp_token',
            response_uri: 'https://verifier.test/response',
            nonce: 'nonce-1',
            response_mode: 'direct_post.jwt',
        });

        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
            new Response(jws, { status: 200, headers: { 'Content-Type': 'application/oauth-authz-req+jwt' } }),
        ));

        const { fetchRequestObject } = await import('./protocol');
        const req = await fetchRequestObject('https://verifier.test/request/1');
        expect(req.response_type).toBe('vp_token');
        expect(req.nonce).toBe('nonce-1');
        expect(req.response_uri).toBe('https://verifier.test/response');
    });

    it('rejects a JAR whose signature does not match the x5c cert', async () => {
        const { generateKeyPair } = await import('jose');
        const { privateKey } = await generateKeyPair('ES256'); // a different key than TEST_X5C
        const jws = await signJws(privateKey as CryptoKey, {
            response_type: 'vp_token', response_uri: 'https://verifier.test/r', nonce: 'n',
        });

        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(jws, { status: 200 })));

        const { fetchRequestObject } = await import('./protocol');
        await expect(fetchRequestObject('https://verifier.test/request/2')).rejects.toThrow();
    });

    it('still accepts a plain-JSON request object', async () => {
        const json = JSON.stringify({
            response_type: 'vp_token', response_uri: 'https://verifier.test/r', nonce: 'n',
        });
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
            new Response(json, { status: 200, headers: { 'Content-Type': 'application/json' } }),
        ));
        const { fetchRequestObject } = await import('./protocol');
        const req = await fetchRequestObject('https://verifier.test/request/3');
        expect(req.nonce).toBe('n');
    });
});

describe('submitPresentation', () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it('direct_post sends vp_token and state as plaintext form params', async () => {
        const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
        vi.stubGlobal('fetch', fetchMock);

        const { submitPresentation } = await import('./protocol');
        await submitPresentation({
            response_type: 'vp_token', client_id: 'verifier', response_mode: 'direct_post',
            response_uri: 'https://verifier.test/response', nonce: 'n', state: 'st',
        }, 'vptoken~kb');

        const [, init] = fetchMock.mock.calls[0];
        const body = new URLSearchParams(init.body as string);
        expect(body.get('vp_token')).toBe('vptoken~kb');
        expect(body.get('state')).toBe('st');
        expect(body.get('response')).toBeNull();
    });

    it('direct_post.jwt encrypts an Authorization Response the verifier can decrypt', async () => {
        const { generateKeyPair, exportJWK, compactDecrypt } = await import('jose');
        const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { extractable: true });
        const publicJwk = await exportJWK(publicKey);
        publicJwk.kid = 'verifier-enc-1';
        publicJwk.use = 'enc';

        const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
        vi.stubGlobal('fetch', fetchMock);

        const { submitPresentation } = await import('./protocol');
        await submitPresentation({
            response_type: 'vp_token', client_id: 'verifier', response_mode: 'direct_post.jwt',
            response_uri: 'https://verifier.test/response', nonce: 'n', state: 'st-123',
            client_metadata: {
                authorization_encrypted_response_alg: 'ECDH-ES',
                authorization_encrypted_response_enc: 'A128GCM',
                jwks: { keys: [publicJwk] },
            },
        }, 'theVpToken~kb');

        const [, init] = fetchMock.mock.calls[0];
        const body = new URLSearchParams(init.body as string);
        const jwe = body.get('response');
        expect(jwe).toBeTruthy();
        expect(body.get('vp_token')).toBeNull();

        // The verifier decrypts the JWE and recovers vp_token + state.
        const { plaintext, protectedHeader } = await compactDecrypt(jwe as string, privateKey);
        expect(protectedHeader.alg).toBe('ECDH-ES');
        expect(protectedHeader.enc).toBe('A128GCM');
        const decoded = JSON.parse(new TextDecoder().decode(plaintext));
        expect(decoded.vp_token).toBe('theVpToken~kb');
        expect(decoded.state).toBe('st-123');
    });
});
