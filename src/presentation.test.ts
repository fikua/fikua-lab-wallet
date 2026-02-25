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
        vct: 'urn:eu.europa.ec.eudi:pid:1',
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
            vct: 'urn:eu.europa.ec.eudi:pid:1',
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
            vct: 'urn:eu.europa.ec.eudi:pid:1',
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
