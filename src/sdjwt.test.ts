import { describe, it, expect } from 'vitest';
import { parseSdJwt } from './sdjwt';
import { base64urlEncodeJson } from './utils';

// Build a minimal SD-JWT for testing:
// header.payload~disclosure1~disclosure2~
function buildTestSdJwt(options?: {
    header?: Record<string, unknown>;
    payload?: Record<string, unknown>;
    disclosures?: Array<[string, string, unknown]>;
}): string {
    const header = options?.header ?? { alg: 'ES256', typ: 'dc+sd-jwt' };
    const payload = options?.payload ?? {
        iss: 'https://issuer.example.com',
        iat: 1700000000,
        exp: 1700086400,
        vct: 'eu.europa.ec.eudi.pid.1',
        _sd_alg: 'sha-256',
        _sd: ['hash1', 'hash2'],
    };
    const disclosures = options?.disclosures ?? [
        ['salt1', 'given_name', 'John'],
        ['salt2', 'family_name', 'Doe'],
        ['salt3', 'birth_date', '1990-01-15'],
    ];

    const headerB64 = base64urlEncodeJson(header);
    const payloadB64 = base64urlEncodeJson(payload);
    const fakeSignature = 'fakesig';
    const jwt = `${headerB64}.${payloadB64}.${fakeSignature}`;

    const disclosureParts = disclosures.map(d => base64urlEncodeJson(d));
    return jwt + '~' + disclosureParts.join('~') + '~';
}

describe('parseSdJwt', () => {
    it('parses header and payload from the JWT part', () => {
        const sdJwt = buildTestSdJwt();
        const parsed = parseSdJwt(sdJwt);

        expect(parsed.header.alg).toBe('ES256');
        expect(parsed.header.typ).toBe('dc+sd-jwt');
        expect(parsed.issuer).toBe('https://issuer.example.com');
        expect(parsed.vct).toBe('eu.europa.ec.eudi.pid.1');
        expect(parsed.issuedAt).toBe(1700000000);
        expect(parsed.expiresAt).toBe(1700086400);
        expect(parsed.sdAlg).toBe('sha-256');
    });

    it('extracts disclosed claims from disclosure segments', () => {
        const sdJwt = buildTestSdJwt();
        const parsed = parseSdJwt(sdJwt);

        expect(parsed.disclosedClaims).toEqual({
            given_name: 'John',
            family_name: 'Doe',
            birth_date: '1990-01-15',
        });
        expect(parsed.disclosures).toHaveLength(3);
        expect(parsed.disclosures[0]).toMatchObject({
            salt: 'salt1',
            name: 'given_name',
            value: 'John',
        });
    });

    it('merges payload claims and disclosed claims into allClaims', () => {
        const sdJwt = buildTestSdJwt();
        const parsed = parseSdJwt(sdJwt);

        // allClaims should contain payload claims (except internal SD fields)
        expect(parsed.allClaims.iss).toBe('https://issuer.example.com');
        expect(parsed.allClaims.vct).toBe('eu.europa.ec.eudi.pid.1');
        expect(parsed.allClaims.iat).toBe(1700000000);

        // allClaims should also contain disclosed claims
        expect(parsed.allClaims.given_name).toBe('John');
        expect(parsed.allClaims.family_name).toBe('Doe');

        // Internal SD fields should be excluded
        expect(parsed.allClaims._sd).toBeUndefined();
        expect(parsed.allClaims._sd_alg).toBeUndefined();
        expect(parsed.allClaims.cnf).toBeUndefined();
        expect(parsed.allClaims.status).toBeUndefined();
    });

    it('disclosed claims override payload claims with same key', () => {
        const sdJwt = buildTestSdJwt({
            payload: { iss: 'https://issuer.example.com', name: 'payload-name' },
            disclosures: [['s1', 'name', 'disclosed-name']],
        });
        const parsed = parseSdJwt(sdJwt);
        expect(parsed.allClaims.name).toBe('disclosed-name');
    });

    it('preserves the raw SD-JWT string', () => {
        const sdJwt = buildTestSdJwt();
        const parsed = parseSdJwt(sdJwt);
        expect(parsed.raw).toBe(sdJwt);
    });

    it('handles SD-JWT without disclosures', () => {
        const sdJwt = buildTestSdJwt({ disclosures: [] });
        const parsed = parseSdJwt(sdJwt);
        expect(parsed.disclosures).toHaveLength(0);
        expect(parsed.disclosedClaims).toEqual({});
        // Payload claims should still be in allClaims
        expect(parsed.allClaims.iss).toBe('https://issuer.example.com');
    });

    it('skips malformed disclosure segments gracefully', () => {
        const header = base64urlEncodeJson({ alg: 'ES256' });
        const payload = base64urlEncodeJson({ iss: 'test' });
        const validDisclosure = base64urlEncodeJson(['salt', 'name', 'value']);
        const sdJwt = `${header}.${payload}.sig~${validDisclosure}~not-valid-base64~`;

        const parsed = parseSdJwt(sdJwt);
        expect(parsed.disclosures).toHaveLength(1);
        expect(parsed.disclosedClaims.name).toBe('value');
    });

    it('handles cnf claim in payload', () => {
        const sdJwt = buildTestSdJwt({
            payload: {
                iss: 'https://issuer.example.com',
                cnf: { jwk: { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' } },
            },
        });
        const parsed = parseSdJwt(sdJwt);
        expect(parsed.cnf).toEqual({ jwk: { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' } });
        // cnf should not be in allClaims (it's an internal field)
        expect(parsed.allClaims.cnf).toBeUndefined();
    });

    it('handles numeric and object disclosure values', () => {
        const sdJwt = buildTestSdJwt({
            disclosures: [
                ['s1', 'age', 34],
                ['s2', 'address', { street: '123 Main St', city: 'Barcelona' }],
            ],
        });
        const parsed = parseSdJwt(sdJwt);
        expect(parsed.disclosedClaims.age).toBe(34);
        expect(parsed.disclosedClaims.address).toEqual({ street: '123 Main St', city: 'Barcelona' });
    });
});
