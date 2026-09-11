import { describe, it, expect } from 'vitest';
import { scalarMultBase } from './p256';

// The P-256 base point G's own coordinates, per SEC 2 / FIPS 186-4.
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
// The curve order n.
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
// The field prime p.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;

describe('scalarMultBase', () => {
    it('G * 1 = G (the base point itself)', () => {
        const { x, y } = scalarMultBase(1n);
        expect(x).toBe(GX);
        expect(y).toBe(GY);
    });

    it("matches a WebCrypto-generated key pair's own public point", async () => {
        // Independent oracle: generate a real ECDSA key pair, read back its
        // private scalar and public coordinates, and confirm
        // scalarMultBase(scalar) reproduces the same public point — this is
        // exactly what prf.ts relies on to derive a PRF-based key's public
        // half, since SubtleCrypto itself cannot do scalar-mult from a bare
        // private scalar.
        const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
        const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
        const d = BigInt('0x' + Buffer.from(jwk.d!, 'base64url').toString('hex'));
        const expectedX = BigInt('0x' + Buffer.from(jwk.x!, 'base64url').toString('hex'));
        const expectedY = BigInt('0x' + Buffer.from(jwk.y!, 'base64url').toString('hex'));

        const { x, y } = scalarMultBase(d);
        expect(x).toBe(expectedX);
        expect(y).toBe(expectedY);
    });

    it('is deterministic for the same scalar', () => {
        const a = scalarMultBase(12345n);
        const b = scalarMultBase(12345n);
        expect(a).toEqual(b);
    });

    it('different scalars produce different points', () => {
        const a = scalarMultBase(1n);
        const b = scalarMultBase(2n);
        expect(a).not.toEqual(b);
    });

    it('reduces a scalar equal to the curve order plus one back to G (k mod n)', () => {
        const { x, y } = scalarMultBase(N + 1n);
        expect(x).toBe(GX);
        expect(y).toBe(GY);
    });

    it('treats a zero scalar as 1 (documented fallback, avoids point at infinity)', () => {
        const zero = scalarMultBase(0n);
        const one = scalarMultBase(1n);
        expect(zero).toEqual(one);
    });

    it('returns coordinates within the field', () => {
        const { x, y } = scalarMultBase(999999n);
        expect(x).toBeGreaterThanOrEqual(0n);
        expect(x).toBeLessThan(P);
        expect(y).toBeGreaterThanOrEqual(0n);
        expect(y).toBeLessThan(P);
    });
});
