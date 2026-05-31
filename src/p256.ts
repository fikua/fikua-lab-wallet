// Minimal secp256r1 (P-256) base-point scalar multiplication.
//
// SubtleCrypto cannot turn a raw private scalar into its public point, and the
// PRF-derived key needs exactly that. This implements just enough EC math —
// Jacobian-coordinate double-and-add over the P-256 curve — to compute
// G * d = (x, y). Not constant-time; for a test wallet deriving its own key
// locally that is acceptable (no remote secret-dependent timing surface).

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

function mod(a: bigint, m: bigint = P): bigint {
    const r = a % m;
    return r >= 0n ? r : r + m;
}

function invMod(a: bigint, m: bigint = P): bigint {
    // Extended Euclidean.
    let [old_r, r] = [mod(a, m), m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    return mod(old_s, m);
}

// Jacobian point: (X, Y, Z) with affine x = X/Z^2, y = Y/Z^3. Infinity: Z = 0.
type J = { X: bigint; Y: bigint; Z: bigint };

function jDouble(p: J): J {
    if (p.Z === 0n) return p;
    const { X, Y, Z } = p;
    const S = mod(4n * X * Y * Y);
    const Z2 = mod(Z * Z);
    const Z4 = mod(Z2 * Z2);
    const M = mod(3n * mod(X * X) + mod(A * Z4));
    const X2 = mod(M * M - 2n * S);
    const Y2 = mod(M * (S - X2) - 8n * mod(mod(Y * Y) * mod(Y * Y)));
    const Zo = mod(2n * Y * Z);
    return { X: X2, Y: Y2, Z: Zo };
}

function jAdd(p: J, q: J): J {
    if (p.Z === 0n) return q;
    if (q.Z === 0n) return p;
    const Z1Z1 = mod(p.Z * p.Z);
    const Z2Z2 = mod(q.Z * q.Z);
    const U1 = mod(p.X * Z2Z2);
    const U2 = mod(q.X * Z1Z1);
    const S1 = mod(p.Y * q.Z * Z2Z2);
    const S2 = mod(q.Y * p.Z * Z1Z1);
    if (U1 === U2) {
        if (S1 !== S2) return { X: 1n, Y: 1n, Z: 0n }; // infinity
        return jDouble(p);
    }
    const H = mod(U2 - U1);
    const R = mod(S2 - S1);
    const H2 = mod(H * H);
    const H3 = mod(H2 * H);
    const X3 = mod(R * R - H3 - 2n * U1 * H2);
    const Y3 = mod(R * (U1 * H2 - X3) - S1 * H3);
    const Z3 = mod(p.Z * q.Z * H);
    return { X: X3, Y: Y3, Z: Z3 };
}

function toAffine(p: J): { x: bigint; y: bigint } {
    if (p.Z === 0n) throw new Error('point at infinity');
    const zInv = invMod(p.Z);
    const zInv2 = mod(zInv * zInv);
    return { x: mod(p.X * zInv2), y: mod(p.Y * zInv2 * zInv) };
}

/** Compute G * k on P-256, returning affine (x, y). k is reduced mod n. */
export function scalarMultBase(k: bigint): { x: bigint; y: bigint } {
    let d = mod(k, N);
    if (d === 0n) d = 1n; // avoid infinity for a zero scalar (shouldn't happen)
    return toAffine(doubleAndAdd(d));
}

function doubleAndAdd(k: bigint): J {
    let R: J = { X: 1n, Y: 1n, Z: 0n }; // infinity
    let base: J = { X: GX, Y: GY, Z: 1n };
    while (k > 0n) {
        if (k & 1n) R = jAdd(R, base);
        base = jDouble(base);
        k >>= 1n;
    }
    return R;
}
