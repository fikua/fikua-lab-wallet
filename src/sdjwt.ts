import { base64urlDecodeJson } from './utils';
import type { ParsedSdJwt, Disclosure } from './types';

/** Filter an SD-JWT's disclosures to only include the requested claims. */
export function filterDisclosuresForPresentation(
    sdJwtString: string,
    requestedClaims: string[],
): { issuerJwt: string; disclosures: string[] } {
    const parts = sdJwtString.split('~').filter(p => p.length > 0);
    const issuerJwt = parts[0];
    const allDisclosures = parts.slice(1);
    const requested = new Set(requestedClaims);

    const filtered: string[] = [];
    for (const d of allDisclosures) {
        try {
            const decoded = base64urlDecodeJson(d) as unknown;
            if (Array.isArray(decoded) && decoded.length >= 3) {
                const name = decoded[1] as string;
                if (requested.has(name)) filtered.push(d);
            }
        } catch {
            // skip unparseable
        }
    }

    return { issuerJwt, disclosures: filtered };
}

/** Parse an SD-JWT VC string into structured data. */
export function parseSdJwt(sdJwtString: string): ParsedSdJwt {
    const parts = sdJwtString.split('~').filter(p => p.length > 0);
    const jwt = parts[0];
    const disclosureParts = parts.slice(1);

    const jwtParts = jwt.split('.');
    const header = base64urlDecodeJson(jwtParts[0]);
    const payload = base64urlDecodeJson(jwtParts[1]);

    const disclosedClaims: Record<string, unknown> = {};
    const disclosures: Disclosure[] = [];

    for (const d of disclosureParts) {
        try {
            const decoded = base64urlDecodeJson(d) as unknown;
            if (Array.isArray(decoded) && decoded.length >= 3) {
                const [salt, name, value] = decoded as [string, string, unknown];
                disclosedClaims[name] = value;
                disclosures.push({ salt, name, value, raw: d });
            }
        } catch {
            // skip unparseable disclosures
        }
    }

    // Merge plain claims from payload (skip internal SD-JWT fields)
    const allClaims: Record<string, unknown> = {};
    const skipKeys = new Set(['_sd', '_sd_alg', 'cnf', 'status']);
    for (const [k, v] of Object.entries(payload)) {
        if (!skipKeys.has(k)) allClaims[k] = v;
    }
    Object.assign(allClaims, disclosedClaims);

    return {
        raw: sdJwtString,
        header,
        payload,
        disclosedClaims,
        allClaims,
        disclosures,
        issuer: payload.iss as string,
        subject: payload.sub as string | undefined,
        vct: payload.vct as string | undefined,
        issuedAt: payload.iat as number | undefined,
        expiresAt: payload.exp as number | undefined,
        cnf: payload.cnf as { jwk?: JsonWebKey } | undefined,
        status: payload.status,
        sdAlg: payload._sd_alg as string | undefined,
    };
}
