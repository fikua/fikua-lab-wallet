/**
 * Parse an mdoc IssuerSigned CBOR credential into structured data.
 *
 * Structure expected (per ISO 18013-5 / OID4VCI A.2.4):
 *   IssuerSigned = {
 *     "issuerAuth": COSE_Sign1 (untagged array),
 *     "nameSpaces": { namespace -> [Tag24(IssuerSignedItem), ...] }
 *   }
 *
 *   IssuerSignedItem = {
 *     "digestID": int,
 *     "random": bytes,
 *     "elementIdentifier": string,
 *     "elementValue": value
 *   }
 */

import { decodeCbor, isCborTagged } from './cbor';
import type { CborValue, CborMap, CborTagged } from './cbor';
import { base64urlDecode } from './utils';
import type { ParsedMdoc } from './types';

/** Parse a base64url-encoded IssuerSigned CBOR into structured data. */
export function parseMdoc(base64urlCredential: string): ParsedMdoc {
    const bytes = base64urlDecode(base64urlCredential);
    const decoded = decodeCbor(bytes);

    if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded) || decoded instanceof Uint8Array) {
        throw new Error('mdoc: expected CBOR map at top level');
    }

    const issuerSigned = decoded as CborMap;
    const nameSpaces = issuerSigned['nameSpaces'] as CborMap | undefined;
    const issuerAuth = issuerSigned['issuerAuth'] as CborValue[] | undefined;

    const claims: Record<string, unknown> = {};
    let docType: string | undefined;
    let validFrom: string | undefined;
    let validUntil: string | undefined;

    // Extract claims from nameSpaces
    if (nameSpaces && typeof nameSpaces === 'object' && !Array.isArray(nameSpaces) && !(nameSpaces instanceof Uint8Array)) {
        for (const [namespace, items] of Object.entries(nameSpaces)) {
            if (!docType) docType = namespace;
            if (!Array.isArray(items)) continue;

            for (const item of items) {
                const signedItem = unwrapTagged(item);
                if (!signedItem || typeof signedItem !== 'object' || Array.isArray(signedItem) || signedItem instanceof Uint8Array) continue;

                const map = signedItem as CborMap;
                const elementId = map['elementIdentifier'];
                const elementValue = map['elementValue'];

                if (typeof elementId === 'string' && elementValue !== undefined) {
                    claims[elementId] = cborValueToJs(elementValue);
                }
            }
        }
    }

    // Extract MSO from issuerAuth for docType and validity
    // COSE_Sign1[2] is a bstr containing tag24(MSO) — decode the bytes, then unwrap tag 24
    if (Array.isArray(issuerAuth) && issuerAuth.length >= 3) {
        const payloadBytes = issuerAuth[2];
        if (payloadBytes instanceof Uint8Array) {
            try {
                const decoded = decodeCbor(payloadBytes);
                const mso = unwrapTagged(decoded); // unwrap tag 24
                if (mso && typeof mso === 'object' && !Array.isArray(mso) && !(mso instanceof Uint8Array)) {
                    const msoMap = mso as CborMap;
                    if (typeof msoMap['docType'] === 'string') docType = msoMap['docType'];

                    const validity = msoMap['validityInfo'] as CborMap | undefined;
                    if (validity && typeof validity === 'object' && !Array.isArray(validity) && !(validity instanceof Uint8Array)) {
                        validFrom = extractDateString(validity['validFrom']);
                        validUntil = extractDateString(validity['validUntil']);
                    }
                }
            } catch {
                // MSO parsing is best-effort — claims are the priority
            }
        }
    }

    return {
        raw: base64urlCredential,
        docType: docType ?? 'unknown',
        claims,
        validFrom: validFrom ?? null,
        validUntil: validUntil ?? null,
    };
}

/** Unwrap a Tag24-wrapped value, or return the value if not tagged. */
function unwrapTagged(value: CborValue): CborValue | null {
    if (isCborTagged(value)) {
        return (value as CborTagged).value;
    }
    return value;
}

/** Convert CBOR values to plain JS (handle tagged dates, nested maps, etc). */
function cborValueToJs(value: CborValue): unknown {
    if (value === null || value === undefined) return null;
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
        return typeof value === 'bigint' ? Number(value) : value;
    }
    if (value instanceof Uint8Array) return value;
    if (Array.isArray(value)) return value.map(cborValueToJs);

    // Tagged value (e.g., tag 0 = datetime string, tag 1 = epoch)
    if (isCborTagged(value)) {
        const tagged = value as CborTagged;
        if (tagged.tag === 0 && typeof tagged.value === 'string') return tagged.value; // RFC 3339 datetime
        if (tagged.tag === 1 && typeof tagged.value === 'number') return new Date(tagged.value * 1000).toISOString();
        if (tagged.tag === 1004 && typeof tagged.value === 'string') return tagged.value; // full-date (RFC 8943)
        return cborValueToJs(tagged.value);
    }

    // Map
    if (typeof value === 'object') {
        const result: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value)) {
            result[k] = cborValueToJs(v);
        }
        return result;
    }

    return value;
}

/** Extract an ISO date string from a CBOR tagged datetime. */
function extractDateString(value: CborValue | undefined): string | undefined {
    if (!value) return undefined;
    if (typeof value === 'string') return value;
    if (isCborTagged(value)) {
        const tagged = value as CborTagged;
        if (tagged.tag === 0 && typeof tagged.value === 'string') return tagged.value;
        if (tagged.tag === 1 && typeof tagged.value === 'number') return new Date(tagged.value * 1000).toISOString();
    }
    return undefined;
}
