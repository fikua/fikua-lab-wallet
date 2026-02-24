import { describe, it, expect } from 'vitest';
import { parseMdoc } from './mdoc';
import { base64urlEncode } from './utils';

/** CBOR encoding helpers for building test fixtures. */
function cborUint8(value: number): Uint8Array {
    if (value < 24) return new Uint8Array([value]);
    if (value < 256) return new Uint8Array([0x18, value]);
    return new Uint8Array([0x19, (value >> 8) & 0xff, value & 0xff]);
}

function cborText(str: string): Uint8Array {
    const encoded = new TextEncoder().encode(str);
    const len = encoded.length;
    if (len < 24) {
        const buf = new Uint8Array(1 + len);
        buf[0] = 0x60 | len;
        buf.set(encoded, 1);
        return buf;
    }
    if (len < 256) {
        const buf = new Uint8Array(2 + len);
        buf[0] = 0x78;
        buf[1] = len;
        buf.set(encoded, 2);
        return buf;
    }
    const buf = new Uint8Array(3 + len);
    buf[0] = 0x79;
    buf[1] = (len >> 8) & 0xff;
    buf[2] = len & 0xff;
    buf.set(encoded, 3);
    return buf;
}

function cborBytes(data: Uint8Array): Uint8Array {
    const len = data.length;
    if (len < 24) {
        const buf = new Uint8Array(1 + len);
        buf[0] = 0x40 | len;
        buf.set(data, 1);
        return buf;
    }
    if (len < 256) {
        const buf = new Uint8Array(2 + len);
        buf[0] = 0x58;
        buf[1] = len;
        buf.set(data, 2);
        return buf;
    }
    const buf = new Uint8Array(3 + len);
    buf[0] = 0x59;
    buf[1] = (len >> 8) & 0xff;
    buf[2] = len & 0xff;
    buf.set(data, 3);
    return buf;
}

function cborArray(items: Uint8Array[]): Uint8Array {
    const len = items.length;
    const header = len < 24 ? new Uint8Array([0x80 | len]) : new Uint8Array([0x98, len]);
    return concat([header, ...items]);
}

function cborMap(entries: [Uint8Array, Uint8Array][]): Uint8Array {
    const len = entries.length;
    const header = len < 24 ? new Uint8Array([0xa0 | len]) : new Uint8Array([0xb8, len]);
    const parts = [header];
    for (const [k, v] of entries) { parts.push(k, v); }
    return concat(parts);
}

function cborTag(tag: number, value: Uint8Array): Uint8Array {
    if (tag < 24) return concat([new Uint8Array([0xc0 | tag]), value]);
    return concat([new Uint8Array([0xd8, tag]), value]);
}

function concat(parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((s, p) => s + p.length, 0);
    const buf = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) { buf.set(p, offset); offset += p.length; }
    return buf;
}

/** Build a minimal IssuerSignedItem as CBOR map. */
function buildIssuerSignedItem(digestId: number, elementId: string, elementValue: string): Uint8Array {
    return cborMap([
        [cborText('digestID'), cborUint8(digestId)],
        [cborText('random'), cborBytes(new Uint8Array(16))],
        [cborText('elementIdentifier'), cborText(elementId)],
        [cborText('elementValue'), cborText(elementValue)],
    ]);
}

/** Wrap as tag 24 (encoded-cbor): tag(24, bstr(cbor_bytes)). */
function wrapTag24(cbor: Uint8Array): Uint8Array {
    return cborTag(24, cborBytes(cbor));
}

/** Build a minimal MSO with docType and validityInfo. */
function buildMso(docType: string): Uint8Array {
    return cborMap([
        [cborText('version'), cborText('1.0')],
        [cborText('digestAlgorithm'), cborText('SHA-256')],
        [cborText('docType'), cborText(docType)],
        [cborText('validityInfo'), cborMap([
            [cborText('signed'), cborTag(0, cborText('2026-02-24T12:00:00Z'))],
            [cborText('validFrom'), cborTag(0, cborText('2026-02-24T12:00:00Z'))],
            [cborText('validUntil'), cborTag(0, cborText('2027-02-24T12:00:00Z'))],
        ])],
    ]);
}

/** Build a minimal IssuerSigned CBOR structure. */
function buildIssuerSigned(
    namespace: string,
    items: Array<{ digestId: number; elementId: string; elementValue: string }>,
): Uint8Array {
    const nsItems = items.map(i => wrapTag24(buildIssuerSignedItem(i.digestId, i.elementId, i.elementValue)));

    // Build a minimal COSE_Sign1 array with MSO in payload
    const mso = buildMso(namespace);
    const msoTagged = wrapTag24(mso); // tag 24 wrapping MSO
    const coseSign1 = cborArray([
        cborBytes(new Uint8Array([0xa1, 0x01, 0x26])), // protected: {1: -7} (ES256)
        cborMap([]),                                      // unprotected (empty for test)
        cborBytes(msoTagged),                             // payload: tag24(MSO) as bstr
        cborBytes(new Uint8Array(64)),                    // signature: 64 zero bytes
    ]);

    return cborMap([
        [cborText('issuerAuth'), coseSign1],
        [cborText('nameSpaces'), cborMap([
            [cborText(namespace), cborArray(nsItems)],
        ])],
    ]);
}

describe('parseMdoc', () => {
    it('extracts claims from IssuerSigned CBOR', () => {
        const cbor = buildIssuerSigned('eu.europa.ec.eudi.pid.1', [
            { digestId: 0, elementId: 'given_name', elementValue: 'Jan' },
            { digestId: 1, elementId: 'family_name', elementValue: 'Kowalski' },
            { digestId: 2, elementId: 'birth_date', elementValue: '1990-01-01' },
        ]);
        const b64 = base64urlEncode(cbor);
        const result = parseMdoc(b64);

        expect(result.claims['given_name']).toBe('Jan');
        expect(result.claims['family_name']).toBe('Kowalski');
        expect(result.claims['birth_date']).toBe('1990-01-01');
    });

    it('extracts docType from MSO', () => {
        const cbor = buildIssuerSigned('eu.europa.ec.eudi.pid.1', [
            { digestId: 0, elementId: 'given_name', elementValue: 'Jan' },
        ]);
        const b64 = base64urlEncode(cbor);
        const result = parseMdoc(b64);

        expect(result.docType).toBe('eu.europa.ec.eudi.pid.1');
    });

    it('extracts validity dates from MSO', () => {
        const cbor = buildIssuerSigned('eu.europa.ec.eudi.pid.1', [
            { digestId: 0, elementId: 'given_name', elementValue: 'Jan' },
        ]);
        const b64 = base64urlEncode(cbor);
        const result = parseMdoc(b64);

        expect(result.validFrom).toBe('2026-02-24T12:00:00Z');
        expect(result.validUntil).toBe('2027-02-24T12:00:00Z');
    });

    it('preserves raw credential string', () => {
        const cbor = buildIssuerSigned('eu.europa.ec.eudi.pid.1', [
            { digestId: 0, elementId: 'given_name', elementValue: 'Jan' },
        ]);
        const b64 = base64urlEncode(cbor);
        const result = parseMdoc(b64);

        expect(result.raw).toBe(b64);
    });

    it('handles multiple elements in namespace', () => {
        const items = [
            { digestId: 0, elementId: 'given_name', elementValue: 'Maria' },
            { digestId: 1, elementId: 'family_name', elementValue: 'Garcia' },
            { digestId: 2, elementId: 'birth_date', elementValue: '1985-03-15' },
            { digestId: 3, elementId: 'issuing_authority', elementValue: 'Fikua Lab' },
            { digestId: 4, elementId: 'issuing_country', elementValue: 'ES' },
        ];
        const cbor = buildIssuerSigned('eu.europa.ec.eudi.pid.1', items);
        const b64 = base64urlEncode(cbor);
        const result = parseMdoc(b64);

        expect(Object.keys(result.claims)).toHaveLength(5);
        expect(result.claims['given_name']).toBe('Maria');
        expect(result.claims['issuing_country']).toBe('ES');
    });

    it('throws on invalid CBOR', () => {
        // Not valid CBOR
        const invalid = base64urlEncode(new Uint8Array([0xff, 0xfe, 0xfd]));
        expect(() => parseMdoc(invalid)).toThrow();
    });
});
