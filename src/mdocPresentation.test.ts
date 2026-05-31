import { describe, it, expect } from 'vitest';
import { Encoder, Tag } from 'cbor-x';
import { buildMdocDeviceResponse } from './mdocPresentation';
import { base64urlEncode, base64urlDecode } from './utils';

const codec = new Encoder({ useRecords: false, mapsAsObjects: false, variableMapSize: true });
const cborEncode = (v: unknown) => new Uint8Array(codec.encode(v));
const cborDecode = (b: Uint8Array) => codec.decode(b);

const DOCTYPE = 'eu.europa.ec.eudi.pid.1';

/** Build a minimal but well-formed IssuerSigned (base64url) for two elements. */
function makeIssuerSigned(): string {
    const item = (digestID: number, id: string, value: string) =>
        new Tag(cborEncode(new Map<string, unknown>([
            ['digestID', digestID],
            ['random', new Uint8Array(16)],
            ['elementIdentifier', id],
            ['elementValue', value],
        ])), 24);

    const issuerSigned = new Map<string, unknown>([
        ['nameSpaces', new Map<string, Tag[]>([
            [DOCTYPE, [item(0, 'given_name', 'ORIOL'), item(1, 'family_name', 'CANADES')]],
        ])],
        // issuerAuth is opaque to the presentation builder; a placeholder COSE array.
        ['issuerAuth', [new Uint8Array([0xa0]), new Map(), new Uint8Array([0x01]), new Uint8Array([0x02])]],
    ]);
    return base64urlEncode(cborEncode(issuerSigned));
}

async function holderKeyPair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
}

describe('buildMdocDeviceResponse', () => {
    it('produces a decodable DeviceResponse with filtered namespaces and deviceSignature', async () => {
        const b64 = await buildMdocDeviceResponse({
            rawMdoc: makeIssuerSigned(),
            docType: DOCTYPE,
            requestedElements: ['given_name'], // only one of the two
            holderKey: await holderKeyPair(),
            clientId: 'x509_hash:abc',
            nonce: 'nonce-1',
            responseUri: 'https://verifier.test/response',
            encryptionJwk: { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'BBBB' },
        });

        const dr = cborDecode(base64urlDecode(b64)) as Map<string, unknown>;
        expect(dr.get('version')).toBe('1.0');
        expect(dr.get('status')).toBe(0);

        const doc = (dr.get('documents') as unknown[])[0] as Map<string, unknown>;
        expect(doc.get('docType')).toBe(DOCTYPE);

        // Only the requested element survived the filter.
        const issuerSigned = doc.get('issuerSigned') as Map<string, unknown>;
        const ns = issuerSigned.get('nameSpaces') as Map<string, Tag[]>;
        const items = ns.get(DOCTYPE)!;
        expect(items).toHaveLength(1);
        const kept = cborDecode((items[0] as Tag).value as Uint8Array) as Map<string, unknown>;
        expect(kept.get('elementIdentifier')).toBe('given_name');

        // deviceSignature is a COSE_Sign1 [protected, {}, null, sig].
        const deviceSigned = doc.get('deviceSigned') as Map<string, unknown>;
        const deviceAuth = deviceSigned.get('deviceAuth') as Map<string, unknown>;
        const cose = deviceAuth.get('deviceSignature') as unknown[];
        expect(cose).toHaveLength(4);
        expect(cose[2]).toBeNull();
        expect(cose[3]).toBeInstanceOf(Uint8Array);
        expect((cose[3] as Uint8Array).length).toBe(64); // raw r||s for P-256
    });

    it('omits the thumbprint (null) when there is no encryption key', async () => {
        // Just exercises the unencrypted transcript path without throwing.
        const b64 = await buildMdocDeviceResponse({
            rawMdoc: makeIssuerSigned(),
            docType: DOCTYPE,
            requestedElements: ['given_name', 'family_name'],
            holderKey: await holderKeyPair(),
            clientId: 'x509_hash:abc',
            nonce: 'n',
            responseUri: 'https://verifier.test/r',
            encryptionJwk: null,
        });
        const dr = cborDecode(base64urlDecode(b64)) as Map<string, unknown>;
        const doc = (dr.get('documents') as unknown[])[0] as Map<string, unknown>;
        const ns = (doc.get('issuerSigned') as Map<string, unknown>).get('nameSpaces') as Map<string, Tag[]>;
        expect(ns.get(DOCTYPE)).toHaveLength(2);
    });
});
