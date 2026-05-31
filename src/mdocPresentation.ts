/**
 * Build an ISO 18013-5 mdoc DeviceResponse for OID4VP presentation
 * (response_mode direct_post.jwt, HAIP).
 *
 * The verifier reconstructs the same SessionTranscript and verifies the
 * deviceSignature, so the CBOR bytes must match the spec exactly:
 *
 *   SessionTranscript = [ null, null, OpenID4VPHandover ]
 *   OpenID4VPHandover = [ "OpenID4VPHandover", SHA256(HandoverInfo) ]
 *   HandoverInfo      = [ client_id, nonce, jwkThumbprint | null, response_uri ]
 *
 *   DeviceAuthentication = [ "DeviceAuthentication", SessionTranscript,
 *                            DocType, DeviceNameSpacesBytes ]
 *   deviceSignature = COSE_Sign1 over Tag24(DeviceAuthentication), detached payload
 *
 * See OID4VP 1.0 Final appendix B.2.6.
 */

import { Encoder, Tag } from 'cbor-x';
import { base64urlDecode, base64urlEncode } from './utils';

// Deterministic / canonical CBOR (ISO 18013-5 requires it for the transcript).
// mapsAsObjects:false makes decode() return Map instances, preserving key order
// and binary keys; the same instance encodes and decodes for symmetry.
const codec = new Encoder({ useRecords: false, mapsAsObjects: false, variableMapSize: true });

function cborEncode(value: unknown): Uint8Array {
    return new Uint8Array(codec.encode(value));
}

function cborDecode(bytes: Uint8Array): unknown {
    return codec.decode(bytes);
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data as Uint8Array<ArrayBuffer>));
}

/** RFC 7638 JWK thumbprint (raw SHA-256 bytes) of an EC public JWK. */
async function ecJwkThumbprint(jwk: { crv: string; kty: string; x: string; y: string }): Promise<Uint8Array> {
    // Canonical member ordering per RFC 7638: crv, kty, x, y.
    const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
    return sha256(new TextEncoder().encode(canonical));
}

/**
 * Build the OID4VP session transcript bytes.
 * jwkThumbprint is the raw SHA-256 of the verifier's response-encryption JWK
 * (for encrypted responses); pass null for unencrypted.
 */
async function buildSessionTranscript(
    clientId: string, nonce: string, responseUri: string, jwkThumbprint: Uint8Array | null,
): Promise<Uint8Array> {
    const handoverInfo = cborEncode([
        clientId, nonce, jwkThumbprint ?? null, responseUri,
    ]);
    const handoverInfoHash = await sha256(handoverInfo);
    const handover = ['OpenID4VPHandover', handoverInfoHash];
    return cborEncode([null, null, handover]);
}

interface MdocPresentationInputs {
    /** base64url IssuerSigned CBOR as stored at issuance. */
    rawMdoc: string;
    docType: string;
    /** Element identifiers the verifier requested (within docType namespace). */
    requestedElements: string[];
    holderKey: CryptoKeyPair;
    clientId: string;
    nonce: string;
    responseUri: string;
    /** Verifier response-encryption public JWK (for direct_post.jwt). */
    encryptionJwk: { crv: string; kty: string; x: string; y: string } | null;
}

/**
 * Produce a base64url-encoded DeviceResponse presenting the requested elements
 * of the stored mdoc, bound to the verifier via the OID4VP session transcript.
 */
export async function buildMdocDeviceResponse(inputs: MdocPresentationInputs): Promise<string> {
    const { rawMdoc, docType, requestedElements, holderKey, clientId, nonce, responseUri, encryptionJwk } = inputs;

    // Re-decode the stored IssuerSigned with cbor-x so we keep the exact
    // structures (Tag 24 item wrappers, the issuerAuth COSE_Sign1) for re-encoding.
    const issuerSigned = cborDecode(base64urlDecode(rawMdoc)) as Map<string, unknown>;
    const nameSpaces = issuerSigned.get('nameSpaces') as Map<string, Tag[]>;
    const issuerAuth = issuerSigned.get('issuerAuth');

    // Filter each namespace's IssuerSignedItems down to the requested elements.
    const filteredNameSpaces = new Map<string, Tag[]>();
    for (const [ns, items] of nameSpaces) {
        const kept = items.filter(itemTag => {
            const item = cborDecode(itemTag.value as Uint8Array) as Map<string, unknown>;
            return requestedElements.includes(item.get('elementIdentifier') as string);
        });
        if (kept.length > 0) filteredNameSpaces.set(ns, kept);
    }

    // DeviceNameSpaces is empty for a simple presentation (no device-signed
    // claims); DeviceNameSpacesBytes = Tag24(cbor({})).
    const deviceNameSpacesBytes = new Tag(cborEncode(new Map()), 24);

    // SessionTranscript bound to this verifier + nonce + response-encryption key.
    const jwkThumbprint = encryptionJwk ? await ecJwkThumbprint(encryptionJwk) : null;
    const sessionTranscript = cborDecode(
        await buildSessionTranscript(clientId, nonce, responseUri, jwkThumbprint),
    );

    // DeviceAuthentication is the detached COSE_Sign1 payload (wrapped in Tag 24).
    const deviceAuthentication = ['DeviceAuthentication', sessionTranscript, docType, deviceNameSpacesBytes];
    const deviceAuthBytes = cborEncode(new Tag(cborEncode(deviceAuthentication), 24));

    const deviceSignature = await coseSign1(holderKey.privateKey, deviceAuthBytes);

    const deviceResponse = new Map<string, unknown>([
        ['version', '1.0'],
        ['documents', [new Map<string, unknown>([
            ['docType', docType],
            ['issuerSigned', new Map<string, unknown>([
                ['nameSpaces', filteredNameSpaces],
                ['issuerAuth', issuerAuth],
            ])],
            ['deviceSigned', new Map<string, unknown>([
                ['nameSpaces', deviceNameSpacesBytes],
                ['deviceAuth', new Map<string, unknown>([['deviceSignature', deviceSignature]])],
            ])],
        ])]],
        ['status', 0],
    ]);

    return base64urlEncode(cborEncode(deviceResponse));
}

/**
 * COSE_Sign1 with a detached payload (ISO mdoc deviceSignature):
 *   [ protected_bstr({1: -7}), {}, null, signature ]
 * Sig_structure = [ "Signature1", protected, external_aad(empty), payload ].
 */
async function coseSign1(privateKey: CryptoKey, payload: Uint8Array): Promise<unknown[]> {
    const protectedHeader = cborEncode(new Map<number, number>([[1, -7]])); // alg: ES256
    const sigStructure = cborEncode(['Signature1', protectedHeader, new Uint8Array(0), payload]);

    const sig = new Uint8Array(await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' }, privateKey, sigStructure as Uint8Array<ArrayBuffer>,
    ));
    // Web Crypto already returns the raw r||s (IEEE P1363) form COSE expects.
    return [protectedHeader, new Map(), null, sig];
}
