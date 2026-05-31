import { WALLET_BASE, WALLET_PROVIDER_BASE, PRE_AUTH_GRANT } from './constants';
import { base64urlEncode, generateRandomString } from './utils';
import { buildJwt, exportPublicJwk, sha256 } from './crypto';
import type {
    CredentialOffer,
    CredentialIssuerMetadata,
    AuthServerMetadata,
    TokenResponse,
    NonceResponse,
    CredentialResponse,
    GrantInfo,
    OfferData,
    TokenRequestOptions,
    CredentialRequestOptions,
    PreAuthGrant,
    Oid4vpAuthorizationRequest,
    StoredCredential,
} from './types';
import { filterDisclosuresForPresentation } from './sdjwt';
import { CompactEncrypt, importJWK, importX509, compactVerify, type JWK } from 'jose';

// =========================================================================
// Credential Offer
// =========================================================================

export function parseCredentialOfferFromUrl(params: URLSearchParams): OfferData | null {
    const offerJson = params.get('credential_offer');
    const offerUri = params.get('credential_offer_uri');
    if (offerJson) return { offer: JSON.parse(decodeURIComponent(offerJson)), source: 'by_value' };
    if (offerUri) return { offerUri: decodeURIComponent(offerUri), source: 'by_reference' };
    return null;
}

export async function fetchCredentialOffer(uri: string): Promise<CredentialOffer> {
    const res = await fetch(uri);
    if (!res.ok) throw new Error('Failed to fetch credential offer: ' + res.status);
    return res.json();
}

// =========================================================================
// Metadata
// =========================================================================

export async function fetchIssuerMetadata(issuerUrl: string): Promise<CredentialIssuerMetadata> {
    const res = await fetch(issuerUrl + '/.well-known/openid-credential-issuer');
    if (!res.ok) throw new Error('Failed to fetch issuer metadata: ' + res.status);
    return res.json();
}

export async function fetchAuthServerMetadata(issuerUrl: string): Promise<AuthServerMetadata> {
    const res = await fetch(issuerUrl + '/.well-known/oauth-authorization-server');
    if (!res.ok) throw new Error('Failed to fetch auth server metadata: ' + res.status);
    return res.json();
}

// =========================================================================
// Grant Analysis
// =========================================================================

export function analyzeGrant(offer: CredentialOffer): GrantInfo {
    const grants = offer.grants ?? {};
    const preAuth = grants[PRE_AUTH_GRANT];
    if (preAuth) return { type: 'pre-authorized_code', data: preAuth };
    if (grants.authorization_code) return { type: 'authorization_code', data: grants.authorization_code };
    throw new Error('No supported grant type in credential offer');
}

// =========================================================================
// Token Request
// =========================================================================

export async function requestToken(
    tokenEndpoint: string,
    params: Record<string, string>,
    options?: TokenRequestOptions,
): Promise<TokenResponse> {
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (options?.dpopProof) headers['DPoP'] = options.dpopProof;
    if (options?.wiaJwt) headers['OAuth-Client-Attestation'] = options.wiaJwt;
    if (options?.popJwt) headers['OAuth-Client-Attestation-PoP'] = options.popJwt;

    const res = await fetch(tokenEndpoint, {
        method: 'POST',
        headers,
        body: new URLSearchParams(params).toString(),
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({} as Record<string, string>));
        throw new Error('Token request failed: ' + (err.error_description || err.error || res.status));
    }
    return res.json();
}

// =========================================================================
// Nonce
// =========================================================================

export async function requestNonce(
    nonceEndpoint: string,
    options?: { dpopProof?: string },
): Promise<NonceResponse> {
    const headers: Record<string, string> = {};
    if (options?.dpopProof) headers['DPoP'] = options.dpopProof;
    const res = await fetch(nonceEndpoint, { method: 'POST', headers });
    if (!res.ok) throw new Error('Nonce request failed: ' + res.status);
    return res.json();
}

// =========================================================================
// Proof JWT
// =========================================================================

export async function buildProofJwt(
    keyPair: CryptoKeyPair,
    clientId: string,
    audience: string,
    nonce: string,
): Promise<string> {
    const pubJwk = await exportPublicJwk(keyPair);
    const header = { typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: pubJwk };
    const payload = {
        iss: clientId,
        aud: audience,
        iat: Math.floor(Date.now() / 1000),
        nonce,
    };
    return buildJwt(header, payload, keyPair.privateKey);
}

// =========================================================================
// Credential Request
// =========================================================================

export async function requestCredential(
    credentialEndpoint: string,
    accessToken: string,
    tokenType: string,
    credentialConfigId: string,
    proofJwt: string,
    options?: CredentialRequestOptions,
): Promise<CredentialResponse> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const scheme = tokenType === 'DPoP' ? 'DPoP' : 'Bearer';
    headers['Authorization'] = scheme + ' ' + accessToken;
    if (options?.dpopProof) headers['DPoP'] = options.dpopProof;

    const body = {
        credential_configuration_id: credentialConfigId,
        proof: { proof_type: 'jwt', jwt: proofJwt },
    };
    const res = await fetch(credentialEndpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({} as Record<string, string>));
        throw new Error('Credential request failed: ' + (err.error_description || err.error || res.status));
    }
    return res.json();
}

// =========================================================================
// Notification
// =========================================================================

export async function sendNotification(
    endpoint: string,
    accessToken: string,
    tokenType: string,
    notificationId: string,
    event: string,
    description?: string,
): Promise<void> {
    try {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        const scheme = tokenType === 'DPoP' ? 'DPoP' : 'Bearer';
        headers['Authorization'] = scheme + ' ' + accessToken;
        const body: Record<string, string> = { notification_id: notificationId, event };
        if (description) body.event_description = description;
        await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(body) });
    } catch (e) {
        console.warn('Notification failed:', e);
    }
}

// =========================================================================
// DPoP
// =========================================================================

export async function buildDpopProof(
    keyPair: CryptoKeyPair,
    method: string,
    uri: string,
    accessToken?: string,
    nonce?: string,
): Promise<string> {
    const pubJwk = await exportPublicJwk(keyPair);
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: pubJwk };
    const payload: Record<string, unknown> = {
        htm: method,
        htu: uri,
        iat: Math.floor(Date.now() / 1000),
        jti: generateRandomString(16),
    };
    if (accessToken) payload.ath = base64urlEncode(await sha256(accessToken));
    if (nonce) payload.nonce = nonce;
    return buildJwt(header, payload, keyPair.privateKey);
}

// =========================================================================
// WIA (Wallet Instance Attestation) — self-signed for testing
// =========================================================================

/**
 * Obtain a Wallet Instance Attestation. Prefers a WP-issued WIA (signed by the
 * Wallet Provider with an x5c chain to a trusted anchor); falls back to a
 * self-signed WIA if the Wallet Provider is unreachable. The wallet's PoP
 * public key is bound via cnf in both cases.
 */
export async function obtainWia(wiaKeyPair: CryptoKeyPair, clientId: string): Promise<string> {
    const pubJwk = await exportPublicJwk(wiaKeyPair);
    try {
        const res = await fetch(WALLET_PROVIDER_BASE + '/issue-wia', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_id: clientId, jwk: pubJwk }),
        });
        if (res.ok) {
            const data = await res.json();
            if (data.wia) return data.wia as string;
        }
    } catch {
        // WP unreachable — fall back to self-signed below
    }
    return generateWia(wiaKeyPair, clientId);
}

export async function generateWia(wiaKeyPair: CryptoKeyPair, clientId: string): Promise<string> {
    const pubJwk = await exportPublicJwk(wiaKeyPair);
    const header = { typ: 'wallet-attestation+jwt', alg: 'ES256', jwk: pubJwk };
    const payload = {
        iss: WALLET_BASE,
        sub: clientId,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        cnf: { jwk: pubJwk },
    };
    return buildJwt(header, payload, wiaKeyPair.privateKey);
}

export async function generateWiaPop(
    wiaKeyPair: CryptoKeyPair,
    clientId: string,
    audience: string,
): Promise<string> {
    const pubJwk = await exportPublicJwk(wiaKeyPair);
    const header = { typ: 'wallet-attestation-pop+jwt', alg: 'ES256', jwk: pubJwk };
    const payload = {
        iss: clientId,
        aud: audience,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        jti: generateRandomString(16),
    };
    return buildJwt(header, payload, wiaKeyPair.privateKey);
}

// =========================================================================
// PAR (Pushed Authorization Request)
// =========================================================================

export async function pushAuthorizationRequest(
    parEndpoint: string,
    params: Record<string, string>,
    dpopProof?: string,
    wiaJwt?: string,
    popJwt?: string,
): Promise<{ request_uri: string; expires_in: number }> {
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (dpopProof) headers['DPoP'] = dpopProof;
    if (wiaJwt) headers['OAuth-Client-Attestation'] = wiaJwt;
    if (popJwt) headers['OAuth-Client-Attestation-PoP'] = popJwt;
    const res = await fetch(parEndpoint, {
        method: 'POST',
        headers,
        body: new URLSearchParams(params).toString(),
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({} as Record<string, string>));
        throw new Error('PAR failed: ' + (err.error_description || err.error || res.status));
    }
    return res.json();
}

// =========================================================================
// Pre-auth grant data helper
// =========================================================================

export function getPreAuthCode(grant: GrantInfo): string {
    return (grant.data as PreAuthGrant)['pre-authorized_code'];
}

export function getPreAuthTxCode(grant: GrantInfo): PreAuthGrant['tx_code'] | undefined {
    return (grant.data as PreAuthGrant).tx_code;
}

// =========================================================================
// OID4VP — Presentation
// =========================================================================

/**
 * Fetch the Authorization Request (Request Object) from the verifier.
 *
 * HAIP (request_method=request_uri_signed) serves a signed JAR: a compact JWS
 * (typ=oauth-authz-req+jwt) whose payload is the request parameters, with the
 * verifier's signing cert chain in the x5c header. We verify the JWS against
 * the leaf certificate in x5c and read the parameters from the payload. A
 * plain-JSON request object is still accepted for non-signed flows.
 */
export async function fetchRequestObject(requestUri: string): Promise<Oid4vpAuthorizationRequest> {
    const res = await fetch(requestUri, {
        headers: { 'Accept': 'application/oauth-authz-req+jwt, application/json' },
    });
    if (!res.ok) throw new Error('Failed to fetch request object: ' + res.status);

    const text = (await res.text()).trim();

    let authReq: Oid4vpAuthorizationRequest;
    if (isCompactJws(text)) {
        authReq = await verifySignedRequestObject(text);
    } else {
        authReq = JSON.parse(text) as Oid4vpAuthorizationRequest;
    }

    if (authReq.response_type !== 'vp_token') {
        throw new Error('Unsupported response_type: ' + authReq.response_type);
    }
    // state is optional in OID4VP 1.0 Final; only response_uri and nonce are required.
    if (!authReq.response_uri || !authReq.nonce) {
        throw new Error('Missing required fields in authorization request');
    }
    return authReq;
}

/** True for a compact JWS (three base64url segments separated by dots). */
function isCompactJws(s: string): boolean {
    const parts = s.split('.');
    return parts.length === 3 && parts.every(p => /^[A-Za-z0-9_-]+$/.test(p));
}

/**
 * Verify a signed request object (JAR) against the leaf certificate in its x5c
 * header and return the request parameters from the payload. Throws if the x5c
 * is absent or the signature does not verify.
 */
async function verifySignedRequestObject(jws: string): Promise<Oid4vpAuthorizationRequest> {
    const protectedHeader = JSON.parse(
        new TextDecoder().decode(base64urlToBytes(jws.split('.')[0])),
    ) as { x5c?: string[]; alg?: string };

    const x5c = protectedHeader.x5c;
    if (!x5c || x5c.length === 0) {
        throw new Error('Signed request object has no x5c certificate');
    }

    // jose's importX509 expects a PEM; wrap the base64 DER from x5c[0] (leaf).
    const leafPem = derToPem(x5c[0]);
    const leafKey = await importX509(leafPem, protectedHeader.alg ?? 'ES256');

    const { payload } = await compactVerify(jws, leafKey);
    return JSON.parse(new TextDecoder().decode(payload)) as Oid4vpAuthorizationRequest;
}

/** Decode a base64url segment to bytes. */
function base64urlToBytes(s: string): Uint8Array {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
    const bin = atob(b64);
    return Uint8Array.from(bin, c => c.charCodeAt(0));
}

/** Wrap a base64 DER certificate (x5c entry) as a PEM string. */
function derToPem(b64der: string): string {
    const lines = b64der.match(/.{1,64}/g)?.join('\n') ?? b64der;
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

/**
 * Build VP Token: SD-JWT presentation with selective disclosures + KB-JWT.
 * Format: <issuer-jwt>~<disc1>~<disc2>~...~<kb-jwt>
 */
export async function buildVpToken(
    credential: StoredCredential,
    requestedClaims: string[],
    nonce: string,
    audience: string,
): Promise<string> {
    const { issuerJwt, disclosures } = filterDisclosuresForPresentation(
        credential.rawSdJwt, requestedClaims,
    );

    // Build the SD-JWT without KB-JWT (for sd_hash calculation). Each
    // disclosure is followed by a '~'; with zero disclosures this is just
    // "<issuer-jwt>~" (not "<issuer-jwt>~~", which is malformed).
    const sdJwtWithoutKb = issuerJwt + '~' + disclosures.map(d => d + '~').join('');

    // Compute sd_hash = base64url(SHA-256(sd-jwt-without-kb-jwt))
    const hash = await sha256(sdJwtWithoutKb);
    const sdHash = base64urlEncode(hash);

    // Build KB-JWT
    const kbHeader = { typ: 'kb+jwt', alg: 'ES256' };
    const kbPayload = {
        iat: Math.floor(Date.now() / 1000),
        aud: audience,
        nonce,
        sd_hash: sdHash,
    };
    const kbJwt = await buildJwt(kbHeader, kbPayload, credential.holderKey.privateKey);

    return sdJwtWithoutKb + kbJwt;
}

/**
 * Submit the VP Token to the verifier's response_uri.
 *
 * For response_mode `direct_post` the vp_token and state are sent as plaintext
 * form params. For `direct_post.jwt` (HAIP §5) the Authorization Response is
 * encrypted as a JWE to the verifier's response-encryption key (published in
 * client_metadata.jwks) and sent as the single `response` form param.
 */
export async function submitPresentation(
    authReq: Oid4vpAuthorizationRequest,
    vpToken: Record<string, string[]>,
): Promise<Response> {
    const { response_uri: responseUri, state, response_mode: responseMode } = authReq;

    let body: URLSearchParams;
    if (responseMode === 'direct_post.jwt') {
        const jwe = await encryptAuthorizationResponse(authReq, vpToken);
        body = new URLSearchParams({ response: jwe });
    } else {
        // OID4VP 1.0 Final with DCQL: vp_token is a JSON object keyed by the
        // DCQL credential id, serialized into the form param.
        body = new URLSearchParams({ vp_token: JSON.stringify(vpToken) });
        if (state) body.set('state', state); // state is optional in OID4VP 1.0 Final
    }

    return fetch(responseUri, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
    });
}

/**
 * Encrypt the Authorization Response ({vp_token, state}) as a compact JWE to
 * the verifier's response-encryption key. alg/enc come from the request
 * (authorization_encrypted_response_alg/enc), defaulting to ECDH-ES / A128GCM
 * per HAIP. The recipient key is the first usable EC key in
 * client_metadata.jwks.keys.
 */
async function encryptAuthorizationResponse(
    authReq: Oid4vpAuthorizationRequest,
    vpToken: Record<string, string[]>,
): Promise<string> {
    const metadata = authReq.client_metadata ?? {};
    const alg = (metadata.authorization_encrypted_response_alg as string) ?? 'ECDH-ES';
    const enc = (metadata.authorization_encrypted_response_enc as string) ?? 'A128GCM';

    const recipientJwk = selectEncryptionJwk(metadata);
    if (!recipientJwk) {
        throw new Error('No response-encryption key found in client_metadata.jwks');
    }
    const recipientKey = await importJWK(recipientJwk, alg);

    // vp_token is a DCQL-keyed JSON object (OID4VP 1.0 Final §8.1). state is
    // optional (omitted by the happy flow); only include it when present.
    const responseObj: Record<string, unknown> = { vp_token: vpToken };
    if (authReq.state) responseObj.state = authReq.state;
    const payload = Uint8Array.from(new TextEncoder().encode(JSON.stringify(responseObj)));

    const header: Record<string, unknown> = { alg, enc };
    if (recipientJwk.kid) header.kid = recipientJwk.kid;

    return new CompactEncrypt(payload)
        .setProtectedHeader(header as Parameters<CompactEncrypt['setProtectedHeader']>[0])
        .encrypt(recipientKey);
}

/** Pick the first EC encryption key from client_metadata.jwks.keys. */
function selectEncryptionJwk(metadata: Record<string, unknown>): JWK | null {
    const jwks = metadata.jwks as { keys?: JWK[] } | undefined;
    const keys = jwks?.keys ?? [];
    // Prefer an explicit use=enc key; otherwise fall back to the first EC key.
    return keys.find(k => k.kty === 'EC' && k.use === 'enc')
        ?? keys.find(k => k.kty === 'EC')
        ?? null;
}
