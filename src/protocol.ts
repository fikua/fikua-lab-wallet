import { WALLET_BASE, PRE_AUTH_GRANT } from './constants';
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
} from './types';

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
