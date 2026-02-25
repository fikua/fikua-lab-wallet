// =========================================================================
// OID4VCI Protocol Types
// =========================================================================

export interface CredentialOffer {
    credential_issuer: string;
    credential_configuration_ids: string[];
    grants?: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: PreAuthGrant;
        authorization_code?: AuthCodeGrant;
    };
}

export interface PreAuthGrant {
    'pre-authorized_code': string;
    tx_code?: TxCodeConfig;
}

export interface AuthCodeGrant {
    issuer_state?: string;
}

export interface TxCodeConfig {
    length?: number;
    input_mode?: string;
    description?: string;
}

export interface CredentialIssuerMetadata {
    credential_issuer: string;
    credential_endpoint: string;
    nonce_endpoint?: string;
    notification_endpoint?: string;
    credential_configurations_supported: Record<string, CredentialConfiguration>;
    display?: IssuerDisplay[];
}

export interface CredentialConfiguration {
    format: string;
    credential_metadata?: {
        display?: Array<{ name: string; description?: string }>;
    };
    claims?: unknown[];
}

export interface IssuerDisplay {
    name: string;
    locale?: string;
}

export interface AuthServerMetadata {
    issuer: string;
    token_endpoint: string;
    authorization_endpoint?: string;
    pushed_authorization_request_endpoint?: string;
    jwks_uri?: string;
    grant_types_supported?: string[];
    code_challenge_methods_supported?: string[];
    dpop_signing_alg_values_supported?: string[];
    require_pushed_authorization_requests?: boolean;
}

export interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in?: number;
    c_nonce?: string;
    c_nonce_expires_in?: number;
}

export interface NonceResponse {
    c_nonce: string;
    c_nonce_expires_in?: number;
}

export interface CredentialResponse {
    credentials: Array<{ credential: string }>;
    notification_id?: string;
    c_nonce?: string;
}

// =========================================================================
// Storage Types
// =========================================================================

export interface StoredCredential {
    id: string;
    rawSdJwt: string;
    format: string;
    issuer: string;
    issuerName: string;
    credentialConfigId: string;
    vct: string;
    claims: Record<string, unknown>;
    metadata: CredentialMetadata;
    accessToken: string;
    tokenType: string;
    holderKey: CryptoKeyPair;
    issuedAt: number;
}

export interface CredentialMetadata {
    alg: string;
    issuedAt: string | null;
    expiresAt: string | null;
    notificationId: string | null;
    notificationEndpoint: string | null;
}

export interface ActivityEntry {
    id?: number;
    action: string;
    credentialName: string;
    issuerOrVerifier: string;
    type: 'issued' | 'presented' | 'deleted' | 'failed';
    timestamp: number;
    details: string | null;
}

// =========================================================================
// SD-JWT Types
// =========================================================================

export interface ParsedSdJwt {
    raw: string;
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    disclosedClaims: Record<string, unknown>;
    allClaims: Record<string, unknown>;
    disclosures: Disclosure[];
    issuer: string;
    subject?: string;
    vct?: string;
    issuedAt?: number;
    expiresAt?: number;
    cnf?: { jwk?: JsonWebKey };
    status?: unknown;
    sdAlg?: string;
}

export interface Disclosure {
    salt: string;
    name: string;
    value: unknown;
    raw: string;
}

// =========================================================================
// mdoc Types
// =========================================================================

export interface ParsedMdoc {
    raw: string;
    docType: string;
    claims: Record<string, unknown>;
    validFrom: string | null;
    validUntil: string | null;
}

// =========================================================================
// Flow State (persisted in sessionStorage during auth code redirect)
// =========================================================================

export interface AuthFlowState {
    offer: CredentialOffer | null;
    issuerMeta: CredentialIssuerMetadata;
    authMeta: AuthServerMetadata;
    configId: string;
    state: string;
    codeVerifier: string;
    isHaip: boolean;
    clientId: string;
    redirectUri: string;
    issuerUrl: string;
    dpopKeyPair?: ExportedKeyPair;
    wiaKeyPair?: ExportedKeyPair;
}

export interface ExportedKeyPair {
    privateKey: JsonWebKey;
    publicKey: JsonWebKey;
}

export interface GrantInfo {
    type: 'pre-authorized_code' | 'authorization_code';
    data: PreAuthGrant | AuthCodeGrant;
}

export interface OfferData {
    offer?: CredentialOffer;
    offerUri?: string;
    source: 'by_value' | 'by_reference';
}

export interface TokenRequestOptions {
    dpopProof?: string;
    wiaJwt?: string;
    popJwt?: string;
}

export interface CredentialRequestOptions {
    dpopProof?: string;
}

// =========================================================================
// OID4VP Protocol Types
// =========================================================================

export interface Oid4vpAuthorizationRequest {
    response_type: string;
    client_id: string;
    response_mode: string;
    response_uri: string;
    nonce: string;
    state: string;
    dcql_query?: DcqlQuery;
    client_metadata?: Record<string, unknown>;
}

export interface DcqlQuery {
    credentials: DcqlCredentialQuery[];
}

export interface DcqlCredentialQuery {
    id: string;
    format: string;
    meta?: { vct_values?: string[] };
    claims?: DcqlClaimQuery[];
}

export interface DcqlClaimQuery {
    path: string[];
    values?: string[];
    essential?: boolean;
}
