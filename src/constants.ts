export const ISSUER_BASE = 'https://lab.fikua.com/issuer';
// The wallet PWA is mounted at /wallet/ under lab.fikua.com.
export const WALLET_BASE = location.origin + '/wallet';

// Wallet Provider (Fikua Lab) — issues the Wallet Instance Attestation. The
// wallet requests a WP-signed WIA here; falls back to self-signed if offline.
export const WALLET_PROVIDER_BASE = 'https://lab.fikua.com/wallet-provider';

export const DB_NAME = 'fikua-wallet';
export const DB_VERSION = 1;
export const STORE_CREDENTIALS = 'credentials';
export const STORE_ACTIVITY = 'activity';

export const PASSKEY_KEY = 'fikua_passkey';
export const SESSION_KEY = 'fikua_session';
export const USER_KEY = 'fikua_user';
export const PRIVACY_KEY = 'fikua_privacy';
export const AUTH_FLOW_KEY = 'fikua_auth_flow';
export const PENDING_OFFER_KEY = 'fikua_pending_offer';
// Per-wallet salt for the WebAuthn PRF extension (WIA key derivation).
export const PRF_SALT_KEY = 'fikua_prf_salt';

export const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
