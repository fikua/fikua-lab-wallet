// The Credential Issuer. Its own metadata's authorization_servers[0]
// points at fikua-lab-idp (see protocol.ts's resolveAuthServerUrl) —
// this constant is never assumed to also be the Authorization Server.
export const ISSUER_BASE = 'https://issuer.fikua.com';
// The wallet PWA is served at its own domain's root, wallet.fikua.com —
// matching the convention issuer.fikua.com/idp.fikua.com/
// attestation-registry.fikua.com already follow. location.origin alone
// is correct here since there is no /wallet subpath to account for
// anymore (see wrangler.toml / src/worker/index.ts).
export const WALLET_BASE = location.origin;

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
