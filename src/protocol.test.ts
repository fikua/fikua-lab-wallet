import { describe, it, expect } from 'vitest';
import { PRE_AUTH_GRANT } from './constants';
import {
    parseCredentialOfferFromUrl,
    analyzeGrant,
    getPreAuthCode,
    getPreAuthTxCode,
} from './protocol';
import type { CredentialOffer } from './types';

describe('parseCredentialOfferFromUrl', () => {
    it('parses credential_offer from query params (by_value)', () => {
        const offer: CredentialOffer = {
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['eu.europa.ec.eudi.pid.1'],
            grants: {
                [PRE_AUTH_GRANT]: {
                    'pre-authorized_code': 'abc123',
                },
            },
        };
        const params = new URLSearchParams({
            credential_offer: JSON.stringify(offer),
        });

        const result = parseCredentialOfferFromUrl(params);
        expect(result).not.toBeNull();
        expect(result!.source).toBe('by_value');
        expect(result!.offer).toEqual(offer);
        expect(result!.offerUri).toBeUndefined();
    });

    it('parses credential_offer_uri from query params (by_reference)', () => {
        const uri = 'https://issuer.example.com/offers/123';
        const params = new URLSearchParams({
            credential_offer_uri: uri,
        });

        const result = parseCredentialOfferFromUrl(params);
        expect(result).not.toBeNull();
        expect(result!.source).toBe('by_reference');
        expect(result!.offerUri).toBe(uri);
        expect(result!.offer).toBeUndefined();
    });

    it('returns null when no offer params present', () => {
        const params = new URLSearchParams({ code: 'xyz', state: 'abc' });
        expect(parseCredentialOfferFromUrl(params)).toBeNull();
    });

    it('prefers credential_offer over credential_offer_uri', () => {
        const offer: CredentialOffer = {
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['pid'],
        };
        const params = new URLSearchParams({
            credential_offer: JSON.stringify(offer),
            credential_offer_uri: 'https://issuer.example.com/offers/123',
        });

        const result = parseCredentialOfferFromUrl(params);
        expect(result!.source).toBe('by_value');
    });

    it('handles URL-encoded credential_offer', () => {
        const offer: CredentialOffer = {
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['pid'],
        };
        const encoded = encodeURIComponent(JSON.stringify(offer));
        const params = new URLSearchParams(`credential_offer=${encoded}`);

        const result = parseCredentialOfferFromUrl(params);
        expect(result!.offer!.credential_issuer).toBe('https://issuer.example.com');
    });
});

describe('analyzeGrant', () => {
    it('detects pre-authorized_code grant', () => {
        const offer: CredentialOffer = {
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['pid'],
            grants: {
                [PRE_AUTH_GRANT]: {
                    'pre-authorized_code': 'code123',
                },
            },
        };

        const grant = analyzeGrant(offer);
        expect(grant.type).toBe('pre-authorized_code');
        expect((grant.data as { 'pre-authorized_code': string })['pre-authorized_code']).toBe('code123');
    });

    it('detects authorization_code grant', () => {
        const offer: CredentialOffer = {
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['pid'],
            grants: {
                authorization_code: { issuer_state: 'state123' },
            },
        };

        const grant = analyzeGrant(offer);
        expect(grant.type).toBe('authorization_code');
        expect((grant.data as { issuer_state?: string }).issuer_state).toBe('state123');
    });

    it('prefers pre-authorized_code when both grants present', () => {
        const offer: CredentialOffer = {
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['pid'],
            grants: {
                [PRE_AUTH_GRANT]: { 'pre-authorized_code': 'pre-code' },
                authorization_code: { issuer_state: 'state' },
            },
        };

        const grant = analyzeGrant(offer);
        expect(grant.type).toBe('pre-authorized_code');
    });

    it('throws when no supported grant type found', () => {
        const offer: CredentialOffer = {
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['pid'],
        };
        expect(() => analyzeGrant(offer)).toThrow('No supported grant type');
    });

    it('throws when grants is empty object', () => {
        const offer: CredentialOffer = {
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['pid'],
            grants: {},
        };
        expect(() => analyzeGrant(offer)).toThrow('No supported grant type');
    });
});

describe('getPreAuthCode', () => {
    it('extracts pre-authorized_code from grant data', () => {
        const grant = analyzeGrant({
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['pid'],
            grants: {
                [PRE_AUTH_GRANT]: { 'pre-authorized_code': 'my-code' },
            },
        });
        expect(getPreAuthCode(grant)).toBe('my-code');
    });
});

describe('getPreAuthTxCode', () => {
    it('returns tx_code config when present', () => {
        const grant = analyzeGrant({
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['pid'],
            grants: {
                [PRE_AUTH_GRANT]: {
                    'pre-authorized_code': 'code',
                    tx_code: { length: 6, input_mode: 'numeric', description: 'Enter PIN' },
                },
            },
        });
        const txCode = getPreAuthTxCode(grant);
        expect(txCode).toBeDefined();
        expect(txCode!.length).toBe(6);
        expect(txCode!.input_mode).toBe('numeric');
    });

    it('returns undefined when no tx_code', () => {
        const grant = analyzeGrant({
            credential_issuer: 'https://issuer.example.com',
            credential_configuration_ids: ['pid'],
            grants: {
                [PRE_AUTH_GRANT]: { 'pre-authorized_code': 'code' },
            },
        });
        expect(getPreAuthTxCode(grant)).toBeUndefined();
    });
});
