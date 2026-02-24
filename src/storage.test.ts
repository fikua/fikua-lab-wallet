import { describe, it, expect, beforeEach } from 'vitest';
import { DB_NAME } from './constants';
import {
    openDb, saveCredential, getCredential, getAllCredentials,
    deleteCredentialById, logActivity, getAllActivity,
    _resetDbForTest,
} from './storage';
import type { StoredCredential } from './types';

function makeCredential(overrides?: Partial<StoredCredential>): StoredCredential {
    return {
        id: overrides?.id ?? crypto.randomUUID(),
        rawSdJwt: 'header.payload.sig~disclosure1~',
        format: 'dc+sd-jwt',
        issuer: 'https://issuer.example.com',
        issuerName: 'Example Issuer',
        credentialConfigId: 'eu.europa.ec.eudi.pid.1',
        vct: 'eu.europa.ec.eudi.pid.1',
        claims: { given_name: 'John', family_name: 'Doe' },
        metadata: {
            alg: 'ES256',
            issuedAt: '2024-06-15T12:00:00Z',
            expiresAt: null,
            notificationId: null,
            notificationEndpoint: null,
        },
        accessToken: 'token-123',
        tokenType: 'Bearer',
        holderKey: {} as CryptoKeyPair,
        issuedAt: Date.now(),
        ...overrides,
    };
}

beforeEach(async () => {
    _resetDbForTest();
    indexedDB.deleteDatabase(DB_NAME);
});

describe('openDb', () => {
    it('opens the database and creates object stores', async () => {
        const db = await openDb();
        expect(db.objectStoreNames.contains('credentials')).toBe(true);
        expect(db.objectStoreNames.contains('activity')).toBe(true);
    });
});

describe('credentials CRUD', () => {
    it('saves and retrieves a credential', async () => {
        await openDb();
        const cred = makeCredential({ id: 'test-1' });
        await saveCredential(cred);

        const retrieved = await getCredential('test-1');
        expect(retrieved).toBeDefined();
        expect(retrieved!.id).toBe('test-1');
        expect(retrieved!.claims.given_name).toBe('John');
        expect(retrieved!.issuer).toBe('https://issuer.example.com');
    });

    it('returns undefined for non-existent credential', async () => {
        await openDb();
        const result = await getCredential('non-existent');
        expect(result).toBeUndefined();
    });

    it('lists all credentials', async () => {
        await openDb();
        await saveCredential(makeCredential({ id: 'cred-1' }));
        await saveCredential(makeCredential({ id: 'cred-2' }));
        await saveCredential(makeCredential({ id: 'cred-3' }));

        const all = await getAllCredentials();
        expect(all).toHaveLength(3);
        const ids = all.map(c => c.id).sort();
        expect(ids).toEqual(['cred-1', 'cred-2', 'cred-3']);
    });

    it('deletes a credential', async () => {
        await openDb();
        await saveCredential(makeCredential({ id: 'to-delete' }));
        expect(await getCredential('to-delete')).toBeDefined();

        await deleteCredentialById('to-delete');
        expect(await getCredential('to-delete')).toBeUndefined();
    });

    it('updates a credential with same id (upsert via put)', async () => {
        await openDb();
        await saveCredential(makeCredential({ id: 'update-me', vct: 'v1' }));
        await saveCredential(makeCredential({ id: 'update-me', vct: 'v2' }));

        const all = await getAllCredentials();
        expect(all).toHaveLength(1);
        expect(all[0].vct).toBe('v2');
    });
});

describe('activity logging', () => {
    it('logs and retrieves activity entries', async () => {
        await openDb();
        await logActivity('Credential received', 'PID', 'Example Issuer', 'issued');
        await logActivity('Credential deleted', 'PID', 'Example Issuer', 'deleted');

        const all = await getAllActivity();
        expect(all).toHaveLength(2);
        expect(all[0].action).toBe('Credential received');
        expect(all[0].type).toBe('issued');
        expect(all[0].timestamp).toBeGreaterThan(0);
        expect(all[1].action).toBe('Credential deleted');
    });

    it('stores optional details', async () => {
        await openDb();
        await logActivity('Issuance failed', 'PID', 'Issuer', 'failed', 'Token request failed: 401');

        const all = await getAllActivity();
        expect(all[0].details).toBe('Token request failed: 401');
    });

    it('sets details to null when not provided', async () => {
        await openDb();
        await logActivity('Credential received', 'PID', 'Issuer', 'issued');

        const all = await getAllActivity();
        expect(all[0].details).toBeNull();
    });

    it('auto-increments activity IDs', async () => {
        await openDb();
        await logActivity('First', 'PID', 'Issuer', 'issued');
        await logActivity('Second', 'PID', 'Issuer', 'issued');

        const all = await getAllActivity();
        expect(all[0].id).toBeDefined();
        expect(all[1].id).toBeDefined();
        expect(all[0].id).not.toBe(all[1].id);
    });
});
