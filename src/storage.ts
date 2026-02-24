import { DB_NAME, DB_VERSION, STORE_CREDENTIALS, STORE_ACTIVITY } from './constants';
import type { StoredCredential, ActivityEntry } from './types';

let db: IDBDatabase | null = null;

/** @internal Reset cached db reference (for testing only). */
export function _resetDbForTest(): void {
    if (db) { db.close(); db = null; }
}

export function openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        if (db) return resolve(db);
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = (e) => {
            const idb = (e.target as IDBOpenDBRequest).result;
            if (!idb.objectStoreNames.contains(STORE_CREDENTIALS)) {
                const cs = idb.createObjectStore(STORE_CREDENTIALS, { keyPath: 'id' });
                cs.createIndex('issuedAt', 'issuedAt');
            }
            if (!idb.objectStoreNames.contains(STORE_ACTIVITY)) {
                const as = idb.createObjectStore(STORE_ACTIVITY, { keyPath: 'id', autoIncrement: true });
                as.createIndex('timestamp', 'timestamp');
            }
        };
        request.onsuccess = (e) => {
            db = (e.target as IDBOpenDBRequest).result;
            resolve(db);
        };
        request.onerror = (e) => reject((e.target as IDBOpenDBRequest).error);
    });
}

async function dbPut(storeName: string, item: unknown): Promise<void> {
    const d = await openDb();
    return new Promise((resolve, reject) => {
        const tx = d.transaction(storeName, 'readwrite');
        tx.objectStore(storeName).put(item);
        tx.oncomplete = () => resolve();
        tx.onerror = (e) => reject((e.target as IDBTransaction).error);
    });
}

async function dbGet<T>(storeName: string, key: string | number): Promise<T | undefined> {
    const d = await openDb();
    return new Promise((resolve, reject) => {
        const tx = d.transaction(storeName, 'readonly');
        const req = tx.objectStore(storeName).get(key);
        req.onsuccess = () => resolve(req.result as T | undefined);
        req.onerror = (e) => reject((e.target as IDBRequest).error);
    });
}

async function dbGetAll<T>(storeName: string): Promise<T[]> {
    const d = await openDb();
    return new Promise((resolve, reject) => {
        const tx = d.transaction(storeName, 'readonly');
        const req = tx.objectStore(storeName).getAll();
        req.onsuccess = () => resolve((req.result || []) as T[]);
        req.onerror = (e) => reject((e.target as IDBRequest).error);
    });
}

async function dbDelete(storeName: string, key: string | number): Promise<void> {
    const d = await openDb();
    return new Promise((resolve, reject) => {
        const tx = d.transaction(storeName, 'readwrite');
        tx.objectStore(storeName).delete(key);
        tx.oncomplete = () => resolve();
        tx.onerror = (e) => reject((e.target as IDBTransaction).error);
    });
}

// --- Typed helpers ---

export async function saveCredential(cred: StoredCredential): Promise<void> {
    return dbPut(STORE_CREDENTIALS, cred);
}

export async function getCredential(id: string): Promise<StoredCredential | undefined> {
    return dbGet<StoredCredential>(STORE_CREDENTIALS, id);
}

export async function getAllCredentials(): Promise<StoredCredential[]> {
    return dbGetAll<StoredCredential>(STORE_CREDENTIALS);
}

export async function deleteCredentialById(id: string): Promise<void> {
    return dbDelete(STORE_CREDENTIALS, id);
}

export async function logActivity(
    action: string,
    credentialName: string,
    issuerOrVerifier: string,
    type: ActivityEntry['type'],
    details?: string,
): Promise<void> {
    const entry: Omit<ActivityEntry, 'id'> = {
        action,
        credentialName,
        issuerOrVerifier,
        type,
        timestamp: Date.now(),
        details: details ?? null,
    };
    return dbPut(STORE_ACTIVITY, entry);
}

export async function getAllActivity(): Promise<ActivityEntry[]> {
    return dbGetAll<ActivityEntry>(STORE_ACTIVITY);
}
