import { describe, it, expect } from 'vitest';
import {
    base64urlEncode, base64urlDecode, base64urlDecodeJson, base64urlEncodeJson,
    esc, formatTime, formatDate, generateRandomString,
} from './utils';

describe('base64urlEncode / base64urlDecode', () => {
    it('round-trips binary data', () => {
        const input = new Uint8Array([0, 1, 2, 255, 128, 64]);
        const encoded = base64urlEncode(input);
        const decoded = base64urlDecode(encoded);
        expect(Array.from(decoded)).toEqual(Array.from(input));
    });

    it('produces URL-safe output (no +, /, =)', () => {
        // Use data that would produce +, / and = in standard base64
        const data = new Uint8Array([251, 239, 190, 255, 63]);
        const encoded = base64urlEncode(data);
        expect(encoded).not.toContain('+');
        expect(encoded).not.toContain('/');
        expect(encoded).not.toContain('=');
    });

    it('handles empty input', () => {
        const encoded = base64urlEncode(new Uint8Array(0));
        expect(encoded).toBe('');
        const decoded = base64urlDecode('');
        expect(decoded.length).toBe(0);
    });
});

describe('base64urlEncodeJson / base64urlDecodeJson', () => {
    it('round-trips a JSON object', () => {
        const obj = { alg: 'ES256', typ: 'jwt' };
        const encoded = base64urlEncodeJson(obj);
        const decoded = base64urlDecodeJson(encoded);
        expect(decoded).toEqual(obj);
    });

    it('handles nested objects', () => {
        const obj = { cnf: { jwk: { kty: 'EC', crv: 'P-256' } } };
        const encoded = base64urlEncodeJson(obj);
        expect(base64urlDecodeJson(encoded)).toEqual(obj);
    });

    it('handles unicode characters', () => {
        const obj = { name: 'José García' };
        const encoded = base64urlEncodeJson(obj);
        expect(base64urlDecodeJson(encoded)).toEqual(obj);
    });
});

describe('esc', () => {
    it('escapes HTML special characters', () => {
        expect(esc('<script>alert("xss")</script>')).toBe(
            '&lt;script&gt;alert("xss")&lt;/script&gt;',
        );
    });

    it('escapes ampersands', () => {
        expect(esc('a&b')).toBe('a&amp;b');
    });

    it('returns empty string for falsy values', () => {
        expect(esc(null)).toBe('');
        expect(esc(undefined)).toBe('');
        expect(esc('')).toBe('');
        expect(esc(0)).toBe('');
    });

    it('converts non-string values to string', () => {
        expect(esc(42)).toBe('42');
        expect(esc(true)).toBe('true');
    });
});

describe('formatDate', () => {
    it('returns ISO date string (YYYY-MM-DD)', () => {
        // 2024-06-15T12:00:00Z
        const ts = Date.UTC(2024, 5, 15, 12, 0, 0);
        expect(formatDate(ts)).toBe('2024-06-15');
    });
});

describe('formatTime', () => {
    it('returns a string containing date and time', () => {
        const ts = Date.now();
        const result = formatTime(ts);
        // Should contain at least a colon (from time) and some digits
        expect(result).toMatch(/\d/);
        expect(result).toMatch(/:/);
    });
});

describe('generateRandomString', () => {
    it('returns a non-empty string', () => {
        const str = generateRandomString(32);
        expect(str.length).toBeGreaterThan(0);
    });

    it('returns different values on successive calls', () => {
        const a = generateRandomString(32);
        const b = generateRandomString(32);
        expect(a).not.toBe(b);
    });

    it('produces URL-safe characters only', () => {
        const str = generateRandomString(64);
        expect(str).toMatch(/^[A-Za-z0-9_-]+$/);
    });
});
