import { describe, it, expect } from 'vitest';
import { decodeCbor, isCborTagged } from './cbor';
import type { CborMap, CborTagged } from './cbor';

/** Helper: hand-craft minimal CBOR bytes for testing. */
function cborUint8(value: number): Uint8Array {
    // Major type 0 (unsigned int), value < 24 = single byte
    if (value < 24) return new Uint8Array([value]);
    if (value < 256) return new Uint8Array([0x18, value]);
    return new Uint8Array([0x19, (value >> 8) & 0xff, value & 0xff]);
}

function cborNegInt(value: number): Uint8Array {
    // Major type 1, encodes -1 - value
    const n = -1 - value; // value = -1 - n => n = -1 - value (we want cbor neg for `value`, so n = -1 - value)
    // Actually: major type 1, additional = |value| - 1
    const absMinusOne = Math.abs(value) - 1;
    if (absMinusOne < 24) return new Uint8Array([0x20 | absMinusOne]);
    return new Uint8Array([0x38, absMinusOne]);
}

function cborText(str: string): Uint8Array {
    const encoded = new TextEncoder().encode(str);
    const len = encoded.length;
    if (len < 24) {
        const buf = new Uint8Array(1 + len);
        buf[0] = 0x60 | len; // major type 3
        buf.set(encoded, 1);
        return buf;
    }
    if (len < 256) {
        const buf = new Uint8Array(2 + len);
        buf[0] = 0x78;
        buf[1] = len;
        buf.set(encoded, 2);
        return buf;
    }
    const buf = new Uint8Array(3 + len);
    buf[0] = 0x79;
    buf[1] = (len >> 8) & 0xff;
    buf[2] = len & 0xff;
    buf.set(encoded, 3);
    return buf;
}

function cborBytes(data: Uint8Array): Uint8Array {
    const len = data.length;
    if (len < 24) {
        const buf = new Uint8Array(1 + len);
        buf[0] = 0x40 | len; // major type 2
        buf.set(data, 1);
        return buf;
    }
    if (len < 256) {
        const buf = new Uint8Array(2 + len);
        buf[0] = 0x58;
        buf[1] = len;
        buf.set(encoded(data), 2);
        return buf;
    }
    const buf = new Uint8Array(3 + len);
    buf[0] = 0x59;
    buf[1] = (len >> 8) & 0xff;
    buf[2] = len & 0xff;
    buf.set(data, 3);
    return buf;
}

function encoded(data: Uint8Array): Uint8Array { return data; }

function cborArray(items: Uint8Array[]): Uint8Array {
    const len = items.length;
    const header = len < 24 ? new Uint8Array([0x80 | len]) : new Uint8Array([0x98, len]);
    return concat([header, ...items]);
}

function cborMap(entries: [Uint8Array, Uint8Array][]): Uint8Array {
    const len = entries.length;
    const header = len < 24 ? new Uint8Array([0xa0 | len]) : new Uint8Array([0xb8, len]);
    const parts = [header];
    for (const [k, v] of entries) { parts.push(k, v); }
    return concat(parts);
}

function cborTag(tag: number, value: Uint8Array): Uint8Array {
    if (tag < 24) return concat([new Uint8Array([0xc0 | tag]), value]);
    return concat([new Uint8Array([0xd8, tag]), value]);
}

function concat(parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((s, p) => s + p.length, 0);
    const buf = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) { buf.set(p, offset); offset += p.length; }
    return buf;
}

describe('CBOR decoder', () => {
    it('decodes unsigned integers', () => {
        expect(decodeCbor(new Uint8Array([0x00]))).toBe(0);
        expect(decodeCbor(new Uint8Array([0x17]))).toBe(23);
        expect(decodeCbor(new Uint8Array([0x18, 0x18]))).toBe(24);
        expect(decodeCbor(new Uint8Array([0x18, 0xff]))).toBe(255);
        expect(decodeCbor(new Uint8Array([0x19, 0x01, 0x00]))).toBe(256);
    });

    it('decodes negative integers', () => {
        expect(decodeCbor(cborNegInt(-1))).toBe(-1);
        expect(decodeCbor(cborNegInt(-10))).toBe(-10);
        expect(decodeCbor(cborNegInt(-24))).toBe(-24);
    });

    it('decodes text strings', () => {
        expect(decodeCbor(cborText(''))).toBe('');
        expect(decodeCbor(cborText('hello'))).toBe('hello');
        expect(decodeCbor(cborText('given_name'))).toBe('given_name');
    });

    it('decodes byte strings', () => {
        const bytes = new Uint8Array([1, 2, 3]);
        const result = decodeCbor(cborBytes(bytes));
        expect(result).toBeInstanceOf(Uint8Array);
        expect(result).toEqual(bytes);
    });

    it('decodes arrays', () => {
        const arr = cborArray([cborUint8(1), cborUint8(2), cborText('three')]);
        const result = decodeCbor(arr);
        expect(result).toEqual([1, 2, 'three']);
    });

    it('decodes maps', () => {
        const map = cborMap([
            [cborText('name'), cborText('Jan')],
            [cborText('age'), cborUint8(30)],
        ]);
        const result = decodeCbor(map) as CborMap;
        expect(result['name']).toBe('Jan');
        expect(result['age']).toBe(30);
    });

    it('decodes maps with integer keys', () => {
        const map = cborMap([
            [cborUint8(1), cborUint8(2)],
            [cborNegInt(-1), cborUint8(1)],
        ]);
        const result = decodeCbor(map) as CborMap;
        expect(result['1']).toBe(2);
        expect(result['-1']).toBe(1);
    });

    it('decodes tag 24 (encoded-cbor) — unwraps inner CBOR', () => {
        // Tag 24 wrapping a map: {"a": 1}
        const inner = cborMap([[cborText('a'), cborUint8(1)]]);
        const tagged = cborTag(24, cborBytes(inner));
        const result = decodeCbor(tagged);
        expect(isCborTagged(result)).toBe(true);
        const t = result as CborTagged;
        expect(t.tag).toBe(24);
        expect((t.value as CborMap)['a']).toBe(1);
    });

    it('decodes tag 0 (datetime string)', () => {
        const dateStr = '2026-02-24T12:00:00Z';
        const tagged = cborTag(0, cborText(dateStr));
        const result = decodeCbor(tagged);
        expect(isCborTagged(result)).toBe(true);
        const t = result as CborTagged;
        expect(t.tag).toBe(0);
        expect(t.value).toBe(dateStr);
    });

    it('decodes simple values (true, false, null)', () => {
        expect(decodeCbor(new Uint8Array([0xf4]))).toBe(false);
        expect(decodeCbor(new Uint8Array([0xf5]))).toBe(true);
        expect(decodeCbor(new Uint8Array([0xf6]))).toBeNull();
    });

    it('decodes nested structures', () => {
        const nested = cborMap([
            [cborText('list'), cborArray([cborUint8(1), cborText('two')])],
            [cborText('inner'), cborMap([[cborText('x'), cborUint8(42)]])],
        ]);
        const result = decodeCbor(nested) as CborMap;
        expect(result['list']).toEqual([1, 'two']);
        expect((result['inner'] as CborMap)['x']).toBe(42);
    });
});
