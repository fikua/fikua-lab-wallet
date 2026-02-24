/**
 * Minimal CBOR decoder (RFC 8949) — decode only, no encoding.
 * Supports: unsigned/negative ints, byte strings, text strings,
 * arrays, maps, tags (including tag 24 encoded-cbor), simple values.
 */

export type CborValue = number | bigint | string | Uint8Array | CborValue[] | CborMap | boolean | null | CborTagged;

export interface CborMap {
    [key: string]: CborValue;
}

export interface CborTagged {
    tag: number;
    value: CborValue;
}

function isCborTagged(v: CborValue): v is CborTagged {
    return v !== null && typeof v === 'object' && 'tag' in v && 'value' in v && !Array.isArray(v) && !(v instanceof Uint8Array);
}

class CborDecoder {
    private data: Uint8Array;
    private pos: number;

    constructor(data: Uint8Array) {
        this.data = data;
        this.pos = 0;
    }

    decode(): CborValue {
        return this.readValue();
    }

    private readValue(): CborValue {
        const initial = this.data[this.pos++];
        const majorType = initial >> 5;
        const additionalInfo = initial & 0x1f;

        switch (majorType) {
            case 0: return this.readUint(additionalInfo);          // unsigned int
            case 1: return -1 - Number(this.readUint(additionalInfo)); // negative int
            case 2: return this.readBytes(additionalInfo);         // byte string
            case 3: return this.readText(additionalInfo);          // text string
            case 4: return this.readArray(additionalInfo);         // array
            case 5: return this.readMap(additionalInfo);           // map
            case 6: return this.readTag(additionalInfo);           // tag
            case 7: return this.readSimple(additionalInfo);        // simple/float
            default: throw new Error('CBOR: unknown major type ' + majorType);
        }
    }

    private readUint(info: number): number | bigint {
        if (info < 24) return info;
        if (info === 24) return this.data[this.pos++];
        if (info === 25) {
            const v = (this.data[this.pos] << 8) | this.data[this.pos + 1];
            this.pos += 2;
            return v;
        }
        if (info === 26) {
            const v = ((this.data[this.pos] << 24) >>> 0)
                    | (this.data[this.pos + 1] << 16)
                    | (this.data[this.pos + 2] << 8)
                    | this.data[this.pos + 3];
            this.pos += 4;
            return v >>> 0; // ensure unsigned
        }
        if (info === 27) {
            const dv = new DataView(this.data.buffer, this.data.byteOffset + this.pos, 8);
            this.pos += 8;
            const hi = dv.getUint32(0);
            const lo = dv.getUint32(4);
            if (hi === 0) return lo;
            if (hi <= 0x1fffff) return hi * 0x100000000 + lo; // safe integer range
            return (BigInt(hi) << 32n) | BigInt(lo);
        }
        throw new Error('CBOR: unsupported additional info ' + info);
    }

    private readLength(info: number): number {
        const len = this.readUint(info);
        return Number(len);
    }

    private readBytes(info: number): Uint8Array {
        const len = this.readLength(info);
        const bytes = this.data.slice(this.pos, this.pos + len);
        this.pos += len;
        return bytes;
    }

    private readText(info: number): string {
        const bytes = this.readBytes(info);
        return new TextDecoder().decode(bytes);
    }

    private readArray(info: number): CborValue[] {
        const len = this.readLength(info);
        const arr: CborValue[] = [];
        for (let i = 0; i < len; i++) arr.push(this.readValue());
        return arr;
    }

    private readMap(info: number): CborMap {
        const len = this.readLength(info);
        const map: CborMap = {};
        for (let i = 0; i < len; i++) {
            const key = this.readValue();
            const val = this.readValue();
            map[String(key)] = val;
        }
        return map;
    }

    private readTag(info: number): CborValue {
        const tag = Number(this.readUint(info));
        const value = this.readValue();

        // Tag 24 = encoded-cbor: decode the embedded CBOR bytes
        if (tag === 24 && value instanceof Uint8Array) {
            return { tag: 24, value: decodeCbor(value) };
        }

        return { tag, value };
    }

    private readSimple(info: number): boolean | null | number {
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        if (info === 23) return null; // undefined → null
        if (info === 25) {
            // float16
            const dv = new DataView(this.data.buffer, this.data.byteOffset + this.pos, 2);
            this.pos += 2;
            return this.decodeFloat16(dv.getUint16(0));
        }
        if (info === 26) {
            const dv = new DataView(this.data.buffer, this.data.byteOffset + this.pos, 4);
            this.pos += 4;
            return dv.getFloat32(0);
        }
        if (info === 27) {
            const dv = new DataView(this.data.buffer, this.data.byteOffset + this.pos, 8);
            this.pos += 8;
            return dv.getFloat64(0);
        }
        return info; // other simple values
    }

    private decodeFloat16(half: number): number {
        const exp = (half >> 10) & 0x1f;
        const mant = half & 0x3ff;
        const sign = half & 0x8000 ? -1 : 1;
        if (exp === 0) return sign * 5.960464477539063e-8 * mant; // subnormal
        if (exp === 31) return mant === 0 ? sign * Infinity : NaN;
        return sign * Math.pow(2, exp - 15) * (1 + mant / 1024);
    }
}

/** Decode a CBOR byte array into a JavaScript value. */
export function decodeCbor(data: Uint8Array): CborValue {
    return new CborDecoder(data).decode();
}

/** Type guard for CborTagged values. */
export { isCborTagged };
