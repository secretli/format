import type { BundleRangeFetcher } from "../src/bundle";
import type { KeySet } from "../src/encryption";
import { BUNDLE_PIECE_SIZE } from "../src/stream";

/** xorshift32 bytes: varied content without storing it. */
export function xorshift32(seed: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let x = seed >>> 0;
  for (let i = 0; i < length; i++) {
    x = (x ^ (x << 13)) >>> 0;
    x = (x ^ (x >>> 17)) >>> 0;
    x = (x ^ (x << 5)) >>> 0;
    out[i] = x & 0xff;
  }
  return out;
}

/** A File takes an ArrayBuffer; a Uint8Array over a shared buffer would not do. */
export function fileOf(bytes: Uint8Array, name: string, type = ""): File {
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  return new File([buffer as ArrayBuffer], name, { type });
}

export const fixedPrefix = () => Uint8Array.from({ length: 16 }, (_, i) => 0xf0 - i);

export async function blobBytes(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

/** A fetcher over bytes in memory that remembers every range it was asked for. */
export function countingFetcher(bytes: Uint8Array): {
  fetch: BundleRangeFetcher;
  ranges: Array<[number, number]>;
} {
  const ranges: Array<[number, number]> = [];
  return {
    ranges,
    fetch: async (start, end) => {
      ranges.push([start, end]);
      if (start < 0 || end >= bytes.length || end < start) {
        throw new Error("bundle range size mismatch");
      }
      return bytes.slice(start, end + 1);
    },
  };
}

/** Seals any stream plaintext as a bundle, so tests can make lists no writer would. */
export function sealStream(keySet: KeySet, stream: Uint8Array): Uint8Array {
  const prefix = fixedPrefix();
  const chunks = Math.ceil(stream.length / BUNDLE_PIECE_SIZE);
  const parts: Uint8Array[] = [prefix];
  for (let i = 0; i < chunks; i++) {
    const piece = stream.subarray(i * BUNDLE_PIECE_SIZE, (i + 1) * BUNDLE_PIECE_SIZE);
    parts.push(keySet.encryptBundleChunk(prefix, i, i === chunks - 1, piece));
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** A stream holding this list, these contents, and zeros up to length. */
export function streamOf(list: string, contents: Uint8Array, length: number): Uint8Array {
  const listBytes = new TextEncoder().encode(list);
  const stream = new Uint8Array(length);
  new DataView(stream.buffer).setUint32(0, listBytes.length, false);
  stream.set(listBytes, 4);
  stream.set(contents, 4 + listBytes.length);
  return stream;
}
