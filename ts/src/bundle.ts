import { padme } from "./padme.js";

export { padme };

/** The most plaintext one request fetches when reading, unless told otherwise. */
export const MAX_BUNDLE_COALESCED_PLAINTEXT_BYTES = 16 * 1024 * 1024;
/** What a reader may fetch per request when it downloads every file of a bundle. */
export const DOWNLOAD_ALL_BUNDLE_COALESCED_PLAINTEXT_BYTES = 64 * 1024 * 1024;
/**
 * Bundles at or below this size are fetched in one request and served from memory. Without
 * it, reading a short text secret costs several round trips for a few hundred bytes. Of a
 * larger bundle, openBundle fetches this much first.
 */
export const SMALL_BUNDLE_CACHE_BYTES = 1024 * 1024;
/** The size writers pad the smallest streams to, so that every short note looks the same. */
export const MIN_PADDED_BUNDLE_SIZE = 4096;

/** Reads the bundle bytes from start to end, both inclusive. */
export type BundleRangeFetcher = (start: number, end: number) => Promise<Uint8Array>;

/**
 * The size writers pad a stream of this size to: Padmé rounding, and never less than 4,096
 * bytes.
 */
export function paddedBundleSize(size: number): number {
  return Math.max(MIN_PADDED_BUNDLE_SIZE, padme(size));
}

/** The lower-case hex SHA-256 the API takes for upload parts. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
