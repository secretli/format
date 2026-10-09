import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { base64UrlDecode, base64UrlEncode } from "./base64.js";
import { padme } from "./padme.js";

export interface EncodedKeySet {
  readonly shareSecret: string;
  readonly publicID: string;
  readonly metadataToken: string;
  readonly blobToken: string;
  readonly deletionToken: string;
}

/**
 * The metadata envelope: what anyone with the link can read. The files'
 * names are only in the bundle; envelopes written before bundle version 3
 * also carry bundle_name, which readers ignore.
 */
export interface SecretMeta {
  readonly type: "text" | "bundle";
  readonly password_protected: boolean;
}

const ENVELOPE_VERSION = "v2";
const DERIVATION_VERSION = "v1";
const DERIVATION_PREFIX = `secretli:derivation:${DERIVATION_VERSION}`;
const V2_NONCE_LENGTH = 24;
const POLY1305_TAG_LENGTH = 16;

/** Nonce plus Poly1305 tag stored alongside every version 2 bundle record. */
export const BUNDLE_RECORD_OVERHEAD_BYTES = V2_NONCE_LENGTH + POLY1305_TAG_LENGTH;
export const SHARE_SECRET_LENGTH = 32;
/** The random prefix in front of a bundle, which every chunk's nonce begins with. */
export const BUNDLE_PREFIX_LENGTH = 16;
/** What a bundle chunk adds to its plaintext: the Poly1305 tag. The nonce is not stored. */
export const BUNDLE_CHUNK_OVERHEAD_BYTES = POLY1305_TAG_LENGTH;
/** The envelope's padded plaintext: 512 bytes at least, at most what 8,192 characters hold. */
const META_MIN_PADDED = 512;
const META_MAX_PADDED = 6101;
const STREAM_AAD_SUFFIX = new TextEncoder().encode("stream:v3");

function buildAad(publicID: Uint8Array, purpose: "meta" | "bundle"): Uint8Array {
  const suffix = new TextEncoder().encode(purpose);
  const aad = new Uint8Array(publicID.length + suffix.length);
  aad.set(publicID, 0);
  aad.set(suffix, publicID.length);
  return aad;
}

export class KeySet {
  private readonly shareSecret: Uint8Array;
  private readonly metaKey: Uint8Array;
  private readonly blobKey: Uint8Array;
  private readonly publicID: Uint8Array;
  private readonly metadataToken: Uint8Array;
  private readonly blobToken: Uint8Array;
  private readonly deletionToken: Uint8Array;

  private constructor(
    shareSecret: Uint8Array,
    metaKey: Uint8Array,
    blobKey: Uint8Array,
    publicID: Uint8Array,
    metadataToken: Uint8Array,
    blobToken: Uint8Array,
    deletionToken: Uint8Array,
  ) {
    this.shareSecret = shareSecret;
    this.metaKey = metaKey;
    this.blobKey = blobKey;
    this.publicID = publicID;
    this.metadataToken = metadataToken;
    this.blobToken = blobToken;
    this.deletionToken = deletionToken;
  }

  static async generateRandom(): Promise<KeySet> {
    const shareSecret = crypto.getRandomValues(new Uint8Array(32));
    const deletionToken = crypto.getRandomValues(new Uint8Array(32));
    const baseKeys = deriveBaseKeys(shareSecret);
    const blobKeys = deriveBlobKeys(shareSecret);
    return new KeySet(
      shareSecret,
      baseKeys.metaKey,
      blobKeys.blobKey,
      baseKeys.publicID,
      baseKeys.metadataToken,
      blobKeys.blobToken,
      deletionToken,
    );
  }

  static async fromShareSecret(encoded: string, password?: string): Promise<KeySet> {
    const shareSecretBytes = base64UrlDecode(encoded);
    if (shareSecretBytes.length !== SHARE_SECRET_LENGTH) {
      throw new Error("invalid share secret");
    }
    const baseKeys = deriveBaseKeys(shareSecretBytes);
    const blobMaterial = password
      ? await derivePasswordMaterial(shareSecretBytes, password)
      : shareSecretBytes;
    const blobKeys = deriveBlobKeys(blobMaterial);
    const deletionToken = new Uint8Array(0);
    return new KeySet(
      shareSecretBytes,
      baseKeys.metaKey,
      blobKeys.blobKey,
      baseKeys.publicID,
      baseKeys.metadataToken,
      blobKeys.blobToken,
      deletionToken,
    );
  }

  /**
   * Encrypt a metadata object into the envelope format: v2$base64url(nonce)$base64url(ciphertext).
   * The JSON is padded with spaces, so that the envelope's length says nothing about
   * what it holds (FORMAT.md section 4).
   */
  async encryptMeta(meta: SecretMeta): Promise<string> {
    const nonce = crypto.getRandomValues(new Uint8Array(V2_NONCE_LENGTH));
    const json = new TextEncoder().encode(
      JSON.stringify({ type: meta.type, password_protected: meta.password_protected }),
    );
    const plaintext = new Uint8Array(metaPaddedLength(json.length)).fill(0x20);
    plaintext.set(json, 0);
    const aad = buildAad(this.publicID, "meta");
    const cipher = xchacha20poly1305(this.metaKey, nonce, aad);
    const ciphertext = cipher.encrypt(plaintext);

    return `${ENVELOPE_VERSION}$${base64UrlEncode(nonce)}$${base64UrlEncode(ciphertext)}`;
  }

  /**
   * Decrypt an envelope string back to a metadata object. JSON allows white space after a
   * value, so the padding needs no handling, and an envelope from before it opens alike.
   */
  async decryptMeta(envelope: string): Promise<SecretMeta> {
    const parts = envelope.split("$");
    if (parts.length !== 3) {
      throw new Error("invalid metadata envelope format");
    }

    const version = parts[0];
    const nonce = base64UrlDecode(parts[1]);
    const ciphertext = base64UrlDecode(parts[2]);

    if (version !== ENVELOPE_VERSION || nonce.length !== V2_NONCE_LENGTH) {
      throw new Error("invalid metadata envelope format");
    }

    const aad = buildAad(this.publicID, "meta");
    const cipher = xchacha20poly1305(this.metaKey, nonce, aad);
    const plaintext = cipher.decrypt(ciphertext);

    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  /**
   * Seals chunk `index` of a bundle. The nonce is not stored: it is the bundle's prefix, the
   * index in seven bytes and the last flag, so a chunk opens only in its own place and the
   * last one only as the last (FORMAT.md section 5).
   */
  encryptBundleChunk(
    prefix: Uint8Array,
    index: number,
    last: boolean,
    plaintext: Uint8Array,
  ): Uint8Array {
    const nonce = bundleChunkNonce(prefix, index, last);
    return xchacha20poly1305(this.blobKey, nonce, this.streamAad()).encrypt(plaintext);
  }

  /** Opens a chunk sealed by encryptBundleChunk for the same place. */
  decryptBundleChunk(
    prefix: Uint8Array,
    index: number,
    last: boolean,
    chunk: Uint8Array,
  ): Uint8Array {
    const nonce = bundleChunkNonce(prefix, index, last);
    if (chunk.length < BUNDLE_CHUNK_OVERHEAD_BYTES) {
      throw new Error("invalid bundle chunk");
    }
    return xchacha20poly1305(this.blobKey, nonce, this.streamAad()).decrypt(chunk);
  }

  private streamAad(): Uint8Array {
    return bundleAad(this.publicID, STREAM_AAD_SUFFIX);
  }

  /** Encrypts one version 2 bundle record with a fresh random nonce; the nonce is stored in the record. */
  encryptBundlePart(data: Uint8Array, aadSuffix: Uint8Array): Uint8Array {
    const nonce = crypto.getRandomValues(new Uint8Array(V2_NONCE_LENGTH));
    return this.encryptBundlePartWithNonce(data, aadSuffix, nonce);
  }

  private encryptBundlePartWithNonce(
    data: Uint8Array,
    aadSuffix: Uint8Array,
    nonce: Uint8Array,
  ): Uint8Array {
    const aad = bundleAad(this.publicID, aadSuffix);
    const cipher = xchacha20poly1305(this.blobKey, nonce, aad);
    const ciphertext = cipher.encrypt(data);
    const output = new Uint8Array(nonce.length + ciphertext.length);
    output.set(nonce, 0);
    output.set(ciphertext, nonce.length);
    return output;
  }

  decryptBundlePart(record: Uint8Array, aadSuffix: Uint8Array): Uint8Array {
    if (record.length < V2_NONCE_LENGTH + POLY1305_TAG_LENGTH) {
      throw new Error("invalid bundle record");
    }
    const nonce = record.slice(0, V2_NONCE_LENGTH);
    const ciphertext = record.slice(V2_NONCE_LENGTH);
    const aad = bundleAad(this.publicID, aadSuffix);
    const cipher = xchacha20poly1305(this.blobKey, nonce, aad);
    return cipher.decrypt(ciphertext);
  }

  getEncoded(): EncodedKeySet {
    return {
      shareSecret: base64UrlEncode(this.shareSecret),
      publicID: base64UrlEncode(this.publicID),
      metadataToken: base64UrlEncode(this.metadataToken),
      blobToken: base64UrlEncode(this.blobToken),
      deletionToken: base64UrlEncode(this.deletionToken),
    };
  }
}

/**
 * The nonce of a bundle chunk: prefix (16 bytes) | index (7 bytes, big-endian) | last (1 byte).
 */
export function bundleChunkNonce(prefix: Uint8Array, index: number, last: boolean): Uint8Array {
  if (prefix.length !== BUNDLE_PREFIX_LENGTH) {
    throw new Error("bundle prefix must be 16 bytes");
  }
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new Error("chunk index out of range");
  }
  const nonce = new Uint8Array(V2_NONCE_LENGTH);
  nonce.set(prefix, 0);
  let rest = index;
  for (let i = V2_NONCE_LENGTH - 2; i >= BUNDLE_PREFIX_LENGTH; i--) {
    nonce[i] = rest % 256;
    rest = Math.floor(rest / 256);
  }
  nonce[V2_NONCE_LENGTH - 1] = last ? 1 : 0;
  return nonce;
}

/**
 * How long the envelope's plaintext is for JSON of n bytes: max(512, padme(n)), but no
 * more than 6,101 bytes, and JSON longer than that is not padded.
 */
function metaPaddedLength(n: number): number {
  if (n > META_MAX_PADDED) {
    return n;
  }
  return Math.min(META_MAX_PADDED, Math.max(META_MIN_PADDED, padme(n)));
}

function bundleAad(publicID: Uint8Array, suffix: Uint8Array): Uint8Array {
  const prefix = buildAad(publicID, "bundle");
  const aad = new Uint8Array(prefix.length + 1 + suffix.length);
  aad.set(prefix, 0);
  aad[prefix.length] = 0;
  aad.set(suffix, prefix.length + 1);
  return aad;
}

const encoder = new TextEncoder();

function deriveBaseKeys(keyBytes: Uint8Array): {
  metaKey: Uint8Array;
  publicID: Uint8Array;
  metadataToken: Uint8Array;
} {
  const metaKey = hkdf(sha512, keyBytes, undefined, label("meta_key"), 32);
  const publicID = hkdf(sha512, keyBytes, undefined, label("public_id"), 16);
  const metadataToken = hkdf(sha512, keyBytes, undefined, label("metadata_token"), 32);
  return { metaKey, publicID, metadataToken };
}

function deriveBlobKeys(keyBytes: Uint8Array): {
  blobKey: Uint8Array;
  blobToken: Uint8Array;
} {
  const blobKey = hkdf(sha512, keyBytes, undefined, label("blob_key"), 32);
  const blobToken = hkdf(sha512, keyBytes, undefined, label("blob_token"), 32);
  return { blobKey, blobToken };
}

/**
 * scrypt, yielding to the browser every few milliseconds so the page keeps
 * rendering (spinners, input) while the key is derived. The output is the
 * same as the synchronous function's.
 */
function derivePasswordMaterial(shareSecret: Uint8Array, password: string): Promise<Uint8Array> {
  return scryptAsync(new TextEncoder().encode(password), passwordSalt(shareSecret), {
    N: 2 ** 14,
    r: 8,
    p: 1,
    dkLen: 32,
  });
}

function passwordSalt(shareSecret: Uint8Array): Uint8Array {
  return hkdf(sha512, shareSecret, undefined, label("password_salt"), 32);
}

function label(name: string): Uint8Array {
  return encoder.encode(`${DERIVATION_PREFIX}:${name}`);
}
