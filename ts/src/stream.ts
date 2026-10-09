import { MIN_PADDED_BUNDLE_SIZE } from "./bundle.js";
import { BUNDLE_CHUNK_OVERHEAD_BYTES, BUNDLE_PREFIX_LENGTH, type KeySet } from "./encryption.js";
import { padme } from "./padme.js";

/** The plaintext of every chunk of a bundle but the last. */
export const BUNDLE_PIECE_SIZE = 64 * 1024;
/** The size of every chunk of a bundle but the last. */
export const SEALED_BUNDLE_CHUNK_SIZE = BUNDLE_PIECE_SIZE + BUNDLE_CHUNK_OVERHEAD_BYTES;
/** The file list's cap: 4 MiB hold tens of thousands of files. */
export const MAX_BUNDLE_LIST_BYTES = 4 * 1024 * 1024;
/** How much of a file encryptStream reads at once unless told otherwise. */
export const BUNDLE_READ_BYTES = 4 * 1024 * 1024;

const LIST_LENGTH_BYTES = 4;
const DEFAULT_TYPE = "application/octet-stream";
const textEncoder = new TextEncoder();

/** A file to plan a bundle for: a File will do, its content is not read. */
export interface BundleFileInput {
  readonly name: string;
  /** The MIME type; empty or absent is application/octet-stream. */
  readonly type?: string;
  readonly size: number;
}

/** One file of a bundle as a reader sees it. */
export interface BundleEntry {
  /** The file's position in the bundle. */
  readonly index: number;
  readonly name: string;
  /** The MIME type, application/octet-stream when it is unknown. */
  readonly type: string;
  readonly size: number;
}

/**
 * The layout of a bundle, worked out from the files' names, types and sizes before a byte
 * of content is read (FORMAT.md section 9).
 */
export interface StreamPlan {
  /** The file list as it is encrypted: lone surrogates replaced, empty types defaulted. */
  readonly files: readonly BundleEntry[];
  /** The file list exactly as it is encrypted, as UTF-8 (FORMAT.md section 6). */
  readonly listBytes: Uint8Array;
  /** Where each file's bytes begin in the stream. */
  readonly starts: readonly number[];
  /** The stream before its padding: the list's length, the list and the files. */
  readonly contentLength: number;
  /** The padded stream, max(4096, padme(contentLength)). */
  readonly streamLength: number;
  /** How many chunks the stream is sealed in. */
  readonly chunks: number;
  /** The size of the bundle, declared to the server. */
  readonly totalSize: number;
}

export interface EncryptStreamOptions {
  /**
   * The bundle's prefix instead of a freshly drawn one. With it fixed nothing in a bundle
   * is random, which the vectors need (FORMAT.md section 10). Leave it unset otherwise:
   * the same prefix for two bundles under the same keys breaks the encryption.
   */
  readonly prefix?: Uint8Array;
  /** How much of a file is read at once; BUNDLE_READ_BYTES unless set. */
  readonly readBytes?: number;
}

/**
 * Lays out a bundle of these files. It reads only their names, types and sizes, so the
 * exact size is known before anything is encrypted.
 */
export function planStream(files: readonly BundleFileInput[]): StreamPlan {
  if (files.length === 0) {
    throw new Error("bundle must contain at least one file");
  }
  let content = 0;
  const entries = files.map((file, index): BundleEntry => {
    if (typeof file.name !== "string" || file.name === "") {
      throw new Error("bundle file needs a name");
    }
    if (
      !Number.isSafeInteger(file.size) ||
      file.size < 0 ||
      content > Number.MAX_SAFE_INTEGER - file.size
    ) {
      throw new Error("invalid bundle file size");
    }
    content += file.size;
    return {
      index,
      name: wellFormed(file.name),
      type: wellFormed(file.type || DEFAULT_TYPE),
      size: file.size,
    };
  });
  // JSON.stringify is the reference encoding: compact, keys in this order.
  const listBytes = textEncoder.encode(
    JSON.stringify({ files: entries.map(({ name, type, size }) => ({ name, type, size })) }),
  );
  if (listBytes.length > MAX_BUNDLE_LIST_BYTES) {
    throw new Error("bundle file list is too large");
  }
  const starts: number[] = [];
  let position = LIST_LENGTH_BYTES + listBytes.length;
  for (const entry of entries) {
    starts.push(position);
    position += entry.size;
  }
  // Positions past 2^53 − 1 would not be exact.
  const streamLength = Number.isSafeInteger(position)
    ? Math.max(MIN_PADDED_BUNDLE_SIZE, padme(position))
    : Number.POSITIVE_INFINITY;
  const chunks = Math.ceil(streamLength / BUNDLE_PIECE_SIZE);
  const totalSize = BUNDLE_PREFIX_LENGTH + streamLength + chunks * BUNDLE_CHUNK_OVERHEAD_BYTES;
  if (!Number.isSafeInteger(totalSize)) {
    throw new Error("invalid bundle file size");
  }
  return {
    files: entries,
    listBytes,
    starts,
    contentLength: position,
    streamLength,
    chunks,
    totalSize,
  };
}

/**
 * The exact size of the bundle these files make, padding included, to check against the
 * upload limit before anything is read. Throws as planStream does.
 */
export function plannedBundleSize(files: readonly BundleFileInput[]): number {
  return planStream(files).totalSize;
}

/**
 * The bundle as a stream of bytes: the prefix, then each chunk in order, encrypted only
 * when it is asked for. Files are read in slices of options.readBytes, so a bundle of any
 * size streams in little memory; cutIntoParts makes upload parts of it.
 */
export async function* encryptStream(
  plan: StreamPlan,
  files: readonly Blob[],
  keySet: KeySet,
  options: EncryptStreamOptions = {},
): AsyncGenerator<Uint8Array> {
  if (files.length !== plan.files.length || files.some((f, i) => f.size !== plan.files[i].size)) {
    throw new Error("bundle files do not match the plan");
  }
  const prefix = options.prefix ?? crypto.getRandomValues(new Uint8Array(BUNDLE_PREFIX_LENGTH));
  if (prefix.length !== BUNDLE_PREFIX_LENGTH) {
    throw new Error("bundle prefix must be 16 bytes");
  }
  const readBytes = options.readBytes ?? BUNDLE_READ_BYTES;
  if (!Number.isSafeInteger(readBytes) || readBytes <= 0) {
    throw new Error("invalid read size");
  }
  yield prefix.slice();

  let index = 0;
  const seal = (piece: Uint8Array) =>
    keySet.encryptBundleChunk(prefix, index, index === plan.chunks - 1, piece);
  const piece = new Uint8Array(BUNDLE_PIECE_SIZE);
  let filled = 0;
  for await (const segment of streamContent(plan, files, readBytes)) {
    let offset = 0;
    while (offset < segment.length) {
      if (filled === 0 && segment.length - offset >= BUNDLE_PIECE_SIZE) {
        // A whole piece in what was read: no need to copy it first.
        yield seal(segment.subarray(offset, offset + BUNDLE_PIECE_SIZE));
        index++;
        offset += BUNDLE_PIECE_SIZE;
        continue;
      }
      const n = Math.min(BUNDLE_PIECE_SIZE - filled, segment.length - offset);
      piece.set(segment.subarray(offset, offset + n), filled);
      filled += n;
      offset += n;
      if (filled === BUNDLE_PIECE_SIZE) {
        yield seal(piece);
        index++;
        filled = 0;
      }
    }
  }
  // Zeros after the last file, up to the padded length.
  let padding = plan.streamLength - plan.contentLength;
  while (padding > 0) {
    const n = Math.min(BUNDLE_PIECE_SIZE - filled, padding);
    piece.fill(0, filled, filled + n);
    filled += n;
    padding -= n;
    if (filled === BUNDLE_PIECE_SIZE) {
      yield seal(piece);
      index++;
      filled = 0;
    }
  }
  if (filled > 0) {
    yield seal(piece.subarray(0, filled));
    index++;
  }
  if (index !== plan.chunks) {
    throw new Error("bundle size mismatch");
  }
}

/** The stream before its padding: the list's length, the list, and the files' bytes. */
async function* streamContent(
  plan: StreamPlan,
  files: readonly Blob[],
  readBytes: number,
): AsyncGenerator<Uint8Array> {
  const header = new Uint8Array(LIST_LENGTH_BYTES + plan.listBytes.length);
  new DataView(header.buffer).setUint32(0, plan.listBytes.length, false);
  header.set(plan.listBytes, LIST_LENGTH_BYTES);
  yield header;
  for (const [i, file] of files.entries()) {
    const size = plan.files[i].size;
    for (let start = 0; start < size; start += readBytes) {
      const end = Math.min(start + readBytes, size);
      const bytes = new Uint8Array(await file.slice(start, end).arrayBuffer());
      if (bytes.length !== end - start) {
        throw new Error("bundle file changed during encryption");
      }
      yield bytes;
    }
  }
}

/**
 * Re-cuts a stream of bytes into parts of exactly partSize bytes, the last one shorter, as
 * uploads at fixed offsets need them (FORMAT.md section 9).
 */
export async function* cutIntoParts(
  stream: AsyncIterable<Uint8Array>,
  partSize: number,
): AsyncGenerator<Uint8Array> {
  if (!Number.isSafeInteger(partSize) || partSize <= 0) {
    throw new Error("invalid part size");
  }
  let pieces: Uint8Array[] = [];
  let filled = 0;
  for await (const bytes of stream) {
    let offset = 0;
    while (offset < bytes.length) {
      const n = Math.min(partSize - filled, bytes.length - offset);
      pieces.push(bytes.subarray(offset, offset + n));
      filled += n;
      offset += n;
      if (filled === partSize) {
        yield concat(pieces, filled);
        pieces = [];
        filled = 0;
      }
    }
  }
  if (filled > 0) {
    yield concat(pieces, filled);
  }
}

/**
 * Builds a whole bundle in memory, with a fresh prefix unless the options fix one. Uploads
 * stream encryptStream in parts instead; this is for small bundles and tests.
 */
export async function createStreamBundle(
  files: readonly File[],
  keySet: KeySet,
  options: EncryptStreamOptions = {},
): Promise<{ blob: Blob; plan: StreamPlan }> {
  const plan = planStream(files);
  const parts: ArrayBuffer[] = [];
  for await (const bytes of encryptStream(plan, files, keySet, options)) {
    parts.push(toArrayBuffer(bytes));
  }
  const blob = new Blob(parts, { type: "application/octet-stream" });
  if (blob.size !== plan.totalSize) {
    throw new Error("bundle size mismatch");
  }
  return { blob, plan };
}

function concat(pieces: readonly Uint8Array[], length: number): Uint8Array {
  const out = new Uint8Array(length);
  let offset = 0;
  for (const piece of pieces) {
    out.set(piece, offset);
    offset += piece.length;
  }
  return out;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/**
 * Replaces lone surrogates with U+FFFD, as String.prototype.toWellFormed does (ES2024):
 * JSON.stringify would escape them instead, and the list must be Unicode text.
 */
function wellFormed(text: string): string {
  let out = "";
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
        continue;
      }
    } else if (unit < 0xdc00 || unit > 0xdfff) {
      continue;
    }
    out += `${text.slice(start, i)}\ufffd`;
    start = i + 1;
  }
  return start === 0 ? text : out + text.slice(start);
}
