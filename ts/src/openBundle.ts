import {
  type BundleRangeFetcher,
  MAX_BUNDLE_COALESCED_PLAINTEXT_BYTES,
  SMALL_BUNDLE_CACHE_BYTES,
} from "./bundle.js";
import { BUNDLE_CHUNK_OVERHEAD_BYTES, BUNDLE_PREFIX_LENGTH, type KeySet } from "./encryption.js";
import {
  BUNDLE_PIECE_SIZE,
  type BundleEntry,
  MAX_BUNDLE_LIST_BYTES,
  SEALED_BUNDLE_CHUNK_SIZE,
} from "./stream.js";

/**
 * When files are read together, chunks less than this far apart are fetched in one request,
 * the chunks between included.
 */
export const BUNDLE_GAP_BYTES = 1024 * 1024;

const LIST_LENGTH_BYTES = 4;
const MIN_LIST_BYTES = 2;
/** The list is UTF-8 without a byte order mark: one makes it invalid JSON, as it does in Go. */
const listDecoder = new TextDecoder("utf-8", { ignoreBOM: true });

export interface DecryptFilesOptions {
  /**
   * The most plaintext one request fetches; MAX_BUNDLE_COALESCED_PLAINTEXT_BYTES unless set.
   * Downloading everything may take DOWNLOAD_ALL_BUNDLE_COALESCED_PLAINTEXT_BYTES.
   */
  readonly maxCoalescedPlaintextBytes?: number;
  /** Told after every request how much of the selection's plaintext has been decrypted. */
  readonly onProgress?: (progress: {
    readonly decryptedBytes: number;
    readonly totalBytes: number;
  }) => void;
}

export interface DecryptedEntry {
  readonly entry: BundleEntry;
  readonly blob: Blob;
}

/** An opened bundle: its files, and what reading them takes. */
export interface OpenedBundle {
  /** The files in bundle order. */
  readonly files: readonly BundleEntry[];
  /** The plaintext size of every file together. */
  readonly totalSize: number;
  /**
   * Decrypts the files at these indices, all of them when indices is undefined, into one
   * Blob each, in bundle order. Neighbouring chunks are fetched in one request, also across
   * gaps of less than BUNDLE_GAP_BYTES, and every chunk is decrypted once however many files
   * share it (FORMAT.md section 8).
   */
  decryptFiles(
    indices?: readonly number[],
    options?: DecryptFilesOptions,
  ): Promise<DecryptedEntry[]>;
  /** Decrypts one file. */
  decryptFile(index: number, options?: DecryptFilesOptions): Promise<Blob>;
}

/**
 * Reads a bundle's file list (FORMAT.md sections 5 and 6). A bundle of at most
 * SMALL_BUNDLE_CACHE_BYTES is fetched whole, in one request that serves everything after it.
 * Of a larger one, the first SMALL_BUNDLE_CACHE_BYTES are fetched and, if the list goes on,
 * the chunks that hold the rest (section 8). The list is checked before the bundle is
 * returned. A size that cannot be a prefix and chunks is refused before anything is fetched.
 */
export async function openBundle(
  fetchRange: BundleRangeFetcher,
  keySet: KeySet,
  size: number,
): Promise<OpenedBundle> {
  if (!Number.isSafeInteger(size) || !validStreamSize(size)) {
    throw new Error("invalid bundle size");
  }
  // A small bundle is fetched whole: then every chunk is in the head, and reading files makes
  // no further request.
  const head = await fetchExact(fetchRange, 0, Math.min(size, SMALL_BUNDLE_CACHE_BYTES));
  return openStream(fetchRange, keySet, size, head);
}

/** The state of an opened bundle. */
interface Stream {
  readonly fetch: BundleRangeFetcher;
  readonly keySet: KeySet;
  readonly size: number;
  readonly prefix: Uint8Array;
  readonly chunks: number;
  readonly files: readonly BundleEntry[];
  readonly starts: readonly number[];
  /** The start of the bundle as it was fetched while opening, the whole of a small one. */
  readonly head: Uint8Array;
  /** The chunks complete in head: reading them again costs no request. */
  readonly headChunks: number;
}

/** Reads the file list from the head, the start of the bundle as it was fetched. */
async function openStream(
  fetch: BundleRangeFetcher,
  keySet: KeySet,
  size: number,
  fetched: Uint8Array,
): Promise<OpenedBundle> {
  const chunks = Math.ceil((size - BUNDLE_PREFIX_LENGTH) / SEALED_BUNDLE_CHUNK_SIZE);
  let head = fetched;
  const prefix = head.slice(0, BUNDLE_PREFIX_LENGTH);
  const completeChunks = (n: number) =>
    n >= size
      ? chunks
      : Math.min(
          chunks,
          Math.max(0, Math.floor((n - BUNDLE_PREFIX_LENGTH) / SEALED_BUNDLE_CHUNK_SIZE)),
        );
  let headChunks = completeChunks(head.length);
  const stream = size - BUNDLE_PREFIX_LENGTH - chunks * BUNDLE_CHUNK_OVERHEAD_BYTES;
  const openHeadChunk = (index: number) =>
    keySet.decryptBundleChunk(
      prefix,
      index,
      index === chunks - 1,
      head.subarray(chunkStart(index), chunkEnd(index, size)),
    );

  const first = openHeadChunk(0);
  if (first.length < LIST_LENGTH_BYTES) {
    throw new Error("invalid bundle file list");
  }
  const listLength = new DataView(first.buffer, first.byteOffset, LIST_LENGTH_BYTES).getUint32(
    0,
    false,
  );
  const listEnd = LIST_LENGTH_BYTES + listLength;
  if (listLength < MIN_LIST_BYTES || listLength > MAX_BUNDLE_LIST_BYTES || listEnd > stream) {
    throw new Error("invalid bundle file list");
  }
  const lastListChunk = Math.floor((listEnd - 1) / BUNDLE_PIECE_SIZE);
  if (lastListChunk >= headChunks) {
    // The list goes on past what was fetched: fetch on to the end of its last chunk, and
    // keep that too.
    const more = await fetchExact(fetch, head.length, chunkEnd(lastListChunk, size));
    const longer = new Uint8Array(head.length + more.length);
    longer.set(head, 0);
    longer.set(more, head.length);
    head = longer;
    headChunks = lastListChunk + 1;
  }
  const list = new Uint8Array(listEnd);
  for (let i = 0; i <= lastListChunk; i++) {
    const plaintext = i === 0 ? first : openHeadChunk(i);
    const offset = i * BUNDLE_PIECE_SIZE;
    list.set(plaintext.subarray(0, Math.min(plaintext.length, listEnd - offset)), offset);
  }
  const { files, starts } = parseList(list.subarray(LIST_LENGTH_BYTES), stream);
  const state: Stream = { fetch, keySet, size, prefix, chunks, files, starts, head, headChunks };
  const decryptFiles = (indices?: readonly number[], options: DecryptFilesOptions = {}) =>
    decryptStreamFiles(state, selection(indices, files.length), options);
  return {
    files,
    totalSize: totalOf(files),
    decryptFiles,
    decryptFile: async (index, options) => (await decryptFiles([index], options))[0].blob,
  };
}

/** Whether size can be a prefix and chunks whose last one holds plaintext. */
function validStreamSize(size: number): boolean {
  if (size <= BUNDLE_PREFIX_LENGTH + BUNDLE_CHUNK_OVERHEAD_BYTES) {
    return false;
  }
  const chunks = Math.ceil((size - BUNDLE_PREFIX_LENGTH) / SEALED_BUNDLE_CHUNK_SIZE);
  return (
    size - BUNDLE_PREFIX_LENGTH - SEALED_BUNDLE_CHUNK_SIZE * (chunks - 1) >
    BUNDLE_CHUNK_OVERHEAD_BYTES
  );
}

function chunkStart(index: number): number {
  return BUNDLE_PREFIX_LENGTH + index * SEALED_BUNDLE_CHUNK_SIZE;
}

/** Where chunk index ends, exclusive. */
function chunkEnd(index: number, size: number): number {
  return Math.min(chunkStart(index + 1), size);
}

/** Checks the file list (FORMAT.md section 6) and works out where each file starts. */
function parseList(raw: Uint8Array, stream: number): { files: BundleEntry[]; starts: number[] } {
  let list: unknown;
  try {
    list = JSON.parse(listDecoder.decode(raw));
  } catch {
    throw new Error("invalid bundle file list");
  }
  if (typeof list !== "object" || list === null || Array.isArray(list)) {
    throw new Error("invalid bundle file list");
  }
  const listed = (list as { files?: unknown }).files;
  if (!Array.isArray(listed) || listed.length === 0) {
    throw new Error("invalid bundle file list");
  }
  let position = LIST_LENGTH_BYTES + raw.length;
  let remaining = stream - position;
  const files: BundleEntry[] = [];
  const starts: number[] = [];
  for (const [index, file] of listed.entries()) {
    if (typeof file !== "object" || file === null) {
      throw new Error("invalid bundle file list");
    }
    const { name, type, size } = file as Record<string, unknown>;
    if (
      typeof name !== "string" ||
      name === "" ||
      typeof type !== "string" ||
      typeof size !== "number" ||
      !Number.isSafeInteger(size) ||
      size < 0
    ) {
      throw new Error("invalid bundle file list");
    }
    // Checked before adding: a sum past 2^53 would lose precision.
    if (size > remaining) {
      throw new Error("invalid bundle file list");
    }
    // -0 is an integer too; keep it from showing.
    const exact = size === 0 ? 0 : size;
    files.push({ index, name, type, size: exact });
    starts.push(position);
    position += exact;
    remaining -= exact;
  }
  return { files, starts };
}

/** A run of chunks, both ends included. */
interface Span {
  first: number;
  last: number;
}

/**
 * Plans requests over the needed chunks: one request takes up to maxChunks chunks, and goes
 * on across fewer than BUNDLE_GAP_BYTES of chunks that are not needed.
 */
function coalesceChunkRuns(needed: readonly Span[], maxChunks: number): Span[] {
  const requests: Span[] = [];
  for (const run of needed) {
    for (let next = run.first; next <= run.last; ) {
      const previous = requests.at(-1);
      if (
        previous &&
        (next - previous.last - 1) * SEALED_BUNDLE_CHUNK_SIZE < BUNDLE_GAP_BYTES &&
        next - previous.first < maxChunks
      ) {
        previous.last = Math.min(run.last, previous.first + maxChunks - 1);
        next = previous.last + 1;
        continue;
      }
      const last = Math.min(run.last, next + maxChunks - 1);
      requests.push({ first: next, last });
      next = last + 1;
    }
  }
  return requests;
}

async function decryptStreamFiles(
  state: Stream,
  selected: readonly number[],
  options: DecryptFilesOptions,
): Promise<DecryptedEntry[]> {
  const { files, starts, headChunks } = state;
  const maxPlaintext = options.maxCoalescedPlaintextBytes ?? MAX_BUNDLE_COALESCED_PLAINTEXT_BYTES;
  const maxChunks = Math.max(1, Math.floor(maxPlaintext / BUNDLE_PIECE_SIZE));

  // The chunks the selection needs beyond the head, merged where they touch or overlap.
  const needed: Span[] = [];
  for (const i of selected) {
    if (files[i].size === 0) continue;
    const first = Math.max(Math.floor(starts[i] / BUNDLE_PIECE_SIZE), headChunks);
    const last = Math.floor((starts[i] + files[i].size - 1) / BUNDLE_PIECE_SIZE);
    if (first > last) continue;
    const previous = needed.at(-1);
    if (previous && first <= previous.last + 1) {
      previous.last = Math.max(previous.last, last);
      continue;
    }
    needed.push({ first, last });
  }
  const requests = coalesceChunkRuns(needed, maxChunks);

  // Each file grows into one Blob, extended after every request. Browsers can page Blob
  // storage to disk, whereas holding every decrypted ArrayBuffer until the end keeps the
  // whole download in the JS heap and kills the tab for gigabyte bundles.
  const blobs = selected.map(
    (i) => new Blob([], { type: files[i].type || "application/octet-stream" }),
  );
  let pending: Uint8Array[][] = selected.map(() => []);
  const totalBytes = selected.reduce((sum, i) => sum + files[i].size, 0);
  let decryptedBytes = 0;
  let reported = -1;
  const flush = (final: boolean) => {
    for (const [slot, parts] of pending.entries()) {
      if (parts.length > 0) {
        blobs[slot] = new Blob([blobs[slot], ...parts.map(toArrayBuffer)], {
          type: blobs[slot].type,
        });
      }
    }
    pending = selected.map(() => []);
    if (final || decryptedBytes !== reported) {
      reported = decryptedBytes;
      options.onProgress?.({ decryptedBytes, totalBytes });
    }
  };

  // Chunks come in order, from the head or from the planned requests; the last one stays
  // decrypted, since the next file may start in it.
  let request = 0;
  let sealed: Uint8Array | undefined;
  let openIndex = -1;
  let opened: Uint8Array = new Uint8Array(0);
  const chunk = async (index: number): Promise<Uint8Array> => {
    if (index === openIndex) {
      return opened;
    }
    let bytes: Uint8Array;
    if (index < headChunks) {
      bytes = state.head.subarray(chunkStart(index), chunkEnd(index, state.size));
    } else {
      while (request < requests.length && requests[request].last < index) {
        request++;
        sealed = undefined;
      }
      const planned = requests[request];
      if (!planned || planned.first > index) {
        throw new Error("bundle chunk was not planned");
      }
      if (!sealed) {
        if (decryptedBytes > 0) flush(false);
        sealed = await fetchExact(
          state.fetch,
          chunkStart(planned.first),
          chunkEnd(planned.last, state.size),
        );
      }
      const offset = chunkStart(index) - chunkStart(planned.first);
      bytes = sealed.subarray(offset, offset + chunkEnd(index, state.size) - chunkStart(index));
    }
    opened = state.keySet.decryptBundleChunk(
      state.prefix,
      index,
      index === state.chunks - 1,
      bytes,
    );
    openIndex = index;
    return opened;
  };

  for (const [slot, i] of selected.entries()) {
    const start = starts[i];
    const end = start + files[i].size;
    for (let position = start; position < end; ) {
      const index = Math.floor(position / BUNDLE_PIECE_SIZE);
      const plaintext = await chunk(index);
      const from = position - index * BUNDLE_PIECE_SIZE;
      const to = Math.min(plaintext.length, end - index * BUNDLE_PIECE_SIZE);
      if (from >= to) {
        throw new Error("invalid bundle file list");
      }
      pending[slot].push(plaintext.subarray(from, to));
      position += to - from;
      decryptedBytes += to - from;
    }
  }
  flush(true);
  return selected.map((i, slot) => ({ entry: files[i], blob: blobs[slot] }));
}

/** Sorts the indices and drops repeats; undefined selects every file. */
function selection(indices: readonly number[] | undefined, count: number): number[] {
  if (indices === undefined) {
    return Array.from({ length: count }, (_, i) => i);
  }
  const selected = [...new Set(indices)].sort((a, b) => a - b);
  for (const i of selected) {
    if (!Number.isInteger(i) || i < 0 || i >= count) {
      throw new Error(`bundle has no file ${i}`);
    }
  }
  return selected;
}

function totalOf(files: readonly BundleEntry[]): number {
  return files.reduce((sum, file) => sum + file.size, 0);
}

/** Fetches the bytes from start up to end, end excluded, and checks it got that many. */
async function fetchExact(
  fetch: BundleRangeFetcher,
  start: number,
  end: number,
): Promise<Uint8Array> {
  const bytes = await fetch(start, end - 1);
  if (bytes.length !== end - start) {
    throw new Error("bundle range size mismatch");
  }
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
