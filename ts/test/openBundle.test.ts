import { KeySet } from "../src/encryption";
import { openBundle } from "../src/openBundle";
import {
  BUNDLE_PIECE_SIZE,
  createStreamBundle,
  SEALED_BUNDLE_CHUNK_SIZE,
  type StreamPlan,
} from "../src/stream";
import {
  blobBytes,
  countingFetcher,
  fileOf,
  fixedPrefix,
  sealStream,
  streamOf,
  xorshift32,
} from "./helpers";

const MiB = 1024 * 1024;
const chunkStart = (i: number) => 16 + i * SEALED_BUNDLE_CHUNK_SIZE;
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

async function bundleOf(
  files: File[],
  keySet: KeySet,
): Promise<{ bytes: Uint8Array; plan: StreamPlan }> {
  const { blob, plan } = await createStreamBundle(files, keySet, { prefix: fixedPrefix() });
  return { bytes: await blobBytes(blob), plan };
}

/** Files of these sizes, with varied content. */
function sized(...sizes: number[]): { files: File[]; contents: Uint8Array[] } {
  const contents = sizes.map((size, i) => xorshift32(i + 1, size));
  return { contents, files: contents.map((c, i) => fileOf(c, `file-${i}.bin`)) };
}

// Bundles of a few MiB through pure-JS XChaCha20 both ways: quick locally, slower on CI.
const SLOW = 60_000;

describe("opening a bundle", () => {
  it(
    "fetches a file's chunks together, up to the coalescing limit",
    async () => {
      const keySet = await KeySet.generateRandom();
      const { files, contents } = sized(5 * MiB);
      const { bytes, plan } = await bundleOf(files, keySet);
      const { fetch, ranges } = countingFetcher(bytes);
      const opened = await openBundle(fetch, keySet, bytes.length);
      expect(opened.files).toEqual([
        { index: 0, name: "file-0.bin", type: "application/octet-stream", size: 5 * MiB },
      ]);
      expect(opened.totalSize).toBe(5 * MiB);
      const progress: number[] = [];
      const blob = await opened.decryptFile(0, {
        maxCoalescedPlaintextBytes: MiB,
        onProgress: ({ decryptedBytes, totalBytes }) => {
          expect(totalBytes).toBe(5 * MiB);
          progress.push(decryptedBytes);
        },
      });
      expect(hex(await blobBytes(blob))).toBe(hex(contents[0]));
      // The first MiB with its 15 whole chunks, then the rest of the file's chunks in
      // requests of 16 (1 MiB).
      const lastChunk = Math.floor((plan.contentLength - 1) / BUNDLE_PIECE_SIZE);
      const want: Array<[number, number]> = [[0, MiB - 1]];
      for (let first = 15; first <= lastChunk; first += 16) {
        want.push([chunkStart(first), chunkStart(Math.min(first + 16, lastChunk + 1)) - 1]);
      }
      expect(ranges).toEqual(want);
      expect(progress.at(-1)).toBe(5 * MiB);
      expect(progress).toEqual([...progress].sort((a, b) => a - b));
      // Once for what the first MiB held, then once per request after it.
      expect(progress.length).toBe(want.length);
    },
    SLOW,
  );

  it(
    "reads a selection in one pass, across short gaps",
    async () => {
      const keySet = await KeySet.generateRandom();
      const { files, contents } = sized(3 * MiB, 100, 900 * 1024, 100, 2 * MiB, 100, 0);
      const { bytes, plan } = await bundleOf(files, keySet);
      const { fetch, ranges } = countingFetcher(bytes);
      const opened = await openBundle(fetch, keySet, bytes.length);
      const decrypted = await opened.decryptFiles([5, 1, 3, 6, 1]);
      expect(decrypted.map((d) => d.entry.index)).toEqual([1, 3, 5, 6]);
      for (const { entry, blob } of decrypted) {
        expect(hex(await blobBytes(blob))).toBe(hex(contents[entry.index]));
      }
      const chunkOf = (i: number) => Math.floor(plan.starts[i] / BUNDLE_PIECE_SIZE);
      // Fewer than 16 chunks between the first two (under 1 MiB), more after.
      expect(chunkOf(3) - chunkOf(1) - 1).toBeLessThan(16);
      expect(chunkOf(5) - chunkOf(3) - 1).toBeGreaterThanOrEqual(16);
      expect(ranges).toEqual([
        [0, MiB - 1],
        [chunkStart(chunkOf(1)), chunkStart(chunkOf(3) + 1) - 1],
        [chunkStart(chunkOf(5)), chunkStart(chunkOf(5) + 1) - 1],
      ]);
    },
    SLOW,
  );

  it(
    "fetches across a gap of 15 chunks but not of 16",
    async () => {
      const keySet = await KeySet.generateRandom();
      for (const [gap, requests] of [
        [15, 1],
        [16, 2],
      ]) {
        // A small file at the end of a chunk, the gap, a small file at the start of the next.
        const start = 2 * MiB;
        const first = 10;
        const files = sized(start, first, 0, 10).files;
        const plan0 = (await bundleOf(files, keySet)).plan;
        const toBoundary = BUNDLE_PIECE_SIZE - ((plan0.starts[1] + first) % BUNDLE_PIECE_SIZE);
        const { files: spaced, contents } = sized(
          start,
          first,
          toBoundary + gap * BUNDLE_PIECE_SIZE,
          10,
        );
        const { bytes, plan } = await bundleOf(spaced, keySet);
        const chunkOf = (i: number) => Math.floor(plan.starts[i] / BUNDLE_PIECE_SIZE);
        expect(chunkOf(3) - chunkOf(1) - 1).toBe(gap);
        const { fetch, ranges } = countingFetcher(bytes);
        const opened = await openBundle(fetch, keySet, bytes.length);
        const decrypted = await opened.decryptFiles([1, 3]);
        expect(hex(await blobBytes(decrypted[1].blob))).toBe(hex(contents[3]));
        expect(ranges.length - 1).toBe(requests);
      }
    },
    SLOW,
  );

  it(
    "takes few requests for many small files",
    async () => {
      const keySet = await KeySet.generateRandom();
      const { files, contents } = sized(...Array.from({ length: 10000 }, (_, i) => i % 300));
      const { bytes } = await bundleOf(files, keySet);
      expect(bytes.length).toBeGreaterThan(MiB);
      const { fetch, ranges } = countingFetcher(bytes);
      const opened = await openBundle(fetch, keySet, bytes.length);
      const decrypted = await opened.decryptFiles();
      expect(decrypted.length).toBe(10000);
      for (const i of [0, 1, 299, 5000, 9999]) {
        expect(hex(await blobBytes(decrypted[i].blob))).toBe(hex(contents[i]));
      }
      // The first MiB, and the rest in one request.
      expect(ranges.length).toBe(2);
    },
    SLOW,
  );

  it(
    "fetches the rest of a list longer than the first MiB",
    async () => {
      const keySet = await KeySet.generateRandom();
      const files = Array.from({ length: 20000 }, (_, i) =>
        fileOf(
          new Uint8Array(0),
          `a-rather-long-file-name-${String(i).padStart(5, "0")}.txt`,
          "text/plain",
        ),
      );
      files.push(fileOf(new TextEncoder().encode("the end"), "last.bin"));
      const { bytes, plan } = await bundleOf(files, keySet);
      expect(plan.listBytes.length).toBeGreaterThan(MiB);
      const { fetch, ranges } = countingFetcher(bytes);
      const opened = await openBundle(fetch, keySet, bytes.length);
      const lastListChunk = Math.floor((3 + plan.listBytes.length) / BUNDLE_PIECE_SIZE);
      expect(ranges).toEqual([
        [0, MiB - 1],
        [MiB, chunkStart(lastListChunk + 1) - 1],
      ]);
      expect(opened.files.length).toBe(20001);
      expect(opened.files[12345].name).toBe("a-rather-long-file-name-12345.txt");
      await expect((await opened.decryptFile(20000)).text()).resolves.toBe("the end");
    },
    SLOW,
  );

  it("reads a small bundle with one request", async () => {
    const keySet = await KeySet.generateRandom();
    // More than 64 KiB of list: it spans two chunks.
    const files = Array.from({ length: 1500 }, (_, i) =>
      fileOf(
        new TextEncoder().encode(String(i)),
        `note-${String(i).padStart(4, "0")}.txt`,
        "text/plain",
      ),
    );
    const { bytes, plan } = await bundleOf(files, keySet);
    expect(plan.listBytes.length).toBeGreaterThan(BUNDLE_PIECE_SIZE);
    expect(bytes.length).toBeLessThanOrEqual(MiB);
    const { fetch, ranges } = countingFetcher(bytes);
    const opened = await openBundle(fetch, keySet, bytes.length);
    const decrypted = await opened.decryptFiles();
    await expect(decrypted[1499].blob.text()).resolves.toBe("1499");
    expect(decrypted[1499].blob.type).toBe("text/plain");
    expect(ranges).toEqual([[0, bytes.length - 1]]);
  });
});

describe("a tampered bundle", () => {
  it(
    "does not open",
    async () => {
      const keySet = await KeySet.generateRandom();
      // Four chunks: the list and a file in all of them, a little padding.
      const content = xorshift32(5, 65536 * 3 + 1000);
      const { bytes, plan } = await bundleOf([fileOf(content, "a.bin")], keySet);
      expect(plan.chunks).toBe(4);
      const read = async (data: Uint8Array, size: number, keys: KeySet) => {
        const opened = await openBundle(async (s, e) => data.slice(s, e + 1), keys, size);
        return blobBytes(await opened.decryptFile(0));
      };
      expect(hex(await read(bytes, bytes.length, keySet))).toBe(hex(content));

      const copy = () => bytes.slice();
      const swapped = copy();
      swapped.set(bytes.subarray(chunkStart(2), chunkStart(3)), chunkStart(1));
      swapped.set(bytes.subarray(chunkStart(1), chunkStart(2)), chunkStart(2));
      const duplicated = copy();
      duplicated.set(bytes.subarray(chunkStart(1), chunkStart(2)), chunkStart(2));
      const extended = new Uint8Array(bytes.length + SEALED_BUNDLE_CHUNK_SIZE);
      extended.set(bytes);
      const extendedByOne = new Uint8Array(bytes.length + 1);
      extendedByOne.set(bytes);
      const flipped = (at: number) => {
        const b = copy();
        b[at] ^= 1;
        return b;
      };
      const withPassword = await KeySet.fromShareSecret(keySet.getEncoded().shareSecret, "pw");
      const cases: Array<[string, Promise<unknown>]> = [
        ["swapped chunks", read(swapped, bytes.length, keySet)],
        ["a chunk twice", read(duplicated, bytes.length, keySet)],
        ["cut short by a byte", read(bytes.subarray(0, -1), bytes.length - 1, keySet)],
        ["cut short by a chunk", read(bytes.subarray(0, chunkStart(3)), chunkStart(3), keySet)],
        ["extended by a chunk", read(extended, extended.length, keySet)],
        ["extended by a byte", read(extendedByOne, extendedByOne.length, keySet)],
        ["another secret's keys", read(bytes, bytes.length, await KeySet.generateRandom())],
        ["another blob key", read(bytes, bytes.length, withPassword)],
        ["a flipped prefix bit", read(flipped(0), bytes.length, keySet)],
        ["a flipped content bit", read(flipped(chunkStart(2) + 5), bytes.length, keySet)],
        ["a flipped last-tag bit", read(flipped(bytes.length - 1), bytes.length, keySet)],
      ];
      for (const [name, attempt] of cases) {
        await expect(attempt, name).rejects.toThrow();
      }

      // What comes before a cut is still exactly what was written: the list opens, and the
      // file fails only at the chunk that was cut.
      const shortened = bytes.subarray(0, -10);
      const opened = await openBundle(
        async (s, e) => shortened.slice(s, e + 1),
        keySet,
        shortened.length,
      );
      await expect(opened.decryptFile(0)).rejects.toThrow();
    },
    SLOW,
  );

  it("is refused for sizes no bundle has, before anything is fetched", async () => {
    const keySet = await KeySet.generateRandom();
    for (const size of [
      0,
      1,
      32,
      16 + SEALED_BUNDLE_CHUNK_SIZE + 16,
      16 + SEALED_BUNDLE_CHUNK_SIZE + 10,
    ]) {
      const { fetch, ranges } = countingFetcher(new Uint8Array(size));
      await expect(openBundle(fetch, keySet, size), String(size)).rejects.toThrow(
        "invalid bundle size",
      );
      expect(ranges).toEqual([]);
    }
    const tiny = sealStream(keySet, new Uint8Array([0]));
    await expect(
      openBundle(async (s, e) => tiny.slice(s, e + 1), keySet, tiny.length),
    ).rejects.toThrow("invalid bundle file list");
  });
});

describe("the file list", () => {
  const file = (fields: string) => `{"files":[${fields}]}`;

  async function open(stream: Uint8Array, keySet: KeySet) {
    const bytes = sealStream(keySet, stream);
    return openBundle(async (s, e) => bytes.slice(s, e + 1), keySet, bytes.length);
  }

  it("is checked before it is used", async () => {
    const keySet = await KeySet.generateRandom();
    const invalid: Record<string, string> = {
      "not JSON": '{"files":[',
      "an array": '[{"name":"a","type":"t","size":1}]',
      "no files": "{}",
      "files null": '{"files":null}',
      "files an object": '{"files":{"name":"a","type":"t","size":1}}',
      "files a string": '{"files":"a"}',
      "no file": '{"files":[]}',
      "a file not an object": file("5"),
      "a file null": file("null"),
      "no name": file('{"type":"t","size":1}'),
      "an empty name": file('{"name":"","type":"t","size":1}'),
      "a name not a string": file('{"name":5,"type":"t","size":1}'),
      "a name null": file('{"name":null,"type":"t","size":1}'),
      "a name in capitals": file('{"NAME":"a","type":"t","size":1}'),
      "no type": file('{"name":"a","size":1}'),
      "a type not a string": file('{"name":"a","type":[],"size":1}'),
      "no size": file('{"name":"a","type":"t"}'),
      "a negative size": file('{"name":"a","type":"t","size":-1}'),
      "a fractional size": file('{"name":"a","type":"t","size":1.5}'),
      "a size of 2^53": file('{"name":"a","type":"t","size":9007199254740992}'),
      "a size as a string": file('{"name":"a","type":"t","size":"1"}'),
      "a size null": file('{"name":"a","type":"t","size":null}'),
      "a size true": file('{"name":"a","type":"t","size":true}'),
      "more than the stream": file('{"name":"a","type":"t","size":4100}'),
      "more, summed": file(
        '{"name":"a","type":"t","size":2050},{"name":"b","type":"t","size":2050}',
      ),
      "a byte order mark": `\ufeff${file('{"name":"a","type":"t","size":1}')}`,
      "trailing garbage": `${file('{"name":"a","type":"t","size":1}')}x`,
    };
    for (const [name, list] of Object.entries(invalid)) {
      await expect(
        open(streamOf(list, new TextEncoder().encode("x"), 4096), keySet),
        name,
      ).rejects.toThrow("invalid bundle file list");
    }
    for (const [name, length] of [
      ["0", 0],
      ["1", 1],
      ["past 4 MiB", 4 * MiB + 1],
      ["past the stream", 4093],
    ] as const) {
      const stream = streamOf("{}", new Uint8Array(0), 4096);
      new DataView(stream.buffer).setUint32(0, length, false);
      await expect(open(stream, keySet), name).rejects.toThrow("invalid bundle file list");
    }
  });

  it("may hold fields readers do not know, and integers however written", async () => {
    const keySet = await KeySet.generateRandom();
    const accepted: Array<[string, unknown[]]> = [
      [
        '{"version":9,"files":[{"mtime":1,"name":"a","Name":"b","type":"t","size":1,"extra":{"x":[1]}}],"later":null}',
        [{ index: 0, name: "a", type: "t", size: 1 }],
      ],
      [
        '\n { "files" : [ { "size" : 1 , "type" : "" , "name" : "a" } ] } \t',
        [{ index: 0, name: "a", type: "", size: 1 }],
      ],
      [
        file(
          '{"name":"a","type":"t","size":1.0},{"name":"b","type":"t","size":1e1},{"name":"c","type":"t","size":-0},{"name":"d","type":"t","size":0.2e1}',
        ),
        [
          { index: 0, name: "a", type: "t", size: 1 },
          { index: 1, name: "b", type: "t", size: 10 },
          { index: 2, name: "c", type: "t", size: 0 },
          { index: 3, name: "d", type: "t", size: 2 },
        ],
      ],
      [
        file('{"name":"\\u00e9\\ud83d\\udcc4\\/","type":"t","size":0}'),
        [{ index: 0, name: "\u00e9\ud83d\udcc4/", type: "t", size: 0 }],
      ],
    ];
    for (const [list, want] of accepted) {
      const opened = await open(streamOf(list, new Uint8Array(13).fill(0x7a), 4096), keySet);
      expect(opened.files).toEqual(want);
      expect(Object.is(opened.files.at(-1)?.size, -0)).toBe(false);
    }
    // A list and a file that fill the stream to its last byte.
    const size = 4096 - 4 - file('{"name":"a","type":"t","size":4057}').length;
    const list = file(`{"name":"a","type":"t","size":${size}}`);
    const opened = await open(streamOf(list, new Uint8Array(size).fill(0x71), 4096), keySet);
    await expect(opened.decryptFile(0).then((b) => b.text())).resolves.toBe("q".repeat(size));
  });
});
