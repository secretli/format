import {
  BUNDLE_FOOTER_LENGTH,
  type BundleFile,
  buildBundleFooter,
  bundleManifestAad,
  cachingRangeFetcher,
  DEFAULT_BUNDLE_CHUNK_SIZE,
  DOWNLOAD_ALL_BUNDLE_COALESCED_PLAINTEXT_BYTES,
  decryptBundleFiles,
  estimateBundleEncryptedSize,
  MAX_BUNDLE_MANIFEST_BYTES,
  MIN_PADDED_BUNDLE_SIZE,
  paddedBundleSize,
  padme,
  parseBundleFooter,
  planBundle,
  readBundleManifest,
  sha256Hex,
} from "../src/bundle";
import { createEncryptedBundle } from "../src/encryptBundle";
import { KeySet } from "../src/encryption";

async function blobBytes(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

describe("encrypted bundles", () => {
  it("rejects empty bundles", async () => {
    const keySet = await KeySet.generateRandom();

    await expect(createEncryptedBundle([], keySet)).rejects.toThrow("at least one file");
  });

  it("round-trips a single file through manifest and chunk ranges", async () => {
    const keySet = await KeySet.generateRandom();
    const file = new File(["hello bundle"], "notes.txt", { type: "text/plain" });
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);
    const fetchRange = async (start: number, end: number) => bytes.slice(start, end + 1);

    const { manifest } = await readBundleManifest(fetchRange, keySet, bytes.length);
    expect(manifest.files).toHaveLength(1);
    expect(manifest.files[0].path).toBe("notes.txt");

    const [{ blob: decrypted }] = await decryptBundleFiles(manifest.files, keySet, fetchRange);
    await expect(decrypted.text()).resolves.toBe("hello bundle");
  });

  it("round-trips an empty file", async () => {
    const keySet = await KeySet.generateRandom();
    const file = new File([], "empty.txt", { type: "text/plain" });
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);
    const fetchRange = async (start: number, end: number) => bytes.slice(start, end + 1);

    const { manifest } = await readBundleManifest(fetchRange, keySet, bytes.length);
    const [{ blob: decrypted }] = await decryptBundleFiles(manifest.files, keySet, fetchRange);

    expect(manifest.files[0].chunks).toEqual([]);
    await expect(decrypted.arrayBuffer()).resolves.toHaveProperty("byteLength", 0);
  });

  it("uses 4 MiB chunks for large bundle files", async () => {
    const keySet = await KeySet.generateRandom();
    const payload = new Uint8Array(DEFAULT_BUNDLE_CHUNK_SIZE + 1);
    const file = new File([payload], "large.bin");
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);
    const fetchRange = async (start: number, end: number) => bytes.slice(start, end + 1);

    const { manifest } = await readBundleManifest(fetchRange, keySet, bytes.length);

    expect(DEFAULT_BUNDLE_CHUNK_SIZE).toBe(4 * 1024 * 1024);
    expect(manifest.chunkSize).toBe(DEFAULT_BUNDLE_CHUNK_SIZE);
    expect(manifest.files[0].chunks.map((chunk) => chunk.plaintextSize)).toEqual([
      DEFAULT_BUNDLE_CHUNK_SIZE,
      1,
    ]);
  });

  it("coalesces consecutive chunks into bounded range fetches", async () => {
    const keySet = await KeySet.generateRandom();
    const payload = new Uint8Array(DEFAULT_BUNDLE_CHUNK_SIZE * 4 + 1);
    payload[0] = 1;
    payload[DEFAULT_BUNDLE_CHUNK_SIZE] = 2;
    payload[payload.length - 1] = 3;
    const file = new File([payload], "large.bin");
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);
    const fetchRange = async (start: number, end: number) => bytes.slice(start, end + 1);
    const { manifest } = await readBundleManifest(fetchRange, keySet, bytes.length);
    const fileManifest = manifest.files[0];
    const ranges: Array<[number, number]> = [];
    const recordingRange = async (start: number, end: number) => {
      ranges.push([start, end]);
      return bytes.slice(start, end + 1);
    };

    const [{ blob: decrypted }] = await decryptBundleFiles([fileManifest], keySet, recordingRange);
    const decryptedBytes = await blobBytes(decrypted);

    expect(fileManifest.chunks).toHaveLength(5);
    expect(ranges).toEqual([
      [
        fileManifest.chunks[0].offset,
        fileManifest.chunks[3].offset + fileManifest.chunks[3].length - 1,
      ],
      [
        fileManifest.chunks[4].offset,
        fileManifest.chunks[4].offset + fileManifest.chunks[4].length - 1,
      ],
    ]);
    expect(decryptedBytes[0]).toBe(1);
    expect(decryptedBytes[DEFAULT_BUNDLE_CHUNK_SIZE]).toBe(2);
    expect(decryptedBytes[decryptedBytes.length - 1]).toBe(3);
    // 16 MiB through pure-JS XChaCha20 both ways: well under a second locally,
    // but past the 5 s default on a CI runner busy with the scrypt tests.
  }, 30_000);

  it("uses the download-all coalescing option", async () => {
    const ranges: Array<[number, number]> = [];
    const file: BundleFile = {
      index: 0,
      path: "alpha.bin",
      name: "alpha.bin",
      type: "application/octet-stream",
      size: 6,
      chunks: Array.from({ length: 6 }, (_, index) => ({
        index,
        offset: index,
        length: 1,
        plaintextSize: 1,
      })),
    };
    const fakeKeySet = {
      decryptBundlePart: () => new Uint8Array([1]),
    } as unknown as KeySet;
    const recordingRange = async (start: number, end: number) => {
      ranges.push([start, end]);
      return new Uint8Array(end - start + 1);
    };

    const progress: number[] = [];
    const decrypted = await decryptBundleFiles([file], fakeKeySet, recordingRange, {
      maxCoalescedPlaintextBytes: 4,
      onProgress: ({ decryptedBytes }) => progress.push(decryptedBytes),
    });

    expect(DOWNLOAD_ALL_BUNDLE_COALESCED_PLAINTEXT_BYTES).toBe(64 * 1024 * 1024);
    expect(ranges).toEqual([
      [0, 3],
      [4, 5],
    ]);
    expect(progress).toEqual([4, 6]);
    await expect(decrypted[0].blob.arrayBuffer()).resolves.toHaveProperty("byteLength", 6);
    expect(decrypted[0].blob.type).toBe("application/octet-stream");
  });

  it("rejects a manifest range outside the reported bundle size", async () => {
    const keySet = await KeySet.generateRandom();
    const file = new File(["hello bundle"], "notes.txt", { type: "text/plain" });
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);
    const fetchRange = async (start: number, end: number) => bytes.slice(start, end + 1);

    await expect(readBundleManifest(fetchRange, keySet, bytes.length - 1)).rejects.toThrow(
      "invalid bundle footer",
    );
  });

  it("rejects a tampered v2 manifest hash", async () => {
    const keySet = await KeySet.generateRandom();
    const file = new File(["hello bundle"], "notes.txt", { type: "text/plain" });
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);
    const footer = parseBundleFooter(bytes.slice(bytes.length - BUNDLE_FOOTER_LENGTH));
    const manifestOffset = bytes.length - BUNDLE_FOOTER_LENGTH - footer.manifestLength;
    const tampered = bytes.slice();
    tampered[manifestOffset] ^= 1;
    const fetchRange = async (start: number, end: number) => tampered.slice(start, end + 1);

    await expect(readBundleManifest(fetchRange, keySet, bytes.length)).rejects.toThrow(
      "invalid bundle manifest hash",
    );
  });

  it("rejects malformed v2 footers", async () => {
    const keySet = await KeySet.generateRandom();
    const file = new File(["hello bundle"], "notes.txt", { type: "text/plain" });
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);
    const footerBytes = bytes.slice(bytes.length - BUNDLE_FOOTER_LENGTH);
    const malformedVersion = footerBytes.slice();
    new DataView(malformedVersion.buffer).setUint32(8, 99, false);

    expect(() => parseBundleFooter(malformedVersion)).toThrow("invalid bundle footer");
  });

  it("round-trips multiple files without storing a zip", async () => {
    const keySet = await KeySet.generateRandom();
    const files = [
      new File(["alpha"], "a.txt", { type: "text/plain" }),
      new File(["bravo"], "b.txt", { type: "text/plain" }),
    ];
    const { blob } = await createEncryptedBundle(files, keySet);
    const bytes = await blobBytes(blob);
    const fetchRange = async (start: number, end: number) => bytes.slice(start, end + 1);

    const { manifest } = await readBundleManifest(fetchRange, keySet, bytes.length);
    expect(manifest.files.map((file) => file.path)).toEqual(["a.txt", "b.txt"]);

    const decrypted = await decryptBundleFiles(manifest.files, keySet, fetchRange);
    await expect(decrypted[0].blob.text()).resolves.toBe("alpha");
    await expect(decrypted[1].blob.text()).resolves.toBe("bravo");
  });

  it("rejects tampered chunks", async () => {
    const keySet = await KeySet.generateRandom();
    const file = new File(["hello bundle"], "notes.txt");
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);
    const fetchRange = async (start: number, end: number) => bytes.slice(start, end + 1);
    const { manifest } = await readBundleManifest(fetchRange, keySet, bytes.length);
    const chunk = manifest.files[0].chunks[0];
    const tampered = bytes.slice();
    tampered[chunk.offset] ^= 1;
    const tamperedRange = async (start: number, end: number) => tampered.slice(start, end + 1);

    await expect(decryptBundleFiles([manifest.files[0]], keySet, tamperedRange)).rejects.toThrow();
  });

  it("rejects a tampered record on decryption", async () => {
    const keySet = await KeySet.generateRandom();
    const file = new File(["hello bundle"], "notes.txt", { type: "text/plain" });
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);
    const { manifest } = await readBundleManifest(
      async (start, end) => bytes.slice(start, end + 1),
      keySet,
      bytes.length,
    );

    // Flip a byte inside the first record's ciphertext. There is no separate
    // checksum any more; the Poly1305 tag has to catch this.
    const chunk = manifest.files[0].chunks[0];
    const tampered = bytes.slice();
    tampered[chunk.offset + chunk.length - 1] ^= 1;

    await expect(
      decryptBundleFiles(manifest.files, keySet, async (start, end) =>
        tampered.slice(start, end + 1),
      ),
    ).rejects.toThrow();
  });

  it("keeps the manifest free of per-record checksums", async () => {
    const keySet = await KeySet.generateRandom();
    const file = new File(["hello bundle"], "notes.txt", { type: "text/plain" });
    const { blob, manifest } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);

    expect(JSON.stringify({ ...manifest, padding: "" })).not.toContain("sha256");
    // The planned size is exact, so the server can validate the declared size.
    const plan = planBundle([file]);
    expect(plan.totalSize).toBe(bytes.length);
  });

  it("serves a small bundle from one fetched copy", async () => {
    const keySet = await KeySet.generateRandom();
    const file = new File(["a short secret"], "secret.txt", { type: "text/plain" });
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);

    let fetches = 0;
    const counting = async (start: number, end: number) => {
      fetches++;
      return bytes.slice(start, end + 1);
    };
    const fetchRange = await cachingRangeFetcher(counting, bytes.length);

    const { manifest } = await readBundleManifest(fetchRange, keySet, bytes.length);
    const [only] = await decryptBundleFiles(manifest.files, keySet, fetchRange);

    await expect(only.blob.text()).resolves.toBe("a short secret");
    expect(fetches).toBe(1);
  });

  it("passes large bundles through without caching", async () => {
    const ranges: Array<[number, number]> = [];
    const passthrough = async (start: number, end: number) => {
      ranges.push([start, end]);
      return new Uint8Array(end - start + 1);
    };
    const fetchRange = await cachingRangeFetcher(passthrough, 4096, 1024);

    await fetchRange(0, 9);
    await fetchRange(10, 19);
    expect(ranges).toEqual([
      [0, 9],
      [10, 19],
    ]);
  });
});

const BUNDLE_RECORD_OVERHEAD = 40;
const PADDING_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** A plan of one empty file whose manifest, with empty padding, is exactly this long. */
function planWithManifest(length: number) {
  const file = new File([], "a");
  const base = JSON.stringify({
    version: 2,
    bundleName: "",
    chunkSize: DEFAULT_BUNDLE_CHUNK_SIZE,
    files: [
      {
        index: 0,
        path: "a",
        name: "a",
        type: "application/octet-stream",
        size: 0,
        chunks: [],
      },
    ],
    padding: "",
  }).length;
  const plan = planBundle([file], "x".repeat(length - base));
  expect(plan.totalSize - plan.paddingLength - BUNDLE_RECORD_OVERHEAD - BUNDLE_FOOTER_LENGTH).toBe(
    length,
  );
  return plan;
}

describe("padding", () => {
  it("rounds sizes with Padmé", () => {
    const table: Array<[number, number]> = [
      [0, 0],
      [1, 1],
      [2, 2],
      [3, 3],
      [5, 5],
      [9, 10],
      [100, 104],
      [1000, 1024],
      [4095, 4096],
      [4096, 4096],
      [4097, 4352],
      [10000, 10240],
      [10544, 10752],
      [65535, 65536],
      [65536, 65536],
      [65537, 67584],
      [2 ** 20 - 1, 2 ** 20],
      [2 ** 20, 2 ** 20],
      [2 ** 20 + 1, 1081344],
      [2 ** 30 - 1, 2 ** 30],
      [2 ** 30, 2 ** 30],
      [2 ** 30 + 1, 1107296256],
    ];
    for (const [size, want] of table) {
      expect([size, padme(size)]).toEqual([size, want]);
    }
  });

  it("never shrinks, is stable, costs at most 12.5% and stays below the next power of two", () => {
    const check = (size: number) => {
      const p = padme(size);
      const power = 2 ** (size - 1).toString(2).length;
      if (p < size || padme(p) !== p || (p - size) * 8 > size || p > power) {
        throw new Error(`padme(${size}) = ${p}`);
      }
    };
    for (let size = 2; size <= 2 ** 17; size++) check(size);
    for (let size = 2 ** 17; size < 2 ** 52; size = Math.floor((size * 9) / 8) + 12345) check(size);
  });

  it("pads small bundles to 4,096 bytes", () => {
    expect(MIN_PADDED_BUNDLE_SIZE).toBe(4096);
    for (const [size, want] of [
      [1, 4096],
      [300, 4096],
      [4095, 4096],
      [4096, 4096],
      [4097, 4352],
    ]) {
      expect(paddedBundleSize(size)).toBe(want);
    }
  });

  it("writes exactly the planned, padded size", async () => {
    const keySet = await KeySet.generateRandom();
    for (const size of [0, 14, 2048, 3900, 4100, 10 * 1024, 2 ** 20]) {
      const file = new File([new Uint8Array(size)], "secret.txt", { type: "text/plain" });
      const plan = planBundle([file]);
      const unpadded = plan.totalSize - plan.paddingLength;
      expect(plan.totalSize).toBe(paddedBundleSize(unpadded));
      const padding = plan.manifest.padding ?? "";
      expect(padding.length).toBe(plan.paddingLength);
      expect([...padding].every((c) => PADDING_ALPHABET.includes(c))).toBe(true);
      expect(JSON.stringify(plan.manifest).endsWith(`,"padding":"${padding}"}`)).toBe(true);

      const { blob } = await createEncryptedBundle([file], keySet);
      const bytes = await blobBytes(blob);
      expect(bytes.length).toBe(plan.totalSize);
      const { manifest } = await readBundleManifest(
        async (start, end) => bytes.slice(start, end + 1),
        keySet,
        bytes.length,
      );
      expect(manifest.files).toEqual(plan.manifest.files);
    }
  });

  it("maps random bytes to characters without bias", () => {
    let next = 0;
    const plan = planBundle([new File([], "a")], "a", (bytes) => {
      for (let i = 0; i < bytes.length; i++) bytes[i] = next++ & 0xff;
    });
    const padding = plan.manifest.padding ?? "";
    expect(padding.length).toBeGreaterThan(0);
    for (let i = 0; i < padding.length; i++) {
      expect(padding[i]).toBe(PADDING_ALPHABET[i % 64]);
    }
  });

  it("draws large padding in pieces crypto.getRandomValues accepts", () => {
    // A bundle just past 4 MiB rounds up by about 128 KiB, more than one call
    // to crypto.getRandomValues may fill.
    const file = new File([new Uint8Array(DEFAULT_BUNDLE_CHUNK_SIZE + 1)], "big.bin");
    const plan = planBundle([file]);
    expect(plan.paddingLength).toBeGreaterThan(65536);
    expect(plan.totalSize).toBe(paddedBundleSize(plan.totalSize - plan.paddingLength));
  });

  it("does not pad at all when the padding would not fit the manifest", () => {
    // 262,100 + 104 = 262,204 bytes would round to 270,336: no room.
    const capped = planWithManifest(262100);
    expect(capped.paddingLength).toBe(0);
    expect(capped.manifest.padding).toBe("");
    expect(capped.totalSize).toBe(262204);
    // 258,100 + 104 rounds to 262,144, and that padding still fits.
    const fits = planWithManifest(258100);
    expect(fits.paddingLength).toBe(262144 - 258204);
    expect(fits.totalSize).toBe(262144);
    // The cap itself counts the empty padding field.
    expect(() => planBundle([new File([], "a")], "x".repeat(MAX_BUNDLE_MANIFEST_BYTES))).toThrow(
      "bundle manifest is too large",
    );
    // The upload estimate still covers padded bundles.
    expect(estimateBundleEncryptedSize([0])).toBeGreaterThanOrEqual(capped.totalSize);
    expect(estimateBundleEncryptedSize([3000])).toBeGreaterThanOrEqual(
      planBundle([new File([new Uint8Array(3000)], "a")]).totalSize,
    );
  });

  it("is ignored by readers, whatever it holds", async () => {
    const keySet = await KeySet.generateRandom();
    const file = new File(["payload"], "a.txt", { type: "text/plain" });
    const { blob } = await createEncryptedBundle([file], keySet);
    const bytes = await blobBytes(blob);
    const footer = parseBundleFooter(bytes.slice(bytes.length - BUNDLE_FOOTER_LENGTH));
    const records = bytes.slice(0, bytes.length - BUNDLE_FOOTER_LENGTH - footer.manifestLength);
    const { padding: _, ...bare } = planBundle([file]).manifest;
    const json = JSON.stringify(bare);
    const open = json.slice(0, -1);

    for (const manifestJson of [
      json,
      `${open},"padding":""}`,
      `{"padding":"AAAA",${json.slice(1)}`,
      `${open},"padding":{"n":[1,2,3]}}`,
      `${open},"padding":"<&>\\u00e9 \\n"}`,
      `${open},"padding":"x","later":true}`,
    ]) {
      const encrypted = keySet.encryptBundlePart(
        new TextEncoder().encode(manifestJson),
        bundleManifestAad(),
      );
      const trailer = buildBundleFooter({
        version: 2,
        footerLength: BUNDLE_FOOTER_LENGTH,
        manifestLength: encrypted.length,
        manifestSha256: await sha256Hex(encrypted),
      });
      const assembled = new Uint8Array(records.length + encrypted.length + trailer.length);
      assembled.set(records, 0);
      assembled.set(encrypted, records.length);
      assembled.set(trailer, records.length + encrypted.length);
      const fetchRange = async (start: number, end: number) => assembled.slice(start, end + 1);

      const { manifest } = await readBundleManifest(fetchRange, keySet, assembled.length);
      expect(manifest.files).toEqual(bare.files);
      const [{ blob: decrypted }] = await decryptBundleFiles(manifest.files, keySet, fetchRange);
      await expect(decrypted.text()).resolves.toBe("payload");
    }
  });
});
