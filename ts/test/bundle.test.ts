import {
  DOWNLOAD_ALL_BUNDLE_COALESCED_PLAINTEXT_BYTES,
  MAX_BUNDLE_COALESCED_PLAINTEXT_BYTES,
  MIN_PADDED_BUNDLE_SIZE,
  paddedBundleSize,
  padme,
  SMALL_BUNDLE_CACHE_BYTES,
  sha256Hex,
} from "../src/bundle";

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
});

describe("reading and uploading", () => {
  it("fetches up to these amounts per request", () => {
    expect(SMALL_BUNDLE_CACHE_BYTES).toBe(1024 * 1024);
    expect(MAX_BUNDLE_COALESCED_PLAINTEXT_BYTES).toBe(16 * 1024 * 1024);
    expect(DOWNLOAD_ALL_BUNDLE_COALESCED_PLAINTEXT_BYTES).toBe(64 * 1024 * 1024);
  });

  it("hashes upload parts as lower-case hex SHA-256", async () => {
    await expect(sha256Hex(new TextEncoder().encode("abc"))).resolves.toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    const bytes = new TextEncoder().encode("xabcx").subarray(1, 4);
    await expect(sha256Hex(bytes)).resolves.toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});
