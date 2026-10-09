import { KeySet } from "../src/encryption";
import { openBundle } from "../src/openBundle";
import {
  BUNDLE_PIECE_SIZE,
  createStreamBundle,
  cutIntoParts,
  encryptStream,
  MAX_BUNDLE_LIST_BYTES,
  plannedBundleSize,
  planStream,
  SEALED_BUNDLE_CHUNK_SIZE,
} from "../src/stream";
import { blobBytes, fileOf, fixedPrefix, xorshift32 } from "./helpers";

/** The size of one file named f that makes the content exactly this long. */
function sizeFilling(content: number): number {
  let size = content;
  for (let i = 0; i < 3; i++) {
    size = content - 4 - planStream([{ name: "f", size }]).listBytes.length;
  }
  return size;
}

async function bundleBytes(files: File[], keySet: KeySet, readBytes?: number) {
  const { blob, plan } = await createStreamBundle(files, keySet, {
    prefix: fixedPrefix(),
    readBytes,
  });
  return { bytes: await blobBytes(blob), plan };
}

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

describe("planning a bundle", () => {
  it("pads the stream and works out the exact size", async () => {
    const keySet = await KeySet.generateRandom();
    for (const [size, stream] of [
      [14, 4096],
      [0, 4096],
      [10000, 10240],
      [sizeFilling(65536), 65536],
      [sizeFilling(3 * 65536), 3 * 65536],
      [sizeFilling(65537), 67584],
      [2 ** 20, 1081344],
    ]) {
      const plan = planStream([{ name: "f", size }]);
      expect(plan.starts[0]).toBe(4 + plan.listBytes.length);
      expect(plan.contentLength).toBe(plan.starts[0] + size);
      expect(plan.streamLength).toBe(stream);
      const chunks = Math.ceil(stream / BUNDLE_PIECE_SIZE);
      expect(plan.chunks).toBe(chunks);
      expect(plan.totalSize).toBe(16 + stream + 16 * chunks);
      expect(plannedBundleSize([{ name: "f", size }])).toBe(plan.totalSize);

      const content = xorshift32(size + 1, size);
      const { bytes } = await bundleBytes([fileOf(content, "f")], keySet);
      expect(bytes.length).toBe(plan.totalSize);
      if (stream % BUNDLE_PIECE_SIZE === 0) {
        expect(bytes.length).toBe(16 + chunks * SEALED_BUNDLE_CHUNK_SIZE);
      }
      const opened = await openBundle(
        async (start, end) => bytes.slice(start, end + 1),
        keySet,
        bytes.length,
      );
      expect(hex(await blobBytes(await opened.decryptFile(0)))).toBe(hex(content));
    }
  }, 30_000);

  it("needs only names, types and sizes", () => {
    const plan = planStream([
      { name: "a.txt", type: "text/plain", size: 5 },
      { name: "b.bin", size: 0 },
      { name: "c.bin", type: "", size: 70000 },
    ]);
    const list =
      '{"files":[{"name":"a.txt","type":"text/plain","size":5},{"name":"b.bin","type":"application/octet-stream","size":0},{"name":"c.bin","type":"application/octet-stream","size":70000}]}';
    expect(new TextDecoder().decode(plan.listBytes)).toBe(list);
    const h = 4 + list.length;
    expect(plan.starts).toEqual([h, h + 5, h + 5]);
    expect(plan.contentLength).toBe(h + 70005);
    expect(plan.files[1]).toEqual({
      index: 1,
      name: "b.bin",
      type: "application/octet-stream",
      size: 0,
    });
  });

  it("encodes the list byte for byte as the Go implementation does", () => {
    // The same list as bundle/stream_test.go's, whose expected bytes are these.
    const plan = planStream([
      { name: "<a & b>.txt", type: "text/plain", size: 0 },
      { name: 'say "hi".txt', type: 'text/plain; charset="utf-8"', size: 1 },
      { name: "back\\slash/and/slash.txt", size: 2 },
      { name: "tab\there\b\f\n\r\u0007\u001f\u007f.txt", type: "application/x-\u0000", size: 3 },
      { name: "Grüße \u2028\u2029 📄.txt", type: "text/plain", size: 123456789 },
    ]);
    // Node was given 2^53 − 1 for the last size, more than a bundle can hold.
    const got = new TextDecoder().decode(plan.listBytes).replace("123456789", "9007199254740991");
    expect(hex(new TextEncoder().encode(got))).toBe(
      "7b2266696c6573223a5b7b226e616d65223a223c61202620623e2e747874222c2274797065223a22746578742f706c61696e222c2273697a65223a307d2c7b226e616d65223a22736179205c2268695c222e747874222c2274797065223a22746578742f706c61696e3b20636861727365743d5c227574662d385c22222c2273697a65223a317d2c7b226e616d65223a226261636b5c5c736c6173682f616e642f736c6173682e747874222c2274797065223a226170706c69636174696f6e2f6f637465742d73747265616d222c2273697a65223a327d2c7b226e616d65223a227461625c74686572655c625c665c6e5c725c75303030375c75303031667f2e747874222c2274797065223a226170706c69636174696f6e2f782d5c7530303030222c2273697a65223a337d2c7b226e616d65223a224772c3bcc39f6520e280a8e280a920f09f93842e747874222c2274797065223a22746578742f706c61696e222c2273697a65223a393030373139393235343734303939317d5d7d",
    );
  });

  it("replaces lone surrogates, which are not Unicode text", () => {
    const plan = planStream([
      { name: "a\ud800b\udc00c\ud83d\udcc4\ud83d", type: "\udfff", size: 0 },
    ]);
    expect(plan.files[0].name).toBe("a\ufffdb\ufffdc📄\ufffd");
    expect(new TextDecoder().decode(plan.listBytes)).toBe(
      '{"files":[{"name":"a\ufffdb\ufffdc📄\ufffd","type":"\ufffd","size":0}]}',
    );
  });

  it("refuses what no reader could read", () => {
    expect(() => planStream([])).toThrow("at least one file");
    expect(() => planStream([{ name: "", size: 1 }])).toThrow("needs a name");
    for (const size of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, Number.NaN]) {
      expect(() => planStream([{ name: "a", size }])).toThrow("invalid bundle file size");
    }
    expect(() =>
      planStream([
        { name: "a", size: Number.MAX_SAFE_INTEGER },
        { name: "b", size: 1 },
      ]),
    ).toThrow("invalid bundle file size");
    expect(() => planStream([{ name: "a", size: Number.MAX_SAFE_INTEGER - 100 }])).toThrow(
      "invalid bundle file size",
    );

    // 11 + 4,095 × (32 + 992) + 32 + 981 bytes of list is 4 MiB.
    const many = Array.from({ length: 4096 }, () => ({
      name: "x".repeat(992),
      type: "t",
      size: 0,
    }));
    many[4095] = { name: "y".repeat(981), type: "t", size: 0 };
    expect(planStream(many).listBytes.length).toBe(MAX_BUNDLE_LIST_BYTES);
    many[4095] = { name: "y".repeat(982), type: "t", size: 0 };
    expect(() => planStream(many)).toThrow("bundle file list is too large");
  });
});

describe("writing a bundle", () => {
  it("is the same bundle for the same prefix, however the files are read", async () => {
    const keySet = await KeySet.generateRandom();
    const files = [fileOf(xorshift32(1, 100000), "a"), fileOf(xorshift32(2, 5), "b")];
    const { bytes } = await bundleBytes(files, keySet);
    expect(Array.from(bytes.subarray(0, 16))).toEqual(Array.from(fixedPrefix()));
    for (const readBytes of [1, 1000, BUNDLE_PIECE_SIZE, 70000]) {
      expect(hex((await bundleBytes(files, keySet, readBytes)).bytes)).toBe(hex(bytes));
    }
    const drawn = await blobBytes((await createStreamBundle(files, keySet)).blob);
    const again = await blobBytes((await createStreamBundle(files, keySet)).blob);
    expect(hex(drawn.subarray(0, 16))).not.toBe(hex(again.subarray(0, 16)));
    expect(drawn.length).toBe(bytes.length);
  });

  it("refuses files that do not match the plan or changed", async () => {
    const keySet = await KeySet.generateRandom();
    const plan = planStream([{ name: "f", size: 100 }]);
    const drain = async (files: Blob[], prefix?: Uint8Array) => {
      for await (const _ of encryptStream(plan, files, keySet, { prefix })) {
        // nothing
      }
    };
    await expect(drain([new Blob([new Uint8Array(99)])])).rejects.toThrow("do not match");
    await expect(drain([])).rejects.toThrow("do not match");
    await expect(drain([new Blob([new Uint8Array(100)])], new Uint8Array(15))).rejects.toThrow(
      "16 bytes",
    );
    // A File whose content went away reads short.
    const changed = {
      size: 100,
      slice: () => new Blob([new Uint8Array(90)]),
    } as unknown as Blob;
    await expect(drain([changed])).rejects.toThrow("bundle file changed during encryption");
  });

  it("cuts parts of exactly the part size, the last one shorter", async () => {
    async function* pieces(sizes: number[]) {
      let n = 0;
      for (const size of sizes) {
        yield Uint8Array.from({ length: size }, () => n++ & 0xff);
      }
    }
    const collect = async (sizes: number[], partSize: number) => {
      const parts: Uint8Array[] = [];
      for await (const part of cutIntoParts(pieces(sizes), partSize)) parts.push(part);
      return parts;
    };
    const parts = await collect([16, 65552, 65552, 3, 1000], 50000);
    expect(parts.map((p) => p.length)).toEqual([50000, 50000, 32123]);
    const joined = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) {
      joined.set(part, offset);
      offset += part.length;
    }
    expect(joined.every((byte, i) => byte === (i & 0xff))).toBe(true);
    expect((await collect([10, 10], 10)).map((p) => p.length)).toEqual([10, 10]);
    expect(await collect([], 10)).toEqual([]);
    await expect(collect([1], 0)).rejects.toThrow("invalid part size");

    // A real bundle, cut and joined again.
    const keySet = await KeySet.generateRandom();
    const files = [fileOf(xorshift32(3, 200000), "a")];
    const { bytes, plan } = await bundleBytes(files, keySet);
    const cut: number[] = [];
    let at = 0;
    for await (const part of cutIntoParts(
      encryptStream(plan, files, keySet, { prefix: fixedPrefix() }),
      65536,
    )) {
      cut.push(part.length);
      expect(hex(part)).toBe(hex(bytes.subarray(at, at + part.length)));
      at += part.length;
    }
    expect(cut).toEqual([65536, 65536, 65536, bytes.length - 3 * 65536]);
  });
});
