import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { base64UrlEncode } from "../src/base64";
import { DEFAULT_BUNDLE_CHUNK_SIZE, decryptBundleFiles, readBundleManifest } from "../src/bundle";
import { createEncryptedBundle } from "../src/encryptBundle";
import { KeySet, type SecretMeta } from "../src/encryption";

/**
 * The Go implementation (keys, bundle) and this one must read each other's
 * output; FORMAT.md section 10 describes the vector files.
 * This side writes ts-vectors.json and reads go-vectors.json.
 *
 * Regenerate the committed TypeScript vectors with
 *
 *   WRITE_VECTORS=../vectors/testdata pnpm vitest run test/vectors.test.ts
 *
 * CI writes fresh, larger vectors on both sides at every run (VECTORS_BIG=1)
 * and reads the other side's from a temporary directory (VECTORS_DIR).
 */
const TESTDATA = path.resolve(__dirname, "../../vectors/testdata");

interface Generated {
  seed: number;
  length: number;
}

interface VectorFile {
  name: string;
  type: string;
  content_base64?: string;
  generated?: Generated;
}

interface VectorCase {
  name: string;
  share_secret: string;
  password: string;
  derived: {
    public_id: string;
    metadata_token: string;
    blob_token: string;
    password_blob_token: string;
  };
  meta: SecretMeta;
  encrypted_meta: string;
  bundle_name: string;
  files: VectorFile[];
  /** The whole encrypted bundle, sealed with this case's blob keys. */
  bundle_base64: string;
}

interface Vectors {
  cases: VectorCase[];
}

// Big cases encrypt 20 MiB and run scrypt; slow on a busy CI runner.
const LONG = { timeout: 180_000 };

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "base64"));
}

/** The generator FORMAT.md defines for generated content. */
function xorshift32(seed: number, length: number): Uint8Array {
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

function contentOf(file: VectorFile): Uint8Array {
  if (file.generated) return xorshift32(file.generated.seed, file.generated.length);
  return fromBase64(file.content_base64 ?? "");
}

/** A File takes an ArrayBuffer; a Uint8Array over a shared buffer would not do. */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function makeCase(
  name: string,
  secretByte: number,
  password: string,
  metaType: "text" | "bundle",
  files: VectorFile[],
): Promise<VectorCase> {
  const secret = new Uint8Array(32);
  for (let i = 0; i < secret.length; i++) secret[i] = (secretByte + i) & 0xff;
  const shareSecret = base64UrlEncode(secret);
  const base = await KeySet.fromShareSecret(shareSecret);
  const blob = password ? await KeySet.fromShareSecret(shareSecret, password) : base;

  const fileObjects = files.map(
    (f) => new File([toArrayBuffer(contentOf(f))], f.name, { type: f.type }),
  );
  const { blob: bundle, manifest } = await createEncryptedBundle(fileObjects, blob);
  const meta: SecretMeta = {
    type: metaType,
    password_protected: password !== "",
    bundle_name: manifest.bundleName,
  };
  const encoded = base.getEncoded();
  return {
    name,
    share_secret: shareSecret,
    password,
    derived: {
      public_id: encoded.publicID,
      metadata_token: encoded.metadataToken,
      blob_token: encoded.blobToken,
      password_blob_token: blob.getEncoded().blobToken,
    },
    meta,
    encrypted_meta: await base.encryptMeta(meta),
    bundle_name: manifest.bundleName,
    files,
    bundle_base64: toBase64(new Uint8Array(await bundle.arrayBuffer())),
  };
}

async function checkCase(c: VectorCase) {
  const base = await KeySet.fromShareSecret(c.share_secret);
  const encoded = base.getEncoded();
  expect(encoded.publicID).toBe(c.derived.public_id);
  expect(encoded.metadataToken).toBe(c.derived.metadata_token);
  expect(encoded.blobToken).toBe(c.derived.blob_token);
  const blob = c.password ? await KeySet.fromShareSecret(c.share_secret, c.password) : base;
  expect(blob.getEncoded().blobToken).toBe(c.derived.password_blob_token);

  await expect(base.decryptMeta(c.encrypted_meta)).resolves.toEqual(c.meta);

  const bytes = fromBase64(c.bundle_base64);
  const fetchRange = async (start: number, end: number) => bytes.slice(start, end + 1);
  const { manifest } = await readBundleManifest(fetchRange, blob, bytes.length);
  expect(manifest.bundleName).toBe(c.bundle_name);
  expect(manifest.files.map((f) => [f.name, f.type])).toEqual(c.files.map((f) => [f.name, f.type]));
  const decrypted = await decryptBundleFiles(manifest.files, blob, fetchRange);
  for (const [i, { blob: content }] of decrypted.entries()) {
    const got = new Uint8Array(await content.arrayBuffer());
    const want = contentOf(c.files[i]);
    expect(got.length).toBe(want.length);
    expect(Buffer.from(got).equals(Buffer.from(want))).toBe(true);
  }
}

describe("cross-implementation vectors", () => {
  it("writes this implementation's vectors when asked", LONG, async () => {
    const target = process.env.WRITE_VECTORS;
    if (!target) return;
    const dir = target === "1" ? TESTDATA : path.resolve(target);

    const text = toBase64(new TextEncoder().encode("hello from typescript\n"));
    const bytes = toBase64(new Uint8Array(Array.from({ length: 256 }, (_, i) => i)));
    const cases = [
      await makeCase("text", 0x01, "", "text", [
        { name: "secret.txt", type: "text/plain", content_base64: text },
      ]),
      await makeCase("files-password", 0x21, "correct horse battery staple", "bundle", [
        { name: "hello.txt", type: "text/plain", content_base64: text },
        { name: "empty.bin", type: "application/octet-stream", content_base64: "" },
        { name: "bytes.bin", type: "application/octet-stream", content_base64: bytes },
      ]),
    ];
    if (process.env.VECTORS_BIG) {
      const chunk = DEFAULT_BUNDLE_CHUNK_SIZE;
      const octet = "application/octet-stream";
      cases.push(
        await makeCase("boundaries", 0x41, "", "bundle", [
          { name: "zero.bin", type: octet, generated: { seed: 11, length: 0 } },
          { name: "one.bin", type: octet, generated: { seed: 12, length: 1 } },
          { name: "under.bin", type: octet, generated: { seed: 13, length: chunk - 1 } },
          { name: "exact.bin", type: octet, generated: { seed: 14, length: chunk } },
          { name: "over.bin", type: octet, generated: { seed: 15, length: chunk + 1 } },
          { name: "two-plus.bin", type: octet, generated: { seed: 16, length: 2 * chunk + 3 } },
        ]),
      );
    }
    mkdirSync(dir, { recursive: true });
    const vectors: Vectors = { cases };
    writeFileSync(path.join(dir, "ts-vectors.json"), `${JSON.stringify(vectors, null, 2)}\n`);
  });

  const files = [path.join(TESTDATA, "go-vectors.json")];
  if (process.env.VECTORS_DIR) {
    const dir = path.resolve(process.env.VECTORS_DIR);
    for (const name of readdirSync(dir)) {
      if (name.endsWith(".json")) files.push(path.join(dir, name));
    }
  }
  for (const file of files) {
    it(`reads what the other implementation wrote: ${path.basename(file)}`, LONG, async () => {
      if (!existsSync(file)) {
        throw new Error(`${file} is missing; see the comment at the top of this test`);
      }
      const v: Vectors = JSON.parse(readFileSync(file, "utf8"));
      expect(v.cases.length).toBeGreaterThan(0);
      for (const c of v.cases) {
        await checkCase(c);
      }
    });
  }
});
