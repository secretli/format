import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base64UrlDecode, base64UrlEncode } from "../src/base64";
import {
  calculateGenerator,
  cpaceIsk,
  cpaceShare,
  scalarFromBytesLE,
  scalarMultVfy,
} from "../src/cpace";
import { KeySet, type SecretMeta } from "../src/encryption";
import { openBundle } from "../src/openBundle";
import { padme } from "../src/padme";
import { BUNDLE_PIECE_SIZE, encryptStream, planStream } from "../src/stream";
import {
  channelIdentifier,
  confirmationTag,
  deriveTransferKeys,
  openLink,
  sealLink,
} from "../src/transfer";
import { parseCode, TRANSFER_WORDS, transferPassword } from "../src/transferWords";

/**
 * The Go implementation (keys, bundle, transfer) and this one must read each other's
 * output; FORMAT.md section 10 describes the vector files.
 * This side writes ts-vectors.json and reads go-vectors.json. Their cases are bundles with
 * a fixed prefix, which each side must reproduce byte for byte.
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
  files: VectorFile[];
  /** The bundle's prefix, which a writer given it reproduces exactly. */
  prefix: string;
  /** The whole encrypted bundle, sealed with this case's blob keys. */
  bundle_base64: string;
}

/** One short-code transfer with fixed scalars; bytes are hex. */
interface TransferCase {
  name: string;
  code: string;
  origin: string;
  sid: string;
  sender_scalar: string;
  receiver_scalar: string;
  link: string;
  word_list_sha256: string;
  derived: TransferDerived;
  /** The delivery leg, sealed with the payload key. */
  sealed: string;
}

interface TransferDerived {
  password: string;
  channel_identifier: string;
  generator: string;
  sender_share: string;
  receiver_share: string;
  k: string;
  isk: string;
  confirm_key: string;
  payload_key: string;
  confirmation: string;
}

interface Vectors {
  cases: VectorCase[];
  transfer: TransferCase[];
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

/** Encrypts the files with a share secret and a prefix fixed by the seed byte. */
async function makeCase(
  name: string,
  secretByte: number,
  password: string,
  metaType: "text" | "bundle",
  files: VectorFile[],
): Promise<VectorCase> {
  const secret = new Uint8Array(32);
  for (let i = 0; i < secret.length; i++) secret[i] = (secretByte + i) & 0xff;
  const prefix = Uint8Array.from({ length: 16 }, (_, i) => ((secretByte ^ 0x5a) + 3 * i) & 0xff);
  const shareSecret = base64UrlEncode(secret);
  const base = await KeySet.fromShareSecret(shareSecret);
  const blob = password ? await KeySet.fromShareSecret(shareSecret, password) : base;

  const bundle = await writeBundle(files, blob, prefix);
  const meta: SecretMeta = { type: metaType, password_protected: password !== "" };
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
    files,
    prefix: base64UrlEncode(prefix),
    bundle_base64: toBase64(bundle),
  };
}

/**
 * Writes the files as a bundle with this prefix. It plans from the names and types as they
 * are: a File would lower-case its type, and drop one with characters outside printable
 * ASCII, as browsers do.
 */
async function writeBundle(
  files: VectorFile[],
  keySet: KeySet,
  prefix: Uint8Array,
): Promise<Uint8Array> {
  const contents = files.map(contentOf);
  const plan = planStream(
    files.map((f, i) => ({ name: f.name, type: f.type, size: contents[i].length })),
  );
  const parts: Uint8Array[] = [];
  const blobs = contents.map((c) => new Blob([toArrayBuffer(c)]));
  for await (const part of encryptStream(plan, blobs, keySet, { prefix })) {
    parts.push(part);
  }
  const out = new Uint8Array(plan.totalSize);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  expect(offset).toBe(plan.totalSize);
  return out;
}

/**
 * Reads the case's bundle and expects its files. The case is then written again with its
 * prefix and must come out byte for byte the same, and its envelope must be padded as
 * FORMAT.md section 4 says.
 */
async function checkCase(c: VectorCase) {
  const base = await KeySet.fromShareSecret(c.share_secret);
  const encoded = base.getEncoded();
  expect(encoded.publicID).toBe(c.derived.public_id);
  expect(encoded.metadataToken).toBe(c.derived.metadata_token);
  expect(encoded.blobToken).toBe(c.derived.blob_token);
  const blob = c.password ? await KeySet.fromShareSecret(c.share_secret, c.password) : base;
  expect(blob.getEncoded().blobToken).toBe(c.derived.password_blob_token);

  const meta = await base.decryptMeta(c.encrypted_meta);
  expect({ type: meta.type, password_protected: meta.password_protected }).toEqual({
    type: c.meta.type,
    password_protected: c.meta.password_protected,
  });

  const bytes = fromBase64(c.bundle_base64);
  const fetchRange = async (start: number, end: number) => bytes.slice(start, end + 1);
  const opened = await openBundle(fetchRange, blob, bytes.length);
  expect(opened.files.map((f) => [f.name, f.type])).toEqual(c.files.map((f) => [f.name, f.type]));
  const decrypted = await opened.decryptFiles();
  for (const [i, { blob: content }] of decrypted.entries()) {
    const got = new Uint8Array(await content.arrayBuffer());
    const want = contentOf(c.files[i]);
    expect(got.length).toBe(want.length);
    expect(Buffer.from(got).equals(Buffer.from(want))).toBe(true);
  }

  const prefix = base64UrlDecode(c.prefix);
  expect(prefix.length).toBe(16);
  const written = await writeBundle(c.files, blob, prefix);
  expect(written.length).toBe(bytes.length);
  expect(Buffer.from(written).equals(Buffer.from(bytes))).toBe(true);
  checkEnvelopePadding(c);
}

/** Opens the envelope with keys derived here, apart from KeySet, and checks its padding. */
function checkEnvelopePadding(c: VectorCase) {
  const secret = base64UrlDecode(c.share_secret);
  const label = (name: string) => new TextEncoder().encode(`secretli:derivation:v1:${name}`);
  const metaKey = hkdf(sha512, secret, undefined, label("meta_key"), 32);
  const publicID = hkdf(sha512, secret, undefined, label("public_id"), 16);
  const [, nonce, ciphertext] = c.encrypted_meta.split("$");
  const aad = new Uint8Array([...publicID, ...new TextEncoder().encode("meta")]);
  const plaintext = xchacha20poly1305(metaKey, base64UrlDecode(nonce), aad).decrypt(
    base64UrlDecode(ciphertext),
  );
  const json = new TextDecoder().decode(plaintext).replace(/ +$/, "");
  const n = new TextEncoder().encode(json).length;
  const padded = n > 6101 ? n : Math.min(6101, Math.max(512, padme(n)));
  expect(plaintext.length).toBe(padded);
  expect(JSON.parse(json)).toEqual(c.meta);
  expect(c.encrypted_meta.length).toBe(740);
}

const utf8 = (s: string) => new TextEncoder().encode(s);

/** Runs both sides of a transfer case with its fixed scalars. */
function deriveTransfer(c: Omit<TransferCase, "derived" | "sealed">): TransferDerived {
  const code = parseCode(c.code);
  if (!code.ok) throw new Error(`cannot parse ${JSON.stringify(c.code)}: ${code.error}`);
  const sid = hexToBytes(c.sid);
  const senderScalar = scalarFromBytesLE(hexToBytes(c.sender_scalar));
  const receiverScalar = scalarFromBytesLE(hexToBytes(c.receiver_scalar));
  const password = transferPassword(code.words);
  const ci = channelIdentifier(c.origin);
  const g = calculateGenerator(password, ci, sid);
  const ya = cpaceShare(g, senderScalar);
  const yb = cpaceShare(g, receiverScalar);
  const k = scalarMultVfy(senderScalar, yb);
  expect(bytesToHex(scalarMultVfy(receiverScalar, ya))).toBe(bytesToHex(k));
  const isk = cpaceIsk(sid, k, ya, utf8("sender"), yb, utf8("receiver"));
  const keys = deriveTransferKeys(isk, sid);
  return {
    password: new TextDecoder().decode(password),
    channel_identifier: bytesToHex(ci),
    generator: bytesToHex(g.toBytes()),
    sender_share: bytesToHex(ya),
    receiver_share: bytesToHex(yb),
    k: bytesToHex(k),
    isk: bytesToHex(isk),
    confirm_key: bytesToHex(keys.confirm),
    payload_key: bytesToHex(keys.payload),
    confirmation: bytesToHex(confirmationTag(keys.confirm, ya, yb)),
  };
}

function wordListSha256(): string {
  return createHash("sha256").update(TRANSFER_WORDS.join("\n")).digest("hex");
}

/** Fixes the session id and both scalars from a seed byte. */
function makeTransferCase(
  name: string,
  code: string,
  origin: string,
  seed: number,
  link: string,
): TransferCase {
  const sid = Uint8Array.from({ length: 32 }, (_, i) => (seed + 0x80 + i) & 0xff);
  const senderScalar = Uint8Array.from({ length: 32 }, (_, i) => (seed + i) & 0xff);
  const receiverScalar = Uint8Array.from({ length: 32 }, (_, i) => (seed + 0x40 + i) & 0xff);
  senderScalar[31] &= 0x0f;
  receiverScalar[31] &= 0x0f;
  const inputs = {
    name,
    code,
    origin,
    sid: bytesToHex(sid),
    sender_scalar: bytesToHex(senderScalar),
    receiver_scalar: bytesToHex(receiverScalar),
    link,
    word_list_sha256: wordListSha256(),
  };
  const derived = deriveTransfer(inputs);
  return {
    ...inputs,
    derived,
    sealed: bytesToHex(sealLink(hexToBytes(derived.payload_key), sid, link)),
  };
}

function checkTransferCase(c: TransferCase) {
  expect(wordListSha256()).toBe(c.word_list_sha256);
  expect(deriveTransfer(c)).toEqual(c.derived);
  const sealed = hexToBytes(c.sealed);
  expect(openLink(hexToBytes(c.derived.payload_key), hexToBytes(c.sid), sealed)).toBe(c.link);
}

describe("cross-implementation vectors", () => {
  it("writes this implementation's vectors when asked", LONG, async () => {
    const target = process.env.WRITE_VECTORS;
    if (!target) return;
    const dir = target === "1" ? TESTDATA : path.resolve(target);

    const text = toBase64(new TextEncoder().encode("hello from typescript\n"));
    const bytes = toBase64(new Uint8Array(Array.from({ length: 256 }, (_, i) => i)));
    const octet = "application/octet-stream";
    const cases = [
      await makeCase("text", 0x01, "", "text", [
        { name: "secret.txt", type: "text/plain", content_base64: text },
      ]),
      await makeCase("files-password", 0x21, "correct horse battery staple", "bundle", [
        { name: "hello.txt", type: "text/plain", content_base64: text },
        { name: "empty.bin", type: octet, content_base64: "" },
        { name: "bytes.bin", type: octet, content_base64: bytes },
      ]),
      // Above the 4,096-byte minimum, so Padmé rounds the stream: to 10,240 bytes.
      await makeCase("rounded", 0x31, "", "bundle", [
        { name: "ten-thousand.bin", type: octet, generated: { seed: 18, length: 10000 } },
      ]),
      // Names that JSON.stringify and Go's encoding/json escape differently, a lone
      // surrogate, empty files, and a file across the first chunk boundary.
      await makeCase("names", 0x51, "", "bundle", [
        { name: "<a & b>.txt", type: "text/plain", content_base64: "" },
        {
          name: 'say "hi".txt',
          type: 'text/plain; charset="utf-8"',
          generated: { seed: 31, length: 30000 },
        },
        { name: "back\\slash/and/slash.txt", type: octet, content_base64: "" },
        {
          name: "tab\there\b\f\n\r\u0007\u001f\u007f.bin",
          type: "application/x-\u0000",
          generated: { seed: 32, length: 40000 },
        },
        {
          name: "Grüße    📄.txt",
          type: "text/plain",
          content_base64: toBase64(new TextEncoder().encode("fünf")),
        },
        { name: "lone \ud800 surrogate.txt", type: "text/plain", content_base64: "" },
      ]),
    ];
    if (process.env.VECTORS_BIG) {
      cases.push(
        await makeCase("boundaries", 0x41, "", "bundle", [
          { name: "zero.bin", type: octet, generated: { seed: 11, length: 0 } },
          { name: "one.bin", type: octet, generated: { seed: 12, length: 1 } },
          {
            name: "under.bin",
            type: octet,
            generated: { seed: 13, length: BUNDLE_PIECE_SIZE - 1 },
          },
          { name: "exact.bin", type: octet, generated: { seed: 14, length: BUNDLE_PIECE_SIZE } },
          { name: "over.bin", type: octet, generated: { seed: 15, length: BUNDLE_PIECE_SIZE + 1 } },
          {
            name: "four-mib-plus.bin",
            type: octet,
            generated: { seed: 16, length: 4 * 1024 * 1024 + 3 },
          },
        ]),
      );
      const many = Array.from({ length: 1500 }, (_, i) => ({
        name: `many/file-${String(i).padStart(4, "0")}.txt`,
        type: "text/plain",
        generated: { seed: 100 + i, length: i % 97 },
      }));
      const listLength = planStream(
        many.map((f) => ({ name: f.name, type: f.type, size: f.generated.length })),
      ).listBytes.length;
      if (listLength <= BUNDLE_PIECE_SIZE) {
        throw new Error(`the list of ${listLength} bytes must span two chunks`);
      }
      cases.push(await makeCase("many", 0x61, "", "bundle", many));
    }
    const transfer = [
      makeTransferCase(
        "canonical",
        "512-zombie-aardvark",
        "https://secretli.app",
        0x20,
        "https://secretli.app/s#dHMtdmVjdG9ycy1zaGFyZS1zZWNyZXQtMDAwMDAwMDA",
      ),
      makeTransferCase(
        "typed",
        "\t9_ABAND aBbReV\n",
        "http://localhost:8080",
        0x60,
        "http://localhost:8080/s#dHMtdmVjdG9ycy1zaGFyZS1zZWNyZXQtMDAwMDAwMDA!dHMtdmVjdG9ycy1kZWxldGlvbi10b2tlbi0wMDAwMDA",
      ),
    ];
    mkdirSync(dir, { recursive: true });
    const vectors: Vectors = { cases, transfer };
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
      expect(v.transfer?.length ?? 0).toBeGreaterThan(0);
      for (const c of v.cases) {
        await checkCase(c);
      }
      for (const c of v.transfer) {
        checkTransferCase(c);
      }
    });
  }
});
