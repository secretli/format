import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { base64UrlDecode, base64UrlEncode } from "../src/base64";
import {
  BUNDLE_CHUNK_OVERHEAD_BYTES,
  BUNDLE_RECORD_OVERHEAD_BYTES,
  bundleChunkNonce,
  KeySet,
  type SecretMeta,
} from "../src/encryption";

// Bundle records are bound to their position in the bundle; any suffix works
// as long as encryption and decryption agree.
const recordAad = new TextEncoder().encode("record:0:0:8");

// Password tests run the real scrypt derivation: well under a second locally,
// but up to and past the 5 s default on a busy CI runner.
const SCRYPT_TESTS = { timeout: 30_000 };

describe("KeySet", () => {
  describe("generateRandom", () => {
    it("creates a keyset with non-empty encoded fields", async () => {
      const ks = await KeySet.generateRandom();
      const encoded = ks.getEncoded();
      expect(encoded.shareSecret).toBeTruthy();
      expect(encoded.publicID).toBeTruthy();
      expect(encoded.metadataToken).toBeTruthy();
      expect(encoded.blobToken).toBeTruthy();
      expect(encoded.deletionToken).toBeTruthy();
    });

    it("generates unique keysets each time", async () => {
      const a = await KeySet.generateRandom();
      const b = await KeySet.generateRandom();
      expect(a.getEncoded().shareSecret).not.toBe(b.getEncoded().shareSecret);
    });
  });

  describe("fromShareSecret", () => {
    it("rejects share secrets that are not 32 bytes", async () => {
      await expect(KeySet.fromShareSecret(base64UrlEncode(new Uint8Array(31)))).rejects.toThrow(
        "invalid share secret",
      );
      await expect(KeySet.fromShareSecret("")).rejects.toThrow("invalid share secret");
      await expect(
        KeySet.fromShareSecret(base64UrlEncode(new Uint8Array(32))),
      ).resolves.toBeInstanceOf(KeySet);
    });
  });

  describe("encryptBundlePart/decryptBundlePart", () => {
    it("round-trips text as bytes", async () => {
      const ks = await KeySet.generateRandom();
      const plaintext = "Hello, secret world!";
      const record = ks.encryptBundlePart(new TextEncoder().encode(plaintext), recordAad);
      expect(new TextDecoder().decode(ks.decryptBundlePart(record, recordAad))).toBe(plaintext);
    });

    it("round-trips empty data", async () => {
      const ks = await KeySet.generateRandom();
      const record = ks.encryptBundlePart(new Uint8Array(0), recordAad);
      expect(ks.decryptBundlePart(record, recordAad).length).toBe(0);
    });

    it("round-trips binary data", async () => {
      const ks = await KeySet.generateRandom();
      const data = crypto.getRandomValues(new Uint8Array(1024));
      const record = ks.encryptBundlePart(data, recordAad);
      expect(ks.decryptBundlePart(record, recordAad)).toEqual(data);
    });

    it("adds exactly a nonce and an auth tag", async () => {
      const ks = await KeySet.generateRandom();
      const record = ks.encryptBundlePart(new Uint8Array(100), recordAad);
      // 24 byte nonce + 100 byte data + 16 byte Poly1305 tag
      expect(BUNDLE_RECORD_OVERHEAD_BYTES).toBe(40);
      expect(record.length).toBe(100 + BUNDLE_RECORD_OVERHEAD_BYTES);
    });

    it("never repeats a record for the same plaintext", async () => {
      const ks = await KeySet.generateRandom();
      const data = new TextEncoder().encode("same plaintext");
      expect(ks.encryptBundlePart(data, recordAad)).not.toEqual(
        ks.encryptBundlePart(data, recordAad),
      );
    });

    it("rejects a record bound to a different position", async () => {
      const ks = await KeySet.generateRandom();
      const record = ks.encryptBundlePart(new TextEncoder().encode("data"), recordAad);
      const otherAad = new TextEncoder().encode("record:1:0:8");
      expect(() => ks.decryptBundlePart(record, otherAad)).toThrow();
    });

    it("rejects a truncated record", async () => {
      const ks = await KeySet.generateRandom();
      expect(() => ks.decryptBundlePart(new Uint8Array(8), recordAad)).toThrow(
        "invalid bundle record",
      );
    });
  });

  describe("encryptMeta/decryptMeta", () => {
    it("round-trips text metadata", async () => {
      const ks = await KeySet.generateRandom();
      const meta = { type: "text" as const, password_protected: false };
      const envelope = await ks.encryptMeta(meta);
      const decrypted = await ks.decryptMeta(envelope);
      expect(decrypted).toEqual(meta);
    });

    it("round-trips bundle metadata", async () => {
      const ks = await KeySet.generateRandom();
      const meta = { type: "bundle" as const, password_protected: true };
      const envelope = await ks.encryptMeta(meta);
      const decrypted = await ks.decryptMeta(envelope);
      expect(decrypted).toEqual(meta);
    });

    it("produces v2$nonce$ciphertext format", async () => {
      const ks = await KeySet.generateRandom();
      const envelope = await ks.encryptMeta({ type: "text", password_protected: false });
      const parts = envelope.split("$");
      expect(parts).toHaveLength(3);
      expect(parts[0]).toBe("v2");
    });

    it("rejects invalid envelope format", async () => {
      const ks = await KeySet.generateRandom();
      await expect(ks.decryptMeta("bad-format")).rejects.toThrow(
        "invalid metadata envelope format",
      );
    });
  });

  describe("fromShareSecret", () => {
    it("derives the same IDs and tokens from the share secret", async () => {
      const original = await KeySet.generateRandom();
      const encoded = original.getEncoded();

      const restored = await KeySet.fromShareSecret(encoded.shareSecret);
      const restoredEncoded = restored.getEncoded();

      expect(restoredEncoded.publicID).toBe(encoded.publicID);
      expect(restoredEncoded.metadataToken).toBe(encoded.metadataToken);
      expect(restoredEncoded.blobToken).toBe(encoded.blobToken);
    });

    it("can decrypt a record encrypted by the original keyset", async () => {
      const original = await KeySet.generateRandom();
      const plaintext = "secret message";
      const record = original.encryptBundlePart(new TextEncoder().encode(plaintext), recordAad);

      const restored = await KeySet.fromShareSecret(original.getEncoded().shareSecret);
      expect(new TextDecoder().decode(restored.decryptBundlePart(record, recordAad))).toBe(
        plaintext,
      );
    });

    it("can decrypt metadata encrypted by the original keyset", async () => {
      const original = await KeySet.generateRandom();
      const meta = { type: "bundle" as const, password_protected: false };
      const envelope = await original.encryptMeta(meta);

      const restored = await KeySet.fromShareSecret(original.getEncoded().shareSecret);
      const decrypted = await restored.decryptMeta(envelope);
      expect(decrypted).toEqual(meta);
    });
  });

  describe("fromShareSecret with password", SCRYPT_TESTS, () => {
    // Pinned to what existing links derive: any change to the password key
    // derivation would lock every password-protected share out.
    it("derives the same keys as before for a known share secret and password", async () => {
      const shareSecret = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => i));
      expect(shareSecret).toBe("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");

      const ks = await KeySet.fromShareSecret(shareSecret, "correct horse battery staple");

      expect(ks.getEncoded()).toMatchObject({
        publicID: "gTqWSKubP-RW3j-tZxyMBQ",
        metadataToken: "upt3zqqpEe7dfskJqEb2rLwnYZHkKscHbfK4r0U_O7o",
        blobToken: "NTy8bKx4HqQl5hYppfexV7RGrA0M3UbJueugqsVeG-w",
      });
    });

    it("derives keys with password and can decrypt own data", async () => {
      const original = await KeySet.generateRandom();
      const shareSecret = original.getEncoded().shareSecret;

      const withPw = await KeySet.fromShareSecret(shareSecret, "my-password");
      const data = new TextEncoder().encode("password-protected secret");
      const record = withPw.encryptBundlePart(data, recordAad);

      const restored = await KeySet.fromShareSecret(shareSecret, "my-password");
      expect(new TextDecoder().decode(restored.decryptBundlePart(record, recordAad))).toBe(
        "password-protected secret",
      );
    });

    it("keeps public metadata identifiers stable across different passwords", async () => {
      const original = await KeySet.generateRandom();
      const shareSecret = original.getEncoded().shareSecret;

      const ks1 = await KeySet.fromShareSecret(shareSecret, "password-a");
      const ks2 = await KeySet.fromShareSecret(shareSecret, "password-b");

      expect(ks1.getEncoded().publicID).toBe(ks2.getEncoded().publicID);
      expect(ks1.getEncoded().metadataToken).toBe(ks2.getEncoded().metadataToken);
      expect(ks1.getEncoded().blobToken).not.toBe(ks2.getEncoded().blobToken);
    });

    it("password-derived blob tokens differ from no-password blob tokens", async () => {
      const original = await KeySet.generateRandom();
      const shareSecret = original.getEncoded().shareSecret;

      const noPw = await KeySet.fromShareSecret(shareSecret);
      const withPw = await KeySet.fromShareSecret(shareSecret, "some-password");

      expect(noPw.getEncoded().publicID).toBe(withPw.getEncoded().publicID);
      expect(noPw.getEncoded().metadataToken).toBe(withPw.getEncoded().metadataToken);
      expect(noPw.getEncoded().blobToken).not.toBe(withPw.getEncoded().blobToken);
    });

    it("wrong password cannot decrypt data", async () => {
      const original = await KeySet.generateRandom();
      const shareSecret = original.getEncoded().shareSecret;

      const withPw = await KeySet.fromShareSecret(shareSecret, "correct-password");
      const record = withPw.encryptBundlePart(new TextEncoder().encode("secret"), recordAad);

      const wrongPw = await KeySet.fromShareSecret(shareSecret, "wrong-password");
      expect(() => wrongPw.decryptBundlePart(record, recordAad)).toThrow();
    });
  });

  describe("password-protected workflow", SCRYPT_TESTS, () => {
    it("metadata encrypted with base key, data with password key", async () => {
      const keySet = await KeySet.generateRandom();
      const shareSecret = keySet.getEncoded().shareSecret;

      // Create: metadata with base key, data with password key
      const meta = { type: "text" as const, password_protected: true };
      const encryptedMeta = await keySet.encryptMeta(meta);
      const passwordKeySet = await KeySet.fromShareSecret(shareSecret, "the-password");
      const record = passwordKeySet.encryptBundlePart(
        new TextEncoder().encode("secret data"),
        recordAad,
      );

      // Retrieve: decrypt metadata with base key (no password needed)
      const restored = await KeySet.fromShareSecret(shareSecret);
      const decryptedMeta = await restored.decryptMeta(encryptedMeta);
      expect(decryptedMeta.password_protected).toBe(true);
      expect(restored.getEncoded().blobToken).not.toBe(passwordKeySet.getEncoded().blobToken);
      expect(() => restored.decryptBundlePart(record, recordAad)).toThrow();

      // Decrypt data with password key
      const restoredPw = await KeySet.fromShareSecret(shareSecret, "the-password");
      expect(new TextDecoder().decode(restoredPw.decryptBundlePart(record, recordAad))).toBe(
        "secret data",
      );

      // Wrong password fails
      const wrongPw = await KeySet.fromShareSecret(shareSecret, "wrong");
      expect(() => wrongPw.decryptBundlePart(record, recordAad)).toThrow();
    });
  });

  describe("AAD enforcement", () => {
    it("rejects decryption with a different KeySet (different publicID)", async () => {
      const ksA = await KeySet.generateRandom();
      const ksB = await KeySet.generateRandom();

      const meta = { type: "text" as const, password_protected: false };
      const envelope = await ksA.encryptMeta(meta);
      await expect(ksB.decryptMeta(envelope)).rejects.toThrow();
    });

    it("rejects record decryption with a different KeySet", async () => {
      const ksA = await KeySet.generateRandom();
      const ksB = await KeySet.generateRandom();

      const record = ksA.encryptBundlePart(new TextEncoder().encode("data"), recordAad);
      expect(() => ksB.decryptBundlePart(record, recordAad)).toThrow();
    });

    it("rejects meta ciphertext used as a bundle record (wrong AAD purpose)", async () => {
      const ks = await KeySet.generateRandom();
      const envelope = await ks.encryptMeta({ type: "text" as const, password_protected: false });

      // Re-frame the metadata nonce and ciphertext as a bundle record.
      const parts = envelope.split("$");
      const nonce = base64UrlDecode(parts[1]);
      const ciphertext = base64UrlDecode(parts[2]);
      const record = new Uint8Array(nonce.length + ciphertext.length);
      record.set(nonce, 0);
      record.set(ciphertext, nonce.length);

      // Decryption fails: the AAD purpose is "bundle", not "meta".
      expect(() => ks.decryptBundlePart(record, recordAad)).toThrow();
    });
  });

  describe("old envelope rejection", () => {
    it("rejects v1 metadata envelopes", async () => {
      const ks = await KeySet.generateRandom();
      const nonce = base64UrlEncode(crypto.getRandomValues(new Uint8Array(12)));
      const ciphertext = base64UrlEncode(new TextEncoder().encode("ciphertext"));

      await expect(ks.decryptMeta(`v1$${nonce}$${ciphertext}`)).rejects.toThrow(
        "invalid metadata envelope format",
      );
    });
  });

  describe("envelope padding", () => {
    const shareSecret = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => i));

    /** Opens an envelope with keys derived here, apart from KeySet: the plaintext, padding included. */
    function openEnvelope(envelope: string): Uint8Array {
      const secret = base64UrlDecode(shareSecret);
      const label = (name: string) => new TextEncoder().encode(`secretli:derivation:v1:${name}`);
      const metaKey = hkdf(sha512, secret, undefined, label("meta_key"), 32);
      const publicID = hkdf(sha512, secret, undefined, label("public_id"), 16);
      const aad = new Uint8Array([...publicID, ...new TextEncoder().encode("meta")]);
      const [, nonce, ciphertext] = envelope.split("$");
      return xchacha20poly1305(metaKey, base64UrlDecode(nonce), aad).decrypt(
        base64UrlDecode(ciphertext),
      );
    }

    it("pads every ordinary envelope to 740 characters", async () => {
      const ks = await KeySet.fromShareSecret(shareSecret);
      for (const meta of [
        { type: "text", password_protected: false },
        { type: "bundle", password_protected: true },
      ] as const) {
        const envelope = await ks.encryptMeta(meta);
        expect(envelope.length).toBe(740);
        const json = JSON.stringify(meta);
        expect(new TextDecoder().decode(openEnvelope(envelope))).toBe(
          json + " ".repeat(512 - json.length),
        );
        await expect(ks.decryptMeta(envelope)).resolves.toEqual(meta);
      }
    });

    it("writes only the fields it knows", async () => {
      const ks = await KeySet.fromShareSecret(shareSecret);
      const old = { type: "bundle", password_protected: false, bundle_name: "secret.txt" };
      const envelope = await ks.encryptMeta(old as SecretMeta);
      expect(new TextDecoder().decode(openEnvelope(envelope)).trimEnd()).toBe(
        '{"type":"bundle","password_protected":false}',
      );
    });

    it("stops where the server's limit would", async () => {
      const ks = await KeySet.fromShareSecret(shareSecret);
      const around = '{"type":"","password_protected":false}'.length;
      // At 6,000 bytes the JSON would round to 6,144: the envelope stops at 8,192.
      for (const [json, plaintext, characters] of [
        [6000, 6101, 8192],
        [6101, 6101, 8192],
        [6200, 6200, 8324],
        [513, 544, 783],
      ]) {
        const meta = { type: "x".repeat(json - around), password_protected: false };
        const envelope = await ks.encryptMeta(meta as unknown as SecretMeta);
        expect(openEnvelope(envelope).length).toBe(plaintext);
        expect(envelope.length).toBe(characters);
        await expect(ks.decryptMeta(envelope)).resolves.toEqual(meta);
      }
    });

    it("opens envelopes from before padding, with the bundle name they carried", async () => {
      // Written by this implementation before envelopes were padded.
      const ks = await KeySet.fromShareSecret(shareSecret);
      const bundle = await ks.decryptMeta(
        "v2$QuBjEhrsGr3pvv9wRhlIac_NN4EVXt54$VE557SnLoKMsmPeMqQY5RT5MvzPF19Zfm3REcqH4hIoNaG9xCWQ4_J2X9o0EYPdUgFnpzE3Dc6MW6LVaFKP4I-Bu9diGeUB9pdJ9dQw4PWNO75NB23qMuOp2jl793KocSRohka4",
      );
      expect(bundle).toMatchObject({ type: "bundle", password_protected: true });
      const text = await ks.decryptMeta(
        "v2$Gbc53Ya5NjqescrUcUjlQyNNXAwRb9Hv$yXIUTdkte_qyeIdL5CN_DFfIngBMB-VoWLgYfDgYSJ6qxsPKqOZSe034Bb8anvoGpbPOAdHvFlqSae2O_fnilbrUYRp9A471Cb5PO25p3NjbtiRO9A",
      );
      expect(text).toMatchObject({ type: "text", password_protected: false });
    });
  });

  describe("bundle chunks", () => {
    const prefix = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);

    it("lays out the nonce as prefix, seven bytes of index and the last flag", () => {
      expect(Array.from(bundleChunkNonce(prefix, 0x0102030405, true))).toEqual([
        ...prefix,
        0,
        0,
        1,
        2,
        3,
        4,
        5,
        1,
      ]);
      expect(Array.from(bundleChunkNonce(prefix, Number.MAX_SAFE_INTEGER, false))).toEqual([
        ...prefix,
        0x1f,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0,
      ]);
      expect(() => bundleChunkNonce(prefix, -1, false)).toThrow("chunk index out of range");
      expect(() => bundleChunkNonce(prefix, 1.5, false)).toThrow("chunk index out of range");
      expect(() => bundleChunkNonce(prefix.subarray(1), 0, false)).toThrow("16 bytes");
    });

    it("seals as FORMAT.md section 5 says and opens only in place", async () => {
      const shareSecret = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => 7 * i));
      const ks = await KeySet.fromShareSecret(shareSecret);
      const plaintext = new TextEncoder().encode("a piece of the stream");
      const chunk = ks.encryptBundleChunk(prefix, 3, false, plaintext);
      expect(chunk.length).toBe(plaintext.length + BUNDLE_CHUNK_OVERHEAD_BYTES);

      const secret = base64UrlDecode(shareSecret);
      const label = (name: string) => new TextEncoder().encode(`secretli:derivation:v1:${name}`);
      const blobKey = hkdf(sha512, secret, undefined, label("blob_key"), 32);
      const publicID = hkdf(sha512, secret, undefined, label("public_id"), 16);
      const aad = new Uint8Array([
        ...publicID,
        ...new TextEncoder().encode("bundle"),
        0,
        ...new TextEncoder().encode("stream:v3"),
      ]);
      const nonce = new Uint8Array([...prefix, 0, 0, 0, 0, 0, 0, 3, 0]);
      expect(xchacha20poly1305(blobKey, nonce, aad).encrypt(plaintext)).toEqual(chunk);

      expect(ks.decryptBundleChunk(prefix, 3, false, chunk)).toEqual(plaintext);
      expect(() => ks.decryptBundleChunk(prefix, 4, false, chunk)).toThrow();
      expect(() => ks.decryptBundleChunk(prefix, 3, true, chunk)).toThrow();
      expect(() =>
        ks.decryptBundleChunk(
          prefix.map((b) => b ^ 1),
          3,
          false,
          chunk,
        ),
      ).toThrow();
      expect(() => ks.decryptBundleChunk(prefix, 3, false, chunk.subarray(0, 15))).toThrow(
        "invalid bundle chunk",
      );
      const other = await KeySet.fromShareSecret(shareSecret, "a password");
      expect(() => other.decryptBundleChunk(prefix, 3, false, chunk)).toThrow();
    });
  });
});
