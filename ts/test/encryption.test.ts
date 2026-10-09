import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { base64UrlDecode, base64UrlEncode } from "../src/base64";
import {
  BUNDLE_CHUNK_OVERHEAD_BYTES,
  bundleChunkNonce,
  KeySet,
  type SecretMeta,
} from "../src/encryption";

// Data sealed as the one chunk of a bundle, with a fixed prefix, and opened again.
const PREFIX = Uint8Array.from({ length: 16 }, (_, i) => i);
const sealChunk = (ks: KeySet, text: string) =>
  ks.encryptBundleChunk(PREFIX, 0, true, new TextEncoder().encode(text));
const openChunk = (ks: KeySet, chunk: Uint8Array) =>
  new TextDecoder().decode(ks.decryptBundleChunk(PREFIX, 0, true, chunk));

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

    it("can decrypt a chunk sealed by the original keyset", async () => {
      const original = await KeySet.generateRandom();
      const chunk = sealChunk(original, "secret message");

      const restored = await KeySet.fromShareSecret(original.getEncoded().shareSecret);
      expect(openChunk(restored, chunk)).toBe("secret message");
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
      const chunk = sealChunk(withPw, "password-protected secret");

      const restored = await KeySet.fromShareSecret(shareSecret, "my-password");
      expect(openChunk(restored, chunk)).toBe("password-protected secret");
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
      const chunk = sealChunk(withPw, "secret");

      const wrongPw = await KeySet.fromShareSecret(shareSecret, "wrong-password");
      expect(() => openChunk(wrongPw, chunk)).toThrow();
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
      const chunk = sealChunk(passwordKeySet, "secret data");

      // Retrieve: decrypt metadata with base key (no password needed)
      const restored = await KeySet.fromShareSecret(shareSecret);
      const decryptedMeta = await restored.decryptMeta(encryptedMeta);
      expect(decryptedMeta.password_protected).toBe(true);
      expect(restored.getEncoded().blobToken).not.toBe(passwordKeySet.getEncoded().blobToken);
      expect(() => openChunk(restored, chunk)).toThrow();

      // Decrypt data with password key
      const restoredPw = await KeySet.fromShareSecret(shareSecret, "the-password");
      expect(openChunk(restoredPw, chunk)).toBe("secret data");

      // Wrong password fails
      const wrongPw = await KeySet.fromShareSecret(shareSecret, "wrong");
      expect(() => openChunk(wrongPw, chunk)).toThrow();
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

    it("rejects chunk decryption with a different KeySet", async () => {
      const ksA = await KeySet.generateRandom();
      const ksB = await KeySet.generateRandom();

      const chunk = sealChunk(ksA, "data");
      expect(() => openChunk(ksB, chunk)).toThrow();
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
