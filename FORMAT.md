# The Secretli format

This is the contract between everything that makes or opens a Secretli secret: the web app and the command-line client, which use the TypeScript (`ts/`) and Go (`keys`, `bundle`, `link`) implementations in this repository, and anything else that wants to interoperate. The server never sees plaintext or keys; it stores what this document calls ciphertext and token hashes, and nothing below depends on how it does that.

Two independent implementations exist on purpose. They are checked against each other by vectors (section 10), so a change to the format is a change to both implementations, both vector files and this document, in one commit.

## 1. Encodings and primitives

- **Bytes as text** are unpadded base64url (RFC 4648 §5, no `=`) everywhere: links, tokens, the metadata envelope.
- **Hashing**: SHA-256, lower-case hex, for the manifest and for upload parts; SHA-512 inside HKDF.
- **Key derivation**: HKDF-SHA512 (RFC 5869) with no salt, which the RFC defines as a salt of 64 zero bytes, and an info string.
- **Password derivation**: scrypt with N = 2^14, r = 8, p = 1, 32 bytes out.
- **Encryption**: XChaCha20-Poly1305 with a 24-byte nonce and a 16-byte tag. Every message gets a fresh random nonce, stored in front of the ciphertext.
- **Integers** in the footer are big-endian.

## 2. The share secret and what is derived from it

A secret begins with 32 random bytes, the **share secret**. It is all a recipient needs, and it travels in the link. Everything else is derived with HKDF-SHA512 and `info = "secretli:derivation:v1:" + name`:

| name | bytes | purpose |
|---|---|---|
| `public_id` | 16 | the id the server files the secret under (22 characters encoded) |
| `metadata_token` | 32 | the right to read the metadata envelope and to ask what became of a gone secret (43 characters) |
| `meta_key` | 32 | encrypts the metadata envelope |
| `blob_key` | 32 | encrypts the bundle records |
| `blob_token` | 32 | the right to open a retrieval session, which reads the bundle (43 characters) |
| `password_salt` | 32 | the salt for the password derivation |

`public_id`, `metadata_token`, `meta_key` and `password_salt` are always derived from the share secret itself. `blob_key` and `blob_token` are derived from the **blob material**: the share secret when the secret has no password, otherwise `scrypt(password as UTF-8, password_salt, N = 2^14, r = 8, p = 1, 32 bytes)`.

So anyone with the link can read the metadata and learn that there is a password, but only the password holder can derive the token the server demands for the content, and the server cannot tell a wrong password from a wrong link.

The **deletion token** is 32 random bytes and is not derived from anything. It is the one thing the owner has and recipients do not.

The server stores SHA-256 hashes of the three tokens, never the tokens, and compares in constant time.

## 3. Links

```
https://<host>/s#<share secret>                      the link to hand out
https://<host>/s#<share secret>!<deletion token>      the owner link
```

Both parts are exactly 43 base64url characters. The fragment never reaches the server. Implementations refuse anything else: another path, another length, other characters.

## 4. The metadata envelope

`GET /api/v1/secrets/{public_id}/meta` returns `encrypted_meta`:

```
v2$<base64url(nonce)>$<base64url(ciphertext)>
```

The plaintext is JSON:

```json
{"type":"text","password_protected":false,"bundle_name":"secret.txt"}
```

sealed with `meta_key`, a random 24-byte nonce, and the AAD `public_id || "meta"` (the 16 raw bytes followed by the four ASCII letters). `type` is `text` for a note and `bundle` for files; either way the content is a bundle (section 5), a note being a bundle of one file named `secret.txt` with type `text/plain`. `bundle_name` is the manifest's bundle name (section 6) and may be absent.

Readers accept only version `v2` and a 24-byte nonce.

## 5. The bundle

The blob the server stores is one bundle:

```
record 0 | record 1 | … | record n−1 | encrypted manifest | footer (64 bytes)
```

Every file is cut into **chunks of 4 MiB (4,194,304 bytes) of plaintext**, the last chunk of a file holding whatever remains. An empty file has no chunks. Each chunk becomes one **record**:

```
nonce (24 bytes) | XChaCha20-Poly1305(blob_key, nonce, chunk, AAD) (chunk length + 16)
```

so a record is 40 bytes longer than its chunk. The records of all files follow one another in file order, then chunk order, starting at offset 0, with no gaps.

The AAD of every record is `public_id || "bundle" || 0x00 || suffix`, where the suffix binds the record to its place:

- for a chunk, `"chunk:" + fileIndex + ":" + chunkIndex + ":" + plaintextSize` in decimal ASCII, `fileIndex` being the file's position in the manifest and `chunkIndex` the chunk's position in the file, both counted from 0;
- for the manifest, `"manifest:v2"`.

Because the AAD carries position and size, a record that is moved, duplicated or cut fails to open, and the content needs no checksum of its own.

## 6. The manifest

The manifest lists the files and where their records are. Its JSON is encrypted as one record with the manifest AAD, so the encrypted manifest is also 40 bytes longer than its plaintext:

```json
{
  "version": 2,
  "bundleName": "Secretli bundle (2 files)",
  "chunkSize": 4194304,
  "files": [
    {
      "index": 0,
      "path": "notes.txt",
      "name": "notes.txt",
      "type": "text/plain",
      "size": 5,
      "chunks": [
        { "index": 0, "offset": 0, "length": 45, "plaintextSize": 5 }
      ]
    }
  ]
}
```

`offset` counts bytes from the start of the bundle; `length` is the record's length. `type` is `application/octet-stream` when the type is unknown. The default bundle name is the file's name for one file (or `Secretli file` when it has none) and `Secretli bundle (N files)` for several. The encoded manifest must not exceed 256 KiB (262,144 bytes).

Readers validate before trusting a manifest: version 2; `chunkSize` 4,194,304; a non-empty bundle name; at least one file; file and chunk indices equal to their positions; non-empty `path` and `name`; `size` ≥ 0; every chunk with `0 < plaintextSize ≤ chunkSize` and `length = plaintextSize + 40`; chunk sizes adding up to the file's size (a file of size 0 has no chunks); and all records together tiling the bytes from offset 0 up to the manifest exactly, with neither gap nor overlap.

## 7. The footer

The last 64 bytes of the bundle:

| offset | bytes | content |
|---|---|---|
| 0 | 8 | magic `SLBNDL2\0`, bytes `53 4C 42 4E 44 4C 32 00` |
| 8 | 4 | version, 2 |
| 12 | 4 | footer length, 64 |
| 16 | 8 | length of the encrypted manifest |
| 24 | 32 | SHA-256 of the encrypted manifest |
| 56 | 8 | zero |

A reader fetches the footer, then the encrypted manifest at `bundleSize − 64 − manifestLength`, checks its hash, opens it, validates it, and only then reads records. A manifest length of 40 bytes or less, or above 262,144 + 40, is rejected.

## 8. Reading

The server serves the bundle by byte range (`GET /api/v1/secrets/{public_id}/blob` with `Range: bytes=a-b`, both ends inclusive, at most 128 MiB per request) within a retrieval session. Both implementations read the footer, the manifest, and then records in runs of neighbouring chunks of up to 16 MiB of plaintext; a bundle of at most 1 MiB is fetched whole in one request. None of this changes the bytes; it is how round trips stay few.

## 9. Making a secret

The client derives everything, encrypts the metadata envelope, plans the bundle so that its exact size is known, and starts an upload session (`POST /api/v1/secrets/uploads`) with the public id, the three tokens, the envelope, the lifetime (`5m`, `10m`, `15m`, `1h`, `4h`, `12h`, `1d`, `3d`, `7d`), the one-time flag and the bundle size. It uploads the bundle as parts of up to 32 MiB (the server states the size), every part but the last at least 5 MiB, each with its SHA-256, and completes the session. Records are encrypted one at a time, so neither side ever holds the bundle whole.

The upload limit is 1 GiB of encrypted bundle. Clients check it beforehand with the estimate `plaintext bytes + records × 40 + 262,144 + 40 + 64`.

## 10. Interop vectors

`vectors/testdata/ts-vectors.json` is written by the TypeScript implementation and read by the Go tests; `go-vectors.json` is written by Go and read by the TypeScript tests. Both hold a list of cases:

```json
{
  "cases": [
    {
      "name": "files-password",
      "share_secret": "<base64url>",
      "password": "correct horse battery staple",
      "derived": { "public_id": "…", "metadata_token": "…", "blob_token": "…", "password_blob_token": "…" },
      "meta": { "type": "bundle", "password_protected": true, "bundle_name": "…" },
      "encrypted_meta": "v2$…$…",
      "bundle_name": "…",
      "files": [
        { "name": "hello.txt", "type": "text/plain", "content_base64": "…" },
        { "name": "big.bin", "type": "application/octet-stream", "generated": { "seed": 7, "length": 4194305 } }
      ],
      "bundle_base64": "<the whole bundle, sealed with this case's blob keys>"
    }
  ]
}
```

`password` is empty for a secret without one, and `password_blob_token` then equals `blob_token`. `generated` content comes from xorshift32: with a 32-bit state `x` starting at `seed`, each byte is the low byte of `x` after `x ^= x << 13; x ^= x >> 17; x ^= x << 5` (unsigned 32-bit arithmetic). It lets the vectors cover multi-chunk files without storing megabytes of plaintext.

The committed files hold small cases. CI generates fresh vectors on both sides at every run, including files of 0, 1, 4 MiB − 1, 4 MiB, 4 MiB + 1 and 8 MiB + 3 bytes, and checks that each side reads the other's. The committed files are regenerated with:

```bash
cd ts && WRITE_VECTORS=../vectors/testdata pnpm vitest run test/vectors.test.ts
go test ./vectors -run TestWritesGoVectors -args -write-vectors=testdata
```

## 11. Changing the format

Bump what changes: `v2` in the envelope, the bundle magic and version, the derivation prefix. Keep reading the old form for as long as old secrets can exist, which is seven days plus a week of tombstones. Change both implementations and both vector files, and update this document, in the same change.
