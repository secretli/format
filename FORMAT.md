# The Secretli format

This is the contract between everything that makes or opens a Secretli secret: the web app and the command-line client, which use the TypeScript (`ts/`) and Go (`keys`, `bundle`, `link`, `cpace`, `transfer`) implementations in this repository, and anything else that wants to interoperate. The server never sees plaintext or keys; it stores what this document calls ciphertext and token hashes, and nothing below depends on how it does that.

Two independent implementations exist on purpose. They are checked against each other by vectors (section 10), so a change to the format is a change to both implementations, both vector files and this document, in one commit.

## 1. Encodings and primitives

- **Bytes as text** are unpadded base64url (RFC 4648 §5, no `=`) everywhere: links, tokens, the metadata envelope.
- **Hashing**: SHA-256, lower-case hex, for the manifest and for upload parts; SHA-512 inside HKDF.
- **Key derivation**: HKDF-SHA512 (RFC 5869) with no salt, which the RFC defines as a salt of 64 zero bytes, and an info string.
- **Password derivation**: scrypt with N = 2^14, r = 8, p = 1, 32 bytes out.
- **Encryption**: XChaCha20-Poly1305 with a 24-byte nonce and a 16-byte tag. Every message gets a fresh random nonce, stored in front of the ciphertext.
- **Integers** in the footer and in a transferred link's length are big-endian.
- **Handing over a link with a code** (section 11): CPace over ristretto255 with SHA-512, HMAC-SHA512, and HKDF-SHA512 salted with the session id.

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

Next to `cases`, each file holds `transfer`: handovers with a code (section 11) whose session id and both scalars are fixed, so that everything but the sealed link's nonce is reproducible. Bytes are lower-case hex:

```json
{
  "transfer": [
    {
      "name": "typed",
      "code": "  42 Zucch.YOYO ",
      "origin": "http://localhost:8080",
      "sid": "<32 bytes>",
      "sender_scalar": "<32 bytes, little-endian>",
      "receiver_scalar": "<32 bytes, little-endian>",
      "link": "http://localhost:8080/s#…",
      "word_list_sha256": "e298b97f…",
      "derived": {
        "password": "zucchini-yoyo", "channel_identifier": "…", "generator": "…",
        "sender_share": "…", "receiver_share": "…", "k": "…", "isk": "…",
        "confirm_key": "…", "payload_key": "…", "confirmation": "…"
      },
      "sealed": "<the delivery leg>"
    }
  ]
}
```

A reader parses the code as typed, runs both sides with the given scalars, expects every derived value, and opens `sealed` with its own `payload_key` to find `link`.

`password` is empty for a secret without one, and `password_blob_token` then equals `blob_token`. `generated` content comes from xorshift32: with a 32-bit state `x` starting at `seed`, each byte is the low byte of `x` after `x ^= x << 13; x ^= x >> 17; x ^= x << 5` (unsigned 32-bit arithmetic). It lets the vectors cover multi-chunk files without storing megabytes of plaintext.

The committed files hold small cases. CI generates fresh vectors on both sides at every run, including files of 0, 1, 4 MiB − 1, 4 MiB, 4 MiB + 1 and 8 MiB + 3 bytes, and checks that each side reads the other's. The committed files are regenerated with:

```bash
cd ts && WRITE_VECTORS=../vectors/testdata pnpm vitest run test/vectors.test.ts
go test ./vectors -run TestWritesGoVectors -args -write-vectors=testdata
```

## 11. Handing a link over with a code

A link can reach another device as a short code read aloud or typed, such as `7-acid-rocket`, instead of the link itself. The two devices run a password-authenticated key exchange through the server's relay with the code's words as the password, and the sender hands the link over only once the receiver has proved it typed the same words. The relay carries public values and one fixed-size ciphertext; it never learns the words or the link.

The exchange is **CPace** as specified in draft-irtf-cfrg-cpace-21, over ristretto255 with SHA-512 (CPACE-RISTR255-SHA512), in the initiator-responder setting with the sender as initiator. Implementations must reproduce the test vectors of the draft's appendix B.3; both here do (`cpace/cpace_test.go`, `ts/test/cpace.test.ts`).

### 11.1 The code

```
<nameplate>-<word>-<word>
```

The **nameplate**, 1 to 999, is handed out by the relay when the transfer opens and only says which transfer is meant; it is public. The two **words** are the secret. Each is drawn independently and uniformly from the EFF short word list 2.0 (1,296 words, by the Electronic Frontier Foundation, CC BY 3.0 US), with `yo-yo` written `yoyo` because a dash separates the parts of a code. The list in `transfer/words.go` and `ts/src/transferWords.ts` has, over its words in order joined by `\n` with no newline at the end, the SHA-256

```
e298b97fdd0dfeb65678c8aaf7cfb010c1831111a28f1b936abc191c5eb7d3af
```

Readers are lenient with typed codes: lower-case the input; split it on runs of white space, `.`, `-` and `_`; require exactly three parts, the first of one to three ASCII digits with a value from 1 to 999; and take each word as a word of the list or as a prefix of at least three letters of one. Every word of the list has its own first three letters, so such a prefix names at most one word. All of this happens on the device, before anything is sent, so a typo never uses up a transfer.

The relay lets a nameplate be claimed once, and a wrong code ends the transfer as a mismatch (section 11.3). Someone guessing therefore gets one try in 1,296² ≈ 1.7 million per transfer, within the transfer's ten minutes.

### 11.2 The exchange

The inputs to CPace:

| input | value |
|---|---|
| `PRS`, the password | UTF-8 of `word1 + "-" + word2`: the two words, never the nameplate |
| `CI`, the channel identifier | UTF-8 of `"secretli-transfer-v1 " + origin`, the origin as in links (`https://secretli.app`: scheme, host and any port, no trailing slash), so a run is bound to this protocol version and to one server |
| `sid`, the session id | 32 random bytes the sender draws; `base64url(sid)` is also the transfer's id at the relay |
| `ADa`, `ADb` | `"sender"` and `"receiver"` |

Following the draft:

- **Generator**: `g` is ristretto255's element derivation (the one-way map of RFC 9496, section 4.3.4) applied to `SHA-512(generator_string("CPaceRistretto255", PRS, CI, sid))`, where `generator_string` is `lv_cat(DSI, PRS, zero padding, CI, sid)` with as many zero bytes as fill the first 128-byte SHA-512 block, and `lv_cat` prefixes each part with its length, LEB128-encoded.
- **Shares**: each side draws a scalar `y` as 32 random bytes, read little-endian, with the top four bits of the last byte cleared (redrawing zero), and sends `Y = y·g` as its 32-byte encoding. The sender's share is `Ya`, the receiver's `Yb`.
- **Shared point**: `K = scalar_mult_vfy(y, X)` for the other side's share `X`: decode `X`, refusing anything that is not a canonical encoding, multiply, and refuse the neutral element. A refused share is a mismatch.
- **Session key**: `ISK = SHA-512(lv_cat("CPaceRistretto255_ISK", sid, K) || lv_cat(Ya, ADa) || lv_cat(Yb, ADb))`.

From `ISK`, with HKDF-SHA512 salted with `sid` (not the zero salt of section 1):

| value | derivation |
|---|---|
| `confirm_key` | `HKDF-SHA512(ISK, salt = sid, info = "secretli transfer v1 confirm", 32 bytes)` |
| `payload_key` | `HKDF-SHA512(ISK, salt = sid, info = "secretli transfer v1 payload", 32 bytes)` |
| `confirmation` | the first 32 bytes of `HMAC-SHA512(confirm_key, "receiver" \|\| Ya \|\| Yb)` |

The link travels **sealed**: a 512-byte plaintext holding the length of the link's UTF-8 bytes as a two-byte big-endian integer, those bytes, and zeros to the end, so a link may be at most 510 bytes; sealed as `nonce (24 random bytes) || XChaCha20-Poly1305(payload_key, nonce, plaintext, AAD = sid || "payload")`. It is always 552 bytes, so the relay cannot tell a link from an owner link by its length. A reader refuses any other size, a ciphertext that does not open and a length above 510, all as a mismatch.

### 11.3 The legs

1. **Offer.** The sender draws `sid` and two words, computes `Ya`, and opens a transfer with `base64url(sid)` and `base64url(Ya)`. The relay replies with a nameplate, and the sender shows the code.
2. **Answer.** The receiver parses the code, claims the nameplate, and gets `sid` (as the transfer id) and `Ya`. It computes `Yb`, `K`, `ISK` and the keys, and posts `Yb` and `confirmation`.
3. **Delivery.** The sender computes `K` from `Yb` and the keys, and compares the confirmation in constant time. If `Yb` is refused or the confirmation differs, it closes the transfer as a mismatch and delivers nothing. Otherwise it posts the sealed link, which ends the transfer, and the receiver opens it with `payload_key`. A receiver whose transfer is closed as a mismatch, or whose sealed link does not open, reports that the code did not match.

The sender learns from the confirmation that the receiver knows the words before anything secret leaves it; the receiver learns that the sender knew them when the link opens, since only a holder of the words can derive `payload_key`. Everything goes over the wire as unpadded base64url.

The relay is the server's (`/api/v1/transfers`: open, claim by nameplate, each leg written once and long-polled for, close with a reason of `cancelled` or `mismatch`; a transfer lives ten minutes). Its API is the server's contract and not part of this format; nothing above depends on how it stores or forwards the legs.

## 12. Changing the format

Bump what changes: `v2` in the envelope, the bundle magic and version, the derivation prefix, the `v1` in the transfer's channel identifier and key labels. Keep reading the old form for as long as old secrets can exist, which is seven days plus a week of tombstones. Change both implementations and both vector files, and update this document, in the same change.
