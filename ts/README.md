# @secretli/format

The encrypted format behind [Secretli](https://secretli.app), in TypeScript: deriving keys and tokens from a share secret, the padded metadata envelope, the bundle (one stream sealed in 64 KiB chunks), share links, and handing a link to another device with a short code.

The package is pure. It talks to no server and keeps no state; encryption and decryption happen wherever the key is. Its only dependencies are [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers), [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes).

A Go implementation of the same format lives in the same repository, and the two are held to each other by vectors that each side encrypts and the other must decrypt. The specification both follow is [FORMAT.md](https://github.com/secretli/format/blob/main/FORMAT.md).

## Install

The package is not on a registry. Each [release](https://github.com/secretli/format/releases) carries it as an archive; depend on the archive's URL:

```bash
pnpm add https://github.com/secretli/format/releases/download/v0.5.0/secretli-format-0.5.0.tgz
```

It ships as ES modules with type declarations, for browsers and Node 20 or later.

## Use

```ts
import { KeySet, cutIntoParts, encryptStream, openBundle, planStream } from "@secretli/format";

// Making a secret: fresh keys, the blob keys optionally derived with a password.
const keys = await KeySet.generateRandom();
const blobKeys = await KeySet.fromShareSecret(keys.getEncoded().shareSecret, "optional password");
const envelope = await keys.encryptMeta({ type: "bundle", password_protected: true });

// The plan needs only names, types and sizes: its totalSize is the exact size of the bundle,
// padding included, to check against the upload limit and declare to the server.
const files = [new File(["notes"], "notes.txt", { type: "text/plain" })];
const plan = planStream(files);
for await (const part of cutIntoParts(encryptStream(plan, files, blobKeys), 32 * 1024 * 1024)) {
  // … upload the part at its offset …
}

// Opening one: the share secret from the link, the password if any, and byte ranges of the bundle.
const opened = await openBundle(fetchRange, blobKeys, size);
for (const file of opened.files) console.log(file.index, file.name, file.type, file.size);
const decrypted = await opened.decryptFiles([0, 2], {
  onProgress: ({ decryptedBytes, totalBytes }) => console.log(decryptedBytes, totalBytes),
});
```

`encryptStream` yields the 16-byte prefix and then one sealed 64 KiB chunk after another, reading each file in 4 MiB slices; `cutIntoParts` turns that into parts of exactly the upload part size, the last one shorter. `plannedBundleSize(files)` is the plan's size alone. `createStreamBundle` builds a whole bundle in memory, which suits tests and small secrets.

`openBundle` fetches a small bundle in one request, and of a larger one only what it needs: the first MiB with the file list, then the chunks of the files asked for, neighbouring ones in one request. `decryptFiles` returns one `Blob` per file, extended as chunks arrive, so a download of a gigabyte never sits in the JavaScript heap. Since 0.5.0 it reads bundle version 3 only; a bundle of version 2 fails to open like a damaged one. Uploading and retrieval sessions belong to the Secretli server's API, not to this package.

A link goes to another device with a code such as `7-acid-rocket`:

```ts
import { createOffer, formatCode, parseCode, randomWords, receiveLink, sendLink } from "@secretli/format";

// Sending: the words and a session id, the offer to open the transfer with, then the link.
const words = randomWords();
const sid = crypto.getRandomValues(new Uint8Array(32));
const party = { words, sid, origin: "https://secretli.app" };
const offer = createOffer(party);
// … open the transfer at the relay with sid and offer.share, get a nameplate …
console.log(formatCode(nameplate, words));
await sendLink(senderRelay, party, offer, link);

// Receiving: parse the typed code, claim the nameplate, get the sid and the offer.
const code = parseCode("7 acid rocket");
if (code.ok) await receiveLink(receiverRelay, { words: code.words, sid, origin }, offerShare);
```

`senderRelay` and `receiverRelay` implement `SenderRelay` and `ReceiverRelay` over the server's transfer API. A wrong code on either side ends in `CodeMismatchError`, and nothing is delivered.

## License

MIT. The code word list is the [EFF short word list 2.0](https://www.eff.org/dice) by the Electronic Frontier Foundation, licensed [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
