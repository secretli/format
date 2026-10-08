# @secretli/format

The encrypted format behind [Secretli](https://secretli.app), in TypeScript: deriving keys and tokens from a share secret, the metadata envelope, the bundle of sealed 4 MiB records with its manifest and footer, share links, and handing a link to another device with a short code.

The package is pure. It talks to no server and keeps no state; encryption and decryption happen wherever the key is. Its only dependencies are [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers), [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes).

A Go implementation of the same format lives in the same repository, and the two are held to each other by vectors that each side encrypts and the other must decrypt. The specification both follow is [FORMAT.md](https://github.com/secretli/format/blob/main/FORMAT.md).

## Install

The package is not on a registry. Each [release](https://github.com/secretli/format/releases) carries it as an archive; depend on the archive's URL:

```bash
pnpm add https://github.com/secretli/format/releases/download/v0.2.0/secretli-format-0.2.0.tgz
```

It ships as ES modules with type declarations, for browsers and Node 20 or later.

## Use

```ts
import {
  KeySet,
  createEncryptedBundle,
  decryptBundleFiles,
  parseShareLink,
  readBundleManifest,
} from "@secretli/format";

// Making a secret: fresh keys, the blob keys optionally derived with a password.
const keys = await KeySet.generateRandom();
const blobKeys = await KeySet.fromShareSecret(keys.getEncoded().shareSecret, "optional password");
const { blob, manifest } = await createEncryptedBundle([new File(["notes"], "notes.txt")], blobKeys);
const envelope = await keys.encryptMeta({
  type: "bundle",
  password_protected: true,
  bundle_name: manifest.bundleName,
});

// Opening one: the share secret from the link, the password if any, and byte ranges of the bundle.
const bytes = new Uint8Array(await blob.arrayBuffer());
const range = async (start: number, end: number) => bytes.slice(start, end + 1);
const read = await readBundleManifest(range, blobKeys, bytes.length);
const files = await decryptBundleFiles(read.manifest.files, blobKeys, range);
```

`createEncryptedBundle` builds the whole bundle in memory, which suits small secrets. For large files, encrypt record by record from `planBundle` and stream the records to wherever they go. The plan's manifest carries the padding that keeps the bundle's size from saying much (FORMAT.md section 6), so encrypting `JSON.stringify(plan.manifest)` after the records and adding the footer gives exactly `plan.totalSize` bytes. Uploading and retrieval sessions belong to the Secretli server's API, not to this package.

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
