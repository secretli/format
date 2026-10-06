# @secretli/format

The encrypted format behind [Secretli](https://secretli.app), in TypeScript: deriving keys and tokens from a share secret, the metadata envelope, the bundle of sealed 4 MiB records with its manifest and footer, and share links.

The package is pure. It talks to no server and keeps no state; encryption and decryption happen wherever the key is. Its only dependencies are [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes).

A Go implementation of the same format lives in the same repository, and the two are held to each other by vectors that each side encrypts and the other must decrypt. The specification both follow is [FORMAT.md](https://github.com/secretli/format/blob/main/FORMAT.md).

## Install

The package is not on a registry. Each [release](https://github.com/secretli/format/releases) carries it as an archive; depend on the archive's URL:

```bash
pnpm add https://github.com/secretli/format/releases/download/v0.1.2/secretli-format-0.1.2.tgz
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

`createEncryptedBundle` builds the whole bundle in memory, which suits small secrets. For large files, encrypt record by record from `planBundle` and stream the records to wherever they go. Uploading and retrieval sessions belong to the Secretli server's API, not to this package.

## License

MIT
