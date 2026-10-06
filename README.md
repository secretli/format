# Secretli format

The encrypted format behind [Secretli](https://secretli.app): how a share secret becomes keys and tokens, how the metadata envelope and the bundle of sealed records are laid out, and what a link looks like. Two implementations, one specification, and tests that hold them to each other.

- **[FORMAT.md](FORMAT.md)** is the specification. Everything else follows it.
- **Go**: `github.com/secretli/format` with the packages `keys`, `bundle` and `link`.
- **TypeScript**: [`@secretli/format`](https://www.npmjs.com/package/@secretli/format) on npm.
- **Vectors**: each implementation encrypts fixtures that the other one's tests must decrypt. The small ones are committed under `vectors/testdata`; CI regenerates large, multi-chunk ones on both sides at every run.

The library is pure. It talks to no server, keeps no state, and has no dependencies beyond the crypto primitives (`golang.org/x/crypto`, `@noble/ciphers`, `@noble/hashes`). What goes over the wire is the business of the clients that use it: the [web app](https://github.com/pscheid92/secretli) and the command-line client.

## Go

```bash
go get github.com/secretli/format
```

```go
import (
    "github.com/secretli/format/bundle"
    "github.com/secretli/format/keys"
    "github.com/secretli/format/link"
)

// Making a secret: fresh keys, optionally with a password, then a bundle.
ks, _ := keys.Generate()
blobKeys, _ := ks.WithPassword("optional")
sources := []bundle.Source{{Name: "notes.txt", Type: "text/plain", Size: 5, Reader: strings.NewReader("notes")}}
plan, _ := bundle.NewPlan(sources, bundle.DefaultBundleName([]string{"notes.txt"}))
envelope, _ := ks.EncryptMeta(keys.Meta{Type: "bundle", PasswordProtected: true, BundleName: plan.Manifest.BundleName})
data, _ := bundle.Encrypt(plan, sources, blobKeys) // small bundles; stream plan.Records yourself for large ones
l := link.Link{Origin: "https://secretli.app", Secret: ks.Encoded().ShareSecret, DeletionToken: ks.Encoded().DeletionToken}

// Opening one: the link's secret, the password if any, and byte ranges of the bundle.
parsed, _ := link.Parse(l.String())
blobKeys, _ = keys.FromShareSecret(parsed.Secret, "optional")
fetch := func(_ context.Context, start, end int64) ([]byte, error) { return data[start : end+1], nil }
manifest, _ := bundle.ReadManifest(ctx, fetch, blobKeys, int64(len(data)))
_ = bundle.DecryptFile(ctx, fetch, blobKeys, manifest.Files[0], os.Stdout, nil)
```

## TypeScript

```bash
npm install @secretli/format
```

```ts
import {
  KeySet, createEncryptedBundle, readBundleManifest, decryptBundleFiles, parseShareLink,
} from "@secretli/format";

const keys = await KeySet.generateRandom();
const blobKeys = await KeySet.fromShareSecret(keys.getEncoded().shareSecret, "optional");
const { blob, manifest } = await createEncryptedBundle([new File(["notes"], "notes.txt")], blobKeys);
const envelope = await keys.encryptMeta({ type: "bundle", password_protected: true, bundle_name: manifest.bundleName });

const bytes = new Uint8Array(await blob.arrayBuffer());
const range = async (start: number, end: number) => bytes.slice(start, end + 1);
const read = await readBundleManifest(range, blobKeys, bytes.length);
const files = await decryptBundleFiles(read.manifest.files, blobKeys, range);
```

Both snippets leave out error handling. The upload protocol (sessions, parts) and the retrieval sessions belong to the server's API, not to this library.

## Changing the format

A change touches the specification, both implementations and both committed vector files in one pull request; CI's interop job fails otherwise. Readers keep accepting the previous form for as long as old secrets can exist. Regenerate the committed vectors with:

```bash
cd ts && WRITE_VECTORS=../vectors/testdata pnpm vitest run test/vectors.test.ts
go test ./vectors -run TestWritesGoVectors -args -write-vectors=testdata
```

## Releases

A tag `v0.1.0` is the Go module version and publishes `@secretli/format@0.1.0` to npm, after the workflow checks that `ts/package.json` carries the same number. Bump the version in one commit, tag it, push the tag.

## License

MIT.
