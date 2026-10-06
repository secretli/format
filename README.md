# Secretli format

The encrypted format behind [Secretli](https://secretli.app): how a share secret becomes keys and tokens, how the metadata envelope and the bundle of sealed records are laid out, and what a link looks like. Two implementations, one specification, and tests that hold them to each other.

- **[FORMAT.md](FORMAT.md)** is the specification. Everything else follows it.
- **Go**: `github.com/secretli/format` with the packages `keys`, `bundle` and `link`.
- **TypeScript**: the package `@secretli/format` in `ts/`, attached to every release as an archive.
- **Vectors**: each implementation encrypts fixtures that the other one's tests must decrypt. The small ones are committed under `vectors/testdata`; CI regenerates large, multi-chunk ones on both sides at every run.

The library is pure. It talks to no server, keeps no state, and has no dependencies beyond the crypto primitives (`golang.org/x/crypto`, `@noble/ciphers`, `@noble/hashes`). What goes over the wire is the business of the clients that use it: the [web app](https://github.com/secretli/web) and the [command-line client](https://github.com/secretli/cli).

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

The package is not on any registry. Every release carries it as an archive, and a project depends on that archive's URL:

```bash
pnpm add https://github.com/secretli/format/releases/download/v0.1.2/secretli-format-0.1.2.tgz
```

From then on it is an ordinary dependency named `@secretli/format`: the lockfile pins the archive by its hash, the code imports it by name, and installs need no token. To move to a newer version, add the newer release's archive the same way. It ships as ES modules with type declarations, for browsers and Node 20 or later.

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

A tag such as `v0.1.2` releases both implementations at that version. For Go the tag is the release: the Go module proxy serves it from this repository. For TypeScript the release workflow checks that `ts/package.json` carries the same version, packs `ts/`, signs the archive with a build attestation, and attaches it to the GitHub release. To check a downloaded archive:

```bash
gh attestation verify secretli-format-0.1.2.tgz --repo secretli/format
```

Bump the version in `ts/package.json` in one commit, tag it, push the tag. Tags are permanent once the Go proxy has seen them: never move or delete one, release a new version instead.

## License

MIT.
