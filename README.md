# Secretli format

The encrypted format behind [Secretli](https://secretli.app): how a share secret becomes keys and tokens, how the metadata envelope and the bundle (one stream sealed in 64 KiB chunks) are laid out, what a link looks like, and how a link is handed to another device with a short code. Two implementations, one specification, and tests that hold them to each other.

- **[spec/FORMAT.md](spec/FORMAT.md)** is the specification. Everything else follows it.
- **Go**: the module `github.com/secretli/format`, whose packages live in `go/`: `keys`, `bundle`, `link`, and `transfer` with `cpace` for the short code.
- **TypeScript**: the package `@secretli/format` in `ts/`, attached to every release as an archive.
- **Vectors**: each implementation encrypts fixtures that the other one's tests must decrypt. The small ones are committed under `spec/vectors`; CI regenerates large, multi-chunk ones on both sides at every run.

The library is pure. It talks to no server, keeps no state, and has no dependencies beyond the crypto primitives (`golang.org/x/crypto` and `github.com/gtank/ristretto255`; `@noble/ciphers`, `@noble/curves` and `@noble/hashes`). What goes over the wire is the business of the clients that use it: the [web app](https://github.com/secretli/web) and the [command-line client](https://github.com/secretli/cli).

## What's where

The repository is split by what a change means for a release (see [Changes and releases](#changes-and-releases)):

```
spec/             the format
  FORMAT.md         the specification
  vectors/          the committed vectors both implementations must read and reproduce
go/               the Go library (module github.com/secretli/format)
  keys/ bundle/ link/ transfer/ cpace/ internal/padme/
  vectors/          the Go side of the interop tests
ts/               the TypeScript library (@secretli/format)
  src/              what the archive ships, compiled to dist/
  test/             its tests, including the TypeScript side of the interop tests
.github/ go.mod go.sum .golangci.yml .nvmrc renovate.json   tooling and module metadata
```

## Go

```bash
go get github.com/secretli/format
```

```go
import (
    "github.com/secretli/format/go/bundle"
    "github.com/secretli/format/go/keys"
    "github.com/secretli/format/go/link"
)

// Making a secret: fresh keys, optionally with a password, then a bundle.
ks, _ := keys.Generate()
blobKeys, _ := ks.WithPassword("optional")
sources := []bundle.Source{{Name: "notes.txt", Type: "text/plain", Size: 5, Reader: strings.NewReader("notes")}}
plan, _ := bundle.NewStreamPlan(sources) // plan.TotalSize is exact before anything is read
envelope, _ := ks.EncryptMeta(keys.Meta{Type: "bundle", PasswordProtected: true})
enc, _ := bundle.NewEncrypter(plan, sources, blobKeys) // an io.Reader: cut it into upload parts
data, _ := io.ReadAll(enc)
l := link.Link{Origin: "https://secretli.app", Secret: ks.Encoded().ShareSecret, DeletionToken: ks.Encoded().DeletionToken}

// Opening one: the link's secret, the password if any, and byte ranges of the bundle.
parsed, _ := link.Parse(l.String())
blobKeys, _ = keys.FromShareSecret(parsed.Secret, "optional")
fetch := func(_ context.Context, start, end int64) ([]byte, error) { return data[start : end+1], nil }
b, _ := bundle.Open(ctx, fetch, blobKeys, int64(len(data))) // b.Files: name, type and size of each
_ = b.DecryptFile(ctx, 0, os.Stdout, nil)                    // b.Decrypt reads several in one pass
```

Handing a link over with a code runs over a relay you implement against the server's transfer API; `transfer` does the cryptography and the order of the legs:

```go
import "github.com/secretli/format/go/transfer"

// Sending: draw the words and the session id, open the transfer with the offer.
words, _ := transfer.RandomWords()
sid, _ := transfer.NewSID()
party := transfer.Party{Words: words, SID: sid, Origin: "https://secretli.app"}
offer, _ := transfer.NewOffer(party)
// … POST the transfer with base64url(sid) and base64url(offer.Share), get a nameplate …
fmt.Println(transfer.Code{Nameplate: nameplate, Words: words}) // 7-acid-rocket
err := transfer.Send(ctx, senderRelay, party, offer, l.String())

// Receiving: parse what was typed, claim the nameplate, get the sid and the offer.
code, _ := transfer.ParseCode("7 acid rocket")
link, err := transfer.Receive(ctx, receiverRelay, transfer.Party{Words: code.Words, SID: sid, Origin: origin}, offerShare)
// errors.Is(err, transfer.ErrCodeMismatch) when the codes differed
```

## TypeScript

The package is not on any registry. Every release carries it as an archive, and a project depends on that archive's URL:

```bash
pnpm add https://github.com/secretli/format/releases/download/v0.5.0/secretli-format-0.5.0.tgz
```

From then on it is an ordinary dependency named `@secretli/format`: the lockfile pins the archive by its hash, the code imports it by name, and installs need no token. To move to a newer version, add the newer release's archive the same way. It ships as ES modules with type declarations, for browsers and Node 20 or later.

```ts
import { KeySet, cutIntoParts, encryptStream, openBundle, planStream } from "@secretli/format";

const keys = await KeySet.generateRandom();
const blobKeys = await KeySet.fromShareSecret(keys.getEncoded().shareSecret, "optional");
const envelope = await keys.encryptMeta({ type: "bundle", password_protected: true });
const files = [new File(["notes"], "notes.txt", { type: "text/plain" })];
const plan = planStream(files); // plan.totalSize is exact before anything is read
for await (const part of cutIntoParts(encryptStream(plan, files, blobKeys), 32 * 1024 * 1024)) {
  // … upload the part …
}

const opened = await openBundle(fetchRange, blobKeys, size); // opened.files: name, type and size
const [{ blob }] = await opened.decryptFiles([0]);
```

The transfer has the same shape: `randomWords`, `createOffer`, `sendLink` and `formatCode` on the sending side, `parseCode` and `receiveLink` on the receiving one, each role over a `SenderRelay` or `ReceiverRelay` you implement.

The snippets leave out error handling. The upload protocol (sessions, parts), the retrieval sessions and the transfer relay belong to the server's API, not to this library.

## Changes and releases

Every change is one of three kinds, and the kind decides the release:

- **The format** (`spec/`): rare and deliberate. One pull request changes the specification, both implementations and both committed vector files; CI's interop job fails otherwise. A committed vector that changes without the specification means an implementation's output changed, which is a break. Readers keep accepting the previous form for as long as old secrets can exist, and the clients ship the reader before anything writes the new form. Released as a minor version while below 1.0, as a major one from then on.
- **The libraries** (the code in `go/` and `ts/src/`, and the runtime dependencies: the `require` lines in `go.mod`, `dependencies` in `ts/package.json`):
  - a fix in our own code is released right away, as a patch version;
  - new or changed API is released as a minor version;
  - a change nobody can observe, such as a refactoring, goes out with the next release.
  
  Dependency updates need no release of their own. The command-line client's `go.mod` and the web app's lockfile choose the versions they install, so they take a fixed `golang.org/x/crypto` or `@noble/*` themselves. Release only to raise the lowest version this library accepts.
- **Tooling** (everything else: tests, CI, lint and Renovate configuration, development dependencies): no release. The TypeScript compiler is tooling too, but it builds the `dist/` the archive ships, so a new compiler reaches the clients with the next release; CI checks that the packed archive works in plain Node.

The TypeScript side builds with Node 24 and pnpm 12, the version `ts/package.json` pins. Regenerate the committed vectors with:

```bash
cd ts && WRITE_VECTORS=../spec/vectors pnpm vitest run test/vectors.test.ts
go test ./go/vectors -run TestWritesGoVectors -args -write-vectors=../../spec/vectors
```

### Releasing

A tag such as `v0.5.0` releases both implementations at that version. For Go the tag is the release: the Go module proxy serves it from this repository. For TypeScript the release workflow checks that `ts/package.json` carries the same version, packs `ts/`, signs the archive with a build attestation, and attaches it to the GitHub release. To check a downloaded archive:

```bash
gh attestation verify secretli-format-0.5.0.tgz --repo secretli/format
```

Bump the version in `ts/package.json` in one commit, tag it, push the tag. Tags are permanent once the Go proxy has seen them: never move or delete one, release a new version instead.

## License

MIT. The code word list is the [EFF short word list 2.0](https://www.eff.org/dice) by the Electronic Frontier Foundation, licensed [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
