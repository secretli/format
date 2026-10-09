package vectors

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/secretli/format/bundle"
	"github.com/secretli/format/cpace"
	"github.com/secretli/format/keys"
	"github.com/secretli/format/transfer"
)

// The TypeScript implementation (ts/) and this one must read each other's
// output; FORMAT.md section 10 describes the vector files.
// testdata/ts-vectors.json is written by the TypeScript tests and read here;
// testdata/go-vectors.json is written here and read there. Their cases are
// version 3 bundles with a fixed prefix, which each side must reproduce byte
// for byte.
//
// The *-v2.json and *-unpadded.json files hold version 2 bundles from before
// version 3 and from before writers padded. They are never regenerated, so
// that readers keep reading such bundles until version 2 goes.
//
// Regenerate the committed Go vectors with
//
//	go test ./vectors -run TestWritesGoVectors -args -write-vectors=testdata
//
// CI writes fresh, larger vectors on both sides at every run (-big) and
// reads the other side's from a temporary directory (-vectors-dir).
var (
	writeVectors = flag.String("write-vectors", "", "directory to write go-vectors.json into")
	bigVectors   = flag.Bool("big", false, "include large and many-file cases in the written vectors")
	vectorsDir   = flag.String("vectors-dir", "", "a directory of additional *.json vector files to read")
)

type generated struct {
	Seed   uint32 `json:"seed"`
	Length int64  `json:"length"`
}

type vectorFile struct {
	Name          string     `json:"name"`
	Type          string     `json:"type"`
	ContentBase64 *string    `json:"content_base64,omitempty"`
	Generated     *generated `json:"generated,omitempty"`
}

type vectorCase struct {
	Name        string `json:"name"`
	ShareSecret string `json:"share_secret"`
	Password    string `json:"password"`
	Derived     struct {
		PublicID          string `json:"public_id"`
		MetadataToken     string `json:"metadata_token"`
		BlobToken         string `json:"blob_token"`
		PasswordBlobToken string `json:"password_blob_token"`
	} `json:"derived"`
	// Meta of a version 2 case also has bundle_name, which keys.Meta, like
	// every reader, ignores.
	Meta          keys.Meta    `json:"meta"`
	EncryptedMeta string       `json:"encrypted_meta"`
	Files         []vectorFile `json:"files"`
	// Prefix is a version 3 bundle's; version 2 cases have none, but a
	// bundle name.
	Prefix       string `json:"prefix,omitempty"`
	BundleName   string `json:"bundle_name,omitempty"`
	BundleBase64 string `json:"bundle_base64"`
}

// transferCase is one short-code transfer with fixed scalars, so that every
// value but the sealed link's nonce is reproducible. Bytes are hex.
type transferCase struct {
	Name           string          `json:"name"`
	Code           string          `json:"code"`
	Origin         string          `json:"origin"`
	SID            string          `json:"sid"`
	SenderScalar   string          `json:"sender_scalar"`
	ReceiverScalar string          `json:"receiver_scalar"`
	Link           string          `json:"link"`
	WordListSHA256 string          `json:"word_list_sha256"`
	Derived        transferDerived `json:"derived"`
	// Sealed is the delivery leg, sealed with the payload key.
	Sealed string `json:"sealed"`
}

type transferDerived struct {
	Password          string `json:"password"`
	ChannelIdentifier string `json:"channel_identifier"`
	Generator         string `json:"generator"`
	SenderShare       string `json:"sender_share"`
	ReceiverShare     string `json:"receiver_share"`
	K                 string `json:"k"`
	ISK               string `json:"isk"`
	ConfirmKey        string `json:"confirm_key"`
	PayloadKey        string `json:"payload_key"`
	Confirmation      string `json:"confirmation"`
}

type vectors struct {
	Cases    []vectorCase   `json:"cases"`
	Transfer []transferCase `json:"transfer"`
}

// xorshift32 is the generator FORMAT.md defines for generated content.
func xorshift32(seed uint32, length int64) []byte {
	out := make([]byte, length)
	x := seed
	for i := range out {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		out[i] = byte(x)
	}
	return out
}

func (f vectorFile) content(t *testing.T) []byte {
	t.Helper()
	switch {
	case f.Generated != nil:
		return xorshift32(f.Generated.Seed, f.Generated.Length)
	case f.ContentBase64 != nil:
		b, err := base64.StdEncoding.DecodeString(*f.ContentBase64)
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		return b
	}
	return nil
}

func TestReadsVectors(t *testing.T) {
	current := []string{filepath.Join("testdata", "ts-vectors.json")}
	if *vectorsDir != "" {
		more, err := filepath.Glob(filepath.Join(*vectorsDir, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		current = append(current, more...)
	}
	frozen := map[string]bool{
		filepath.Join("testdata", "ts-vectors-v2.json"):       true,
		filepath.Join("testdata", "ts-vectors-unpadded.json"): false,
	}
	files := append(current, filepath.Join("testdata", "ts-vectors-v2.json"), filepath.Join("testdata", "ts-vectors-unpadded.json"))
	for _, path := range files {
		padded, isFrozen := frozen[path]
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing vectors (see the comment at the top of this file): %v", err)
			}
			var v vectors
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			if len(v.Cases) == 0 || len(v.Transfer) == 0 {
				t.Fatalf("%d cases and %d transfer cases; both are required", len(v.Cases), len(v.Transfer))
			}
			for _, c := range v.Cases {
				t.Run(c.Name, func(t *testing.T) {
					switch {
					case !isFrozen:
						checkCase(t, c)
					case padded:
						checkV2Case(t, c, true)
					default:
						checkV2Case(t, c, false)
					}
				})
			}
			for _, c := range v.Transfer {
				t.Run("transfer/"+c.Name, func(t *testing.T) { checkTransferCase(t, c) })
			}
		})
	}
}

// openCase checks the derived values and the envelope, then opens the
// bundle and expects the case's files in it.
func openCase(t *testing.T, c vectorCase, version int) (*keys.KeySet, []byte, []bundle.Source) {
	t.Helper()
	base, err := keys.FromShareSecret(c.ShareSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	enc := base.Encoded()
	if enc.PublicID != c.Derived.PublicID || enc.MetadataToken != c.Derived.MetadataToken || enc.BlobToken != c.Derived.BlobToken {
		t.Errorf("derived %+v, other side derived %+v", enc, c.Derived)
	}
	blob, err := keys.FromShareSecret(c.ShareSecret, c.Password)
	if err != nil {
		t.Fatal(err)
	}
	if blob.Encoded().BlobToken != c.Derived.PasswordBlobToken {
		t.Errorf("password blob token = %s, other side %s", blob.Encoded().BlobToken, c.Derived.PasswordBlobToken)
	}

	meta, err := base.DecryptMeta(c.EncryptedMeta)
	if err != nil {
		t.Fatalf("decrypt metadata: %v", err)
	}
	if meta != c.Meta {
		t.Errorf("meta = %+v, want %+v", meta, c.Meta)
	}

	data, err := base64.StdEncoding.DecodeString(c.BundleBase64)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fetch := func(_ context.Context, start, end int64) ([]byte, error) { return data[start : end+1], nil }
	b, err := bundle.Open(ctx, fetch, blob, int64(len(data)))
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	if b.Version != version || len(b.Files) != len(c.Files) {
		t.Fatalf("version %d with %d files, want version %d with %d", b.Version, len(b.Files), version, len(c.Files))
	}
	sources := make([]bundle.Source, len(c.Files))
	got := make([][]byte, len(c.Files))
	err = b.Decrypt(ctx, nil, func(e bundle.Entry) (io.WriteCloser, error) {
		want := c.Files[e.Index]
		if e.Name != want.Name || e.Type != want.Type {
			t.Errorf("file %d = %q (%q), want %q (%q)", e.Index, e.Name, e.Type, want.Name, want.Type)
		}
		return &collect{done: func(b []byte) { got[e.Index] = b }}, nil
	}, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	for i, f := range c.Files {
		content := f.content(t)
		if !bytes.Equal(got[i], content) {
			t.Errorf("%s: got %d bytes, want %d, and not the same", f.Name, len(got[i]), len(content))
		}
		sources[i] = bundle.Source{Name: f.Name, Type: f.Type, Size: int64(len(content)), Reader: bytes.NewReader(content)}
	}
	return blob, data, sources
}

type collect struct {
	bytes.Buffer
	done func([]byte)
}

func (c *collect) Close() error {
	c.done(c.Bytes())
	return nil
}

// checkCase reads a version 3 case, then writes the same files with the
// case's prefix and expects exactly the same bundle, and checks that the
// envelope is padded as FORMAT.md section 4 says.
func checkCase(t *testing.T, c vectorCase) {
	t.Helper()
	blob, data, sources := openCase(t, c, 3)
	prefix, err := base64.RawURLEncoding.DecodeString(c.Prefix)
	if err != nil || len(prefix) != bundle.PrefixLength {
		t.Fatalf("prefix %q: %v", c.Prefix, err)
	}
	plan, err := bundle.NewStreamPlan(sources)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := bundle.NewEncrypterWithPrefix(plan, sources, blob, prefix)
	if err != nil {
		t.Fatal(err)
	}
	written, err := io.ReadAll(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, data) {
		t.Errorf("this side writes %d bytes, the other side wrote %d, and not the same", len(written), len(data))
	}
	checkEnvelopePadding(t, c)
}

// checkV2Case reads a frozen version 2 case. For a padded one it also plans
// the same files itself and expects the other side's bundle to have exactly
// that size, so both version 2 writers pad alike.
func checkV2Case(t *testing.T, c vectorCase, padded bool) {
	t.Helper()
	_, data, sources := openCase(t, c, 2)
	if !padded {
		return
	}
	plan, err := bundle.NewPlan(sources, c.BundleName)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) != plan.TotalSize {
		t.Errorf("bundle is %d bytes, this side pads the same files to %d", len(data), plan.TotalSize)
	}
}

// checkEnvelopePadding opens the envelope with keys derived here, apart from
// package keys, and expects the JSON followed by spaces to its padded length.
func checkEnvelopePadding(t *testing.T, c vectorCase) {
	t.Helper()
	secret, err := base64.RawURLEncoding.DecodeString(c.ShareSecret)
	if err != nil {
		t.Fatal(err)
	}
	derive := func(name string, length int) []byte {
		key, err := hkdf.Key(sha512.New, secret, make([]byte, sha512.Size), "secretli:derivation:v1:"+name, length)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	parts := strings.Split(c.EncryptedMeta, "$")
	nonce, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(derive("meta_key", 32))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, append(derive("public_id", 16), "meta"...))
	if err != nil {
		t.Fatal(err)
	}
	encoded := bytes.TrimRight(plaintext, " ")
	n := int64(len(encoded))
	padded := n
	if n <= 6101 {
		padded = min(6101, max(512, bundle.Padme(n)))
	}
	if int64(len(plaintext)) != padded {
		t.Errorf("envelope plaintext is %d bytes for %d of JSON, want %d", len(plaintext), n, padded)
	}
	var meta keys.Meta
	if err := json.Unmarshal(encoded, &meta); err != nil || meta != c.Meta {
		t.Errorf("envelope JSON %s: %v", encoded, err)
	}
	if len(c.EncryptedMeta) != 740 {
		t.Errorf("envelope is %d characters, want 740", len(c.EncryptedMeta))
	}
}

func TestWritesGoVectors(t *testing.T) {
	if *writeVectors == "" {
		t.Skip("run with -args -write-vectors=<dir> to write go-vectors.json")
	}
	text := base64.StdEncoding.EncodeToString([]byte("hello from go\n"))
	empty := ""
	bytes256 := make([]byte, 300)
	for i := range bytes256 {
		bytes256[i] = byte(255 - i%256)
	}
	bytesB64 := base64.StdEncoding.EncodeToString(bytes256)
	five := base64.StdEncoding.EncodeToString([]byte("fünf"))
	octet := "application/octet-stream"

	v := vectors{Cases: []vectorCase{
		makeCase(t, "text", 0x80, "", "text", []vectorFile{
			{Name: "secret.txt", Type: "text/plain", ContentBase64: &text},
		}),
		makeCase(t, "files-password", 0xa0, "correct horse battery staple", "bundle", []vectorFile{
			{Name: "hello.txt", Type: "text/plain", ContentBase64: &text},
			{Name: "empty.bin", Type: octet, ContentBase64: &empty},
			{Name: "bytes.bin", Type: octet, ContentBase64: &bytesB64},
		}),
		// Above the 4,096-byte minimum, so Padmé rounds the stream: to
		// 10,240 bytes.
		makeCase(t, "rounded", 0xb0, "", "bundle", []vectorFile{
			{Name: "ten-thousand.bin", Type: octet, Generated: &generated{Seed: 8, Length: 10000}},
		}),
		// Names that JSON.stringify and encoding/json escape differently,
		// empty files, and a file across the first chunk boundary.
		makeCase(t, "names", 0xc0, "", "bundle", []vectorFile{
			{Name: "<a & b>.txt", Type: "text/plain", ContentBase64: &empty},
			{Name: `say "hi".txt`, Type: `text/plain; charset="utf-8"`, Generated: &generated{Seed: 21, Length: 30000}},
			{Name: `back\slash/and/slash.txt`, Type: octet, ContentBase64: &empty},
			{Name: "tab\there\b\f\n\r\x07\x1f\x7f.bin", Type: "application/x-\x00", Generated: &generated{Seed: 22, Length: 40000}},
			{Name: "Grüße \u2028\u2029 📄.txt", Type: "text/plain", ContentBase64: &five},
			{Name: "bad \xff byte.txt", Type: "text/plain", ContentBase64: &empty},
		}),
	}, Transfer: []transferCase{
		makeTransferCase(t, "canonical", "7-acid-rocket", "https://secretli.app", 0x10,
			"https://secretli.app/s#Z28tdmVjdG9ycy1zaGFyZS1zZWNyZXQtMDAwMDAwMDA"),
		makeTransferCase(t, "typed", "  42 Zucch.YOYO ", "http://localhost:8080", 0x50,
			"http://localhost:8080/s#Z28tdmVjdG9ycy1zaGFyZS1zZWNyZXQtMDAwMDAwMDA!Z28tdmVjdG9ycy1kZWxldGlvbi10b2tlbi0wMDAwMDA"),
	}}
	if *bigVectors {
		v.Cases = append(v.Cases, makeCase(t, "boundaries", 0xd0, "", "bundle", []vectorFile{
			{Name: "zero.bin", Type: octet, Generated: &generated{Seed: 1, Length: 0}},
			{Name: "one.bin", Type: octet, Generated: &generated{Seed: 2, Length: 1}},
			{Name: "under.bin", Type: octet, Generated: &generated{Seed: 3, Length: bundle.PieceSize - 1}},
			{Name: "exact.bin", Type: octet, Generated: &generated{Seed: 4, Length: bundle.PieceSize}},
			{Name: "over.bin", Type: octet, Generated: &generated{Seed: 5, Length: bundle.PieceSize + 1}},
			{Name: "four-mib-plus.bin", Type: octet, Generated: &generated{Seed: 6, Length: 4<<20 + 3}},
		}))
		many := make([]vectorFile, 1500)
		for i := range many {
			many[i] = vectorFile{
				Name:      fmt.Sprintf("many/file-%04d.txt", i),
				Type:      "text/plain",
				Generated: &generated{Seed: uint32(100 + i), Length: int64(i % 97)},
			}
		}
		c := makeCase(t, "many", 0xe0, "", "bundle", many)
		if list := listLength(t, c); list <= bundle.PieceSize {
			t.Fatalf("the list of %d bytes must span two chunks", list)
		}
		v.Cases = append(v.Cases, c)
	}

	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(*writeVectors, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(*writeVectors, "go-vectors.json")
	if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (%d cases)", path, len(v.Cases))
}

// listLength plans the case's files to see how long their list is.
func listLength(t *testing.T, c vectorCase) int {
	t.Helper()
	sources := make([]bundle.Source, len(c.Files))
	for i, f := range c.Files {
		sources[i] = bundle.Source{Name: f.Name, Type: f.Type, Size: int64(len(f.content(t)))}
	}
	plan, err := bundle.NewStreamPlan(sources)
	if err != nil {
		t.Fatal(err)
	}
	return len(plan.ListJSON)
}

// makeCase encrypts the files with a share secret and a prefix fixed by the
// seed byte, so the case is reproducible except for the envelope's nonce.
func makeCase(t *testing.T, name string, secretByte byte, password, metaType string, files []vectorFile) vectorCase {
	t.Helper()
	secret := make([]byte, keys.ShareSecretLength)
	for i := range secret {
		secret[i] = secretByte + byte(i)
	}
	prefix := make([]byte, bundle.PrefixLength)
	for i := range prefix {
		prefix[i] = secretByte ^ 0x5a + byte(3*i)
	}
	var c vectorCase
	c.Name = name
	c.ShareSecret = base64.RawURLEncoding.EncodeToString(secret)
	c.Password = password
	c.Files = files
	c.Prefix = base64.RawURLEncoding.EncodeToString(prefix)

	base, err := keys.FromShareSecret(c.ShareSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := keys.FromShareSecret(c.ShareSecret, password)
	if err != nil {
		t.Fatal(err)
	}
	enc := base.Encoded()
	c.Derived.PublicID, c.Derived.MetadataToken, c.Derived.BlobToken = enc.PublicID, enc.MetadataToken, enc.BlobToken
	c.Derived.PasswordBlobToken = blob.Encoded().BlobToken

	sources := make([]bundle.Source, len(files))
	for i, f := range files {
		content := f.content(t)
		sources[i] = bundle.Source{Name: f.Name, Type: f.Type, Size: int64(len(content)), Reader: bytes.NewReader(content)}
	}
	c.Meta = keys.Meta{Type: metaType, PasswordProtected: password != ""}
	if c.EncryptedMeta, err = base.EncryptMeta(c.Meta); err != nil {
		t.Fatal(err)
	}
	plan, err := bundle.NewStreamPlan(sources)
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := bundle.NewEncrypterWithPrefix(plan, sources, blob, prefix)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(encrypter)
	if err != nil {
		t.Fatal(err)
	}
	c.BundleBase64 = base64.StdEncoding.EncodeToString(data)
	return c
}

// deriveTransfer runs both sides of a transfer case with its fixed scalars.
func deriveTransfer(t *testing.T, c transferCase) transferDerived {
	t.Helper()
	code, err := transfer.ParseCode(c.Code)
	if err != nil {
		t.Fatalf("parse %q: %v", c.Code, err)
	}
	sid, senderScalar, receiverScalar := unhex(t, c.SID), unhex(t, c.SenderScalar), unhex(t, c.ReceiverScalar)
	p := transfer.Party{Words: code.Words, SID: sid, Origin: c.Origin}
	g := transfer.Generator(p)
	ya, err := cpace.Share(g, senderScalar)
	if err != nil {
		t.Fatal(err)
	}
	yb, err := cpace.Share(g, receiverScalar)
	if err != nil {
		t.Fatal(err)
	}
	k, err := cpace.ScalarMultVfy(senderScalar, yb)
	if err != nil {
		t.Fatal(err)
	}
	if kb, err := cpace.ScalarMultVfy(receiverScalar, ya); err != nil || !bytes.Equal(k, kb) {
		t.Fatalf("the two sides derive different K: %x and %x (%v)", k, kb, err)
	}
	isk := cpace.ISK(sid, k, ya, []byte("sender"), yb, []byte("receiver"))
	keys, err := transfer.SessionKeys(sid, k, ya, yb)
	if err != nil {
		t.Fatal(err)
	}
	return transferDerived{
		Password:          string(transfer.Password(code.Words)),
		ChannelIdentifier: hex.EncodeToString(transfer.ChannelIdentifier(c.Origin)),
		Generator:         hex.EncodeToString(g),
		SenderShare:       hex.EncodeToString(ya),
		ReceiverShare:     hex.EncodeToString(yb),
		K:                 hex.EncodeToString(k),
		ISK:               hex.EncodeToString(isk),
		ConfirmKey:        hex.EncodeToString(keys.Confirm),
		PayloadKey:        hex.EncodeToString(keys.Payload),
		Confirmation:      hex.EncodeToString(transfer.ConfirmationTag(keys.Confirm, ya, yb)),
	}
}

func wordListSHA256() string {
	sum := sha256.Sum256([]byte(strings.Join(transfer.Words[:], "\n")))
	return hex.EncodeToString(sum[:])
}

func checkTransferCase(t *testing.T, c transferCase) {
	t.Helper()
	if got := wordListSHA256(); got != c.WordListSHA256 {
		t.Fatalf("word list SHA-256 = %s, other side %s", got, c.WordListSHA256)
	}
	if got := deriveTransfer(t, c); got != c.Derived {
		t.Errorf("derived\n%+v\nother side derived\n%+v", got, c.Derived)
	}
	link, err := transfer.Open(unhex(t, c.Derived.PayloadKey), unhex(t, c.SID), unhex(t, c.Sealed))
	if err != nil {
		t.Fatalf("open the sealed link: %v", err)
	}
	if link != c.Link {
		t.Errorf("link = %q, want %q", link, c.Link)
	}
}

// makeTransferCase fixes the session id and both scalars from a seed byte.
func makeTransferCase(t *testing.T, name, code, origin string, seed byte, link string) transferCase {
	t.Helper()
	sid := make([]byte, transfer.SIDSize)
	senderScalar := make([]byte, cpace.ScalarSize)
	receiverScalar := make([]byte, cpace.ScalarSize)
	for i := range sid {
		sid[i] = seed + 0x80 + byte(i)
		senderScalar[i] = seed + byte(i)
		receiverScalar[i] = seed + 0x40 + byte(i)
	}
	senderScalar[cpace.ScalarSize-1] &= 0x0f
	receiverScalar[cpace.ScalarSize-1] &= 0x0f

	c := transferCase{
		Name:           name,
		Code:           code,
		Origin:         origin,
		SID:            hex.EncodeToString(sid),
		SenderScalar:   hex.EncodeToString(senderScalar),
		ReceiverScalar: hex.EncodeToString(receiverScalar),
		Link:           link,
		WordListSHA256: wordListSHA256(),
	}
	c.Derived = deriveTransfer(t, c)
	sealed, err := transfer.Seal(unhex(t, c.Derived.PayloadKey), sid, link)
	if err != nil {
		t.Fatal(err)
	}
	c.Sealed = hex.EncodeToString(sealed)
	return c
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
