package vectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/secretli/format/bundle"
	"github.com/secretli/format/keys"
)

// The TypeScript implementation (ts/) and this one must read each other's
// output; FORMAT.md section 10 describes the vector files.
// testdata/ts-vectors.json is written by the TypeScript tests and read here;
// testdata/go-vectors.json is written here and read there.
//
// Regenerate the committed Go vectors with
//
//	go test ./vectors -run TestWritesGoVectors -args -write-vectors=testdata
//
// CI writes fresh, larger vectors on both sides at every run (-big) and
// reads the other side's from a temporary directory (-vectors-dir).
var (
	writeVectors = flag.String("write-vectors", "", "directory to write go-vectors.json into")
	bigVectors   = flag.Bool("big", false, "include multi-chunk files in the written vectors")
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
	Meta          keys.Meta    `json:"meta"`
	EncryptedMeta string       `json:"encrypted_meta"`
	BundleName    string       `json:"bundle_name"`
	Files         []vectorFile `json:"files"`
	BundleBase64  string       `json:"bundle_base64"`
}

type vectors struct {
	Cases []vectorCase `json:"cases"`
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
	files := []string{filepath.Join("testdata", "ts-vectors.json")}
	if *vectorsDir != "" {
		more, err := filepath.Glob(filepath.Join(*vectorsDir, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, more...)
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing vectors (see the comment at the top of this file): %v", err)
			}
			var v vectors
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatal(err)
			}
			if len(v.Cases) == 0 {
				t.Fatal("no cases")
			}
			for _, c := range v.Cases {
				t.Run(c.Name, func(t *testing.T) { checkCase(t, c) })
			}
		})
	}
}

func checkCase(t *testing.T, c vectorCase) {
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
	manifest, err := bundle.ReadManifest(ctx, fetch, blob, int64(len(data)))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if manifest.BundleName != c.BundleName || len(manifest.Files) != len(c.Files) {
		t.Fatalf("manifest = %+v", manifest)
	}
	for i, want := range c.Files {
		file := manifest.Files[i]
		if file.Name != want.Name || file.Type != want.Type {
			t.Errorf("file %d = %s (%s), want %s (%s)", i, file.Name, file.Type, want.Name, want.Type)
		}
		var out bytes.Buffer
		if err := bundle.DecryptFile(ctx, fetch, blob, file, &out, nil); err != nil {
			t.Fatalf("decrypt %s: %v", want.Name, err)
		}
		if !bytes.Equal(out.Bytes(), want.content(t)) {
			t.Errorf("%s: got %d bytes, want %d, and not the same", want.Name, out.Len(), len(want.content(t)))
		}
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

	v := vectors{Cases: []vectorCase{
		makeCase(t, "text", 0x80, "", "text", "secret.txt", []vectorFile{
			{Name: "secret.txt", Type: "text/plain", ContentBase64: &text},
		}),
		makeCase(t, "files-password", 0xa0, "correct horse battery staple", "bundle", "", []vectorFile{
			{Name: "hello.txt", Type: "text/plain", ContentBase64: &text},
			{Name: "empty.bin", Type: "application/octet-stream", ContentBase64: &empty},
			{Name: "bytes.bin", Type: "application/octet-stream", ContentBase64: &bytesB64},
		}),
	}}
	if *bigVectors {
		v.Cases = append(v.Cases, makeCase(t, "boundaries", 0xc0, "", "bundle", "", []vectorFile{
			{Name: "zero.bin", Type: "application/octet-stream", Generated: &generated{Seed: 1, Length: 0}},
			{Name: "one.bin", Type: "application/octet-stream", Generated: &generated{Seed: 2, Length: 1}},
			{Name: "under.bin", Type: "application/octet-stream", Generated: &generated{Seed: 3, Length: bundle.ChunkSize - 1}},
			{Name: "exact.bin", Type: "application/octet-stream", Generated: &generated{Seed: 4, Length: bundle.ChunkSize}},
			{Name: "over.bin", Type: "application/octet-stream", Generated: &generated{Seed: 5, Length: bundle.ChunkSize + 1}},
			{Name: "two-plus.bin", Type: "application/octet-stream", Generated: &generated{Seed: 6, Length: 2*bundle.ChunkSize + 3}},
		}))
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

// makeCase encrypts the files with a fixed share secret, so the case is
// reproducible except for the random nonces.
func makeCase(t *testing.T, name string, secretByte byte, password, metaType, bundleName string, files []vectorFile) vectorCase {
	t.Helper()
	secret := make([]byte, keys.ShareSecretLength)
	for i := range secret {
		secret[i] = secretByte + byte(i)
	}
	var c vectorCase
	c.Name = name
	c.ShareSecret = base64.RawURLEncoding.EncodeToString(secret)
	c.Password = password
	c.Files = files

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
	names := make([]string, len(files))
	for i, f := range files {
		content := f.content(t)
		sources[i] = bundle.Source{Name: f.Name, Type: f.Type, Size: int64(len(content)), Reader: bytes.NewReader(content)}
		names[i] = f.Name
	}
	if bundleName == "" {
		bundleName = bundle.DefaultBundleName(names)
	}
	c.BundleName = bundleName
	c.Meta = keys.Meta{Type: metaType, PasswordProtected: password != "", BundleName: bundleName}
	if c.EncryptedMeta, err = base.EncryptMeta(c.Meta); err != nil {
		t.Fatal(err)
	}
	plan, err := bundle.NewPlan(sources, bundleName)
	if err != nil {
		t.Fatal(err)
	}
	data, err := bundle.Encrypt(plan, sources, blob)
	if err != nil {
		t.Fatal(err)
	}
	c.BundleBase64 = base64.StdEncoding.EncodeToString(data)
	return c
}
