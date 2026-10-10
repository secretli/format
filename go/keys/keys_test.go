package keys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func fixedSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, ShareSecretLength)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestDerivationIsDeterministicAndShaped(t *testing.T) {
	a, err := FromShareSecret(fixedSecret(t), "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromShareSecret(fixedSecret(t), "")
	if err != nil {
		t.Fatal(err)
	}
	ea, eb := a.Encoded(), b.Encoded()
	if ea != eb {
		t.Fatalf("same secret derived differently: %+v vs %+v", ea, eb)
	}
	if len(ea.PublicID) != 22 || len(ea.MetadataToken) != 43 || len(ea.BlobToken) != 43 {
		t.Errorf("unexpected lengths: id %d, metadata %d, blob %d", len(ea.PublicID), len(ea.MetadataToken), len(ea.BlobToken))
	}
	if ea.DeletionToken != "" || a.HasDeletionToken() {
		t.Error("a key set from a link must not have a deletion token")
	}
	if ea.PublicID == ea.MetadataToken[:22] || ea.MetadataToken == ea.BlobToken {
		t.Error("derived values must differ from each other")
	}
}

func TestPasswordChangesOnlyTheBlobSide(t *testing.T) {
	plain, err := FromShareSecret(fixedSecret(t), "")
	if err != nil {
		t.Fatal(err)
	}
	withPassword, err := FromShareSecret(fixedSecret(t), "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	ep, ew := plain.Encoded(), withPassword.Encoded()
	if ep.PublicID != ew.PublicID || ep.MetadataToken != ew.MetadataToken {
		t.Error("the public id and metadata token must not depend on the password")
	}
	if ep.BlobToken == ew.BlobToken {
		t.Error("the blob token must depend on the password")
	}
	other, err := FromShareSecret(fixedSecret(t), "wrong horse")
	if err != nil {
		t.Fatal(err)
	}
	if other.Encoded().BlobToken == ew.BlobToken {
		t.Error("different passwords must give different blob tokens")
	}

	// Applying the password to a generated key set matches deriving with it.
	generated, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	applied, err := generated.WithPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	derived, err := FromShareSecret(generated.Encoded().ShareSecret, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if applied.Encoded().BlobToken != derived.Encoded().BlobToken {
		t.Error("WithPassword and FromShareSecret with a password disagree")
	}
	if !applied.HasDeletionToken() || applied.Encoded().DeletionToken != generated.Encoded().DeletionToken {
		t.Error("WithPassword must keep the deletion token")
	}
}

func TestGenerateDrawsFreshSecrets(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.Encoded().ShareSecret == b.Encoded().ShareSecret || a.Encoded().DeletionToken == b.Encoded().DeletionToken {
		t.Error("two generated key sets share material")
	}
	if len(a.Encoded().ShareSecret) != 43 || len(a.Encoded().DeletionToken) != 43 {
		t.Errorf("unexpected lengths: secret %d, deletion %d", len(a.Encoded().ShareSecret), len(a.Encoded().DeletionToken))
	}
}

func TestRejectsMaterialOfTheWrongLength(t *testing.T) {
	if _, err := FromShareSecret(base64.RawURLEncoding.EncodeToString(make([]byte, 31)), ""); !errors.Is(err, ErrInvalidShareSecret) {
		t.Errorf("31 bytes: err = %v, want ErrInvalidShareSecret", err)
	}
	if _, err := FromShareSecret("not base64!", ""); !errors.Is(err, ErrInvalidShareSecret) {
		t.Errorf("garbage: err = %v, want ErrInvalidShareSecret", err)
	}
	ks, err := FromShareSecret(fixedSecret(t), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.WithDeletionToken("short"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("short deletion token: err = %v, want ErrInvalidToken", err)
	}
	owner, err := ks.WithDeletionToken(strings.Repeat("D", 43))
	if err != nil {
		t.Fatal(err)
	}
	if !owner.HasDeletionToken() || ks.HasDeletionToken() {
		t.Error("WithDeletionToken must return a copy with the token, leaving the original alone")
	}
}

func TestMetaEnvelopeRoundTrip(t *testing.T) {
	ks, err := FromShareSecret(fixedSecret(t), "")
	if err != nil {
		t.Fatal(err)
	}
	meta := Meta{Type: "bundle", PasswordProtected: true}
	envelope, err := ks.EncryptMeta(meta)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(envelope, "$")
	if len(parts) != 3 || parts[0] != "v2" {
		t.Fatalf("envelope = %q, want v2$nonce$ciphertext", envelope)
	}
	got, err := ks.DecryptMeta(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if got != meta {
		t.Errorf("meta = %+v, want %+v", got, meta)
	}

	other, err := FromShareSecret(base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.DecryptMeta(envelope); !errors.Is(err, ErrDecrypt) {
		t.Errorf("another key set: err = %v, want ErrDecrypt", err)
	}
	// Flip a bit of the ciphertext itself. Changing the last base64url
	// character would not do: unpadded base64 leaves it a few bits that
	// decoders ignore, so that change may decode to the same bytes.
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1
	tampered := parts[0] + "$" + parts[1] + "$" + base64.RawURLEncoding.EncodeToString(ciphertext)
	if _, err := ks.DecryptMeta(tampered); !errors.Is(err, ErrDecrypt) {
		t.Errorf("tampered ciphertext: err = %v, want ErrDecrypt", err)
	}
	if _, err := ks.DecryptMeta("v1$a$b"); !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("old version: err = %v, want ErrInvalidEnvelope", err)
	}
	if _, err := ks.DecryptMeta("v2$short$" + parts[2]); !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("short nonce: err = %v, want ErrInvalidEnvelope", err)
	}
}

// openMeta returns an envelope's plaintext, padding included.
func openMeta(t *testing.T, ks *KeySet, envelope string) []byte {
	t.Helper()
	parts := strings.Split(envelope, "$")
	nonce, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(ks.metaKey)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, ks.metaAAD())
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

// sealMeta seals any plaintext as an envelope, as older writers did.
func sealMeta(t *testing.T, ks *KeySet, plaintext string) string {
	t.Helper()
	nonce := make([]byte, NonceLength)
	aead, err := chacha20poly1305.NewX(ks.metaKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), ks.metaAAD())
	return "v2$" + base64.RawURLEncoding.EncodeToString(nonce) + "$" + base64.RawURLEncoding.EncodeToString(ciphertext)
}

func TestMetaEnvelopeIsPadded(t *testing.T) {
	ks, err := FromShareSecret(fixedSecret(t), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, meta := range []Meta{{Type: "text"}, {Type: "bundle", PasswordProtected: true}} {
		envelope, err := ks.EncryptMeta(meta)
		if err != nil {
			t.Fatal(err)
		}
		// 512 bytes of plaintext: 528 of ciphertext, 704 characters, behind
		// "v2$", 32 characters of nonce and "$".
		if len(envelope) != 740 {
			t.Errorf("%+v: envelope is %d characters, want 740", meta, len(envelope))
		}
		plaintext := openMeta(t, ks, envelope)
		encoded, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		want := string(encoded) + strings.Repeat(" ", 512-len(encoded))
		if string(plaintext) != want {
			t.Errorf("plaintext = %q, want the JSON and spaces to 512 bytes", plaintext)
		}
	}
}

func TestMetaPaddingIsBounded(t *testing.T) {
	for _, c := range []struct{ n, want int }{
		{0, 512}, {41, 512}, {512, 512}, {513, 544}, {1000, 1024}, {4097, 4352},
		{5900, 6101}, {6000, 6101}, {6101, 6101}, {6102, 6102}, {10000, 10000},
	} {
		if got := metaPaddedLength(c.n); got != c.want {
			t.Errorf("metaPaddedLength(%d) = %d, want %d", c.n, got, c.want)
		}
	}
	ks, err := FromShareSecret(fixedSecret(t), "")
	if err != nil {
		t.Fatal(err)
	}
	// The JSON around the type is 38 bytes. At 6,000 bytes it would round to
	// 6,144, which the server would refuse: the envelope stops at 8,192.
	const around = len(`{"type":"","password_protected":false}`)
	for _, c := range []struct{ typeLength, plaintext int }{{6000 - around, 6101}, {6200 - around, 6200}} {
		meta := Meta{Type: strings.Repeat("x", c.typeLength)}
		envelope, err := ks.EncryptMeta(meta)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(openMeta(t, ks, envelope)); got != c.plaintext {
			t.Errorf("type of %d: plaintext %d bytes, want %d", c.typeLength, got, c.plaintext)
		}
		if got, err := ks.DecryptMeta(envelope); err != nil || got != meta {
			t.Errorf("type of %d: %v", c.typeLength, err)
		}
	}
	envelope, err := ks.EncryptMeta(Meta{Type: strings.Repeat("x", 6000-around)})
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope) != 8192 {
		t.Errorf("clamped envelope is %d characters, want 8,192", len(envelope))
	}
}

func TestOldAndOddEnvelopesStillOpen(t *testing.T) {
	ks, err := FromShareSecret(fixedSecret(t), "")
	if err != nil {
		t.Fatal(err)
	}
	for plaintext, want := range map[string]Meta{
		// Unpadded, with the name envelopes carried before version 3.
		`{"type":"bundle","password_protected":true,"bundle_name":"Secretli bundle (2 files)"}`: {Type: "bundle", PasswordProtected: true},
		`{"type":"text","password_protected":false}`:                                            {Type: "text"},
		"{\"type\":\"text\",\"password_protected\":true} \t\r\n  ":                              {Type: "text", PasswordProtected: true},
		`{"password_protected":true,"later":[1,2],"type":"bundle"}` + strings.Repeat(" ", 600):  {Type: "bundle", PasswordProtected: true},
	} {
		got, err := ks.DecryptMeta(sealMeta(t, ks, plaintext))
		if err != nil || got != want {
			t.Errorf("%q: got %+v (%v), want %+v", plaintext, got, err, want)
		}
	}
	if _, err := ks.DecryptMeta(sealMeta(t, ks, `{"type":"text"} x`)); !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("trailing garbage: err = %v, want ErrInvalidEnvelope", err)
	}

	// Written by the TypeScript implementation before envelopes were padded,
	// for the share secret 00 01 … 1f.
	pinned, err := FromShareSecret("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "")
	if err != nil {
		t.Fatal(err)
	}
	for envelope, want := range map[string]Meta{
		"v2$QuBjEhrsGr3pvv9wRhlIac_NN4EVXt54$VE557SnLoKMsmPeMqQY5RT5MvzPF19Zfm3REcqH4hIoNaG9xCWQ4_J2X9o0EYPdUgFnpzE3Dc6MW6LVaFKP4I-Bu9diGeUB9pdJ9dQw4PWNO75NB23qMuOp2jl793KocSRohka4": {Type: "bundle", PasswordProtected: true},
		"v2$Gbc53Ya5NjqescrUcUjlQyNNXAwRb9Hv$yXIUTdkte_qyeIdL5CN_DFfIngBMB-VoWLgYfDgYSJ6qxsPKqOZSe034Bb8anvoGpbPOAdHvFlqSae2O_fnilbrUYRp9A471Cb5PO25p3NjbtiRO9A":                      {Type: "text"},
	} {
		got, err := pinned.DecryptMeta(envelope)
		if err != nil || got != want {
			t.Errorf("pinned envelope: got %+v (%v), want %+v", got, err, want)
		}
	}
}

func TestChunkNonceLayout(t *testing.T) {
	prefix := make([]byte, ChunkPrefixLength)
	for i := range prefix {
		prefix[i] = 0xa0 + byte(i)
	}
	nonce, err := chunkNonce(prefix, 0x0102030405, true)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append(append([]byte{}, prefix...), 0, 0, 1, 2, 3, 4, 5), 1)
	if !bytes.Equal(nonce, want) {
		t.Errorf("nonce = %x, want %x", nonce, want)
	}
	nonce, err = chunkNonce(prefix, MaxChunkIndex, false)
	if err != nil {
		t.Fatal(err)
	}
	want = append(append(append([]byte{}, prefix...), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), 0)
	if !bytes.Equal(nonce, want) {
		t.Errorf("nonce = %x, want %x", nonce, want)
	}
	for _, index := range []int64{-1, MaxChunkIndex + 1} {
		if _, err := chunkNonce(prefix, index, false); err == nil {
			t.Errorf("index %d: want an error", index)
		}
	}
	if _, err := chunkNonce(prefix[:15], 0, false); err == nil {
		t.Error("a 15-byte prefix: want an error")
	}
}

func TestChunksAreBoundToTheirPlace(t *testing.T) {
	ks, err := FromShareSecret(fixedSecret(t), "")
	if err != nil {
		t.Fatal(err)
	}
	prefix := bytes.Repeat([]byte{7}, ChunkPrefixLength)
	plaintext := []byte("a piece of the stream")
	chunk, err := ks.EncryptChunk(prefix, 3, false, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunk) != len(plaintext)+ChunkOverhead {
		t.Fatalf("chunk is %d bytes, want %d", len(chunk), len(plaintext)+ChunkOverhead)
	}

	// The same seal, built by hand from FORMAT.md section 5.
	nonce := append(append(append([]byte{}, prefix...), 0, 0, 0, 0, 0, 0, 3), 0)
	aad := append(append(append([]byte{}, ks.publicID...), "bundle"...), 0)
	aad = append(aad, "stream:v3"...)
	aead, err := chacha20poly1305.NewX(ks.blobKey)
	if err != nil {
		t.Fatal(err)
	}
	if want := aead.Seal(nil, nonce, plaintext, aad); !bytes.Equal(chunk, want) {
		t.Errorf("chunk = %x, want %x", chunk, want)
	}

	got, err := ks.DecryptChunk(prefix, 3, false, chunk)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("open = %q, %v", got, err)
	}
	otherPrefix := bytes.Repeat([]byte{8}, ChunkPrefixLength)
	for name, open := range map[string]func() ([]byte, error){
		"another index":  func() ([]byte, error) { return ks.DecryptChunk(prefix, 4, false, chunk) },
		"as the last":    func() ([]byte, error) { return ks.DecryptChunk(prefix, 3, true, chunk) },
		"another prefix": func() ([]byte, error) { return ks.DecryptChunk(otherPrefix, 3, false, chunk) },
		"too short":      func() ([]byte, error) { return ks.DecryptChunk(prefix, 3, false, chunk[:ChunkOverhead-1]) },
	} {
		if _, err := open(); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
	other, err := FromShareSecret(base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.DecryptChunk(prefix, 3, false, chunk); !errors.Is(err, ErrDecrypt) {
		t.Errorf("other keys: err = %v, want ErrDecrypt", err)
	}
}
