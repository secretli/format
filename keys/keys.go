// Package keys derives every key and token of a secret from its share secret
// and seals and opens the ciphertext the format has: the metadata envelope
// and the chunks of a bundle. It mirrors ts/src/encryption.ts byte for byte; the vectors test in the parent
// directory checks the two implementations against each other.
package keys

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"

	"github.com/secretli/format/internal/padme"
)

const (
	// ShareSecretLength is the size of the random secret behind a link.
	ShareSecretLength = 32
	// TokenLength is the size of the deletion token, the one token that is
	// random rather than derived.
	TokenLength = 32
	// NonceLength is the XChaCha20-Poly1305 nonce: stored in the metadata
	// envelope, and made of the prefix, index and last flag for a chunk.
	NonceLength = chacha20poly1305.NonceSizeX
	// ChunkPrefixLength is the random prefix in front of a bundle, which every
	// chunk's nonce begins with.
	ChunkPrefixLength = 16
	// ChunkOverhead is what a bundle chunk adds to its plaintext: the
	// Poly1305 tag. The nonce is not stored.
	ChunkOverhead = chacha20poly1305.Overhead
	// MaxChunkIndex is the highest chunk number seven bytes of the nonce hold.
	MaxChunkIndex = 1<<56 - 1

	// metaMinPadded and metaMaxPadded bound the envelope's padded plaintext:
	// 512 bytes at least, and no more than the server's 8,192 characters for
	// an envelope allow (FORMAT.md section 4).
	metaMinPadded = 512
	metaMaxPadded = 6101

	envelopeVersion  = "v2"
	streamAADSuffix  = "stream:v3"
	derivationPrefix = "secretli:derivation:v1"
	publicIDLength   = 16

	scryptN = 1 << 14
	scryptR = 8
	scryptP = 1
)

var (
	// ErrInvalidShareSecret is a share secret that is not 32 base64url bytes.
	ErrInvalidShareSecret = errors.New("invalid share secret")
	// ErrInvalidToken is a token that is not 32 base64url bytes.
	ErrInvalidToken = errors.New("invalid token")
	// ErrInvalidEnvelope is a metadata envelope that is not v2$nonce$ciphertext.
	ErrInvalidEnvelope = errors.New("invalid metadata envelope")
	// ErrDecrypt is a ciphertext that does not open with these keys: a wrong
	// password, a wrong link, or a modified byte.
	ErrDecrypt = errors.New("decryption failed")
)

// Meta is the small envelope stored next to the blob, encrypted with the
// metadata key so that anyone holding the link can read it without opening
// the secret. The files' names are only in the bundle; envelopes written
// before version 3 also carry bundle_name, which readers ignore.
type Meta struct {
	// Type is "text" or "bundle".
	Type              string `json:"type"`
	PasswordProtected bool   `json:"password_protected"`
}

// Encoded is a key set as it appears in links and API calls: unpadded base64url.
type Encoded struct {
	ShareSecret   string
	PublicID      string
	MetadataToken string
	BlobToken     string
	// DeletionToken is empty for a key set made from a recipient's link.
	DeletionToken string
}

// KeySet holds everything derived from a share secret. The blob key and blob
// token come from the share secret alone, or from it and a password.
type KeySet struct {
	shareSecret   []byte
	metaKey       []byte
	blobKey       []byte
	publicID      []byte
	metadataToken []byte
	blobToken     []byte
	deletionToken []byte
}

// Generate draws a fresh share secret and deletion token, for a new secret.
// A password is applied with WithPassword.
func Generate() (*KeySet, error) {
	secret := make([]byte, ShareSecretLength)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("draw share secret: %w", err)
	}
	deletion := make([]byte, TokenLength)
	if _, err := rand.Read(deletion); err != nil {
		return nil, fmt.Errorf("draw deletion token: %w", err)
	}
	return build(secret, secret, deletion)
}

// FromShareSecret rebuilds the key set behind a link. With a password, the
// blob key and token are derived from the password and the secret together,
// as they were when the secret was made with one.
func FromShareSecret(encoded, password string) (*KeySet, error) {
	secret, err := decodeExact(encoded, ShareSecretLength)
	if err != nil {
		return nil, ErrInvalidShareSecret
	}
	material := secret
	if password != "" {
		if material, err = passwordMaterial(secret, password); err != nil {
			return nil, err
		}
	}
	return build(secret, material, nil)
}

// WithPassword returns the same secret with its blob keys derived from the
// password as well, as a sender applies one.
func (k *KeySet) WithPassword(password string) (*KeySet, error) {
	if password == "" {
		return k, nil
	}
	material, err := passwordMaterial(k.shareSecret, password)
	if err != nil {
		return nil, err
	}
	return build(k.shareSecret, material, k.deletionToken)
}

// WithDeletionToken attaches the owner link's deletion token.
func (k *KeySet) WithDeletionToken(encoded string) (*KeySet, error) {
	token, err := decodeExact(encoded, TokenLength)
	if err != nil {
		return nil, ErrInvalidToken
	}
	copied := *k
	copied.deletionToken = token
	return &copied, nil
}

// Encoded returns the key set as links and API calls carry it.
func (k *KeySet) Encoded() Encoded {
	return Encoded{
		ShareSecret:   encode(k.shareSecret),
		PublicID:      encode(k.publicID),
		MetadataToken: encode(k.metadataToken),
		BlobToken:     encode(k.blobToken),
		DeletionToken: encode(k.deletionToken),
	}
}

// HasDeletionToken reports whether this key set came from an owner link.
func (k *KeySet) HasDeletionToken() bool {
	return len(k.deletionToken) > 0
}

// EncryptMeta seals the envelope: v2$base64url(nonce)$base64url(ciphertext).
// The JSON is padded with spaces, so that the envelope's length says nothing
// about what it holds (FORMAT.md section 4).
func (k *KeySet) EncryptMeta(meta Meta) (string, error) {
	encoded, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("encode metadata: %w", err)
	}
	plaintext := make([]byte, metaPaddedLength(len(encoded)))
	copy(plaintext, encoded)
	for i := len(encoded); i < len(plaintext); i++ {
		plaintext[i] = ' '
	}
	nonce, err := newNonce()
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(k.metaKey)
	if err != nil {
		return "", fmt.Errorf("metadata cipher: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, k.metaAAD())
	return envelopeVersion + "$" + encode(nonce) + "$" + encode(ciphertext), nil
}

// DecryptMeta opens an envelope made by EncryptMeta. JSON allows white space
// after a value, so the padding needs no handling, and an envelope from
// before it was padded opens all the same.
func (k *KeySet) DecryptMeta(envelope string) (Meta, error) {
	parts := strings.Split(envelope, "$")
	if len(parts) != 3 || parts[0] != envelopeVersion {
		return Meta{}, ErrInvalidEnvelope
	}
	nonce, err := decodeExact(parts[1], NonceLength)
	if err != nil {
		return Meta{}, ErrInvalidEnvelope
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Meta{}, ErrInvalidEnvelope
	}
	aead, err := chacha20poly1305.NewX(k.metaKey)
	if err != nil {
		return Meta{}, fmt.Errorf("metadata cipher: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, k.metaAAD())
	if err != nil {
		return Meta{}, ErrDecrypt
	}
	var meta Meta
	if err := json.Unmarshal(plaintext, &meta); err != nil {
		return Meta{}, ErrInvalidEnvelope
	}
	return meta, nil
}

// metaPaddedLength is how long the envelope's plaintext is for JSON of n
// bytes: max(512, padme(n)), but no more than 6,101 bytes, and JSON longer
// than that is not padded.
func metaPaddedLength(n int) int {
	if n > metaMaxPadded {
		return n
	}
	return min(metaMaxPadded, max(metaMinPadded, int(padme.Padme(int64(n)))))
}

// EncryptChunk seals chunk index of a bundle. The nonce is not stored: it is
// the bundle's prefix, the index in seven bytes and the last flag, so a chunk
// opens only in its own place and the last one only as the last (FORMAT.md
// section 5). The ciphertext is ChunkOverhead bytes longer than plaintext.
func (k *KeySet) EncryptChunk(prefix []byte, index int64, last bool, plaintext []byte) ([]byte, error) {
	nonce, err := chunkNonce(prefix, index, last)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k.blobKey)
	if err != nil {
		return nil, fmt.Errorf("chunk cipher: %w", err)
	}
	return aead.Seal(make([]byte, 0, len(plaintext)+aead.Overhead()), nonce, plaintext, k.streamAAD()), nil
}

// DecryptChunk opens a chunk made by EncryptChunk for the same place.
func (k *KeySet) DecryptChunk(prefix []byte, index int64, last bool, chunk []byte) ([]byte, error) {
	nonce, err := chunkNonce(prefix, index, last)
	if err != nil {
		return nil, err
	}
	if len(chunk) < ChunkOverhead {
		return nil, ErrDecrypt
	}
	aead, err := chacha20poly1305.NewX(k.blobKey)
	if err != nil {
		return nil, fmt.Errorf("chunk cipher: %w", err)
	}
	plaintext, err := aead.Open(make([]byte, 0, len(chunk)-aead.Overhead()), nonce, chunk, k.streamAAD())
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// chunkNonce is prefix (16 bytes) | index (7 bytes, big-endian) | last (1 byte).
func chunkNonce(prefix []byte, index int64, last bool) ([]byte, error) {
	if len(prefix) != ChunkPrefixLength {
		return nil, errors.New("bundle prefix must be 16 bytes")
	}
	if index < 0 || index > MaxChunkIndex {
		return nil, errors.New("chunk index out of range")
	}
	nonce := make([]byte, NonceLength)
	copy(nonce, prefix)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(index))
	copy(nonce[ChunkPrefixLength:], counter[1:])
	if last {
		nonce[NonceLength-1] = 1
	}
	return nonce, nil
}

func (k *KeySet) metaAAD() []byte {
	return append(append([]byte{}, k.publicID...), "meta"...)
}

// streamAAD is public_id || "bundle" || 0x00 || "stream:v3", the AAD of
// every chunk (FORMAT.md section 5).
func (k *KeySet) streamAAD() []byte {
	aad := append(append([]byte{}, k.publicID...), "bundle"...)
	aad = append(aad, 0)
	return append(aad, streamAADSuffix...)
}

func build(secret, blobMaterial, deletion []byte) (*KeySet, error) {
	metaKey, err := derive(secret, "meta_key", 32)
	if err != nil {
		return nil, err
	}
	publicID, err := derive(secret, "public_id", publicIDLength)
	if err != nil {
		return nil, err
	}
	metadataToken, err := derive(secret, "metadata_token", 32)
	if err != nil {
		return nil, err
	}
	blobKey, err := derive(blobMaterial, "blob_key", 32)
	if err != nil {
		return nil, err
	}
	blobToken, err := derive(blobMaterial, "blob_token", 32)
	if err != nil {
		return nil, err
	}
	return &KeySet{
		shareSecret:   secret,
		metaKey:       metaKey,
		blobKey:       blobKey,
		publicID:      publicID,
		metadataToken: metadataToken,
		blobToken:     blobToken,
		deletionToken: deletion,
	}, nil
}

// derive is HKDF-SHA512 with no salt (a zero salt of the hash's length, as the
// RFC defines) and a labelled info string.
func derive(ikm []byte, name string, length int) ([]byte, error) {
	key, err := hkdf.Key(sha512.New, ikm, make([]byte, sha512.Size), derivationPrefix+":"+name, length)
	if err != nil {
		return nil, fmt.Errorf("derive %s: %w", name, err)
	}
	return key, nil
}

func passwordMaterial(secret []byte, password string) ([]byte, error) {
	salt, err := derive(secret, "password_salt", 32)
	if err != nil {
		return nil, err
	}
	material, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, fmt.Errorf("derive password key: %w", err)
	}
	return material, nil
}

func newNonce() ([]byte, error) {
	nonce := make([]byte, NonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("draw nonce: %w", err)
	}
	return nonce, nil
}

func encode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeExact(s string, length int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != length {
		return nil, errors.New("wrong length")
	}
	return b, nil
}
