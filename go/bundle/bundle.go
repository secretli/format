// Package bundle is the encrypted blob format. A bundle is a random prefix
// and one stream, the file list, the files and zero padding, sealed in
// 64 KiB chunks whose nonces count up from the prefix (FORMAT.md sections 5
// and 6): NewStreamPlan lays it out, NewEncrypter writes it, and Open reads
// it. The package mirrors ts/src; the vectors test checks the two against
// each other.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/secretli/format/go/internal/padme"
)

const (
	// CoalesceBytes bounds how much plaintext one range request fetches when
	// reading: neighbouring chunks are read together up to this much.
	CoalesceBytes = 16 * 1024 * 1024
	// SmallBundleBytes: bundles up to this size are fetched whole, in one
	// request. Of a larger bundle, Open fetches this much first.
	SmallBundleBytes = 1024 * 1024
	// MinPaddedSize is the size writers pad the smallest streams to, so that
	// every short note looks the same to the server.
	MinPaddedSize = 4096
)

var (
	// ErrEmpty is a bundle without files.
	ErrEmpty = errors.New("bundle must contain at least one file")
	// ErrRangeMismatch is a range read that returned the wrong number of bytes.
	ErrRangeMismatch = errors.New("bundle range size mismatch")
)

// Source is a file to bundle. Bytes are read by position, so a file can be
// encrypted chunk by chunk without being held in memory.
type Source struct {
	Name string
	// Type is the MIME type; it defaults to application/octet-stream.
	Type   string
	Size   int64
	Reader io.ReaderAt
}

// PaddedSize is the size writers pad a stream of this size to: Padmé
// rounding, and never less than MinPaddedSize.
func PaddedSize(size int64) int64 {
	return max(MinPaddedSize, Padme(size))
}

// Padme rounds a size up so that it keeps only about log2(log2(size))
// significant bits (Nikitin et al., "Reducing Metadata Leakage from
// Encrypted Files and Communication with PURBs", 2019). That costs at most
// 12.5% and leaks only O(log log size) bits, and a size at or below a power
// of two stays at or below it.
func Padme(size int64) int64 {
	return padme.Padme(size)
}

// SHA256Hex is the lower-case hex digest the API uses for upload parts.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
