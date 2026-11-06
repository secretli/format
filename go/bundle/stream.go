package bundle

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/secretli/format/go/keys"
)

const (
	// PrefixLength is the random prefix in front of a bundle's chunks.
	PrefixLength = keys.ChunkPrefixLength
	// PieceSize is the plaintext of every chunk but the last.
	PieceSize = 64 * 1024
	// ChunkOverhead is what encryption adds to each chunk: the tag.
	ChunkOverhead = keys.ChunkOverhead
	// SealedChunkSize is the size of every chunk but the last.
	SealedChunkSize = PieceSize + ChunkOverhead
	// MaxListBytes caps the file list: 4 MiB hold tens of thousands of files.
	MaxListBytes = 4 * 1024 * 1024
	// MaxFileSize is the largest size the file list can state, 2^53 − 1, the
	// largest integer JavaScript's numbers hold exactly.
	MaxFileSize = 1<<53 - 1
	// GapBytes: when files are read together, chunks less than this far
	// apart are fetched in one request, the chunks between included.
	GapBytes = 1024 * 1024

	// minListBytes is the shortest JSON object, {}.
	minListBytes = 2
	// listLengthSize is the big-endian list length the stream starts with.
	listLengthSize = 4
	defaultType    = "application/octet-stream"
)

var (
	// ErrInvalidSize is a bundle whose size cannot be a prefix and chunks.
	ErrInvalidSize = errors.New("invalid bundle size")
	// ErrInvalidList is a file list that does not describe this bundle.
	ErrInvalidList = errors.New("invalid bundle file list")
	// ErrListTooLarge is a file list past MaxListBytes.
	ErrListTooLarge = errors.New("bundle file list is too large")
	// ErrInvalidSource is a file that cannot go into a bundle: no name, or
	// a size out of range.
	ErrInvalidSource = errors.New("invalid bundle file")
	// ErrSourceChanged is a file whose content changed size while it was
	// encrypted.
	ErrSourceChanged = errors.New("file changed while it was read")
)

// Entry is one file of a bundle as a reader sees it.
type Entry struct {
	// Index is the file's position in the bundle.
	Index int
	Name  string
	// Type is the MIME type, application/octet-stream when it is unknown.
	Type string
	Size int64
}

// StreamPlan is the layout of a bundle, worked out from the files' names,
// types and sizes before a byte of content is read (FORMAT.md section 9).
type StreamPlan struct {
	// Files is the file list as it is encrypted: names and types made valid
	// UTF-8, an empty type replaced with application/octet-stream.
	Files []Entry
	// ListJSON is the file list exactly as it is encrypted (FORMAT.md
	// section 6).
	ListJSON []byte
	// Starts holds where each file's bytes begin in the stream.
	Starts []int64
	// ContentLength is the stream before its padding: the list's length, the
	// list and the files.
	ContentLength int64
	// StreamLength is the padded stream, max(4096, padme(ContentLength)).
	StreamLength int64
	// Chunks is how many chunks the stream is sealed in.
	Chunks int64
	// TotalSize is the size of the bundle, declared to the server.
	TotalSize int64
}

// NewStreamPlan lays out a bundle of these sources. It reads only their
// names, types and sizes, so the exact size is known before anything is
// encrypted.
func NewStreamPlan(sources []Source) (*StreamPlan, error) {
	if len(sources) == 0 {
		return nil, ErrEmpty
	}
	plan := &StreamPlan{
		Files:  make([]Entry, len(sources)),
		Starts: make([]int64, len(sources)),
	}
	var content int64
	for i, src := range sources {
		if src.Name == "" {
			return nil, fmt.Errorf("%w: file %d has no name", ErrInvalidSource, i)
		}
		if src.Size < 0 || src.Size > MaxFileSize || content > MaxFileSize-src.Size {
			return nil, fmt.Errorf("%w: %s has a size of %d", ErrInvalidSource, src.Name, src.Size)
		}
		typ := src.Type
		if typ == "" {
			typ = defaultType
		}
		plan.Files[i] = Entry{Index: i, Name: validUTF8(src.Name), Type: validUTF8(typ), Size: src.Size}
		content += src.Size
	}
	var err error
	if plan.ListJSON, err = marshalList(plan.Files); err != nil {
		return nil, fmt.Errorf("encode the file list: %w", err)
	}
	if len(plan.ListJSON) > MaxListBytes {
		return nil, ErrListTooLarge
	}
	position := int64(listLengthSize + len(plan.ListJSON))
	for i, f := range plan.Files {
		plan.Starts[i] = position
		position += f.Size
	}
	plan.ContentLength = position
	plan.StreamLength = PaddedSize(position)
	plan.Chunks = (plan.StreamLength + PieceSize - 1) / PieceSize
	plan.TotalSize = PrefixLength + plan.StreamLength + plan.Chunks*ChunkOverhead
	if plan.TotalSize > MaxFileSize {
		// Positions past 2^53 − 1 would not be exact for a JavaScript reader.
		return nil, fmt.Errorf("%w: the files are too large for a bundle", ErrInvalidSource)
	}
	return plan, nil
}

// validUTF8 replaces every byte that is not part of valid UTF-8 with U+FFFD.
func validUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	out := make([]byte, 0, len(s)+8)
	for _, r := range s {
		out = utf8.AppendRune(out, r)
	}
	return string(out)
}

// listJSON is the file list as both writers must encode it, so that their
// bundles are identical: compact, keys in this order, strings escaped as
// JSON.stringify escapes them (FORMAT.md section 6). encoding/json/v2 does
// exactly that; it leaves <, >, &, U+2028 and U+2029 as they are.
type listJSON struct {
	Files []listJSONFile `json:"files"`
}

type listJSONFile struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// marshalList encodes the file list. The names and types are valid UTF-8
// already (validUTF8), so encoding cannot fail on them.
func marshalList(files []Entry) ([]byte, error) {
	list := listJSON{Files: make([]listJSONFile, len(files))}
	for i, f := range files {
		list.Files[i] = listJSONFile{Name: f.Name, Type: f.Type, Size: f.Size}
	}
	return json.Marshal(list)
}
