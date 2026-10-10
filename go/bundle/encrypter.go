package bundle

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/secretli/format/go/keys"
)

// Encrypter is a bundle as a byte stream: Read hands out the prefix and then
// the chunks in order, encrypting each chunk only when Read gets to it. It
// reads the files by position and holds one chunk at a time, so a bundle of
// any size streams in constant memory, and parts can be cut from it at any
// fixed offsets (FORMAT.md section 9).
type Encrypter struct {
	plan    *StreamPlan
	sources []Source
	ks      *keys.KeySet
	prefix  []byte
	// header is the start of the stream: the list's length and the list.
	header []byte
	// next is the chunk Read encrypts next.
	next int64
	// file is the first file not yet read to its end.
	file  int
	piece []byte
	// pending is what Read has not handed out yet of the prefix or the last
	// chunk.
	pending []byte
	err     error
}

// NewEncrypter encrypts the sources the plan was made from, with a freshly
// drawn prefix. Each source's Reader must hold exactly Size bytes; a file
// that turns out shorter or longer fails the read with ErrSourceChanged.
func NewEncrypter(plan *StreamPlan, sources []Source, ks *keys.KeySet) (*Encrypter, error) {
	prefix := make([]byte, PrefixLength)
	if _, err := rand.Read(prefix); err != nil {
		return nil, fmt.Errorf("draw bundle prefix: %w", err)
	}
	return NewEncrypterWithPrefix(plan, sources, ks, prefix)
}

// NewEncrypterWithPrefix is NewEncrypter with the prefix given instead of
// drawn. With the prefix fixed nothing in a bundle is random, which the
// vectors need (FORMAT.md section 10). Anything else uses NewEncrypter: the
// same prefix for two bundles under the same keys breaks the encryption.
func NewEncrypterWithPrefix(plan *StreamPlan, sources []Source, ks *keys.KeySet, prefix []byte) (*Encrypter, error) {
	if len(prefix) != PrefixLength {
		return nil, errors.New("bundle prefix must be 16 bytes")
	}
	if len(sources) != len(plan.Files) {
		return nil, fmt.Errorf("%w: %d sources for a plan of %d files", ErrInvalidSource, len(sources), len(plan.Files))
	}
	for i, src := range sources {
		if src.Size != plan.Files[i].Size || (src.Reader == nil && src.Size > 0) {
			return nil, fmt.Errorf("%w: %s does not match the plan", ErrInvalidSource, src.Name)
		}
	}
	header := make([]byte, listLengthSize, listLengthSize+len(plan.ListJSON))
	binary.BigEndian.PutUint32(header, uint32(len(plan.ListJSON))) //nolint:gosec // at most MaxListBytes
	header = append(header, plan.ListJSON...)
	return &Encrypter{
		plan:    plan,
		sources: sources,
		ks:      ks,
		prefix:  bytes.Clone(prefix),
		header:  header,
		piece:   make([]byte, PieceSize),
		pending: bytes.Clone(prefix),
	}, nil
}

// Read fills p with the next bytes of the bundle.
func (e *Encrypter) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) && e.err == nil {
		if len(e.pending) == 0 {
			if e.next == e.plan.Chunks {
				e.err = io.EOF
				break
			}
			if e.pending, e.err = e.encryptNext(); e.err != nil {
				break
			}
		}
		copied := copy(p[n:], e.pending)
		e.pending = e.pending[copied:]
		n += copied
	}
	if n > 0 && errors.Is(e.err, io.EOF) {
		return n, nil
	}
	return n, e.err
}

// encryptNext encrypts the next chunk.
func (e *Encrypter) encryptNext() ([]byte, error) {
	index := e.next
	start := index * PieceSize
	piece := e.piece[:min(PieceSize, e.plan.StreamLength-start)]
	if err := e.fill(piece, start); err != nil {
		return nil, err
	}
	last := index == e.plan.Chunks-1
	if last {
		// Files that end exactly where the stream does have not been
		// checked for growth yet.
		if err := e.finishFiles(e.plan.ContentLength); err != nil {
			return nil, err
		}
	}
	chunk, err := e.ks.EncryptChunk(e.prefix, index, last, piece)
	if err != nil {
		return nil, err
	}
	e.next++
	return chunk, nil
}

// fill writes the stream from position pos into dst: the header, the files'
// bytes, and zeros after the last file.
func (e *Encrypter) fill(dst []byte, pos int64) error {
	for len(dst) > 0 {
		if pos < int64(len(e.header)) {
			n := copy(dst, e.header[pos:])
			dst, pos = dst[n:], pos+int64(n)
			continue
		}
		if err := e.finishFiles(pos); err != nil {
			return err
		}
		if e.file == len(e.sources) {
			clear(dst)
			return nil
		}
		src := e.sources[e.file]
		offset := pos - e.plan.Starts[e.file]
		n := min(int64(len(dst)), src.Size-offset)
		if err := readAt(src, dst[:n], offset); err != nil {
			return err
		}
		dst, pos = dst[n:], pos+n
	}
	return nil
}

// finishFiles moves past the files that end at or before pos, checking that
// none of them has grown.
func (e *Encrypter) finishFiles(pos int64) error {
	for e.file < len(e.sources) && e.plan.Starts[e.file]+e.sources[e.file].Size <= pos {
		src := e.sources[e.file]
		if src.Reader != nil {
			var probe [1]byte
			n, err := src.Reader.ReadAt(probe[:], src.Size)
			if n > 0 {
				return fmt.Errorf("%w: %s is longer than %d bytes", ErrSourceChanged, src.Name, src.Size)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("read %s: %w", src.Name, err)
			}
		}
		e.file++
	}
	return nil
}

// readAt fills buf from the source at offset; a source that ends early has
// changed since it was planned.
func readAt(src Source, buf []byte, offset int64) error {
	n, err := src.Reader.ReadAt(buf, offset)
	if n == len(buf) {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %s is shorter than %d bytes", ErrSourceChanged, src.Name, src.Size)
	}
	return fmt.Errorf("read %s: %w", src.Name, err)
}

// EncryptStream builds a whole bundle in memory, with a fresh prefix.
// Uploads read an Encrypter part by part instead; this is for small bundles
// and for tests.
func EncryptStream(plan *StreamPlan, sources []Source, ks *keys.KeySet) ([]byte, error) {
	enc, err := NewEncrypter(plan, sources, ks)
	if err != nil {
		return nil, err
	}
	return enc.readAll()
}

// readAll reads the whole bundle and checks it has the planned size.
func (e *Encrypter) readAll() ([]byte, error) {
	var out bytes.Buffer
	out.Grow(int(e.plan.TotalSize))
	if _, err := out.ReadFrom(e); err != nil {
		return nil, err
	}
	if int64(out.Len()) != e.plan.TotalSize {
		return nil, errors.New("bundle size mismatch")
	}
	return out.Bytes(), nil
}
