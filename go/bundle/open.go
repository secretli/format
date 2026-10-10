package bundle

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"

	"github.com/secretli/format/go/keys"
)

// RangeFetcher reads the bundle bytes from start to end, both inclusive.
type RangeFetcher func(ctx context.Context, start, end int64) ([]byte, error)

// Bundle is an opened bundle: its files, and what reading them takes.
type Bundle struct {
	// Files lists the files in bundle order.
	Files []Entry

	fetch RangeFetcher
	ks    *keys.KeySet
	size  int64

	prefix []byte
	chunks int64
	starts []int64
	// head is the start of the bundle as Open fetched it, the whole bundle
	// when it is small, and headChunks the chunks complete in it: reading
	// them again costs no request.
	head       []byte
	headChunks int64
}

// Open reads a bundle's file list (FORMAT.md sections 5 and 6). A bundle of
// at most SmallBundleBytes is fetched whole, in one request that serves
// everything after it. Of a larger one, Open fetches the first
// SmallBundleBytes and, if the list goes on, the chunks that hold the rest
// (section 8). The list is checked before Open returns. A size that cannot
// be a prefix and chunks is refused before anything is fetched.
func Open(ctx context.Context, fetch RangeFetcher, ks *keys.KeySet, size int64) (*Bundle, error) {
	if !validStreamSize(size) {
		return nil, ErrInvalidSize
	}
	b := &Bundle{fetch: fetch, ks: ks, size: size}
	b.chunks = (size - PrefixLength + SealedChunkSize - 1) / SealedChunkSize
	// A small bundle is fetched whole: then every chunk is in the head, and
	// reading files makes no further request.
	var err error
	if b.head, err = fetchRange(ctx, fetch, 0, min(size, SmallBundleBytes)); err != nil {
		return nil, err
	}
	b.prefix = b.head[:PrefixLength]
	b.headChunks = b.completeChunks(int64(len(b.head)))
	stream := size - PrefixLength - b.chunks*ChunkOverhead

	first, err := b.headChunk(0)
	if err != nil {
		return nil, err
	}
	if len(first) < listLengthSize {
		return nil, ErrInvalidList
	}
	listLength := int64(binary.BigEndian.Uint32(first))
	listEnd := listLengthSize + listLength
	if listLength < minListBytes || listLength > MaxListBytes || listEnd > stream {
		return nil, fmt.Errorf("%w: a list of %d bytes", ErrInvalidList, listLength)
	}
	lastListChunk := (listEnd - 1) / PieceSize
	if lastListChunk >= b.headChunks {
		// The list goes on past what was fetched: fetch on to the end of its
		// last chunk, and keep that too.
		more, err := fetchRange(ctx, fetch, int64(len(b.head)), chunkEnd(lastListChunk, size))
		if err != nil {
			return nil, err
		}
		b.head = append(b.head[:len(b.head):len(b.head)], more...)
		b.headChunks = lastListChunk + 1
	}
	list := make([]byte, 0, listEnd)
	list = append(list, first...)
	for i := int64(1); i <= lastListChunk; i++ {
		plaintext, err := b.headChunk(i)
		if err != nil {
			return nil, err
		}
		list = append(list, plaintext...)
	}
	if b.Files, b.starts, err = parseList(list[listLengthSize:listEnd], stream); err != nil {
		return nil, err
	}
	return b, nil
}

// TotalSize is the plaintext size of every file together.
func (b *Bundle) TotalSize() int64 {
	var total int64
	for _, f := range b.Files {
		total += f.Size
	}
	return total
}

// validStreamSize reports whether size can be a prefix and chunks whose last
// one holds plaintext.
func validStreamSize(size int64) bool {
	if size <= PrefixLength+ChunkOverhead {
		return false
	}
	chunks := (size - PrefixLength + SealedChunkSize - 1) / SealedChunkSize
	return size-PrefixLength-SealedChunkSize*(chunks-1) > ChunkOverhead
}

// completeChunks is how many chunks the first n bytes of the bundle hold
// whole.
func (b *Bundle) completeChunks(n int64) int64 {
	if n >= b.size {
		return b.chunks
	}
	return min(b.chunks, max(0, (n-PrefixLength)/SealedChunkSize))
}

func chunkStart(index int64) int64 {
	return PrefixLength + index*SealedChunkSize
}

func chunkEnd(index, size int64) int64 {
	return min(chunkStart(index+1), size)
}

// headChunk decrypts a chunk that Open has fetched.
func (b *Bundle) headChunk(index int64) ([]byte, error) {
	return b.ks.DecryptChunk(b.prefix, index, index == b.chunks-1, b.head[chunkStart(index):chunkEnd(index, b.size)])
}

// listFile is one file of the list as it was written; fields are decoded one
// by one, so that their types and exact names are checked as JavaScript
// readers see them.
type listFile map[string]json.RawMessage

// parseList checks the file list (FORMAT.md section 6) and works out where
// each file starts.
func parseList(raw []byte, stream int64) ([]Entry, []int64, error) {
	var list map[string]json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidList, err)
	}
	var files []listFile
	if err := json.Unmarshal(list["files"], &files); err != nil || len(files) == 0 {
		return nil, nil, fmt.Errorf("%w: no files", ErrInvalidList)
	}
	position := int64(listLengthSize + len(raw))
	remaining := stream - position
	entries := make([]Entry, len(files))
	starts := make([]int64, len(files))
	for i, f := range files {
		name, ok := jsonString(f["name"])
		if !ok || name == "" {
			return nil, nil, fmt.Errorf("%w: file %d has no name", ErrInvalidList, i)
		}
		typ, ok := jsonString(f["type"])
		if !ok {
			return nil, nil, fmt.Errorf("%w: file %d has no type", ErrInvalidList, i)
		}
		size, ok := jsonSize(f["size"])
		if !ok {
			return nil, nil, fmt.Errorf("%w: file %d has an invalid size", ErrInvalidList, i)
		}
		if size > remaining {
			return nil, nil, fmt.Errorf("%w: the files are larger than the stream", ErrInvalidList)
		}
		entries[i] = Entry{Index: i, Name: name, Type: typ, Size: size}
		starts[i] = position
		position += size
		remaining -= size
	}
	return entries, starts, nil
}

// jsonString decodes a JSON string, and nothing else.
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// jsonSize decodes a size as a JavaScript reader does, as a double, and
// accepts it if that is an integer from 0 to 2^53 − 1: 1.0 and 1e3 are, 1.5
// and 2^53 are not, nor is a string.
func jsonSize(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || f != math.Trunc(f) || f < 0 || f > MaxFileSize {
		return 0, false
	}
	return int64(f), true
}

// Decrypt decrypts the files at these indices, nil meaning every file, in
// one pass in bundle order. Each file's writer comes from open when the file
// is reached and is closed after its last byte, so one file is open at a
// time; an empty file's is opened and closed at once. If decrypting fails,
// the open writer is closed and the error returned.
//
// Neighbouring chunks are fetched in one request, up to CoalesceBytes of
// plaintext, also across gaps of less than GapBytes, and every chunk is
// decrypted once however many files share it (FORMAT.md section 8).
// progress, if set, is told the plaintext bytes written so far.
func (b *Bundle) Decrypt(ctx context.Context, indices []int, open func(Entry) (io.WriteCloser, error), progress func(written int64)) error {
	selected, err := b.selection(indices)
	if err != nil {
		return err
	}
	var written int64
	chunks := b.newChunkReader(ctx, selected)
	for _, i := range selected {
		file := b.Files[i]
		w, err := open(file)
		if err != nil {
			return err
		}
		base := written
		track := func(n int64) {
			written = base + n
			if progress != nil {
				progress(written)
			}
		}
		if err := chunks.copyFile(w, b.starts[i], file.Size, track); err != nil {
			_ = w.Close()
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
	}
	return nil
}

// DecryptFile streams the file at index to w. Decrypt reads several files at
// once in fewer requests.
func (b *Bundle) DecryptFile(ctx context.Context, index int, w io.Writer, progress func(written int64)) error {
	return b.Decrypt(ctx, []int{index}, func(Entry) (io.WriteCloser, error) { return nopCloser{w}, nil }, progress)
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// selection sorts the indices and drops repeats.
func (b *Bundle) selection(indices []int) ([]int, error) {
	if indices == nil {
		all := make([]int, len(b.Files))
		for i := range all {
			all[i] = i
		}
		return all, nil
	}
	selected := slices.Clone(indices)
	slices.Sort(selected)
	selected = slices.Compact(selected)
	for _, i := range selected {
		if i < 0 || i >= len(b.Files) {
			return nil, fmt.Errorf("bundle has no file %d", i)
		}
	}
	return selected, nil
}

// span is a run of chunks, both ends included.
type span struct{ first, last int64 }

// chunkReader serves the chunks of a selection in order, from the head or
// from requests planned ahead, and keeps the last one decrypted, which the
// next file may start in.
type chunkReader struct {
	ctx      context.Context
	b        *Bundle
	requests []span
	request  int
	sealed   []byte
	index    int64
	plain    []byte
}

func (b *Bundle) newChunkReader(ctx context.Context, selected []int) *chunkReader {
	// The chunks the selection needs, beyond the head, merged where they
	// touch or overlap.
	var needed []span
	for _, i := range selected {
		if b.Files[i].Size == 0 {
			continue
		}
		first := max(b.starts[i]/PieceSize, b.headChunks)
		last := (b.starts[i] + b.Files[i].Size - 1) / PieceSize
		if first > last {
			continue
		}
		if n := len(needed); n > 0 && first <= needed[n-1].last+1 {
			needed[n-1].last = max(needed[n-1].last, last)
			continue
		}
		needed = append(needed, span{first, last})
	}
	return &chunkReader{ctx: ctx, b: b, requests: coalesce(needed, CoalesceBytes/PieceSize), index: -1}
}

// coalesce plans requests over the needed chunks: one request takes up to
// maxChunks chunks, and goes on across fewer than GapBytes of chunks that
// are not needed.
func coalesce(needed []span, maxChunks int64) []span {
	var requests []span
	for _, run := range needed {
		for next := run.first; next <= run.last; {
			if n := len(requests); n > 0 {
				r := &requests[n-1]
				if (next-r.last-1)*SealedChunkSize < GapBytes && next-r.first < maxChunks {
					r.last = min(run.last, r.first+maxChunks-1)
					next = r.last + 1
					continue
				}
			}
			last := min(run.last, next+maxChunks-1)
			requests = append(requests, span{next, last})
			next = last + 1
		}
	}
	return requests
}

// chunk returns chunk index decrypted.
func (r *chunkReader) chunk(index int64) ([]byte, error) {
	if index == r.index {
		return r.plain, nil
	}
	b := r.b
	var sealed []byte
	if index < b.headChunks {
		sealed = b.head[chunkStart(index):chunkEnd(index, b.size)]
	} else {
		for r.request < len(r.requests) && r.requests[r.request].last < index {
			r.request++
			r.sealed = nil
		}
		if r.request == len(r.requests) || r.requests[r.request].first > index {
			return nil, errors.New("bundle chunk was not planned")
		}
		req := r.requests[r.request]
		if r.sealed == nil {
			var err error
			if r.sealed, err = fetchRange(r.ctx, b.fetch, chunkStart(req.first), chunkEnd(req.last, b.size)); err != nil {
				return nil, err
			}
		}
		offset := chunkStart(index) - chunkStart(req.first)
		sealed = r.sealed[offset : offset+chunkEnd(index, b.size)-chunkStart(index)]
	}
	plain, err := b.ks.DecryptChunk(b.prefix, index, index == b.chunks-1, sealed)
	if err != nil {
		return nil, err
	}
	r.index, r.plain = index, plain
	return plain, nil
}

// copyFile writes size bytes of the stream from start to w.
func (r *chunkReader) copyFile(w io.Writer, start, size int64, progress func(written int64)) error {
	for pos, end := start, start+size; pos < end; {
		index := pos / PieceSize
		plain, err := r.chunk(index)
		if err != nil {
			return err
		}
		from, to := pos-index*PieceSize, min(int64(len(plain)), end-index*PieceSize)
		if from >= to {
			return ErrInvalidList
		}
		if _, err := w.Write(plain[from:to]); err != nil {
			return err
		}
		pos += to - from
		progress(pos - start)
	}
	return nil
}

// fetchRange fetches the bytes from start up to end, end excluded, and
// checks it got that many.
func fetchRange(ctx context.Context, fetch RangeFetcher, start, end int64) ([]byte, error) {
	data, err := fetch(ctx, start, end-1)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != end-start {
		return nil, ErrRangeMismatch
	}
	return data, nil
}
