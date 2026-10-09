package bundle

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/secretli/format/keys"
)

func fixedPrefix() []byte {
	prefix := make([]byte, PrefixLength)
	for i := range prefix {
		prefix[i] = 0xf0 - byte(i)
	}
	return prefix
}

// streamBundle plans and encrypts these sources with a fixed prefix.
func streamBundle(t *testing.T, ks *keys.KeySet, sources []Source) (*StreamPlan, []byte) {
	t.Helper()
	plan, err := NewStreamPlan(sources)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := NewEncrypterWithPrefix(plan, sources, ks, fixedPrefix())
	if err != nil {
		t.Fatal(err)
	}
	data, err := enc.readAll()
	if err != nil {
		t.Fatal(err)
	}
	return plan, data
}

// sealStream encrypts any stream plaintext as a bundle, so tests can make
// lists no writer would.
func sealStream(t *testing.T, ks *keys.KeySet, stream []byte) []byte {
	t.Helper()
	out := append([]byte{}, fixedPrefix()...)
	chunks := int64((len(stream) + PieceSize - 1) / PieceSize)
	for i := range chunks {
		piece := stream[i*PieceSize : min(int64(len(stream)), (i+1)*PieceSize)]
		chunk, err := ks.EncryptChunk(fixedPrefix(), i, i == chunks-1, piece)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, chunk...)
	}
	return out
}

// streamOf is a stream holding this list, these contents, and zeros up to
// length.
func streamOf(list string, contents []byte, length int) []byte {
	stream := binary.BigEndian.AppendUint32(nil, uint32(len(list)))
	stream = append(append(stream, list...), contents...)
	return append(stream, make([]byte, length-len(stream))...)
}

// counter counts the requests made through it and remembers their ranges.
type counter struct {
	data   []byte
	ranges [][2]int64
}

func (c *counter) fetch(ctx context.Context, start, end int64) ([]byte, error) {
	c.ranges = append(c.ranges, [2]int64{start, end})
	return memFetcher(c.data)(ctx, start, end)
}

// decryptAll decrypts the selection into buffers, by index, and checks that
// files are opened in order, once each, one at a time.
func decryptAll(t *testing.T, b *Bundle, indices []int) map[int][]byte {
	t.Helper()
	out := map[int][]byte{}
	last, open := -1, false
	err := b.Decrypt(context.Background(), indices, func(e Entry) (io.WriteCloser, error) {
		if e.Index <= last || open {
			t.Fatalf("file %d opened after %d (still open: %v)", e.Index, last, open)
		}
		last, open = e.Index, true
		return &fileWriter{done: func(data []byte) { out[e.Index], open = data, false }}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type fileWriter struct {
	bytes.Buffer
	done func([]byte)
}

func (w *fileWriter) Close() error {
	w.done(w.Bytes())
	return nil
}

// sizeFilling is the size of one file named f that makes the content
// exactly this long.
func sizeFilling(t *testing.T, content int64) int64 {
	t.Helper()
	size := content
	for range 3 {
		plan, err := NewStreamPlan([]Source{{Name: "f", Size: size}})
		if err != nil {
			t.Fatal(err)
		}
		size = content - 4 - int64(len(plan.ListJSON))
	}
	return size
}

func TestStreamPlanSizes(t *testing.T) {
	for _, c := range []struct {
		name   string
		size   int64
		stream int64
	}{
		{"a short note pads to 4,096", 14, 4096},
		{"an empty file", 0, 4096},
		{"Padmé above the floor", 10000, 10240},
		{"exactly one piece", sizeFilling(t, 65536), 65536},
		{"a multiple of the piece size", sizeFilling(t, 3*65536), 3 * 65536},
		{"one byte into a piece", sizeFilling(t, 65537), 67584},
		{"just past a power of two", 1 << 20, 1081344},
	} {
		t.Run(c.name, func(t *testing.T) {
			plan, err := NewStreamPlan([]Source{{Name: "f", Size: c.size}})
			if err != nil {
				t.Fatal(err)
			}
			if plan.ContentLength != 4+int64(len(plan.ListJSON))+c.size || plan.Starts[0] != 4+int64(len(plan.ListJSON)) {
				t.Fatalf("content %d, start %d", plan.ContentLength, plan.Starts[0])
			}
			if plan.StreamLength != c.stream {
				t.Errorf("stream = %d, want %d", plan.StreamLength, c.stream)
			}
			chunks := (c.stream + PieceSize - 1) / PieceSize
			if plan.Chunks != chunks || plan.TotalSize != 16+c.stream+16*chunks {
				t.Errorf("chunks %d, total %d", plan.Chunks, plan.TotalSize)
			}
			ks := testKeys(t)
			_, data := streamBundle(t, ks, []Source{memSource("f", "", big()[:c.size])})
			if int64(len(data)) != plan.TotalSize {
				t.Errorf("wrote %d bytes, planned %d", len(data), plan.TotalSize)
			}
			if c.stream%PieceSize == 0 && len(data) != 16+int(chunks)*SealedChunkSize {
				t.Errorf("a stream of whole pieces makes %d bytes", len(data))
			}
			b, err := Open(context.Background(), memFetcher(data), ks, int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if got := decryptAll(t, b, nil)[0]; !bytes.Equal(got, big()[:c.size]) {
				t.Errorf("read %d bytes back", len(got))
			}
		})
	}
}

func TestStreamPlanNeedsNoContent(t *testing.T) {
	plan, err := NewStreamPlan([]Source{
		{Name: "a.txt", Type: "text/plain", Size: 5},
		{Name: "b.bin", Size: 0},
		{Name: "c.bin", Size: 70000},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"files":[{"name":"a.txt","type":"text/plain","size":5},{"name":"b.bin","type":"application/octet-stream","size":0},{"name":"c.bin","type":"application/octet-stream","size":70000}]}`
	if string(plan.ListJSON) != want {
		t.Errorf("list = %s", plan.ListJSON)
	}
	h := int64(4 + len(want))
	if plan.Starts[0] != h || plan.Starts[1] != h+5 || plan.Starts[2] != h+5 || plan.ContentLength != h+70005 {
		t.Errorf("starts %v, content %d", plan.Starts, plan.ContentLength)
	}
	if plan.Files[1].Type != "application/octet-stream" || plan.Files[2].Index != 2 {
		t.Errorf("files = %+v", plan.Files)
	}
}

func TestStreamPlanRefusesWhatCannotBeRead(t *testing.T) {
	for name, sources := range map[string][]Source{
		"no name":          {{Name: "", Size: 1}},
		"negative size":    {{Name: "a", Size: -1}},
		"past 2^53":        {{Name: "a", Size: MaxFileSize + 1}},
		"sum past 2^53":    {{Name: "a", Size: MaxFileSize}, {Name: "b", Size: 1}},
		"stream past 2^53": {{Name: "a", Size: MaxFileSize - 100}},
	} {
		if _, err := NewStreamPlan(sources); !errors.Is(err, ErrInvalidSource) {
			t.Errorf("%s: err = %v, want ErrInvalidSource", name, err)
		}
	}
	if _, err := NewStreamPlan(nil); !errors.Is(err, ErrEmpty) {
		t.Errorf("no files: err = %v, want ErrEmpty", err)
	}
	// {"files":[ … ]} around 4,096 entries of {"name":"…","type":"t","size":0}
	// and their commas: 11 + 4,095 × (32 + 992) + 32 + 981 bytes is 4 MiB.
	many := make([]Source, 4096)
	for i := range many {
		many[i] = Source{Name: strings.Repeat("x", 992), Type: "t"}
	}
	for last, ok := range map[int]bool{981: true, 982: false} {
		many[4095].Name = strings.Repeat("y", last)
		plan, err := NewStreamPlan(many)
		if ok && (err != nil || len(plan.ListJSON) != MaxListBytes) {
			t.Errorf("a list of exactly 4 MiB: %v", err)
		}
		if !ok && !errors.Is(err, ErrListTooLarge) {
			t.Errorf("a list one byte longer: err = %v, want ErrListTooLarge", err)
		}
	}
}

func TestListIsEncodedAsJSONStringify(t *testing.T) {
	// JSON.stringify's output for the same list, from Node.
	const want = "7b2266696c6573223a5b7b226e616d65223a223c61202620623e2e747874222c2274797065223a22746578742f706c61696e222c2273697a65223a307d2c7b226e616d65223a22736179205c2268695c222e747874222c2274797065223a22746578742f706c61696e3b20636861727365743d5c227574662d385c22222c2273697a65223a317d2c7b226e616d65223a226261636b5c5c736c6173682f616e642f736c6173682e747874222c2274797065223a226170706c69636174696f6e2f6f637465742d73747265616d222c2273697a65223a327d2c7b226e616d65223a227461625c74686572655c625c665c6e5c725c75303030375c75303031667f2e747874222c2274797065223a226170706c69636174696f6e2f782d5c7530303030222c2273697a65223a337d2c7b226e616d65223a224772c3bcc39f6520e280a8e280a920f09f93842e747874222c2274797065223a22746578742f706c61696e222c2273697a65223a393030373139393235343734303939317d5d7d"
	plan, err := NewStreamPlan([]Source{
		{Name: "<a & b>.txt", Type: "text/plain", Size: 0},
		{Name: `say "hi".txt`, Type: `text/plain; charset="utf-8"`, Size: 1},
		{Name: `back\slash/and/slash.txt`, Size: 2},
		{Name: "tab\there\b\f\n\r\x07\x1f\x7f.txt", Type: "application/x-\x00", Size: 3},
		{Name: "Grüße \u2028\u2029 📄.txt", Type: "text/plain", Size: 123456789},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Node was given 2^53 − 1 for the last size, more than a bundle can hold.
	got := strings.Replace(string(plan.ListJSON), "123456789", "9007199254740991", 1)
	if hex.EncodeToString([]byte(got)) != want {
		wantBytes, _ := hex.DecodeString(want)
		t.Errorf("list =\n%s\nwant\n%s", got, wantBytes)
	}
	var decoded struct {
		Files []struct{ Name, Type string }
	}
	if err := json.Unmarshal(plan.ListJSON, &decoded); err != nil || decoded.Files[3].Name != "tab\there\b\f\n\r\x07\x1f\x7f.txt" {
		t.Errorf("the list does not decode to the names: %v", err)
	}
}

func TestListReplacesInvalidUTF8(t *testing.T) {
	plan, err := NewStreamPlan([]Source{{Name: "a\xffb\xed\xa0\x80.txt", Type: "x\xc3", Size: 0}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"files":[{"name":"a` + "\uFFFD" + `b` + "\uFFFD\uFFFD\uFFFD" + `.txt","type":"x` + "\uFFFD" + `","size":0}]}`
	if string(plan.ListJSON) != want {
		t.Errorf("list = %q, want %q", plan.ListJSON, want)
	}
	if plan.Files[0].Name != "a\uFFFDb\uFFFD\uFFFD\uFFFD.txt" {
		t.Errorf("planned name = %q", plan.Files[0].Name)
	}
}

func TestEncrypterIsDeterministicGivenThePrefix(t *testing.T) {
	ks := testKeys(t)
	sources := []Source{memSource("a", "", big()[:100000]), memSource("b", "", big()[:5])}
	plan, first := streamBundle(t, ks, sources)
	_, second := streamBundle(t, ks, sources)
	if !bytes.Equal(first, second) {
		t.Error("the same prefix and files made different bundles")
	}
	if !bytes.Equal(first[:PrefixLength], fixedPrefix()) {
		t.Error("the bundle does not start with its prefix")
	}
	drawn, err := EncryptStream(plan, sources, ks)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncryptStream(plan, sources, ks)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(drawn[:PrefixLength], again[:PrefixLength]) || bytes.Equal(drawn[PrefixLength:], first[PrefixLength:]) {
		t.Error("a drawn prefix must differ every time")
	}

	// Read in odd sizes, the bundle is the same.
	enc, err := NewEncrypterWithPrefix(plan, sources, ks, fixedPrefix())
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	buf := make([]byte, 7777)
	for {
		n, err := enc.Read(buf[:1+len(out)%7776])
		out = append(out, buf[:n]...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(out, first) {
		t.Error("reading in pieces made a different bundle")
	}
	if n, err := enc.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("after the end: %d, %v", n, err)
	}
}

// changing serves other bytes than the plan was made for.
type changing struct {
	data []byte
}

func (c changing) ReadAt(p []byte, off int64) (int, error) {
	return bytes.NewReader(c.data).ReadAt(p, off)
}

func TestEncrypterNoticesFilesThatChanged(t *testing.T) {
	ks := testKeys(t)
	for name, c := range map[string]struct {
		size    int64
		content []byte
	}{
		"shrank":            {100, big()[:90]},
		"grew":              {100, big()[:101]},
		"grew from nothing": {0, []byte("x")},
		"shrank to nothing": {70000, nil},
		"grew, at the end":  {sizeFilling(t, 65536), big()[:65536]},
	} {
		sources := []Source{{Name: "f", Size: c.size, Reader: changing{c.content}}}
		plan, err := NewStreamPlan(sources)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := EncryptStream(plan, sources, ks); !errors.Is(err, ErrSourceChanged) {
			t.Errorf("%s: err = %v, want ErrSourceChanged", name, err)
		}
	}
	plan, err := NewStreamPlan([]Source{{Name: "f", Size: 3}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncrypter(plan, []Source{{Name: "f", Size: 3}}, ks); !errors.Is(err, ErrInvalidSource) {
		t.Errorf("no reader: err = %v, want ErrInvalidSource", err)
	}
	if _, err := NewEncrypter(plan, []Source{memSource("f", "", []byte("four"))}, ks); !errors.Is(err, ErrInvalidSource) {
		t.Errorf("another size: err = %v, want ErrInvalidSource", err)
	}
	if _, err := NewEncrypterWithPrefix(plan, []Source{memSource("f", "", []byte("abc"))}, ks, make([]byte, 15)); err == nil {
		t.Error("a short prefix must be refused")
	}
}
