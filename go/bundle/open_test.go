package bundle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/secretli/format/go/keys"
)

func sizedSources(sizes ...int64) []Source {
	sources := make([]Source, len(sizes))
	offset := int64(0)
	for i, size := range sizes {
		sources[i] = memSource(fmt.Sprintf("file-%d.bin", i), "", big()[offset:offset+size])
		offset = (offset + size) % (twentyMiB / 2)
	}
	return sources
}

func contentOf(src Source) []byte {
	b := make([]byte, src.Size)
	_, _ = src.Reader.ReadAt(b, 0)
	return b
}

func TestOpenCoalescesChunksOfOneFile(t *testing.T) {
	ks := testKeys(t)
	sources := []Source{memSource("big.bin", "", big())}
	plan, data := streamBundle(t, ks, sources)
	c := &counter{data: data}
	b, err := Open(context.Background(), c.fetch, ks, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Files) != 1 || b.Files[0] != (Entry{Index: 0, Name: "big.bin", Type: "application/octet-stream", Size: twentyMiB}) {
		t.Fatalf("opened %+v", b)
	}
	var out bytes.Buffer
	var progress int64
	if err := b.DecryptFile(context.Background(), 0, &out, func(n int64) { progress = n }); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), big()) || progress != twentyMiB {
		t.Errorf("read %d bytes, progress %d", out.Len(), progress)
	}
	size := int64(len(data))
	// The first MiB, which holds 15 whole chunks, then the rest of the
	// file's 321 chunks in requests of 256.
	last := plan.Chunks - 1
	want := [][2]int64{
		{0, SmallBundleBytes - 1},
		{chunkStart(15), chunkStart(15+256) - 1},
		{chunkStart(15 + 256), chunkEnd((twentyMiB+int64(len(plan.ListJSON))+3)/PieceSize, size) - 1},
	}
	if last == (twentyMiB+int64(len(plan.ListJSON))+3)/PieceSize {
		t.Fatal("the test wants padding chunks after the file")
	}
	if fmt.Sprint(c.ranges) != fmt.Sprint(want) {
		t.Errorf("ranges\n%v\nwant\n%v", c.ranges, want)
	}
}

func TestOpenReadsASelectionAcrossShortGaps(t *testing.T) {
	ks := testKeys(t)
	// 3 MiB, then three small files around 900 KiB (fetched across) and
	// 2 MiB (not).
	sources := sizedSources(3<<20, 100, 900<<10, 100, 2<<20, 100, 0)
	plan, data := streamBundle(t, ks, sources)
	c := &counter{data: data}
	b, err := Open(context.Background(), c.fetch, ks, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var progress []int64
	got := map[int][]byte{}
	err = b.Decrypt(context.Background(), []int{5, 1, 3, 6, 1}, func(e Entry) (io.WriteCloser, error) {
		return &fileWriter{done: func(data []byte) { got[e.Index] = data }}, nil
	}, func(n int64) { progress = append(progress, n) })
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{1, 3, 5, 6} {
		if !bytes.Equal(got[i], contentOf(sources[i])) {
			t.Errorf("file %d: %d bytes", i, len(got[i]))
		}
	}
	if len(got) != 4 || fmt.Sprint(progress) != "[100 200 300]" {
		t.Errorf("files %d, progress %v", len(got), progress)
	}
	chunkOf := func(i int) int64 { return plan.Starts[i] / PieceSize }
	// Fewer than 16 chunks between (under 1 MiB), then more.
	if gap := chunkOf(3) - chunkOf(1) - 1; gap < 10 || gap >= 16 || chunkOf(5)-chunkOf(3)-1 < 16 {
		t.Fatalf("gaps of %d and %d chunks", chunkOf(3)-chunkOf(1)-1, chunkOf(5)-chunkOf(3)-1)
	}
	want := [][2]int64{
		{0, SmallBundleBytes - 1},
		{chunkStart(chunkOf(1)), chunkStart(chunkOf(3)+1) - 1},
		{chunkStart(chunkOf(5)), chunkStart(chunkOf(5)+1) - 1},
	}
	if fmt.Sprint(c.ranges) != fmt.Sprint(want) {
		t.Errorf("ranges\n%v\nwant\n%v", c.ranges, want)
	}
}

func TestCoalescePlansRequests(t *testing.T) {
	for _, c := range []struct {
		needed []span
		max    int64
		want   string
	}{
		{[]span{{0, 9}}, 4, "[{0 3} {4 7} {8 9}]"},
		{[]span{{0, 0}, {16, 16}}, 256, "[{0 16}]"},
		{[]span{{0, 0}, {17, 17}}, 256, "[{0 0} {17 17}]"},
		{[]span{{0, 2}, {5, 7}}, 4, "[{0 2} {5 7}]"},
		{[]span{{0, 2}, {3, 7}}, 4, "[{0 3} {4 7}]"},
		{[]span{{0, 1}, {3, 3}, {5, 9}}, 6, "[{0 5} {6 9}]"},
	} {
		if got := fmt.Sprint(coalesce(c.needed, c.max)); got != c.want {
			t.Errorf("coalesce(%v, %d) = %s, want %s", c.needed, c.max, got, c.want)
		}
	}
}

func TestManySmallFilesTakeFewRequests(t *testing.T) {
	ks := testKeys(t)
	sizes := make([]int64, 10000)
	for i := range sizes {
		sizes[i] = int64(i % 300)
	}
	sources := sizedSources(sizes...)
	_, data := streamBundle(t, ks, sources)
	if len(data) <= SmallBundleBytes {
		t.Fatalf("bundle of %d bytes; the test wants one above 1 MiB", len(data))
	}
	c := &counter{data: data}
	b, err := Open(context.Background(), c.fetch, ks, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	got := decryptAll(t, b, nil)
	for i, src := range sources {
		if !bytes.Equal(got[i], contentOf(src)) {
			t.Fatalf("file %d: %d bytes", i, len(got[i]))
		}
	}
	// The first MiB and the remaining ~3 MiB in one request.
	if len(c.ranges) != 2 {
		t.Errorf("%d requests: %v", len(c.ranges), c.ranges)
	}
}

func TestAListPastTheFirstMiB(t *testing.T) {
	ks := testKeys(t)
	sources := make([]Source, 20000)
	for i := range sources {
		sources[i] = memSource(fmt.Sprintf("a-rather-long-file-name-%05d.txt", i), "text/plain", nil)
	}
	sources = append(sources, memSource("last.bin", "", []byte("the end")))
	plan, data := streamBundle(t, ks, sources)
	if len(plan.ListJSON) <= SmallBundleBytes {
		t.Fatalf("list of %d bytes; the test wants one past 1 MiB", len(plan.ListJSON))
	}
	c := &counter{data: data}
	b, err := Open(context.Background(), c.fetch, ks, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	lastListChunk := int64(3+len(plan.ListJSON)) / PieceSize
	want := [][2]int64{
		{0, SmallBundleBytes - 1},
		{SmallBundleBytes, chunkStart(lastListChunk+1) - 1},
	}
	if fmt.Sprint(c.ranges) != fmt.Sprint(want) {
		t.Errorf("ranges\n%v\nwant\n%v", c.ranges, want)
	}
	if len(b.Files) != 20001 || b.Files[12345].Name != "a-rather-long-file-name-12345.txt" {
		t.Fatalf("%d files", len(b.Files))
	}
	var out bytes.Buffer
	if err := b.DecryptFile(context.Background(), 20000, &out, nil); err != nil || out.String() != "the end" {
		t.Errorf("last file = %q, %v", out.String(), err)
	}
}

func TestSmallBundlesAreOneRequest(t *testing.T) {
	ks := testKeys(t)
	// More than 64 KiB of list: it spans two chunks.
	sources := make([]Source, 1500)
	for i := range sources {
		sources[i] = memSource(fmt.Sprintf("note-%04d.txt", i), "text/plain", []byte(fmt.Sprint(i)))
	}
	plan, data := streamBundle(t, ks, sources)
	if len(plan.ListJSON) <= PieceSize || len(data) > SmallBundleBytes {
		t.Fatalf("list of %d bytes, bundle of %d", len(plan.ListJSON), len(data))
	}
	c := &counter{data: data}
	b, err := Open(context.Background(), c.fetch, ks, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	got := decryptAll(t, b, nil)
	if string(got[1499]) != "1499" || len(got) != 1500 {
		t.Errorf("last file = %q", got[1499])
	}
	if len(c.ranges) != 1 {
		t.Errorf("%d requests: %v", len(c.ranges), c.ranges)
	}
}

func TestOpenNoticesTampering(t *testing.T) {
	ks := testKeys(t)
	ctx := context.Background()
	// Four chunks: the list and a file in all of them, a little padding.
	sources := []Source{memSource("a.bin", "", big()[:65536*3+1000])}
	plan, data := streamBundle(t, ks, sources)
	if plan.Chunks != 4 {
		t.Fatalf("%d chunks", plan.Chunks)
	}
	read := func(data []byte, size int64, ks *keys.KeySet) error {
		b, err := Open(ctx, memFetcher(data), ks, size)
		if err != nil {
			return err
		}
		return b.DecryptFile(ctx, 0, io.Discard, nil)
	}
	if err := read(data, int64(len(data)), ks); err != nil {
		t.Fatal(err)
	}

	swapped := append([]byte{}, data...)
	copy(swapped[chunkStart(1):chunkStart(2)], data[chunkStart(2):chunkStart(3)])
	copy(swapped[chunkStart(2):chunkStart(3)], data[chunkStart(1):chunkStart(2)])
	duplicated := append([]byte{}, data...)
	copy(duplicated[chunkStart(2):chunkStart(3)], data[chunkStart(1):chunkStart(2)])
	extended := append(append([]byte{}, data...), make([]byte, SealedChunkSize)...)
	extendedByOne := append(append([]byte{}, data...), 0)
	withPassword, err := keys.FromShareSecret(ks.Encoded().ShareSecret, "a password")
	if err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"swapped chunks":         read(swapped, int64(len(data)), ks),
		"a chunk twice":          read(duplicated, int64(len(data)), ks),
		"cut short by a byte":    read(data[:len(data)-1], int64(len(data)-1), ks),
		"cut short by a chunk":   read(data[:chunkStart(3)], chunkStart(3), ks),
		"extended by a chunk":    read(extended, int64(len(extended)), ks),
		"extended by a byte":     read(extendedByOne, int64(len(extendedByOne)), ks),
		"another secret's keys":  read(data, int64(len(data)), testKeys(t)),
		"another blob key":       read(data, int64(len(data)), withPassword),
		"a flipped prefix bit":   read(append([]byte{data[0] ^ 1}, data[1:]...), int64(len(data)), ks),
		"a flipped content bit":  read(append(append(append([]byte{}, data[:chunkStart(2)+5]...), data[chunkStart(2)+5]^1), data[chunkStart(2)+6:]...), int64(len(data)), ks),
		"a flipped last-tag bit": read(append(append([]byte{}, data[:len(data)-1]...), data[len(data)-1]^1), int64(len(data)), ks),
	} {
		if !errors.Is(err, keys.ErrDecrypt) && !errors.Is(err, ErrInvalidList) {
			t.Errorf("%s: err = %v, want a failure", name, err)
		}
	}

	// What comes before a cut is still exactly what was written.
	shortened := data[:len(data)-10]
	b, err := Open(ctx, memFetcher(shortened), ks, int64(len(shortened)))
	if err != nil {
		t.Fatalf("a bundle cut in its last chunk still has its list: %v", err)
	}
	var out bytes.Buffer
	if err := b.DecryptFile(ctx, 0, &out, nil); !errors.Is(err, keys.ErrDecrypt) || !bytes.Equal(out.Bytes(), big()[:out.Len()]) || out.Len() == 0 {
		t.Errorf("err = %v after %d bytes", err, out.Len())
	}
}

func TestOpenRefusesImpossibleSizes(t *testing.T) {
	ks := testKeys(t)
	for _, size := range []int64{0, 1, 32, 16 + SealedChunkSize + 16, 16 + SealedChunkSize + 10, 16 + 2*SealedChunkSize + 1} {
		c := &counter{data: make([]byte, size)}
		if _, err := Open(context.Background(), c.fetch, ks, size); !errors.Is(err, ErrInvalidSize) {
			t.Errorf("%d bytes: err = %v, want ErrInvalidSize", size, err)
		}
		if len(c.ranges) != 0 {
			t.Errorf("%d bytes: fetched %v before refusing", size, c.ranges)
		}
	}
	// 33 bytes: one chunk with one byte of plaintext, too short for a list.
	b := sealStream(t, ks, []byte{0})
	if _, err := Open(context.Background(), memFetcher(b), ks, int64(len(b))); !errors.Is(err, ErrInvalidList) {
		t.Errorf("33 bytes: err = %v, want ErrInvalidList", err)
	}
}

func TestListValidation(t *testing.T) {
	ks := testKeys(t)
	open := func(stream []byte) (*Bundle, error) {
		data := sealStream(t, ks, stream)
		return Open(context.Background(), memFetcher(data), ks, int64(len(data)))
	}
	file := func(fields string) string { return `{"files":[` + fields + `]}` }

	for name, list := range map[string]string{
		"not JSON":             `{"files":[`,
		"an array":             `[{"name":"a","type":"t","size":1}]`,
		"no files":             `{}`,
		"files null":           `{"files":null}`,
		"files an object":      `{"files":{"name":"a","type":"t","size":1}}`,
		"files a string":       `{"files":"a"}`,
		"no file":              `{"files":[]}`,
		"a file not an object": file(`5`),
		"a file null":          file(`null`),
		"no name":              file(`{"type":"t","size":1}`),
		"an empty name":        file(`{"name":"","type":"t","size":1}`),
		"a name not a string":  file(`{"name":5,"type":"t","size":1}`),
		"a name null":          file(`{"name":null,"type":"t","size":1}`),
		"a name in capitals":   file(`{"NAME":"a","type":"t","size":1}`),
		"no type":              file(`{"name":"a","size":1}`),
		"a type not a string":  file(`{"name":"a","type":[],"size":1}`),
		"no size":              file(`{"name":"a","type":"t"}`),
		"a negative size":      file(`{"name":"a","type":"t","size":-1}`),
		"a fractional size":    file(`{"name":"a","type":"t","size":1.5}`),
		"a size of 2^53":       file(`{"name":"a","type":"t","size":9007199254740992}`),
		"a size as a string":   file(`{"name":"a","type":"t","size":"1"}`),
		"a size null":          file(`{"name":"a","type":"t","size":null}`),
		"a size true":          file(`{"name":"a","type":"t","size":true}`),
		"more than the stream": file(`{"name":"a","type":"t","size":4100}`),
		"more, summed":         file(`{"name":"a","type":"t","size":2050},{"name":"b","type":"t","size":2050}`),
		"a byte order mark":    "\ufeff" + file(`{"name":"a","type":"t","size":1}`),
		"trailing garbage":     file(`{"name":"a","type":"t","size":1}`) + "x",
	} {
		if _, err := open(streamOf(list, []byte("x"), 4096)); !errors.Is(err, ErrInvalidList) {
			t.Errorf("%s: err = %v, want ErrInvalidList", name, err)
		}
	}

	for name, length := range map[string]uint32{"0": 0, "1": 1, "past 4 MiB": MaxListBytes + 1, "past the stream": 4093} {
		stream := streamOf(`{}`, nil, 4096)
		stream[0], stream[1], stream[2], stream[3] = byte(length>>24), byte(length>>16), byte(length>>8), byte(length)
		if _, err := open(stream); !errors.Is(err, ErrInvalidList) {
			t.Errorf("list length %s: err = %v, want ErrInvalidList", name, err)
		}
	}

	// What readers accept: unknown fields anywhere, white space, numbers
	// that are integers however they are written, a list that fills the
	// stream to its last byte.
	for name, c := range map[string]struct {
		list string
		want []Entry
	}{
		"unknown fields": {
			`{"version":9,"files":[{"mtime":1,"name":"a","Name":"b","type":"t","size":1,"extra":{"x":[1]}}],"later":null}`,
			[]Entry{{0, "a", "t", 1}},
		},
		"white space and an empty type": {
			"\n { \"files\" : [ { \"size\" : 1 , \"type\" : \"\" , \"name\" : \"a\" } ] } \t",
			[]Entry{{0, "a", "", 1}},
		},
		"integers written otherwise": {
			file(`{"name":"a","type":"t","size":1.0},{"name":"b","type":"t","size":1e1},{"name":"c","type":"t","size":-0},{"name":"d","type":"t","size":0.2e1}`),
			[]Entry{{0, "a", "t", 1}, {1, "b", "t", 10}, {2, "c", "t", 0}, {3, "d", "t", 2}},
		},
		"escapes": {
			file(`{"name":"\u00e9\ud83d\udcc4\/","type":"t","size":0}`),
			[]Entry{{0, "é📄/", "t", 0}},
		},
	} {
		b, err := open(streamOf(c.list, bytes.Repeat([]byte("z"), 13), 4096))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if fmt.Sprint(b.Files) != fmt.Sprint(c.want) {
			t.Errorf("%s: files %v, want %v", name, b.Files, c.want)
		}
	}
	list := file(`{"name":"a","type":"t","size":` + fmt.Sprint(4096-4-len(file(`{"name":"a","type":"t","size":4057}`))) + `}`)
	b, err := open(streamOf(list, bytes.Repeat([]byte("q"), 4096-4-len(list)), 4096))
	if err != nil || b.Files[0].Size != int64(4096-4-len(list)) {
		t.Fatalf("a list and file that fill the stream: %v", err)
	}
	if got := decryptAll(t, b, nil)[0]; string(got) != strings.Repeat("q", len(got)) {
		t.Errorf("read %q", got)
	}
}
