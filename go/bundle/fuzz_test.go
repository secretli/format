package bundle

import (
	"context"
	"strings"
	"testing"

	"github.com/secretli/format/go/keys"
)

// FuzzParseList fuzzes the file-list parser directly. The list is plaintext
// only the sender writes, so everything here is a malicious-sender probe:
// lengths that lie, sizes that overflow, names that are not strings. The
// parser must never panic and never return a start past the stream.
func FuzzParseList(f *testing.F) {
	f.Add([]byte(`{"files":[{"name":"a.txt","size":3}]}`), int64(65536))
	f.Add([]byte(`{"files":[]}`), int64(10))
	f.Add([]byte(`{}`), int64(10))
	f.Add([]byte(`null`), int64(10))
	f.Add([]byte(`[]`), int64(10))
	f.Add([]byte(`{"files":[{"name":"a","size":9007199254740991}]}`), int64(65536))
	f.Add([]byte(`{"files":[{"name":"a","size":-1}]}`), int64(65536))
	f.Add([]byte(`{"files":[{"name":123,"size":1}]}`), int64(65536))
	f.Add([]byte(`{"files":[{"name":"a","size":1,"type":"text/html"}]}`), int64(65536))
	f.Add([]byte(`{"files":[{"name":"a","size":1},{"name":"b","size":1}]}`), int64(65536))
	f.Add([]byte(`{"files":[`+strings.Repeat(`{"name":"a","size":1},`, 1000)+`{"name":"b","size":1}]}`), int64(65536))
	f.Add([]byte(`{"files":[{"name":"a","size":9223372036854775807},{"name":"b","size":9223372036854775807}]}`), int64(65536))
	f.Add([]byte("\xff\xfe\x00bad json"), int64(65536))
	f.Fuzz(func(t *testing.T, raw []byte, stream int64) {
		entries, starts, err := parseList(raw, stream)
		if err != nil {
			return
		}
		if len(entries) != len(starts) {
			t.Fatalf("entries and starts differ: %d vs %d", len(entries), len(starts))
		}
		for i, s := range starts {
			if s < 0 || s > stream {
				t.Fatalf("file %d starts at %d, stream is %d", i, s, stream)
			}
			if end := s + entries[i].Size; end < s || end > stream {
				t.Fatalf("file %d (%d bytes at %d) overflows the stream %d", i, entries[i].Size, s, stream)
			}
		}
	})
}

// FuzzOpen runs the whole opening path against a server that answers with
// arbitrary bytes: wrong lengths, truncated streams, ciphertext garbage. The
// fetcher must never make Open panic, whatever it returns.
func FuzzOpen(f *testing.F) {
	ks, err := keys.Generate()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(make([]byte, 65581), int64(65581))
	f.Add(make([]byte, 100), int64(65581))
	f.Add(make([]byte, 0), int64(65581))
	f.Add(make([]byte, 65581), int64(131163))
	f.Add(make([]byte, 65581), int64(25))
	f.Add(make([]byte, 65581), int64(0))
	f.Add(make([]byte, 65581), int64(-1))
	f.Add(make([]byte, 1048577), int64(1048577))
	f.Fuzz(func(t *testing.T, data []byte, size int64) {
		// A server that answers with whatever bytes it likes, including
		// short answers: Open must cope with everything.
		fetch := func(ctx context.Context, start, end int64) ([]byte, error) {
			if start < 0 || start > int64(len(data)) {
				return nil, nil
			}
			to := end + 1
			if to > int64(len(data)) {
				to = int64(len(data))
			}
			return data[start:to], nil
		}
		b, err := Open(context.Background(), fetch, ks, size)
		if err != nil {
			return
		}
		_ = b.TotalSize()
	})
}
