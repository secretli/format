package bundle

import (
	"bytes"
	"context"
	"math/bits"
	"sync"
	"testing"

	"github.com/secretli/format/keys"
)

const twentyMiB = 20 * 1024 * 1024

var (
	bigOnce sync.Once
	bigData []byte
)

// big is 20 MiB of varied bytes: more than one coalesced request.
func big() []byte {
	bigOnce.Do(func() {
		bigData = make([]byte, twentyMiB)
		var x uint32 = 2463534242
		for i := range bigData {
			x ^= x << 13
			x ^= x >> 17
			x ^= x << 5
			bigData[i] = byte(x)
		}
	})
	return bigData
}

func testKeys(t *testing.T) *keys.KeySet {
	t.Helper()
	ks, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func memSource(name, typ string, data []byte) Source {
	return Source{Name: name, Type: typ, Size: int64(len(data)), Reader: bytes.NewReader(data)}
}

func memFetcher(data []byte) RangeFetcher {
	return func(_ context.Context, start, end int64) ([]byte, error) {
		if start < 0 || end >= int64(len(data)) || end < start {
			return nil, ErrRangeMismatch
		}
		return data[start : end+1], nil
	}
}

func TestPadme(t *testing.T) {
	for _, c := range []struct{ size, want int64 }{
		{0, 0}, {1, 1}, {2, 2}, {3, 3}, {5, 5}, {9, 10}, {100, 104}, {1000, 1024},
		{4095, 4096}, {4096, 4096}, {4097, 4352}, {10000, 10240}, {10544, 10752},
		{65535, 65536}, {65536, 65536}, {65537, 67584},
		{1<<20 - 1, 1 << 20}, {1 << 20, 1 << 20}, {1<<20 + 1, 1081344},
		{1<<30 - 1, 1 << 30}, {1 << 30, 1 << 30}, {1<<30 + 1, 1107296256},
	} {
		if got := Padme(c.size); got != c.want {
			t.Errorf("Padme(%d) = %d, want %d", c.size, got, c.want)
		}
	}
	// What the format promises of it: never smaller, stable once rounded, at
	// most 12.5% more, and never past a power of two the size was below.
	check := func(size int64) {
		p := Padme(size)
		if p < size || Padme(p) != p || (p-size)*8 > size {
			t.Fatalf("Padme(%d) = %d", size, p)
		}
		if power := int64(1) << bits.Len64(uint64(size-1)); p > power {
			t.Fatalf("Padme(%d) = %d is past %d", size, p, power)
		}
	}
	for size := int64(2); size <= 1<<17; size++ {
		check(size)
	}
	for size := int64(1 << 17); size < 1<<40; size = size*9/8 + 12345 {
		check(size)
	}
}

func TestPaddedSizeHasAMinimum(t *testing.T) {
	for _, c := range []struct{ size, want int64 }{
		{1, 4096}, {300, 4096}, {4095, 4096}, {4096, 4096}, {4097, 4352},
	} {
		if got := PaddedSize(c.size); got != c.want {
			t.Errorf("PaddedSize(%d) = %d, want %d", c.size, got, c.want)
		}
	}
}

func TestSHA256Hex(t *testing.T) {
	if got := SHA256Hex([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("SHA256Hex(abc) = %s", got)
	}
}
