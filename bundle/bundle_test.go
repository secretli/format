package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/bits"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/secretli/format/keys"
)

const twentyMiB = 20 * 1024 * 1024

var (
	bigOnce sync.Once
	bigData []byte
)

// big is 20 MiB of varied bytes: five records, more than one coalesced group.
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

func TestPlanLaysOutRecordsBackToBack(t *testing.T) {
	sources := []Source{
		memSource("a.txt", "text/plain", []byte("hello")),
		memSource("empty.bin", "", nil),
		memSource("big.bin", "", big()),
	}
	plan, err := NewPlan(sources, DefaultBundleName([]string{"a.txt", "empty.bin", "big.bin"}))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Manifest.BundleName != "Secretli bundle (3 files)" {
		t.Errorf("bundle name = %q", plan.Manifest.BundleName)
	}
	if got := len(plan.Records); got != 6 {
		t.Fatalf("records = %d, want 1 + 0 + 5", got)
	}
	var offset int64
	for i, r := range plan.Records {
		if r.Offset != offset || r.Length != r.PlaintextSize+RecordOverhead {
			t.Errorf("record %d: offset %d length %d, want offset %d", i, r.Offset, r.Length, offset)
		}
		offset += r.Length
	}
	if plan.DataSize != offset || plan.TotalSize != offset+plan.EncryptedManifestLength+FooterLength {
		t.Errorf("sizes: data %d total %d", plan.DataSize, plan.TotalSize)
	}
	empty := plan.Manifest.Files[1]
	if empty.Type != "application/octet-stream" || empty.Size != 0 || empty.Chunks == nil || len(empty.Chunks) != 0 {
		t.Errorf("empty file = %+v, want a typed file with an empty, non-nil chunk list", empty)
	}
	if !bytes.Contains(plan.ManifestJSON, []byte(`"chunks":[]`)) {
		t.Error("an empty file's chunks must encode as [] for the web app")
	}
	last := plan.Manifest.Files[2].Chunks[4]
	if last.PlaintextSize != twentyMiB-4*ChunkSize {
		t.Errorf("last chunk plaintext = %d", last.PlaintextSize)
	}
	if _, err := NewPlan(nil, "x"); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty plan: err = %v, want ErrEmpty", err)
	}
	if DefaultBundleName([]string{"one.pdf"}) != "one.pdf" || DefaultBundleName([]string{""}) != "Secretli file" {
		t.Error("single-file bundle names")
	}
}

func TestFooterRoundTrip(t *testing.T) {
	f := Footer{ManifestLength: 12345, ManifestSHA256: sha256.Sum256([]byte("manifest"))}
	b, err := EncodeFooter(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != FooterLength || !bytes.Equal(b[:8], magic) {
		t.Fatalf("footer = %x", b)
	}
	got, err := ParseFooter(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != f {
		t.Errorf("footer = %+v, want %+v", got, f)
	}
	for name, bad := range map[string][]byte{
		"short":   b[:63],
		"magic":   append([]byte("SLBNDL1\x00"), b[8:]...),
		"version": append(append(append([]byte{}, b[:8]...), 0, 0, 0, 3), b[12:]...),
	} {
		if _, err := ParseFooter(bad); !errors.Is(err, ErrInvalidFooter) {
			t.Errorf("%s: err = %v, want ErrInvalidFooter", name, err)
		}
	}
	if _, err := EncodeFooter(Footer{ManifestLength: RecordOverhead}); !errors.Is(err, ErrInvalidFooter) {
		t.Error("a manifest no longer than the overhead is not a manifest")
	}
}

func TestRoundTripThroughRangesAndGroups(t *testing.T) {
	ks := testKeys(t)
	sources := []Source{
		memSource("notes.txt", "text/plain", []byte("hello bundle")),
		memSource("empty.txt", "text/plain", nil),
		memSource("big.bin", "", big()),
	}
	plan, err := NewPlan(sources, "test bundle")
	if err != nil {
		t.Fatal(err)
	}
	data, err := Encrypt(plan, sources, ks)
	if err != nil {
		t.Fatal(err)
	}
	fetchCalls := 0
	fetch := func(ctx context.Context, start, end int64) ([]byte, error) {
		fetchCalls++
		return memFetcher(data)(ctx, start, end)
	}
	ctx := context.Background()
	cached, err := CachingFetcher(ctx, fetch, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(ctx, cached, ks, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.BundleName != "test bundle" || len(manifest.Files) != 3 || manifest.TotalSize() != int64(12+twentyMiB) {
		t.Fatalf("manifest = %+v", manifest)
	}
	for i, want := range [][]byte{[]byte("hello bundle"), {}, big()} {
		var out bytes.Buffer
		var last int64
		if err := DecryptFile(ctx, cached, ks, manifest.Files[i], &out, func(n int64) { last = n }); err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
		if !bytes.Equal(out.Bytes(), want) {
			t.Errorf("file %d: %d bytes, want %d", i, out.Len(), len(want))
		}
		if last != int64(len(want)) {
			t.Errorf("file %d: progress ended at %d", i, last)
		}
	}
	// Footer, manifest, the small file's one record, and the big file's five
	// records as a group of four (16 MiB) and one of one; the bundle is too
	// large to be cached whole.
	if fetchCalls != 5 {
		t.Errorf("fetch calls = %d, want 5", fetchCalls)
	}
}

func TestSmallBundlesAreFetchedOnce(t *testing.T) {
	ks := testKeys(t)
	sources := []Source{memSource("secret.txt", "text/plain", []byte("the launch code"))}
	plan, err := NewPlan(sources, "secret.txt")
	if err != nil {
		t.Fatal(err)
	}
	data, err := Encrypt(plan, sources, ks)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	fetch := func(ctx context.Context, start, end int64) ([]byte, error) {
		calls++
		return memFetcher(data)(ctx, start, end)
	}
	ctx := context.Background()
	cached, err := CachingFetcher(ctx, fetch, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(ctx, cached, ks, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := DecryptFile(ctx, cached, ks, manifest.Files[0], &out, nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != "the launch code" || calls != 1 {
		t.Errorf("text = %q after %d fetches, want one fetch", out.String(), calls)
	}
}

func TestTamperingIsNoticed(t *testing.T) {
	ks := testKeys(t)
	sources := []Source{memSource("a.txt", "text/plain", []byte("payload"))}
	plan, err := NewPlan(sources, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	data, err := Encrypt(plan, sources, ks)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	flippedRecord := append([]byte{}, data...)
	flippedRecord[RecordOverhead] ^= 1 // inside the first record's ciphertext
	manifest, err := ReadManifest(ctx, memFetcher(flippedRecord), ks, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(ctx, memFetcher(flippedRecord), ks, manifest.Files[0], &bytes.Buffer{}, nil); !errors.Is(err, keys.ErrDecrypt) {
		t.Errorf("flipped record: err = %v, want ErrDecrypt", err)
	}

	flippedManifest := append([]byte{}, data...)
	flippedManifest[plan.DataSize+RecordOverhead] ^= 1
	if _, err := ReadManifest(ctx, memFetcher(flippedManifest), ks, int64(len(data))); !errors.Is(err, ErrInvalidManifest) {
		t.Errorf("flipped manifest: err = %v, want the hash check to fail", err)
	}

	other := testKeys(t)
	if _, err := ReadManifest(ctx, memFetcher(data), other, int64(len(data))); !errors.Is(err, keys.ErrDecrypt) {
		t.Errorf("other keys: err = %v, want ErrDecrypt", err)
	}
	if _, err := ReadManifest(ctx, memFetcher(data[:FooterLength-1]), ks, FooterLength-1); !errors.Is(err, ErrInvalidFooter) {
		t.Errorf("truncated: err = %v, want ErrInvalidFooter", err)
	}
}

func TestManifestValidationRejectsBadLayouts(t *testing.T) {
	good := Manifest{Version: 2, BundleName: "b", ChunkSize: ChunkSize, Files: []File{{
		Index: 0, Path: "a", Name: "a", Type: "t", Size: 5,
		Chunks: []Chunk{{Index: 0, Offset: 0, Length: 5 + RecordOverhead, PlaintextSize: 5}},
	}}}
	manifestOffset := int64(5 + RecordOverhead)
	bundleSize := manifestOffset + 100 + FooterLength
	if err := good.validate(manifestOffset, bundleSize); err != nil {
		t.Fatalf("good manifest rejected: %v", err)
	}
	mutate := func(f func(m *Manifest)) Manifest {
		var m Manifest
		raw, _ := json.Marshal(good)
		_ = json.Unmarshal(raw, &m)
		f(&m)
		return m
	}
	bad := map[string]Manifest{
		"version":        mutate(func(m *Manifest) { m.Version = 1 }),
		"chunk size":     mutate(func(m *Manifest) { m.ChunkSize = 1024 }),
		"no name":        mutate(func(m *Manifest) { m.BundleName = "" }),
		"no files":       mutate(func(m *Manifest) { m.Files = nil }),
		"file index":     mutate(func(m *Manifest) { m.Files[0].Index = 1 }),
		"size mismatch":  mutate(func(m *Manifest) { m.Files[0].Size = 6 }),
		"gap at start":   mutate(func(m *Manifest) { m.Files[0].Chunks[0].Offset = 1 }),
		"record length":  mutate(func(m *Manifest) { m.Files[0].Chunks[0].Length = 5 }),
		"past manifest":  mutate(func(m *Manifest) { m.Files[0].Chunks[0].Offset = manifestOffset }),
		"empty w/chunks": mutate(func(m *Manifest) { m.Files[0].Size = 0 }),
	}
	for name, m := range bad {
		if err := m.validate(manifestOffset, bundleSize); !errors.Is(err, ErrInvalidManifest) {
			t.Errorf("%s: err = %v, want ErrInvalidManifest", name, err)
		}
	}
}

func TestEstimateCoversThePlan(t *testing.T) {
	sizes := []int64{5, 0, twentyMiB}
	sources := []Source{memSource("a", "", make([]byte, 5)), memSource("b", "", nil), memSource("c", "", big())}
	plan, err := NewPlan(sources, "x")
	if err != nil {
		t.Fatal(err)
	}
	if est := EstimateEncryptedSize(sizes); est < plan.TotalSize {
		t.Errorf("estimate %d is below the real size %d", est, plan.TotalSize)
	}
	// Padding included: a small bundle grows to 4,096 bytes, and the manifest
	// never past its cap.
	for _, size := range []int64{0, 1, 3000} {
		plan, err := NewPlan([]Source{memSource("a", "", make([]byte, size))}, "a")
		if err != nil {
			t.Fatal(err)
		}
		if est := EstimateEncryptedSize([]int64{size}); est < plan.TotalSize {
			t.Errorf("%d bytes: estimate %d is below the padded size %d", size, est, plan.TotalSize)
		}
	}
	capped := planWithManifest(t, 262100)
	if est := EstimateEncryptedSize([]int64{0}); est < capped.TotalSize {
		t.Errorf("estimate %d is below %d", est, capped.TotalSize)
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

// paddingOf is the padding field of an encoded manifest.
func paddingOf(t *testing.T, manifestJSON []byte) string {
	t.Helper()
	var m struct {
		Padding *string `json:"padding"`
	}
	if err := json.Unmarshal(manifestJSON, &m); err != nil || m.Padding == nil {
		t.Fatalf("manifest without padding field: %v", err)
	}
	return *m.Padding
}

func TestPlansArePaddedToTheirExactSize(t *testing.T) {
	ks := testKeys(t)
	for _, size := range []int{0, 14, 2048, 3900, 4100, 10 * 1024, 1 << 20, ChunkSize + 1} {
		sources := []Source{memSource("secret.txt", "text/plain", big()[:size])}
		plan, err := NewPlan(sources, "secret.txt")
		if err != nil {
			t.Fatal(err)
		}
		unpadded := plan.TotalSize - plan.PaddingLength
		if plan.TotalSize != PaddedSize(unpadded) || plan.TotalSize < MinPaddedSize {
			t.Errorf("%d bytes: total %d, want %d", size, plan.TotalSize, PaddedSize(unpadded))
		}
		padding := paddingOf(t, plan.ManifestJSON)
		if int64(len(padding)) != plan.PaddingLength {
			t.Errorf("%d bytes: %d padding characters, plan says %d", size, len(padding), plan.PaddingLength)
		}
		if !bytes.HasSuffix(plan.ManifestJSON, []byte(`,"padding":"`+padding+`"}`)) {
			t.Errorf("%d bytes: padding is not the manifest's last field", size)
		}
		for _, c := range padding {
			if !strings.ContainsRune(paddingAlphabet, c) {
				t.Fatalf("%d bytes: padding character %q", size, c)
			}
		}
		data, err := Encrypt(plan, sources, ks)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(data)) != plan.TotalSize {
			t.Errorf("%d bytes: wrote %d, planned %d", size, len(data), plan.TotalSize)
		}
		manifest, err := ReadManifest(context.Background(), memFetcher(data), ks, int64(len(data)))
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if !reflect.DeepEqual(*manifest, plan.Manifest) {
			t.Errorf("%d bytes: read %+v, planned %+v", size, *manifest, plan.Manifest)
		}
	}
}

func TestPaddingMapsRandomBytesWithoutBias(t *testing.T) {
	random := make([]byte, 4096)
	for i := range random {
		random[i] = byte(i)
	}
	plan, err := newPlan([]Source{memSource("a", "", nil)}, "a", bytes.NewReader(random))
	if err != nil {
		t.Fatal(err)
	}
	padding := paddingOf(t, plan.ManifestJSON)
	for i := range padding {
		if padding[i] != paddingAlphabet[i%64] {
			t.Fatalf("padding[%d] = %q, want %q", i, padding[i], paddingAlphabet[i%64])
		}
	}
	if _, err := newPlan([]Source{memSource("a", "", nil)}, "a", bytes.NewReader(nil)); err == nil {
		t.Error("a failing random source must fail the plan")
	}
}

// planWithManifest plans one empty file under a bundle name long enough that
// the manifest, with empty padding, is exactly this long.
func planWithManifest(t *testing.T, length int) *Plan {
	t.Helper()
	sources := []Source{memSource("a", "", nil)}
	base, err := json.Marshal(paddedManifest{Manifest: Manifest{
		Version: version, BundleName: "", ChunkSize: ChunkSize,
		Files: []File{{Path: "a", Name: "a", Type: "application/octet-stream", Chunks: []Chunk{}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlan(sources, strings.Repeat("x", length-len(base)))
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.TotalSize - plan.PaddingLength - RecordOverhead - FooterLength; got != int64(length) {
		t.Fatalf("manifest is %d bytes, want %d", got, length)
	}
	return plan
}

func TestPaddingStopsAtTheManifestCap(t *testing.T) {
	// 262,100 + 104 = 262,204 bytes would round to 270,336, which needs more
	// padding than the manifest has room for: no padding at all.
	plan := planWithManifest(t, 262100)
	if plan.PaddingLength != 0 || plan.TotalSize != 262204 || paddingOf(t, plan.ManifestJSON) != "" {
		t.Errorf("padding %d, total %d; want none and 262,204", plan.PaddingLength, plan.TotalSize)
	}
	// 258,100 + 104 rounds to 262,144, and that padding still fits.
	plan = planWithManifest(t, 258100)
	if plan.PaddingLength != 262144-258204 || plan.TotalSize != 262144 || len(plan.ManifestJSON) > MaxManifestBytes {
		t.Errorf("padding %d, total %d; want 3,940 and 262,144", plan.PaddingLength, plan.TotalSize)
	}
	// The cap itself counts the empty padding field.
	sources := []Source{memSource("a", "", nil)}
	if _, err := NewPlan(sources, strings.Repeat("x", MaxManifestBytes)); !errors.Is(err, ErrManifestTooLarge) {
		t.Errorf("err = %v, want ErrManifestTooLarge", err)
	}
}

func TestReadersIgnoreThePadding(t *testing.T) {
	ks := testKeys(t)
	sources := []Source{memSource("a.txt", "text/plain", []byte("payload"))}
	plan, err := NewPlan(sources, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	data, err := Encrypt(plan, sources, ks)
	if err != nil {
		t.Fatal(err)
	}
	records := data[:plan.DataSize]
	bare, err := json.Marshal(plan.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	open := bare[:len(bare)-1]
	for name, manifestJSON := range map[string]string{
		"no padding, as older writers made": string(bare),
		"empty padding":                     string(open) + `,"padding":""}`,
		"padding not last":                  `{"padding":"AAAA",` + string(bare[1:]),
		"padding of another type":           string(open) + `,"padding":{"n":[1,2,3]}}`,
		"padding outside the alphabet":      string(open) + `,"padding":"<&>é \n"}`,
		"another unknown field":             string(open) + `,"padding":"x","later":true}`,
	} {
		encrypted, err := ks.EncryptRecord([]byte(manifestJSON), ManifestAAD())
		if err != nil {
			t.Fatal(err)
		}
		trailer, err := EncodeFooter(Footer{ManifestLength: int64(len(encrypted)), ManifestSHA256: sha256.Sum256(encrypted)})
		if err != nil {
			t.Fatal(err)
		}
		bundle := append(append(append([]byte{}, records...), encrypted...), trailer...)
		manifest, err := ReadManifest(context.Background(), memFetcher(bundle), ks, int64(len(bundle)))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !reflect.DeepEqual(*manifest, plan.Manifest) {
			t.Errorf("%s: read %+v", name, *manifest)
		}
	}
}
