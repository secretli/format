package cpace

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// draft-irtf-cfrg-cpace-21, appendix B.3 (CPACE-RISTR255-SHA512).
var (
	prs      = []byte("Password")
	ci       = h("0b415f696e69746961746f720b425f726573706f6e646572")
	sid      = h("7e4b4791d6a8ef019b936c79fb7f2c57")
	ada      = []byte("ADa")
	adb      = []byte("ADb")
	yaScalar = h("da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08")
	ybScalar = h("d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d")
	ya       = h("d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157")
	yb       = h("3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258")
	k        = h("80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f")
)

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func TestPrependLen(t *testing.T) {
	if got := hexOf(PrependLen(nil)); got != "00" {
		t.Errorf("empty: %s", got)
	}
	if got := hexOf(PrependLen([]byte("1234"))); got != "0431323334" {
		t.Errorf("1234: %s", got)
	}
	long := make([]byte, 128)
	for i := range long {
		long[i] = byte(i)
	}
	if got := hexOf(PrependLen(long)[:3]); got != "800100" {
		t.Errorf("128 bytes: %s", got)
	}
}

func TestLVCat(t *testing.T) {
	got := hexOf(LVCat([]byte("1234"), []byte("5"), nil, []byte("678")))
	if got != "043132333401350003363738" {
		t.Errorf("got %s", got)
	}
}

func TestTranscriptIR(t *testing.T) {
	got := hexOf(TranscriptIR([]byte("123"), []byte("PartyA"), []byte("234"), []byte("PartyB")))
	if got != "03313233065061727479410332333406506172747942" {
		t.Errorf("got %s", got)
	}
}

func TestGenerator(t *testing.T) {
	genStr := GeneratorString(prs, ci, sid)
	want := "11435061636552697374726574746f3235350850617373776f726464" +
		strings.Repeat("00", 100) +
		"180b415f696e69746961746f720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f2c57"
	if len(genStr) != 170 || hexOf(genStr) != want {
		t.Errorf("generator string = %s", hexOf(genStr))
	}
	hash := sha512.Sum512(genStr)
	if got := hexOf(hash[:]); got != "da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288b6663af06bf645c93cd1c51512307199c80e84908916d983b34af77205f90851a657ee27" {
		t.Errorf("hash = %s", got)
	}
	if got := hexOf(Generator(prs, ci, sid)); got != "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56" {
		t.Errorf("generator = %s", got)
	}
}

func TestShares(t *testing.T) {
	g := Generator(prs, ci, sid)
	for _, c := range []struct {
		scalar, want []byte
	}{{yaScalar, ya}, {ybScalar, yb}} {
		got, err := Share(g, c.scalar)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("share = %x, want %x", got, c.want)
		}
	}
}

func TestBothSidesDeriveK(t *testing.T) {
	ka, err := ScalarMultVfy(yaScalar, yb)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := ScalarMultVfy(ybScalar, ya)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, k) || !bytes.Equal(kb, k) {
		t.Errorf("K = %x and %x, want %x", ka, kb, k)
	}
}

func TestISK(t *testing.T) {
	got := hexOf(ISK(sid, k, ya, ada, yb, adb))
	if got != "b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dcae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c3fa2068af7900447" {
		t.Errorf("ISK = %s", got)
	}
}

// B.3.10
func TestScalarMultVfyValid(t *testing.T) {
	s := h("7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05")
	x := h("2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c")
	got, err := ScalarMultVfy(s, x)
	if err != nil {
		t.Fatal(err)
	}
	if hexOf(got) != "7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e" {
		t.Errorf("got %x", got)
	}
}

// B.3.11
func TestScalarMultVfyRejects(t *testing.T) {
	s := h("7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05")
	invalid := h("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c")
	if _, err := ScalarMultVfy(s, invalid); !errors.Is(err, ErrInvalidShare) {
		t.Errorf("invalid encoding: %v", err)
	}
	if _, err := ScalarMultVfy(s, make([]byte, 32)); !errors.Is(err, ErrInvalidShare) {
		t.Errorf("neutral element: %v", err)
	}
	if _, err := ScalarMultVfy(s, make([]byte, 31)); !errors.Is(err, ErrInvalidShare) {
		t.Errorf("short encoding: %v", err)
	}
}

func TestSampleScalar(t *testing.T) {
	for range 50 {
		s, err := SampleScalar()
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != ScalarSize || s[ScalarSize-1] > 0x0f || bytes.Equal(s, make([]byte, ScalarSize)) {
			t.Fatalf("scalar %x", s)
		}
		if _, err := decodeScalar(s); err != nil {
			t.Fatalf("scalar %x is not canonical: %v", s, err)
		}
	}
}
