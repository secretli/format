// Package cpace is CPace over ristretto255 with SHA-512 (CPACE-RISTR255-SHA512),
// as specified in draft-irtf-cfrg-cpace-21, initiator-responder setting. It is
// the password-authenticated key exchange behind the short-code transfer;
// FORMAT.md section 11. Function names follow the draft, and the test vectors
// of its appendix B.3 pin every step. Scalars, shares and points travel as
// their 32-byte encodings.
package cpace

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
)

const (
	// ScalarSize is the encoding of a scalar: 32 bytes, little-endian.
	ScalarSize = 32
	// ShareSize is the encoding of a share or point: 32 bytes.
	ShareSize = 32

	// sha512BlockSize is SHA-512's input block size, which the generator
	// string pads to.
	sha512BlockSize = 128
)

var (
	dsi    = []byte("CPaceRistretto255")
	dsiISK = []byte("CPaceRistretto255_ISK")
)

// ErrInvalidShare is a received share that does not decode, or that leads to
// the neutral element. The run must be aborted.
var ErrInvalidShare = errors.New("invalid CPace share")

// PrependLen prefixes data with its length, LEB128-encoded.
func PrependLen(data []byte) []byte {
	var out []byte
	n := len(data)
	for {
		if n < 0x80 {
			out = append(out, byte(n))
			break
		}
		out = append(out, byte(n&0x7f)|0x80)
		n >>= 7
	}
	return append(out, data...)
}

// LVCat concatenates its arguments, each with its length prepended.
func LVCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, PrependLen(p)...)
	}
	return out
}

// GeneratorString is the input to the generator's hash: the password, padded
// so that it fills the first SHA-512 block, the channel identifier and the
// session id.
func GeneratorString(prs, ci, sid []byte) []byte {
	zpad := max(0, sha512BlockSize-1-len(PrependLen(prs))-len(PrependLen(dsi)))
	return LVCat(dsi, prs, make([]byte, zpad), ci, sid)
}

// Generator is the password-dependent generator g: ristretto255's element
// derivation (RFC 9496, section 4.3.4) over SHA-512 of the generator string.
func Generator(prs, ci, sid []byte) []byte {
	hash := sha512.Sum512(GeneratorString(prs, ci, sid))
	g, err := ristretto255.NewIdentityElement().SetUniformBytes(hash[:])
	if err != nil {
		// SetUniformBytes fails only for input that is not 64 bytes.
		panic(err)
	}
	return g.Bytes()
}

// SampleScalar draws a secret scalar as the draft recommends: 32 random
// bytes with the bits above 252 cleared, so that it is always below the
// group order. Zero is drawn again.
func SampleScalar() ([]byte, error) {
	for {
		b := make([]byte, ScalarSize)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("draw scalar: %w", err)
		}
		b[ScalarSize-1] &= 0x0f
		for _, x := range b {
			if x != 0 {
				return b, nil
			}
		}
	}
}

// Share is this side's public share Y = y·g, for a scalar from SampleScalar
// and a generator from Generator.
func Share(generator, scalar []byte) ([]byte, error) {
	s, err := decodeScalar(scalar)
	if err != nil {
		return nil, err
	}
	g, err := ristretto255.NewIdentityElement().SetCanonicalBytes(generator)
	if err != nil {
		return nil, fmt.Errorf("invalid generator: %w", err)
	}
	return ristretto255.NewIdentityElement().ScalarMult(s, g).Bytes(), nil
}

// ScalarMultVfy is the draft's scalar_mult_vfy: y·X for the other side's
// share X. It returns ErrInvalidShare when X does not decode or the product
// is the neutral element.
func ScalarMultVfy(scalar, encoded []byte) ([]byte, error) {
	s, err := decodeScalar(scalar)
	if err != nil {
		return nil, err
	}
	x, err := ristretto255.NewIdentityElement().SetCanonicalBytes(encoded)
	if err != nil {
		return nil, ErrInvalidShare
	}
	product := ristretto255.NewIdentityElement().ScalarMult(s, x)
	if product.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, ErrInvalidShare
	}
	return product.Bytes(), nil
}

// TranscriptIR is the initiator-responder transcript: the initiator's share
// and associated data, then the responder's.
func TranscriptIR(ya, ada, yb, adb []byte) []byte {
	return append(LVCat(ya, ada), LVCat(yb, adb)...)
}

// ISK is the intermediate session key both sides share when they used the
// same password, channel identifier and session id.
func ISK(sid, k, ya, ada, yb, adb []byte) []byte {
	h := sha512.New()
	h.Write(LVCat(dsiISK, sid, k))
	h.Write(TranscriptIR(ya, ada, yb, adb))
	return h.Sum(nil)
}

func decodeScalar(b []byte) (*ristretto255.Scalar, error) {
	s, err := ristretto255.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		return nil, fmt.Errorf("invalid scalar: %w", err)
	}
	return s, nil
}
