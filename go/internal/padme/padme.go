// Package padme is the Padmé rounding that both the metadata envelope and
// the bundle pad to (FORMAT.md sections 4 and 6). It lives apart so that
// keys and bundle can share it; bundle exports it as bundle.Padme.
package padme

import "math/bits"

// Padme rounds a size up so that it keeps only about log2(log2(size))
// significant bits (Nikitin et al., "Reducing Metadata Leakage from
// Encrypted Files and Communication with PURBs", 2019). That costs at most
// 12.5% and leaks only O(log log size) bits, and a size at or below a power
// of two stays at or below it.
func Padme(size int64) int64 {
	if size < 2 {
		return size
	}
	e := bits.Len64(uint64(size)) - 1 // floor(log2 size)
	s := bits.Len(uint(e))            // floor(log2 e) + 1
	mask := int64(1)<<(e-s) - 1
	return (size + mask) &^ mask
}
