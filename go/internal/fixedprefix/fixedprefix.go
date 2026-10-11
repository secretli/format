// Package fixedprefix gives the vectors tests what nothing else may use: a
// bundle encrypter with a prefix of their choosing. With the prefix fixed,
// nothing in a bundle is random, which the vectors need (FORMAT.md section
// 10); two bundles under the same keys with the same prefix would break the
// encryption, so it is not part of package bundle's API.
package fixedprefix

// NewEncrypter is set by package bundle when it loads, to its encrypter that
// takes the prefix:
//
//	func(*bundle.StreamPlan, []bundle.Source, *keys.KeySet, []byte) (*bundle.Encrypter, error)
//
// It is typed any because this package can't import bundle, which imports it.
var NewEncrypter any
