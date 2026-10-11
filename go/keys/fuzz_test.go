package keys

import (
	"strings"
	"testing"
)

// FuzzDecryptMeta throws arbitrary envelope strings at the metadata
// decryption: the envelope comes from the server, so anything may arrive.
// Whatever it is, DecryptMeta must not panic.
func FuzzDecryptMeta(f *testing.F) {
	ks, err := Generate()
	if err != nil {
		f.Fatal(err)
	}
	meta := Meta{Type: "text", PasswordProtected: false}
	envelope, err := ks.EncryptMeta(meta)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(envelope)
	f.Add("v2$$")
	f.Add("v2$AAAA$AAAA")
	f.Add("v2$" + strings.Repeat("A", 43) + "$")
	f.Add("v1$" + strings.Repeat("A", 43) + "$AAAA")
	f.Add("v2$" + strings.Repeat("A", 43) + "$" + strings.Repeat("A", 1000))
	f.Add("v2$" + strings.Repeat("/", 43) + "$AAAA")
	f.Add(envelope + "$AAAA")
	f.Fuzz(func(t *testing.T, envelope string) {
		m, err := ks.DecryptMeta(envelope)
		if err != nil {
			return
		}
		// Only an envelope sealed with the key gets this far.
		_ = m.Type
	})
}

// FuzzFromShareSecret fuzzes the share-secret parser: the link fragment is
// attacker-influenced text and must decode exactly or not at all.
func FuzzFromShareSecret(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "")
	f.Add("A", "")
	f.Add("", "")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA password", "")
	f.Add("AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAA", "")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "pw")
	f.Fuzz(func(t *testing.T, encoded, password string) {
		ks, err := FromShareSecret(encoded, password)
		if err != nil {
			return
		}
		if ks.Encoded().ShareSecret == "" {
			t.Fatalf("accepted %q with no error but no secret", encoded)
		}
	})
}
