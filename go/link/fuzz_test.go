package link

import "testing"

// FuzzParse throws arbitrary text at the link parser. It must never panic,
// and whatever it accepts must have an origin and a secret, and an optional
// deletion token, in the strict 43-character alphabet (FORMAT.md section 3).
func FuzzParse(f *testing.F) {
	seeds := []string{
		"https://secretli.app/s#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"https://secretli.app/s#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		"http://localhost:8080/s#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"https://host/s#short",
		"https://host/s#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%00",
		"https://host/s%2f#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"https://host/s#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
		" https://host/s#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ",
		"https://host/s?x=1#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"https://user:pw@host/s#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"javascript:alert(1)",
		"https://host/s#AAAA%2FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"https://host\\@evil.com/s#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"https://host/s#-_.~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"https://host/s#+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"https://host/s#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/extra",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		l, err := Parse(raw)
		if err != nil {
			return
		}
		// What was accepted must round-trip into the same secret and token.
		if l.Secret == "" {
			t.Fatalf("accepted empty secret: %q", raw)
		}
		if got := fragment.FindStringSubmatch(l.Secret + optionalToken(l.DeletionToken)); got == nil {
			t.Fatalf("accepted secret/token outside the alphabet: %q -> %q %q", raw, l.Secret, l.DeletionToken)
		}
		if l.Origin == "" {
			t.Fatalf("accepted empty origin: %q", raw)
		}
	})
}

func optionalToken(tok string) string {
	if tok == "" {
		return ""
	}
	return "!" + tok
}
