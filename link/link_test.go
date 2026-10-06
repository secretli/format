package link

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAndPrint(t *testing.T) {
	secret := strings.Repeat("a", 43)
	token := strings.Repeat("b", 43)

	l, err := Parse(" https://secretli.app/s#" + secret + "!" + token + " ")
	if err != nil {
		t.Fatal(err)
	}
	if l.Origin != "https://secretli.app" || l.Secret != secret || l.DeletionToken != token || !l.IsOwner() {
		t.Errorf("link = %+v", l)
	}
	if l.String() != "https://secretli.app/s#"+secret+"!"+token {
		t.Errorf("String() = %s", l)
	}
	if r := l.Recipient(); r.IsOwner() || r.String() != "https://secretli.app/s#"+secret {
		t.Errorf("recipient = %s", r)
	}

	plain, err := Parse("http://localhost:8080/s#" + secret)
	if err != nil {
		t.Fatal(err)
	}
	if plain.IsOwner() || plain.Origin != "http://localhost:8080" {
		t.Errorf("link = %+v", plain)
	}

	for _, bad := range []string{
		"",
		"secretli.app/s#" + secret,
		"https://secretli.app/share#" + secret,
		"https://secretli.app/s#" + secret[:42],
		"https://secretli.app/s#" + secret + "!short",
		"https://secretli.app/s#" + secret + "?" + token,
		"ftp://secretli.app/s#" + secret,
	} {
		if _, err := Parse(bad); !errors.Is(err, ErrNotALink) {
			t.Errorf("%q: err = %v, want ErrNotALink", bad, err)
		}
	}
}
