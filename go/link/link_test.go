package link

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

// linkVectors is spec/vectors/links.json: links and what a reader must make
// of them. The TypeScript reader's tests read the same file.
type linkVectors struct {
	Cases []struct {
		Input         string `json:"input"`
		Refused       bool   `json:"refused"`
		Why           string `json:"why"`
		Origin        string `json:"origin"`
		Secret        string `json:"secret"`
		DeletionToken string `json:"deletion_token"`
	} `json:"cases"`
}

func TestParseFollowsTheLinkVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", "links.json"))
	if err != nil {
		t.Fatalf("read link vectors: %v", err)
	}
	var vectors linkVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse link vectors: %v", err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no link vectors")
	}
	for _, c := range vectors.Cases {
		l, err := Parse(c.Input)
		if c.Refused {
			if err == nil {
				t.Errorf("%q (%s): accepted as %+v, want refused", c.Input, c.Why, l)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: refused, want origin %s", c.Input, c.Origin)
			continue
		}
		if l.Origin != c.Origin || l.Secret != c.Secret || l.DeletionToken != c.DeletionToken {
			t.Errorf("%q: got %+v, want origin %s, secret %s, token %q", c.Input, l, c.Origin, c.Secret, c.DeletionToken)
		}
	}
}
