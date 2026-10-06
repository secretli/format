package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The list's SHA-256 over its words joined by "\n"; FORMAT.md section 11.1.
const wordListSHA256 = "e298b97fdd0dfeb65678c8aaf7cfb010c1831111a28f1b936abc191c5eb7d3af"

func TestWordList(t *testing.T) {
	if len(Words) != 1296 {
		t.Fatalf("%d words", len(Words))
	}
	sum := sha256.Sum256([]byte(strings.Join(Words[:], "\n")))
	if got := hex.EncodeToString(sum[:]); got != wordListSHA256 {
		t.Errorf("word list SHA-256 = %s", got)
	}
	word := regexp.MustCompile(`^[a-z]{3,10}$`)
	prefixes := map[string]bool{}
	for _, w := range Words {
		if !word.MatchString(w) {
			t.Errorf("%q is not a lowercase word of 3 to 10 letters", w)
		}
		if prefixes[w[:3]] {
			t.Errorf("prefix of %q is not unique", w)
		}
		prefixes[w[:3]] = true
	}
}

func TestRandomWords(t *testing.T) {
	for range 20 {
		words, err := RandomWords()
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range words {
			if !slices.Contains(Words[:], w) {
				t.Errorf("%q is not on the list", w)
			}
		}
	}
}

func TestParseCodeReadsAFormattedCode(t *testing.T) {
	want := Code{Nameplate: 7, Words: [2]string{"acid", "rocket"}}
	if want.String() != "7-acid-rocket" {
		t.Errorf("String() = %q", want.String())
	}
	got, err := ParseCode(want.String())
	if err != nil || got != want {
		t.Errorf("ParseCode = %+v, %v", got, err)
	}
}

func TestParseCodeAccepts(t *testing.T) {
	want := Code{Nameplate: 7, Words: [2]string{"acid", "rocket"}}
	for _, input := range []string{
		"7 acid rocket",
		"  7-ACID-Rocket  ",
		"7.acid.rocket",
		"7 - acid - rocket",
		"7_acid_rocket",
		"007-acid-rocket",
		"7-aci-roc",
		"7-acid-rock",
	} {
		got, err := ParseCode(input)
		if err != nil || got != want {
			t.Errorf("ParseCode(%q) = %+v, %v", input, got, err)
		}
	}
}

func TestParseCodeRejectsTheFormat(t *testing.T) {
	for _, input := range []string{
		"",
		"acid-rocket",
		"7-acid",
		"7-acid-rocket-extra",
		"0-acid-rocket",
		"1000-acid-rocket",
		"x-acid-rocket",
		"+7-acid-rocket",
		"٧-acid-rocket",
	} {
		if _, err := ParseCode(input); !errors.Is(err, ErrCodeFormat) {
			t.Errorf("ParseCode(%q) = %v, want ErrCodeFormat", input, err)
		}
	}
}

func TestParseCodeNamesAnUnknownWord(t *testing.T) {
	for input, word := range map[string]string{
		"7-acid-rokcet": "rokcet",
		"7-ac-rocket":   "ac",
	} {
		_, err := ParseCode(input)
		unknown, ok := errors.AsType[*UnknownWordError](err)
		if !ok || unknown.Word != word {
			t.Errorf("ParseCode(%q) = %v, want unknown word %q", input, err, word)
		}
	}
}

func TestCompleteWord(t *testing.T) {
	for typed, want := range map[string]string{"aci": "acid", "acid": "acid", "yoy": "yoyo"} {
		if got, ok := CompleteWord(typed); !ok || got != want {
			t.Errorf("CompleteWord(%q) = %q, %v", typed, got, ok)
		}
	}
	for _, typed := range []string{"ac", "acix", "zzz", "acidic"} {
		if got, ok := CompleteWord(typed); ok {
			t.Errorf("CompleteWord(%q) = %q", typed, got)
		}
	}
}

func TestPasswordUsesOnlyTheWords(t *testing.T) {
	if got := string(Password([2]string{"acid", "rocket"})); got != "acid-rocket" {
		t.Errorf("Password = %q", got)
	}
}
