package transfer

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// MaxNameplate is the highest nameplate the relay hands out, so that codes
// stay at most three digits long.
const MaxNameplate = 999

// ErrCodeFormat is input that is not shaped like a code: a number from 1 to
// MaxNameplate and two words.
var ErrCodeFormat = errors.New("not a transfer code")

// UnknownWordError names a typed word that is not on the list and is not an
// unambiguous prefix of one.
type UnknownWordError struct {
	Word string
}

func (e *UnknownWordError) Error() string {
	return fmt.Sprintf("%q is not a code word", e.Word)
}

// Code is what one side reads out and the other types: the nameplate, which
// tells the relay which transfer is meant, and two words, which are the
// password and never leave the two devices.
type Code struct {
	Nameplate int
	Words     [2]string
}

// String formats the code as it is shown: 7-acid-rocket.
func (c Code) String() string {
	return fmt.Sprintf("%d-%s-%s", c.Nameplate, c.Words[0], c.Words[1])
}

var wordByPrefix = func() map[string]string {
	m := make(map[string]string, len(Words))
	for _, w := range Words {
		m[w[:3]] = w
	}
	return m
}()

// sampleLimit is the largest multiple of the list's size that fits in 16
// bits, for unbiased sampling.
const sampleLimit = 0x10000 / len(Words) * len(Words)

// RandomWords draws the two words of a new code, independently and
// uniformly from the list.
func RandomWords() ([2]string, error) {
	var words [2]string
	for i := range words {
		for {
			var b [2]byte
			if _, err := rand.Read(b[:]); err != nil {
				return words, fmt.Errorf("draw word: %w", err)
			}
			if v := int(binary.BigEndian.Uint16(b[:])); v < sampleLimit {
				words[i] = Words[v%len(Words)]
				break
			}
		}
	}
	return words, nil
}

// CompleteWord returns the full word for a typed one: the word itself, or
// the word a prefix of at least three letters completes to.
func CompleteWord(typed string) (string, bool) {
	if len(typed) < 3 {
		return "", false
	}
	word, ok := wordByPrefix[typed[:3]]
	if !ok || !strings.HasPrefix(word, typed) {
		return "", false
	}
	return word, true
}

// ParseCode reads a typed code like "7-acid-rocket". Case, spaces, dots,
// dashes and underscores as separators, and unambiguous word prefixes are
// all accepted. Errors are ErrCodeFormat or an *UnknownWordError.
func ParseCode(input string) (Code, error) {
	parts := strings.FieldsFunc(strings.ToLower(input), func(r rune) bool {
		return unicode.IsSpace(r) || r == '.' || r == '-' || r == '_'
	})
	if len(parts) != 3 || !isNameplate(parts[0]) {
		return Code{}, ErrCodeFormat
	}
	nameplate, err := strconv.Atoi(parts[0])
	if err != nil || nameplate < 1 || nameplate > MaxNameplate {
		return Code{}, ErrCodeFormat
	}
	code := Code{Nameplate: nameplate}
	for i, typed := range parts[1:] {
		word, ok := CompleteWord(typed)
		if !ok {
			return Code{}, &UnknownWordError{Word: typed}
		}
		code.Words[i] = word
	}
	return code, nil
}

func isNameplate(s string) bool {
	if len(s) < 1 || len(s) > 3 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Password is the CPace password: the two words joined by a dash, never
// the public nameplate.
func Password(words [2]string) []byte {
	return []byte(words[0] + "-" + words[1])
}
