// Package link reads and writes share links: the server, the share secret
// and, for the owner link, the deletion token. FORMAT.md section 3.
package link

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// ErrNotALink is text that is not a Secretli link.
var ErrNotALink = errors.New("not a Secretli link")

var fragment = regexp.MustCompile(`^([A-Za-z0-9_-]{43})(?:!([A-Za-z0-9_-]{43}))?$`)

// Link is a share link: the server's origin, the share secret and, for the
// owner link, the deletion token.
type Link struct {
	Origin        string
	Secret        string
	DeletionToken string
}

// Parse reads a link as the web app prints it: https://host/s#secret or
// https://host/s#secret!deletionToken. Anything else is ErrNotALink.
func Parse(raw string) (Link, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Path != "/s" {
		return Link{}, ErrNotALink
	}
	m := fragment.FindStringSubmatch(u.Fragment)
	if m == nil {
		return Link{}, ErrNotALink
	}
	return Link{Origin: u.Scheme + "://" + u.Host, Secret: m[1], DeletionToken: m[2]}, nil
}

// IsOwner reports whether the link carries the deletion token.
func (l Link) IsOwner() bool { return l.DeletionToken != "" }

// Recipient is the link without the deletion token, the one to hand out.
func (l Link) Recipient() Link { return Link{Origin: l.Origin, Secret: l.Secret} }

func (l Link) String() string {
	s := l.Origin + "/s#" + l.Secret
	if l.DeletionToken != "" {
		s += "!" + l.DeletionToken
	}
	return s
}
