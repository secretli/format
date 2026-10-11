// Package link reads and writes share links: the server, the share secret
// and, for the owner link, the deletion token. FORMAT.md section 3.
package link

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// ErrNotALink is text that is not a Secretli link.
var ErrNotALink = errors.New("not a Secretli link")

// shape is a whole link, FORMAT.md section 3: scheme, host (a name or an
// IPv6 address in brackets), optional port, the path /s, and the fragment.
// Matching the raw text, before any URL parser can decode or tidy it, keeps
// percent-encoding, user info, dot segments and the like out.
var shape = regexp.MustCompile(`^(https?)://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::([0-9]{1,5}))?/s#([A-Za-z0-9_-]{43})(?:!([A-Za-z0-9_-]{43}))?$`)

// Link is a share link: the server's origin, the share secret and, for the
// owner link, the deletion token.
type Link struct {
	Origin        string
	Secret        string
	DeletionToken string
}

// Parse reads a link as the web app prints it: https://host/s#secret or
// https://host/s#secret!deletionToken, with http only for a loopback host.
// Anything else is ErrNotALink. The origin is normalised as FORMAT.md
// section 3 says, the same way the TypeScript reader does.
func Parse(raw string) (Link, error) {
	m := shape.FindStringSubmatch(strings.Trim(raw, " \t\r\n"))
	if m == nil {
		return Link{}, ErrNotALink
	}
	scheme, host, port := m[1], strings.ToLower(m[2]), m[3]
	if strings.HasPrefix(host, "[") {
		addr, err := netip.ParseAddr(host[1 : len(host)-1])
		if err != nil || !addr.Is6() || addr.Is4In6() || addr.Zone() != "" {
			return Link{}, ErrNotALink
		}
		host = "[" + addr.String() + "]"
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n > 65535 {
			return Link{}, ErrNotALink
		}
		port = strconv.Itoa(n)
		if (scheme == "https" && n == 443) || (scheme == "http" && n == 80) {
			port = ""
		}
	}
	if scheme == "http" && !loopback(host) {
		return Link{}, ErrNotALink
	}
	origin := scheme + "://" + host
	if port != "" {
		origin += ":" + port
	}
	return Link{Origin: origin, Secret: m[4], DeletionToken: m[5]}, nil
}

// loopback reports whether a host, normalised as in Parse, is one http is
// allowed for: localhost, 127.0.0.0/8 as four plain numbers, or ::1.
func loopback(host string) bool {
	if host == "localhost" || host == "[::1]" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Is4() && addr.IsLoopback()
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
