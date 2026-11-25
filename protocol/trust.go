package protocol

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Trust is what an application build trusts (spec §2): root public keys,
// distrusted signing keys, and the default address of the activation API.
// Apps receive it at build time; nothing at run time can change it.
type Trust struct {
	Roots      map[uint8]ed25519.PublicKey
	Distrusted map[uint16]bool // signing key numbers
	ServerURL  string          // default activation API address, may be empty
}

// ParseTrust parses the build setting, a comma-separated list of
// "r<N>:<64 hex>" roots, "-s<N>" distrusted signing keys and an optional
// "url=<https URL>" (spec §2).
func ParseTrust(s string) (*Trust, error) {
	t := &Trust{Roots: map[uint8]ed25519.PublicKey{}, Distrusted: map[uint16]bool{}}
	for _, item := range strings.Split(strings.TrimSpace(s), ",") {
		item = strings.TrimSpace(item)
		switch {
		case item == "":
			continue
		case strings.HasPrefix(item, "url="):
			u := item[len("url="):]
			if err := CheckServerURL(u); err != nil {
				return nil, err
			}
			t.ServerURL = strings.TrimRight(u, "/")
		case strings.HasPrefix(item, "-s"):
			n, err := strconv.ParseUint(item[2:], 10, 16)
			if err != nil || n == 0 {
				return nil, fmt.Errorf("trust: bad distrusted key %q", item)
			}
			t.Distrusted[uint16(n)] = true
		case strings.HasPrefix(item, "r"):
			num, key, ok := strings.Cut(item[1:], ":")
			n, err := strconv.ParseUint(num, 10, 8)
			pub, herr := hex.DecodeString(key)
			if !ok || err != nil || n == 0 || herr != nil || len(pub) != ed25519.PublicKeySize || key != strings.ToLower(key) {
				return nil, fmt.Errorf("trust: bad root %q", item)
			}
			if _, dup := t.Roots[uint8(n)]; dup {
				return nil, fmt.Errorf("trust: root %d listed twice", n)
			}
			t.Roots[uint8(n)] = pub
		default:
			return nil, fmt.Errorf("trust: unknown item %q", item)
		}
	}
	if len(t.Roots) == 0 {
		return nil, errors.New("trust: no root keys")
	}
	if len(t.Roots) > MaxRoots {
		return nil, fmt.Errorf("trust: more than %d root keys", MaxRoots)
	}
	return t, nil
}

// String returns the canonical build setting.
func (t *Trust) String() string {
	var items []string
	var roots []int
	for n := range t.Roots {
		roots = append(roots, int(n))
	}
	sort.Ints(roots)
	for _, n := range roots {
		items = append(items, fmt.Sprintf("r%d:%s", n, hex.EncodeToString(t.Roots[uint8(n)])))
	}
	var bad []int
	for n := range t.Distrusted {
		bad = append(bad, int(n))
	}
	sort.Ints(bad)
	for _, n := range bad {
		items = append(items, fmt.Sprintf("-s%d", n))
	}
	if t.ServerURL != "" {
		items = append(items, "url="+t.ServerURL)
	}
	return strings.Join(items, ",")
}

// CheckCert verifies that at least one trusted root signed c and that its
// key is not distrusted.
func (t *Trust) CheckCert(c *Cert) error {
	if t.Distrusted[c.KeyNumber] || len(c.PublicKey) != ed25519.PublicKeySize {
		return &Error{Kind: Untrusted}
	}
	msg := signedMessage(domainCert, c.body())
	for _, s := range c.Sigs {
		if pub, ok := t.Roots[s.Root]; ok && ed25519.Verify(pub, msg, s.Sig) {
			return nil
		}
	}
	return &Error{Kind: Untrusted}
}

// CheckServerURL accepts an https origin with an optional path, or http on
// a loopback host for development. (It parses by hand: the SDK imports no
// net/* package, not even net/url.)
func CheckServerURL(s string) error {
	bad := fmt.Errorf("server URL %q must be an https address such as https://activate.example.com", s)
	rest, ok := strings.CutPrefix(s, "https://")
	loopbackOnly := false
	if !ok {
		if rest, ok = strings.CutPrefix(s, "http://"); !ok {
			return bad
		}
		loopbackOnly = true
	}
	host, _, _ := strings.Cut(rest, "/")
	if host == "" || strings.ContainsAny(s, " ,?#@\\\t\r\n") {
		return bad
	}
	if loopbackOnly {
		name := host
		if i := strings.LastIndex(host, ":"); i >= 0 && !strings.HasSuffix(host, "]") {
			name = host[:i]
		}
		if name != "localhost" && name != "127.0.0.1" && name != "[::1]" {
			return bad
		}
	}
	return nil
}
