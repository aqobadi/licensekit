package protocol

import (
	"crypto/sha256"
	"errors"
	"regexp"
)

// Identity sources (spec §3).
const (
	SourceOS  byte = 0x01
	SourceApp byte = 0x02
)

var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)

// ValidSlug reports whether s is a product slug: 3–40 characters of
// lowercase letters, digits and '-', starting with a letter and not ending
// with '-'.
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// ProductID derives the 16-byte product ID from its slug (spec §3).
func ProductID(slug string) ([16]byte, error) {
	var id [16]byte
	if !ValidSlug(slug) {
		return id, errors.New("protocol: product slug must be 3-40 lowercase letters, digits or '-', starting with a letter")
	}
	h := sha256.Sum256([]byte("ZURVAN/PRODUCT/1\x00" + slug))
	copy(id[:], h[:])
	return id, nil
}

// Fingerprint derives the product-scoped device binding (spec §3). identity
// is the normalized OS identifier for SourceOS, or the application-supplied
// DeviceID (8–256 bytes) for SourceApp.
func Fingerprint(productID [16]byte, source byte, identity []byte) ([15]byte, error) {
	var fp [15]byte
	switch source {
	case SourceOS:
		if len(identity) == 0 {
			return fp, errors.New("protocol: empty OS identity")
		}
	case SourceApp:
		if len(identity) < 8 || len(identity) > 256 {
			return fp, errors.New("protocol: DeviceID must be 8 to 256 bytes")
		}
	default:
		return fp, errors.New("protocol: unknown identity source")
	}
	h := sha256.New()
	h.Write([]byte("ZURVAN/DEVICE/1\x00"))
	h.Write(productID[:])
	h.Write([]byte{source})
	h.Write(identity)
	copy(fp[:], h.Sum(nil))
	return fp, nil
}
