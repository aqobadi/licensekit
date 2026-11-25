package protocol

import (
	"crypto/sha256"
	"crypto/subtle"
)

// LicenseKey is the 96-bit secret of a license key (spec §5.1).
type LicenseKey [12]byte

// String returns the grouped 24-character license key.
func (k LicenseKey) String() string {
	b := appendCRC(append([]byte{FormatLicenseKey}, k[:]...))
	return Group(encode(b))
}

// Hash is the value the Manager stores and request files carry instead of
// the key itself.
func (k LicenseKey) Hash() [32]byte {
	return sha256.Sum256(append([]byte("ZURVAN/LICENSE-KEY/1\x00"), k[:]...))
}

// HashEqual compares two key hashes in constant time.
func HashEqual(a, b [32]byte) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }

// Renewal is a decoded renewal code (spec §5.2): it moves the expiry of the
// license it belongs to to ChainBase + Step.
type Renewal struct {
	Step  uint16
	Value ChainValue
}

// String returns the grouped 24-character renewal code.
func (r Renewal) String() string {
	b := []byte{FormatRenewal, byte(r.Step >> 8), byte(r.Step)}
	b = appendCRC(append(b, r.Value[:]...))
	return Group(encode(b))
}

// Code is a decoded typed code: exactly one of Key or Renewal is set.
type Code struct {
	Key     *LicenseKey
	Renewal *Renewal
}

// ParseCode decodes a license key or a renewal code (spec §4–5).
func ParseCode(input string) (Code, error) {
	b, err := decodeCode(input)
	if err != nil {
		return Code{}, err
	}
	if b[0] == FormatLicenseKey {
		var k LicenseKey
		copy(k[:], b[1:13])
		return Code{Key: &k}, nil
	}
	r := Renewal{Step: uint16(b[1])<<8 | uint16(b[2])}
	copy(r.Value[:], b[3:13])
	if r.Step == 0 {
		return Code{}, &Error{Kind: Malformed}
	}
	return Code{Renewal: &r}, nil
}

// ParseLicenseKey decodes a license key and rejects every other input.
func ParseLicenseKey(input string) (LicenseKey, error) {
	c, err := ParseCode(input)
	if err != nil {
		return LicenseKey{}, err
	}
	if c.Key == nil {
		return LicenseKey{}, &Error{Kind: UnsupportedFormat}
	}
	return *c.Key, nil
}
