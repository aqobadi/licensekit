// Package protocol implements the License-ZG licensing protocol v2
// (PROTOCOL.md in the module root): typed codes (license keys and renewal codes)
// in Crockford Base32 with a CRC-16 typo check, signing-key certificates,
// device-bound licenses, renewal chains, and the signed requests apps send
// to the Manager. It performs no I/O and reads no clock.
package protocol

import (
	"strings"
	"unicode/utf8"
)

// Alphabet is Crockford Base32; a character's value is its index.
const Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Typed codes are 15 bytes, shown as 24 characters in six groups of four.
const (
	CodeChars     = 24
	CodeBytes     = 15
	MaxInputBytes = 64 << 10
)

// Format bytes of typed codes (spec §5).
const (
	FormatLicenseKey byte = 0x21
	FormatRenewal    byte = 0x22
)

var value [256]int8

func init() {
	for i := range value {
		value[i] = -1
	}
	for i := 0; i < len(Alphabet); i++ {
		value[Alphabet[i]] = int8(i)
	}
}

// encode returns the bytes as Crockford Base32 without grouping. The final
// character is padded with zero bits.
func encode(b []byte) string {
	var sb strings.Builder
	sb.Grow((len(b)*8 + 4) / 5)
	var acc uint32
	n := 0
	for _, x := range b {
		acc = acc<<8 | uint32(x)
		n += 8
		for n >= 5 {
			sb.WriteByte(Alphabet[(acc>>(n-5))&31])
			n -= 5
		}
	}
	if n > 0 {
		sb.WriteByte(Alphabet[(acc<<(5-n))&31])
	}
	return sb.String()
}

// Base32 returns the bytes as ungrouped Crockford Base32.
func Base32(b []byte) string { return encode(b) }

// Group formats normalized characters in groups of four joined by '-'.
func Group(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// decodeChars converts normalized characters to exactly n bytes. It returns
// false if any pad bit is nonzero or the length does not match.
func decodeChars(s string, n int) ([]byte, bool) {
	if len(s) != (n*8+4)/5 {
		return nil, false
	}
	out := make([]byte, 0, n)
	var acc uint32
	bits := 0
	for i := 0; i < len(s); i++ {
		acc = acc<<5 | uint32(value[s[i]])
		bits += 5
		if bits >= 8 {
			out = append(out, byte(acc>>(bits-8)))
			bits -= 8
		}
	}
	if acc&(1<<bits-1) != 0 {
		return nil, false
	}
	return out, true
}

// ignored reports whether r is one of the separator code points removed
// during normalization (spec §4 step 3).
func ignored(r rune) bool {
	switch {
	case r == '\t', r == '\n', r == '\r', r == ' ', r == '-':
		return true
	case r == 0x00A0, r >= 0x2002 && r <= 0x200D, r == 0x202F, r == 0x2060, r == 0xFEFF:
		return true
	case r >= 0x2010 && r <= 0x2015, r == 0x2212:
		return true
	}
	return false
}

// Normalize applies spec §4 steps 1–5 and returns the code characters.
func Normalize(input string) (string, error) {
	if len(input) > MaxInputBytes {
		return "", &Error{Kind: TooLong}
	}
	if !utf8.ValidString(input) {
		return "", &Error{Kind: BadCharacter}
	}
	var sb strings.Builder
	lines := strings.FieldsFunc(input, func(r rune) bool { return r == '\n' || r == '\r' })
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimLeftFunc(line, ignored), "#") {
			continue
		}
		for _, r := range line {
			if ignored(r) {
				continue
			}
			if r >= 'a' && r <= 'z' {
				r -= 'a' - 'A'
			}
			switch r {
			case 'O':
				r = '0'
			case 'I', 'L':
				r = '1'
			}
			if r > 0x7f || value[byte(r)] < 0 {
				return "", &Error{Kind: BadCharacter, Group: sb.Len()/4 + 1}
			}
			sb.WriteByte(byte(r))
		}
	}
	if sb.Len() == 0 {
		return "", &Error{Kind: Empty}
	}
	return sb.String(), nil
}

// decodeCode applies spec §4 to a typed code and returns its 15 bytes after
// the length, CRC and format checks.
func decodeCode(input string) ([]byte, error) {
	s, err := Normalize(input)
	if err != nil {
		return nil, err
	}
	switch n := len(s); {
	case n < CodeChars:
		return nil, &Error{Kind: Incomplete, Have: (n + 3) / 4, Want: CodeChars / 4}
	case n > CodeChars:
		return nil, &Error{Kind: TooLong}
	}
	b, ok := decodeChars(s, CodeBytes)
	if !ok || !crcOK(b) {
		return nil, &Error{Kind: Typo, Group: locateTypo(s)}
	}
	if b[0] != FormatLicenseKey && b[0] != FormatRenewal {
		return nil, &Error{Kind: UnsupportedFormat}
	}
	return b, nil
}

// locateTypo returns the 1-based group of the only position where a single
// substitution yields a valid code, or 0 if there is no unique position
// (spec §4.1).
func locateTypo(s string) int {
	found := -1
	buf := []byte(s)
	for i := range buf {
		orig := buf[i]
		hit := false
		for j := 0; j < len(Alphabet) && !hit; j++ {
			if Alphabet[j] == orig {
				continue
			}
			buf[i] = Alphabet[j]
			if b, ok := decodeChars(string(buf), CodeBytes); ok && crcOK(b) {
				hit = true
			}
		}
		buf[i] = orig
		if hit {
			if found >= 0 {
				return 0
			}
			found = i
		}
	}
	if found < 0 {
		return 0
	}
	return found/4 + 1
}
