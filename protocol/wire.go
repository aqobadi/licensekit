package protocol

import (
	"encoding/base64"
	"math/bits"
	"strings"

	"crypto/sha256"
)

// reader consumes a byte slice field by field. After the first short read
// every call returns zero values and ok reports false.
type reader struct {
	b  []byte
	ok bool
}

func newReader(b []byte) *reader { return &reader{b: b, ok: true} }

func (r *reader) take(n int) []byte {
	if !r.ok || n < 0 || len(r.b) < n {
		r.ok = false
		return make([]byte, n&0xffff)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() byte    { return r.take(1)[0] }
func (r *reader) u16() uint16 { b := r.take(2); return uint16(b[0])<<8 | uint16(b[1]) }
func (r *reader) u24() uint32 {
	b := r.take(3)
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}
func (r *reader) u64() uint64 {
	var v uint64
	for _, x := range r.take(8) {
		v = v<<8 | uint64(x)
	}
	return v
}

// done reports whether every byte was consumed without a short read.
func (r *reader) done() bool { return r.ok && len(r.b) == 0 }

func put16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
func put24(b []byte, v uint32) []byte { return append(b, byte(v>>16), byte(v>>8), byte(v)) }
func put64(b []byte, v uint64) []byte {
	for i := 56; i >= 0; i -= 8 {
		b = append(b, byte(v>>i))
	}
	return b
}

func signedMessage(domain string, body []byte) []byte {
	return append([]byte(domain), body...)
}

// Armor labels of the text files apps and the Manager exchange (spec §9).
const (
	LabelLicense = "ZURVAN LICENSE"
	LabelRequest = "ZURVAN LICENSE REQUEST"
)

// Armor returns data as a text block that survives email and chat: optional
// '#' comment lines, then Base64 between BEGIN and END lines.
func Armor(label string, comments []string, data []byte) []byte {
	var sb strings.Builder
	for _, c := range comments {
		sb.WriteString("# " + strings.Join(strings.Fields(c), " ") + "\n")
	}
	sb.WriteString("-----BEGIN " + label + "-----\n")
	s := base64.StdEncoding.EncodeToString(data)
	for len(s) > 64 {
		sb.WriteString(s[:64] + "\n")
		s = s[64:]
	}
	sb.WriteString(s + "\n-----END " + label + "-----\n")
	return []byte(sb.String())
}

// IsArmored reports whether text contains a block with this label.
func IsArmored(text, label string) bool {
	return strings.Contains(text, "-----BEGIN "+label+"-----")
}

// Unarmor extracts the data of the first block with this label.
func Unarmor(text, label string) ([]byte, error) {
	if len(text) > MaxInputBytes {
		return nil, &Error{Kind: TooLong}
	}
	begin, end := "-----BEGIN "+label+"-----", "-----END "+label+"-----"
	i := strings.Index(text, begin)
	if i < 0 {
		return nil, malformed()
	}
	rest := text[i+len(begin):]
	j := strings.Index(rest, end)
	if j < 0 {
		return nil, malformed()
	}
	body := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, rest[:j])
	data, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, malformed()
	}
	return data, nil
}

// WorkBits returns the number of leading zero bits of the proof-of-work
// hash for a challenge nonce and a counter the client chose (spec §10.2).
func WorkBits(nonce [32]byte, counter uint64) int {
	h := sha256.Sum256(put64(append([]byte("ZURVAN/POW/1\x00"), nonce[:]...), counter))
	n := 0
	for _, b := range h {
		if b != 0 {
			return n + bits.LeadingZeros8(b)
		}
		n += 8
	}
	return n
}
