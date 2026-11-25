package protocol

import (
	"crypto/ed25519"
	"errors"
)

// FormatCert is the format byte of a signing-key certificate.
const FormatCert byte = 0x41

// MaxRoots is the most root keys a build trusts and a certificate carries.
const MaxRoots = 4

const domainCert = "ZURVAN/CERT/1\x00"

// Cert certifies a signing key: each root key in Sigs signed it (spec §6.1).
type Cert struct {
	KeyNumber  uint16 // 1..65535
	PublicKey  ed25519.PublicKey
	CreatedDay uint16
	Sigs       []RootSig
}

// RootSig is one root's signature over a certificate.
type RootSig struct {
	Root uint8 // 1..255
	Sig  []byte
}

func (c *Cert) body() []byte {
	b := put16([]byte{FormatCert}, c.KeyNumber)
	b = append(b, c.PublicKey...)
	return put16(b, c.CreatedDay)
}

// Sign adds root's signature. Call it once per root.
func (c *Cert) Sign(root uint8, priv ed25519.PrivateKey) error {
	if root == 0 || len(priv) != ed25519.PrivateKeySize || len(c.PublicKey) != ed25519.PublicKeySize || c.KeyNumber == 0 {
		return errors.New("protocol: invalid certificate or root key")
	}
	if len(c.Sigs) >= MaxRoots {
		return errors.New("protocol: too many certificate signatures")
	}
	for _, s := range c.Sigs {
		if s.Root == root {
			return errors.New("protocol: root already signed this certificate")
		}
	}
	c.Sigs = append(c.Sigs, RootSig{Root: root, Sig: ed25519.Sign(priv, signedMessage(domainCert, c.body()))})
	return nil
}

// Marshal returns the certificate bytes.
func (c *Cert) Marshal() []byte {
	b := append(c.body(), byte(len(c.Sigs)))
	for _, s := range c.Sigs {
		b = append(append(b, s.Root), s.Sig...)
	}
	return b
}

// ParseCert decodes a certificate. It does not check the signatures; see
// Trust.CheckCert.
func ParseCert(data []byte) (*Cert, error) {
	r := newReader(data)
	if r.u8() != FormatCert {
		return nil, &Error{Kind: UnsupportedFormat}
	}
	c := &Cert{KeyNumber: r.u16(), PublicKey: ed25519.PublicKey(append([]byte(nil), r.take(32)...)), CreatedDay: r.u16()}
	n := int(r.u8())
	if n < 1 || n > MaxRoots {
		return nil, malformed()
	}
	seen := map[uint8]bool{}
	for i := 0; i < n; i++ {
		s := RootSig{Root: r.u8(), Sig: append([]byte(nil), r.take(64)...)}
		if s.Root == 0 || seen[s.Root] {
			return nil, malformed()
		}
		seen[s.Root] = true
		c.Sigs = append(c.Sigs, s)
	}
	if !r.done() || c.KeyNumber == 0 {
		return nil, malformed()
	}
	return c, nil
}
