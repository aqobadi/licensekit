package protocol

import (
	"crypto/ed25519"
	"errors"
	"regexp"
	"sort"
)

// FormatLicense is the format byte of a license (spec §6.2).
const FormatLicense byte = 0x31

// MaxLicenseID is the largest 24-bit license ID.
const MaxLicenseID = 1<<24 - 1

// MaxEntitlements is the most feature keys a license names.
const MaxEntitlements = 16

const domainLicense = "ZURVAN/LICENSE/2\x00"

var entitlementRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// ValidEntitlement reports whether s is a feature key such as "export".
func ValidEntitlement(s string) bool { return entitlementRe.MatchString(s) }

// License is a signed license for one product on one computer (spec §6.2).
type License struct {
	ProductID    [16]byte
	Fingerprint  [15]byte
	Source       byte              // SourceOS or SourceApp
	DeviceKey    ed25519.PublicKey // the installation's key; it signs deactivation
	ID           uint32            // 1..MaxLicenseID
	IssuedDay    uint16
	ExpiryDay    uint16 // 0 = perpetual
	ChainBase    uint16 // renewal chain; ChainLength 0 for perpetual licenses
	ChainLength  uint16
	Lock         ChainValue
	Entitlements []string // sorted, unique
	Cert         *Cert    // certifies the key that signed the license
}

// IDString formats a license ID as 5 Crockford characters, e.g. "B8Y92".
func IDString(id uint32) string { return encode([]byte{byte(id >> 16), byte(id >> 8), byte(id)}) }

// Chain returns the context of the license's renewal chain.
func (l *License) Chain() ChainContext {
	return ChainContext{ProductID: l.ProductID, Fingerprint: l.Fingerprint, LicenseID: l.ID}
}

func (l *License) check() error {
	if l.ID == 0 || l.ID > MaxLicenseID || len(l.DeviceKey) != ed25519.PublicKeySize ||
		(l.Source != SourceOS && l.Source != SourceApp) || len(l.Entitlements) > MaxEntitlements {
		return malformed()
	}
	if (l.ExpiryDay == 0) != (l.ChainLength == 0) || int(l.ChainBase)+int(l.ChainLength) > 65535 {
		return malformed()
	}
	if l.ExpiryDay != 0 && l.ExpiryDay < l.ChainBase {
		return malformed()
	}
	for i, e := range l.Entitlements {
		if !ValidEntitlement(e) || i > 0 && l.Entitlements[i-1] >= e {
			return malformed()
		}
	}
	return nil
}

func (l *License) body() []byte {
	b := append([]byte{FormatLicense}, l.ProductID[:]...)
	b = append(b, l.Fingerprint[:]...)
	b = append(append(b, l.Source), l.DeviceKey...)
	b = put24(b, l.ID)
	b = put16(put16(put16(put16(b, l.IssuedDay), l.ExpiryDay), l.ChainBase), l.ChainLength)
	b = append(append(b, l.Lock[:]...), byte(len(l.Entitlements)))
	for _, e := range l.Entitlements {
		b = append(append(b, byte(len(e))), e...)
	}
	return b
}

// Sign signs the license with the certified key and returns its bytes. It
// sorts the entitlements and attaches cert.
func (l *License) Sign(cert *Cert, priv ed25519.PrivateKey) ([]byte, error) {
	if cert == nil || len(priv) != ed25519.PrivateKeySize || !priv.Public().(ed25519.PublicKey).Equal(cert.PublicKey) {
		return nil, errors.New("protocol: the signing key does not match its certificate")
	}
	l.Entitlements = append([]string(nil), l.Entitlements...)
	sort.Strings(l.Entitlements)
	if err := l.check(); err != nil {
		return nil, errors.New("protocol: invalid license fields")
	}
	l.Cert = cert
	body := l.body()
	out := append(body, ed25519.Sign(priv, signedMessage(domainLicense, body))...)
	c := cert.Marshal()
	return append(put16(out, uint16(len(c))), c...), nil
}

// ParseLicense decodes a license and checks its own signature against the
// attached certificate. Callers must still check the certificate with
// Trust.CheckCert and the product and device; Verify does all of it.
func ParseLicense(data []byte) (*License, error) {
	r := newReader(data)
	if r.u8() != FormatLicense {
		return nil, &Error{Kind: UnsupportedFormat}
	}
	l := &License{}
	copy(l.ProductID[:], r.take(16))
	copy(l.Fingerprint[:], r.take(15))
	l.Source = r.u8()
	l.DeviceKey = ed25519.PublicKey(append([]byte(nil), r.take(32)...))
	l.ID = r.u24()
	l.IssuedDay, l.ExpiryDay, l.ChainBase, l.ChainLength = r.u16(), r.u16(), r.u16(), r.u16()
	copy(l.Lock[:], r.take(10))
	n := int(r.u8())
	for i := 0; i < n && r.ok; i++ {
		l.Entitlements = append(l.Entitlements, string(r.take(int(r.u8()))))
	}
	bodyLen := len(data) - len(r.b)
	sig := r.take(64)
	cert, err := ParseCert(r.take(int(r.u16())))
	if !r.done() || err != nil || l.check() != nil {
		return nil, malformed()
	}
	l.Cert = cert
	if !ed25519.Verify(cert.PublicKey, signedMessage(domainLicense, data[:bodyLen]), sig) {
		return nil, &Error{Kind: BadSignature}
	}
	return l, nil
}

// Verify decodes a license and checks everything except time: the
// signature, the certificate against the build's trust, the product and
// this computer's fingerprint (spec §6.3).
func Verify(t *Trust, data []byte, productID [16]byte, fp [15]byte) (*License, error) {
	l, err := ParseLicense(data)
	if err != nil {
		return nil, err
	}
	if err := t.CheckCert(l.Cert); err != nil {
		return nil, err
	}
	if l.ProductID != productID {
		return nil, &Error{Kind: WrongProduct}
	}
	if l.Fingerprint != fp {
		return nil, &Error{Kind: WrongDevice}
	}
	return l, nil
}

// Expiry returns the last valid day after applying a renewal step (0 when
// none is applied). It returns 0 for perpetual licenses.
func (l *License) Expiry(step uint16) uint16 {
	if l.ExpiryDay == 0 {
		return 0
	}
	if step > 0 && l.ChainBase+step > l.ExpiryDay {
		return l.ChainBase + step
	}
	return l.ExpiryDay
}

// CheckRenewal reports whether r belongs to this license's chain.
func (l *License) CheckRenewal(r Renewal) bool {
	return l.ChainLength > 0 && l.Chain().Check(l.Lock, l.ChainLength, r.Step, r.Value)
}
