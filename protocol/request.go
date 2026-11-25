package protocol

import (
	"crypto/ed25519"
	"errors"
)

// Format bytes of the messages between apps and the Manager (spec §8).
const (
	FormatRequest byte = 0x51
	FormatRelease byte = 0x52
	FormatReceipt byte = 0x53
)

const (
	domainRequest  = "ZURVAN/REQUEST/1\x00"
	domainRelease  = "ZURVAN/RELEASE/1\x00"
	domainReleased = "ZURVAN/RELEASED/1\x00"
)

// Request asks the Manager for a license for this computer (spec §8.1). The
// app signs it with its device key. Online setup carries the server's
// challenge nonce; a request file carries a zero nonce.
type Request struct {
	ProductID   [16]byte
	Fingerprint [15]byte
	Source      byte
	DeviceKey   ed25519.PublicKey
	KeyHash     [32]byte // LicenseKey.Hash of the key the customer entered
	Nonce       [32]byte
	Created     int64 // Unix seconds on the device; informational only
}

func (q *Request) body() []byte {
	b := append([]byte{FormatRequest}, q.ProductID[:]...)
	b = append(append(append(b, q.Fingerprint[:]...), q.Source), q.DeviceKey...)
	b = append(append(b, q.KeyHash[:]...), q.Nonce[:]...)
	return put64(b, uint64(q.Created))
}

// Sign returns the signed request bytes.
func (q *Request) Sign(device ed25519.PrivateKey) ([]byte, error) {
	if len(device) != ed25519.PrivateKeySize || !device.Public().(ed25519.PublicKey).Equal(q.DeviceKey) {
		return nil, errors.New("protocol: device key mismatch")
	}
	body := q.body()
	return append(body, ed25519.Sign(device, signedMessage(domainRequest, body))...), nil
}

// ParseRequest decodes a request and verifies the device signature.
func ParseRequest(data []byte) (*Request, error) {
	r := newReader(data)
	if r.u8() != FormatRequest {
		return nil, &Error{Kind: UnsupportedFormat}
	}
	q := &Request{}
	copy(q.ProductID[:], r.take(16))
	copy(q.Fingerprint[:], r.take(15))
	q.Source = r.u8()
	q.DeviceKey = ed25519.PublicKey(append([]byte(nil), r.take(32)...))
	copy(q.KeyHash[:], r.take(32))
	copy(q.Nonce[:], r.take(32))
	q.Created = int64(r.u64())
	n := len(data) - len(r.b)
	sig := r.take(64)
	if !r.done() || q.Source != SourceOS && q.Source != SourceApp {
		return nil, malformed()
	}
	if !ed25519.Verify(q.DeviceKey, signedMessage(domainRequest, data[:n]), sig) {
		return nil, &Error{Kind: BadSignature}
	}
	return q, nil
}

// Release asks the Manager to free the seat of an installed license
// (spec §8.2). Only the installation holding the license's device key can
// make one.
type Release struct {
	ProductID   [16]byte
	Fingerprint [15]byte
	LicenseID   uint32
	DeviceKey   ed25519.PublicKey
	Nonce       [32]byte
}

func (q *Release) body() []byte {
	b := append([]byte{FormatRelease}, q.ProductID[:]...)
	b = put24(append(b, q.Fingerprint[:]...), q.LicenseID)
	return append(append(b, q.DeviceKey...), q.Nonce[:]...)
}

// Sign returns the signed release bytes.
func (q *Release) Sign(device ed25519.PrivateKey) ([]byte, error) {
	if len(device) != ed25519.PrivateKeySize || !device.Public().(ed25519.PublicKey).Equal(q.DeviceKey) {
		return nil, errors.New("protocol: device key mismatch")
	}
	body := q.body()
	return append(body, ed25519.Sign(device, signedMessage(domainRelease, body))...), nil
}

// ParseRelease decodes a release and verifies the device signature.
func ParseRelease(data []byte) (*Release, error) {
	r := newReader(data)
	if r.u8() != FormatRelease {
		return nil, &Error{Kind: UnsupportedFormat}
	}
	q := &Release{}
	copy(q.ProductID[:], r.take(16))
	copy(q.Fingerprint[:], r.take(15))
	q.LicenseID = r.u24()
	q.DeviceKey = ed25519.PublicKey(append([]byte(nil), r.take(32)...))
	copy(q.Nonce[:], r.take(32))
	n := len(data) - len(r.b)
	sig := r.take(64)
	if !r.done() || q.LicenseID == 0 {
		return nil, malformed()
	}
	if !ed25519.Verify(q.DeviceKey, signedMessage(domainRelease, data[:n]), sig) {
		return nil, &Error{Kind: BadSignature}
	}
	return q, nil
}

func (q *Release) receiptMessage() []byte {
	b := append([]byte(domainReleased), q.ProductID[:]...)
	b = put24(append(b, q.Fingerprint[:]...), q.LicenseID)
	return append(b, q.Nonce[:]...)
}

// Receipt is the Manager's signed confirmation that it freed the seat.
func (q *Release) Receipt(cert *Cert, priv ed25519.PrivateKey) []byte {
	b := append([]byte{FormatReceipt}, ed25519.Sign(priv, q.receiptMessage())...)
	c := cert.Marshal()
	return append(put16(b, uint16(len(c))), c...)
}

// CheckReceipt verifies a receipt for this release against the build's trust.
func (q *Release) CheckReceipt(t *Trust, receipt []byte) error {
	r := newReader(receipt)
	if r.u8() != FormatReceipt {
		return &Error{Kind: UnsupportedFormat}
	}
	sig := r.take(64)
	cert, err := ParseCert(r.take(int(r.u16())))
	if !r.done() || err != nil {
		return malformed()
	}
	if err := t.CheckCert(cert); err != nil {
		return err
	}
	if !ed25519.Verify(cert.PublicKey, q.receiptMessage(), sig) {
		return &Error{Kind: BadSignature}
	}
	return nil
}
