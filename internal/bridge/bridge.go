// Package bridge connects licensekit to its network packages (online and
// licenseui) without widening licensekit's public API. Application code
// cannot import it.
package bridge

import "github.com/aqobadi/licensekit/protocol"

// Ops are the operations of one opened license that only the SDK's own
// packages use.
type Ops struct {
	Product   string
	ProductID [16]byte
	ServerURL string // resolved activation API address, may be empty
	Trust     *protocol.Trust
	// SetupRequest returns a signed request for the license key, carrying
	// the server's challenge nonce.
	SetupRequest func(key protocol.LicenseKey, nonce [32]byte) ([]byte, error)
	// Install verifies and saves a license from the activation API.
	Install func(license []byte) error
	// Release returns a signed request to free this computer's seat.
	Release func(nonce [32]byte) (*protocol.Release, []byte, error)
	// Released checks the Manager's receipt and removes the local license.
	Released func(rel *protocol.Release, receipt []byte) error
}

// Of returns the operations of a *licensekit.License. licensekit sets it.
var Of func(license any) Ops

// TestTrust lets licensekittest make test builds trust a throwaway root for
// one product. Production code never sets it.
var TestTrust func(product string) *protocol.Trust
