package licensekit

import "time"

// OpenAt opens with a controllable clock for tests.
func OpenAt(product string, opts Options, now func() time.Time) (*License, error) {
	return open(product, opts, now)
}

// Internal names the external tests need.
var (
	Mkfifo        = mkfifo
	LicenseFile   = licenseFile
	ClockFile     = clockFile
	DeviceKeyFile = deviceKeyFile
)
