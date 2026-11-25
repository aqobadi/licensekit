//go:build !linux && !darwin && !windows

package licensekit

import "errors"

func systemIdentity() (string, error) {
	return "", errors.New("no supported OS machine identifier on this platform")
}
