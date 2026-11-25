//go:build windows

package licensekit

import "errors"

func mkfifo(string) error { return errors.New("no FIFOs on Windows") }
