//go:build linux

package licensekit

import (
	"io"
	"os"
	"strings"
)

// inContainer is best-effort detection of common container runtimes.
func inContainer() bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv", "/run/systemd/container"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" || os.Getenv("container") != "" {
		return true
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, m := range []string{"docker", "kubepods", "containerd", "/lxc", "libpod"} {
			if strings.Contains(s, m) {
				return true
			}
		}
	}
	return false
}

func systemIdentity() (string, error) {
	if inContainer() {
		return "", errContainer
	}
	var lastErr error
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		f, err := os.Open(path)
		if err != nil {
			lastErr = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(f, 4096))
		f.Close()
		if err != nil {
			lastErr = err
			continue
		}
		id, err := parseMachineID(b)
		if err == nil {
			return id, nil
		}
		lastErr = err
	}
	return "", lastErr
}
