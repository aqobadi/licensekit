package licensekit

import (
	"errors"
	"regexp"
	"strings"
)

// errContainer means the OS identifier must not be used inside a container
// (spec §4): images share it.
var errContainer = errors.New("running in a container")

var (
	hex32Re = regexp.MustCompile(`^[0-9a-f]{32}$`)
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ioregRe = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"`)
)

func parseMachineID(b []byte) (string, error) {
	id := strings.ToLower(strings.TrimSpace(string(b)))
	if !hex32Re.MatchString(id) || id == strings.Repeat("0", 32) {
		return "", errors.New("invalid machine-id")
	}
	return id, nil
}

func parseUUID(s string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(s))
	if !uuidRe.MatchString(id) || strings.Trim(id, "0-") == "" {
		return "", errors.New("invalid machine UUID")
	}
	return id, nil
}

func parseIOReg(out string) (string, error) {
	m := ioregRe.FindStringSubmatch(out)
	if m == nil {
		return "", errors.New("IOPlatformUUID not found")
	}
	return parseUUID(m[1])
}
