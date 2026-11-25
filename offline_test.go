package licensekit

import (
	"os/exec"
	"strings"
	"testing"
)

// The SDK must never be able to make network requests: no package in its
// dependency graph may be net or net/*, on any supported OS.
func TestNoNetworkDependencies(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not available")
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		cmd := exec.Command("go", "list", "-deps", ".")
		cmd.Env = append(cmd.Environ(), "GOOS="+goos)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		for _, pkg := range strings.Fields(string(out)) {
			if pkg == "net" || strings.HasPrefix(pkg, "net/") || pkg == "crypto/tls" {
				t.Errorf("%s: SDK depends on %s", goos, pkg)
			}
		}
	}
}
