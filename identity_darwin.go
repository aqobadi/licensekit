//go:build darwin

package licensekit

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

type capped struct{ bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if c.Len()+len(p) > 1<<20 {
		return 0, errors.New("ioreg output too large")
	}
	return c.Buffer.Write(p)
}

func systemIdentity() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out capped
	cmd := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return parseIOReg(out.String())
}
