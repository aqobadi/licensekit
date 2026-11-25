package licensekit

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Files in the state directory (spec §11).
const (
	licenseFile   = "license"    // the armored license
	renewalFile   = "renewal"    // the latest applied renewal code
	deviceKeyFile = "device.key" // this installation's Ed25519 seed (hex)
	clockFile     = "clock"      // the clock high-water mark
)

// defaultStateDir returns the per-user application data directory for a
// product (spec C §1).
func defaultStateDir(product string) (string, error) {
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("LOCALAPPDATA")
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, "Library", "Application Support")
		}
	default:
		base = os.Getenv("XDG_DATA_HOME")
		if base == "" {
			if home, err := os.UserHomeDir(); err == nil {
				base = filepath.Join(home, ".local", "share")
			}
		}
	}
	if base == "" || !filepath.IsAbs(base) {
		return "", errors.New("no per-user application data directory; set Options.StateDir")
	}
	return filepath.Join(base, "licensekit", product), nil
}

// writeAtomic replaces path with data: temp file in the same directory,
// fsync, rename, then fsync the directory where supported.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	var err2 error
	for i := 0; i < 10; i++ { // Windows refuses to replace a file another process has open
		if err2 = os.Rename(tmp, path); err2 == nil || runtime.GOOS != "windows" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err2 != nil {
		return err2
	}
	if runtime.GOOS != "windows" {
		if d, err := os.Open(dir); err == nil {
			d.Sync()
			d.Close()
		}
	}
	return nil
}

// maxStateFile bounds every state file read.
const maxStateFile = 16 << 10

// readSmall reads a small regular file. Symlinks, FIFOs and devices are
// refused so a planted special file cannot block or redirect the SDK.
func readSmall(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("state file is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxStateFile+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxStateFile {
		return "", errors.New("state file too large")
	}
	return string(b), nil
}

func readClock(path string) int64 {
	s, err := readSmall(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}
