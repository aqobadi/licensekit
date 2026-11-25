package licensekit

import (
	"errors"
	"strings"
	"testing"
)

func TestParsers(t *testing.T) {
	if id, err := parseMachineID([]byte(" 0123456789ABCDEF0123456789abcdef\n")); err != nil || id != "0123456789abcdef0123456789abcdef" {
		t.Fatal(id, err)
	}
	for _, bad := range []string{"uninitialized", strings.Repeat("0", 32), "abc", strings.Repeat("g", 32)} {
		if _, err := parseMachineID([]byte(bad)); err == nil {
			t.Error(bad)
		}
	}
	if id, err := parseIOReg(`  "IOPlatformUUID" = "A1B2C3D4-0000-1111-2222-333344445555"`); err != nil || id != "a1b2c3d4-0000-1111-2222-333344445555" {
		t.Fatal(id, err)
	}
	if _, err := parseUUID("00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("zero GUID accepted")
	}
}

func TestNativeIdentity(t *testing.T) {
	id, err := systemIdentity()
	if errors.Is(err, errContainer) {
		t.Skip("running in a container")
	}
	if err != nil {
		t.Fatalf("supported OS without a native identity: %v", err)
	}
	again, _ := systemIdentity()
	if id == "" || id != again {
		t.Fatal("native identity unstable")
	}
}

func TestOpenWithoutBuildTrust(t *testing.T) {
	_, err := Open("unconfigured-app", Options{DeviceID: "device-0001", StateDir: t.TempDir()})
	var e *Error
	if !errors.As(err, &e) || e.Kind != NotConfigured || e.Message == "" {
		t.Fatalf("got %v", err)
	}
	if _, err := Open("Bad Name", Options{}); !errors.As(err, &e) || e.Kind != BadProduct {
		t.Fatalf("got %v", err)
	}
}

func TestProductFromBuild(t *testing.T) {
	const roots = "r1:951a9e4c7e3defb28c5ee9033f60866b8ab55e7a7656917b626db610551e2ff5"
	previous := build
	t.Cleanup(func() { build = previous })
	build = roots
	opts := Options{DeviceID: "device-0001", StateDir: t.TempDir()}
	legacy, err := Open("example-app", opts)
	if err != nil {
		t.Fatal(err)
	}
	var e *Error
	if _, err := Open("", opts); !errors.As(err, &e) || e.Kind != NotConfigured {
		t.Fatalf("missing build product: %v", err)
	}
	build = roots + ",product=example-app"
	current, err := Open("", opts)
	if err != nil {
		t.Fatal(err)
	}
	if current.productID != legacy.productID || current.fp != legacy.fp || current.dir != legacy.dir {
		t.Fatal("build product changed the installation identity")
	}
	if _, err := Open("example-app", opts); err != nil {
		t.Fatal(err)
	}
	if _, err := Open("other-app", opts); !errors.As(err, &e) || e.Kind != NotConfigured {
		t.Fatalf("mismatched build product: %v", err)
	}
}
