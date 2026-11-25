package licensekit_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aqobadi/licensekit"
	"github.com/aqobadi/licensekit/licensekittest"
	"github.com/aqobadi/licensekit/online"
)

const product = "example-app"

// clock is a controllable time source shared by the issuer and the app.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func day(s string) time.Time         { t, _ := time.Parse("2006-01-02", s); return t }
func newClock() *clock               { return &clock{t: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)} }
func kind(err error) licensekit.Kind {
	var e *licensekit.Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return 0
}

type harness struct {
	t   *testing.T
	iss *licensekittest.Issuer
	clk *clock
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, iss: licensekittest.New(t, product), clk: newClock()}
	h.iss.Now = h.clk.now
	return h
}

func (h *harness) open(dir, device string, opts ...licensekit.Options) *licensekit.License {
	h.t.Helper()
	var o licensekit.Options
	if len(opts) > 0 {
		o = opts[0]
	}
	o.StateDir, o.DeviceID = dir, device
	l, err := licensekit.OpenAt(product, o, h.clk.now)
	if err != nil {
		h.t.Fatal(err)
	}
	return l
}

func TestOfflineActivateRenewExpireRestart(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	l := h.open(dir, "device-one-0001")
	if s := l.Status(); s.State != licensekit.NotActivated || s.Message == "" || s.CanDeactivate {
		t.Fatalf("%+v", s)
	}
	key := h.iss.Activate(t, l, licensekittest.Terms{Expires: day("2027-11-24"), Features: []string{"sync", "export"}})
	s := l.Status()
	if s.State != licensekit.Active || s.Expires != day("2027-11-24") || s.DaysLeft != 364 ||
		strings.Join(s.Entitlements, ",") != "export,sync" || !s.CanDeactivate || len(s.LicenseID) != 5 {
		t.Fatalf("%+v", s)
	}
	if !l.Has("export") || l.Has("reports") {
		t.Fatal("Has")
	}
	// It survives a restart.
	if r := h.open(dir, "device-one-0001"); r.Status().State != licensekit.Active {
		t.Fatal("not active after restart")
	}
	// It expires after its last day.
	h.clk.t = day("2027-11-25").Add(time.Hour)
	if s := l.Status(); s.State != licensekit.Expired || l.Has("export") || len(s.Entitlements) != 0 {
		t.Fatalf("%+v", s)
	}
	// A renewal code brings it back, survives a restart, and can't be applied twice.
	code, err := h.iss.RenewalCode(key, day("2028-11-24"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Apply(strings.ToLower(code)); err != nil {
		t.Fatal(err)
	}
	if s := h.open(dir, "device-one-0001").Status(); s.State != licensekit.Active || s.Expires != day("2028-11-24") {
		t.Fatalf("%+v", s)
	}
	if err := l.Apply(code); kind(err) != licensekit.AlreadyApplied {
		t.Fatalf("got %v", err)
	}
	older, _ := h.iss.RenewalCode(key, day("2028-01-01"))
	if err := l.Apply(older); kind(err) != licensekit.AlreadyApplied {
		t.Fatalf("older code: %v", err)
	}
	// A renewal that still ends in the past is refused.
	h.clk.t = day("2029-06-01")
	stale, _ := h.iss.RenewalCode(key, day("2029-01-01"))
	if err := l.Apply(stale); kind(err) != licensekit.AlreadyExpired {
		t.Fatalf("stale code: %v", err)
	}
}

func TestRejections(t *testing.T) {
	h := newHarness(t)
	l := h.open(t.TempDir(), "device-one-0001")
	cases := map[string]licensekit.Kind{
		"":                              licensekit.Empty,
		"7K2P-QX9D":                     licensekit.Incomplete,
		"7K2P-QX9D-4HTM-B8YC-2NFA-R3WU": licensekit.BadCharacter,
		"-----BEGIN ZURVAN LICENSE REQUEST-----\nAAAA\n-----END ZURVAN LICENSE REQUEST-----": licensekit.WrongKind,
		"-----BEGIN ZURVAN LICENSE-----\n!!\n-----END ZURVAN LICENSE-----":                   licensekit.InvalidLicense,
	}
	for in, want := range cases {
		if err := l.Apply(in); kind(err) != want {
			t.Errorf("%q: got %v, want %v", in, err, want)
		}
	}
	key := h.iss.NewKey(licensekittest.Terms{Expires: day("2027-01-01")})
	if err := l.Apply(key); kind(err) != licensekit.NeedsOnline {
		t.Fatalf("license key offline: %v", err)
	}
	// A typo is located.
	bad := []byte(key)
	bad[1] = map[bool]byte{true: 'A', false: 'B'}[bad[1] != 'A']
	var e *licensekit.Error
	if err := l.Apply(string(bad)); !errors.As(err, &e) || e.Kind != licensekit.Typo || !strings.Contains(e.Message, "group") {
		t.Fatalf("typo: %v", err)
	}
	// A renewal code before activation, then one for another license.
	other := h.open(t.TempDir(), "device-two-0002")
	otherKey := h.iss.Activate(t, other, licensekittest.Terms{Expires: day("2027-01-01")})
	code, _ := h.iss.RenewalCode(otherKey, day("2028-01-01"))
	if err := l.Apply(code); kind(err) != licensekit.NeedsActivation {
		t.Fatalf("renewal before activation: %v", err)
	}
	h.iss.Activate(t, l, licensekittest.Terms{Expires: day("2027-01-01")})
	if err := l.Apply(code); kind(err) != licensekit.WrongRenewal {
		t.Fatalf("renewal for another license: %v", err)
	}
	// A license file for another computer, and one from another vendor.
	_, req, _ := other.RequestFile(h.iss.NewKey(licensekittest.Terms{}))
	file, _ := h.iss.LicenseFile(req)
	if err := l.Apply(string(file)); kind(err) != licensekit.OtherComputer {
		t.Fatalf("other computer: %v", err)
	}
	rogue := licensekittest.New(t, "rogue-app")
	rl, _ := licensekit.OpenAt("rogue-app", licensekit.Options{StateDir: t.TempDir(), DeviceID: "device-one-0001"}, h.clk.now)
	_, rreq, _ := rl.RequestFile(rogue.NewKey(licensekittest.Terms{}))
	rfile, _ := rogue.LicenseFile(rreq)
	if err := l.Apply(string(rfile)); kind(err) != licensekit.InvalidLicense {
		t.Fatalf("license for another product: %v", err)
	}
	// A license file that expired before it was installed is refused.
	now := h.clk.t
	h.clk.t = day("2025-01-01")
	_, req, _ = l.RequestFile(h.iss.NewKey(licensekittest.Terms{Expires: day("2025-06-01")}))
	file, _ = h.iss.LicenseFile(req)
	h.clk.t = now
	if err := l.Apply(string(file)); kind(err) != licensekit.AlreadyExpired {
		t.Fatalf("expired: %v", err)
	}
}

func TestPerpetualAndRequestFile(t *testing.T) {
	h := newHarness(t)
	l := h.open(t.TempDir(), "device-one-0001")
	key := h.iss.NewKey(licensekittest.Terms{Features: []string{"export"}})
	name, req, err := l.RequestFile(key)
	if err != nil || name != "example-app license request.txt" {
		t.Fatal(name, err)
	}
	if strings.Contains(strings.ReplaceAll(string(req), "-", ""), strings.ReplaceAll(key, "-", "")) {
		t.Fatal("the request file contains the license key")
	}
	file, err := h.iss.LicenseFile(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Apply("Here is the file:\n" + string(file)); err != nil {
		t.Fatal(err)
	}
	h.clk.add(100 * 365 * 24 * time.Hour)
	if s := l.Status(); s.State != licensekit.Active || !s.Perpetual || !s.Expires.IsZero() || s.Message != "Licensed (no expiry)." {
		t.Fatalf("%+v", s)
	}
	if _, _, err := l.RequestFile("not a key"); err == nil {
		t.Fatal("bad key accepted")
	}
}

func TestCopiedStateAndClock(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	l := h.open(dir, "device-one-0001")
	h.iss.Activate(t, l, licensekittest.Terms{Expires: day("2027-11-24")})
	// The same files on another computer.
	if s := h.open(dir, "device-two-0002").Status(); s.State != licensekit.WrongDevice {
		t.Fatalf("%+v", s)
	}
	// A clock set back more than 48 hours, or before the license was issued.
	h.clk.add(10 * 24 * time.Hour)
	l.Status()
	h.clk.add(-3 * 24 * time.Hour)
	if s := l.Status(); s.State != licensekit.ClockProblem {
		t.Fatalf("%+v", s)
	}
	h.clk.add(2 * 24 * time.Hour)
	if s := l.Status(); s.State != licensekit.Active {
		t.Fatalf("%+v", s)
	}
	fresh := t.TempDir()
	nl := h.open(fresh, "device-three-03")
	h.iss.Activate(t, nl, licensekittest.Terms{Expires: day("2027-11-24")})
	os.Remove(filepath.Join(fresh, licensekit.ClockFile))
	h.clk.t = day("2026-01-01")
	if s := h.open(fresh, "device-three-03").Status(); s.State != licensekit.ClockProblem {
		t.Fatalf("clock before issue: %+v", s)
	}
}

func TestOnlineSetupMoveAndDeactivate(t *testing.T) {
	h := newHarness(t)
	url := h.iss.Server(t)
	opts := licensekit.Options{ServerURL: url}
	ctx := context.Background()
	a := h.open(t.TempDir(), "computer-a-0001", opts)
	b := h.open(t.TempDir(), "computer-b-0002", opts)
	key := h.iss.NewKey(licensekittest.Terms{Expires: day("2027-11-24"), Features: []string{"export"}})
	if err := online.Enter(ctx, a, " "+strings.ToLower(key)+"\n"); err != nil {
		t.Fatal(err)
	}
	if s := a.Status(); s.State != licensekit.Active || !s.CanDeactivate || !a.Has("export") {
		t.Fatalf("%+v", s)
	}
	// Setting up the same computer again is harmless.
	if err := online.Activate(ctx, a, key); err != nil {
		t.Fatal(err)
	}
	if err := online.Activate(ctx, b, key); kind(err) != licensekit.KeyInUse {
		t.Fatalf("second computer: %v", err)
	}
	if err := online.Activate(ctx, b, h.iss.NewKey(licensekittest.Terms{})[:5]+"0000-0000-0000-0000-0000"); kind(err) == 0 {
		t.Fatal("bad key accepted")
	}
	// Renewal codes still work offline after an online setup.
	code, err := h.iss.RenewalCode(key, day("2028-11-24"))
	if err != nil {
		t.Fatal(err)
	}
	if err := online.Enter(ctx, a, code); err != nil {
		t.Fatal(err)
	}
	// Move: deactivate A, then set up B with the same key.
	if err := online.Deactivate(ctx, a); err != nil {
		t.Fatal(err)
	}
	if s := a.Status(); s.State != licensekit.NotActivated || s.CanDeactivate {
		t.Fatalf("%+v", s)
	}
	if err := online.Deactivate(ctx, a); kind(err) != licensekit.NotDeactivatable {
		t.Fatalf("second deactivate: %v", err)
	}
	if err := online.Activate(ctx, b, key); err != nil {
		t.Fatal(err)
	}
	if b.Status().State != licensekit.Active {
		t.Fatal("B not active")
	}
}

func TestOnlineErrorsAndServerAddress(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	key := h.iss.NewKey(licensekittest.Terms{})
	// No server in the build and none configured.
	l := h.open(t.TempDir(), "device-one-0001")
	if err := online.Activate(ctx, l, key); kind(err) != licensekit.Offline {
		t.Fatalf("no server: %v", err)
	}
	// An unreachable server.
	l = h.open(t.TempDir(), "device-one-0001", licensekit.Options{ServerURL: "http://127.0.0.1:1"})
	if err := online.Activate(ctx, l, key); kind(err) != licensekit.Offline {
		t.Fatalf("unreachable: %v", err)
	}
	// The environment overrides the build, and Options override both.
	t.Setenv("LICENSEKIT_SERVER_URL", h.iss.Server(t))
	l = h.open(t.TempDir(), "device-one-0001")
	if err := online.Activate(ctx, l, key); err != nil {
		t.Fatal(err)
	}
	if _, err := licensekit.OpenAt(product, licensekit.Options{ServerURL: "http://example.com", DeviceID: "device-one-0001"}, h.clk.now); kind(err) != licensekit.NotConfigured {
		t.Fatalf("plain http accepted: %v", err)
	}
}

func TestReadOnlyStateDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX permissions as non-root only")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	h := newHarness(t)
	dir := t.TempDir()
	l := h.open(dir, "device-one-0001")
	key := h.iss.Activate(t, l, licensekittest.Terms{Expires: day("2026-12-24")})
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	r := h.open(dir, "device-one-0001")
	if r.Status().State != licensekit.Active {
		t.Fatal("read-only state not honored")
	}
	code, _ := h.iss.RenewalCode(key, day("2027-12-24"))
	if err := r.Apply(code); kind(err) != licensekit.StorageFailed {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o500 {
		t.Fatal("SDK changed an existing directory's mode")
	}
	// The clock high-water persists per user even though the directory is read-only.
	h.clk.add(60 * 24 * time.Hour)
	if s := h.open(dir, "device-one-0001").Status(); s.State != licensekit.Expired {
		t.Fatalf("%+v", s)
	}
	h.clk.add(-55 * 24 * time.Hour)
	if s := h.open(dir, "device-one-0001").Status(); s.State != licensekit.ClockProblem {
		t.Fatalf("rollback after restart not detected: %+v", s)
	}
}

func TestConcurrencyAndOtherProcesses(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	a := h.open(dir, "device-one-0001")
	b := h.open(dir, "device-one-0001") // a second process on the same files
	os.WriteFile(filepath.Join(dir, ".license.tmp-123"), []byte("garbage"), 0o600)
	key := h.iss.Activate(t, a, licensekittest.Terms{Expires: day("2027-01-01"), Features: []string{"export"}})
	if !b.Has("export") {
		t.Fatal("a license installed by another process was not picked up")
	}
	code, _ := h.iss.RenewalCode(key, day("2028-01-01"))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.Apply(code); err != nil && kind(err) != licensekit.AlreadyApplied {
				t.Error(err)
			}
			a.Status()
			b.Has("export")
		}()
	}
	wg.Wait()
	if s := b.Status(); s.Expires != day("2028-01-01") {
		t.Fatalf("%+v", s)
	}
}

func TestSpecialStateFilesRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs")
	}
	h := newHarness(t)
	dir := t.TempDir()
	if err := licensekit.Mkfifo(filepath.Join(dir, licensekit.LicenseFile)); err != nil {
		t.Skip(err)
	}
	os.Symlink("/dev/zero", filepath.Join(dir, licensekit.ClockFile))
	done := make(chan licensekit.State, 1)
	go func() { done <- h.open(dir, "device-one-0001").Status().State }()
	select {
	case st := <-done:
		if st != licensekit.NotActivated {
			t.Fatal(st)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Open blocked on a FIFO")
	}
}

func FuzzApply(f *testing.F) {
	f.Add("7K2P-QX9D-4HTM-B8YC-2NFA-R3WD")
	f.Add("-----BEGIN ZURVAN LICENSE-----\nMQ==\n-----END ZURVAN LICENSE-----")
	iss := licensekittest.New(f, product)
	l := iss.Open(f, licensekit.Options{})
	f.Fuzz(func(t *testing.T, in string) {
		if err := l.Apply(in); err == nil {
			t.Fatalf("accepted %q", in)
		}
	})
}
