// Package licensekit checks License-ZG licenses inside an application.
//
// Call Open with the product's slug, then Status and Has to enforce the
// license, and Apply for renewal codes and license files. Activation with a
// license key goes online once through package licensekit/online (or the
// ready-made page in licensekit/licenseui). This package makes no network
// requests. The trusted keys come from the build (see README.md), never
// from code, files or the environment.
package licensekit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/aqobadi/licensekit/internal/bridge"
	"github.com/aqobadi/licensekit/protocol"
)

// build is the licensing configuration of this build, set with
//
//	-ldflags "-X github.com/aqobadi/licensekit.build=<value>"
//
// where the value is the build setting the License-ZG Manager shows under
// Settings → Signing. It is unexported, so nothing at run time can change it.
var build string

// Options configures Open. The zero value is the recommended default.
type Options struct {
	// StateDir overrides where the license is saved. The default is the
	// per-user application data directory:
	//   Linux   $XDG_DATA_HOME or ~/.local/share  /licensekit/<product>
	//   macOS   ~/Library/Application Support    /licensekit/<product>
	//   Windows %LOCALAPPDATA%                    \licensekit\<product>
	// Servers and containers pass a directory on persistent storage.
	StateDir string

	// DeviceID replaces the OS machine identifier (8–256 bytes). Use it in
	// containers or environments without a stable OS identifier. It must be
	// stable and unique per installation; anyone who copies it can reuse the
	// license.
	DeviceID string

	// ServerURL overrides the activation server address from the build. The
	// LICENSEKIT_SERVER_URL environment variable does the same. It is safe
	// to change: a wrong server can only fail, never grant a license.
	ServerURL string
}

// State is the licensing state reported by Status.
type State int

const (
	NotActivated State = iota // nothing installed, or saved data unreadable
	Active                    // valid; grant access
	Expired                   // the license's last day has passed
	WrongDevice               // the saved license belongs to another computer
	ClockProblem              // the clock is >48h behind the latest time seen, or before the license was issued
	Invalid                   // the saved license is no longer accepted by this build
)

func (s State) String() string {
	names := [...]string{"NotActivated", "Active", "Expired", "WrongDevice", "ClockProblem", "Invalid"}
	if s < 0 || int(s) >= len(names) {
		return "Unknown"
	}
	return names[s]
}

// Status describes the current license. It is safe to show Message to
// customers.
type Status struct {
	State         State
	LicenseID     string    // e.g. "B8Y92"; empty when nothing is installed
	DeviceSource  string    // "os" or "app" (Options.DeviceID)
	Expires       time.Time // last valid day (UTC midnight); zero if perpetual or none
	Perpetual     bool
	DaysLeft      int      // 0 on the last day; negative when expired; 0 when the clock is wrong
	Entitlements  []string // granted feature keys, sorted; empty unless Active
	CanDeactivate bool     // this installation can give the license back online
	Message       string
}

// License is an opened product license. It is safe for concurrent use.
type License struct {
	mu        sync.Mutex
	product   string
	productID [16]byte
	trust     *protocol.Trust
	server    string
	fp        [15]byte
	source    byte
	dir       string
	clockAt   string // clock file path (per-user fallback when dir is read-only)
	now       func() time.Time

	lic     *protocol.License // verified saved license, if any
	licErr  error             // why the saved license was rejected, if it was
	licText string            // file content that lic/licErr were computed from
	step    uint16            // applied renewal step, 0 if none
	renText string
	device  ed25519.PrivateKey // loaded or created on first use
	high    int64              // clock high-water (Unix seconds)
	saved   int64              // high-water last persisted (or attempted)
}

const tolerance = 48 * 3600

// Open prepares licensing for the product with the given slug (as shown in
// the License-ZG Manager, e.g. "moro-ai") and re-verifies any saved
// license. It fails only for build, developer or environment problems.
func Open(product string, opts Options) (*License, error) {
	return open(product, opts, time.Now)
}

func open(product string, opts Options, now func() time.Time) (*License, error) {
	l := &License{product: product, now: now, source: protocol.SourceOS}
	var err error
	if l.productID, err = protocol.ProductID(product); err != nil {
		return nil, &Error{Kind: BadProduct, Message: messages[BadProduct], err: err}
	}
	if l.trust, err = buildTrust(product); err != nil {
		return nil, &Error{Kind: NotConfigured, Message: messages[NotConfigured], err: err}
	}
	if l.server, err = serverURL(opts.ServerURL, l.trust.ServerURL); err != nil {
		return nil, &Error{Kind: NotConfigured, Message: messages[NotConfigured], err: err}
	}
	var identity []byte
	if opts.DeviceID != "" {
		l.source, identity = protocol.SourceApp, []byte(opts.DeviceID)
	} else {
		id, err := systemIdentity()
		if err != nil {
			e := &Error{Kind: DeviceUnavailable, Message: messages[DeviceUnavailable], err: err}
			if errors.Is(err, errContainer) {
				e.Message = "This app is running in a container. It needs a configured device ID before it can be activated."
			}
			return nil, e
		}
		identity = []byte(id)
	}
	if l.fp, err = protocol.Fingerprint(l.productID, l.source, identity); err != nil {
		return nil, &Error{Kind: DeviceUnavailable, Message: "The configured device ID is invalid. Contact the vendor.", err: err}
	}
	l.dir = opts.StateDir
	if l.dir == "" {
		if l.dir, err = defaultStateDir(product); err != nil {
			return nil, &Error{Kind: StorageFailed, Message: messages[StorageFailed], err: err}
		}
	}
	fi, err := os.Stat(l.dir)
	if os.IsNotExist(err) {
		err = os.MkdirAll(l.dir, 0o700)
		fi, _ = os.Stat(l.dir)
	}
	if err != nil || fi == nil || !fi.IsDir() {
		return nil, &Error{Kind: StorageFailed, Message: messages[StorageFailed], err: fmt.Errorf("state directory %s is unusable: %v", l.dir, err)}
	}
	l.clockAt = l.path(clockFile)
	if !writable(l.dir) && opts.StateDir != "" {
		// A per-machine license the user cannot write: keep the clock per
		// user so rollback detection still persists (spec §11).
		if d, err := defaultStateDir(product); err == nil && os.MkdirAll(d, 0o700) == nil && writable(d) {
			l.clockAt = filepath.Join(d, clockFile)
		}
	}
	l.high = max(readClock(l.path(clockFile)), readClock(l.clockAt))
	l.saved = l.high
	l.reload()
	return l, nil
}

// buildTrust returns the trust compiled into this build, or the throwaway
// trust a licensekittest test registered for the product.
func buildTrust(product string) (*protocol.Trust, error) {
	if bridge.TestTrust != nil {
		if t := bridge.TestTrust(product); t != nil {
			return t, nil
		}
	}
	if strings.TrimSpace(build) == "" {
		return nil, errors.New("this build has no trusted keys; set the Manager's build setting with -ldflags -X github.com/aqobadi/licensekit.build=…")
	}
	return protocol.ParseTrust(build)
}

// serverURL resolves the activation API address: Options, then the
// environment, then the build.
func serverURL(option, fromBuild string) (string, error) {
	for _, u := range []string{option, os.Getenv("LICENSEKIT_SERVER_URL")} {
		if u = strings.TrimSpace(u); u != "" {
			if err := protocol.CheckServerURL(u); err != nil {
				return "", err
			}
			return strings.TrimRight(u, "/"), nil
		}
	}
	return fromBuild, nil
}

// writable reports whether files can be created in dir.
func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

func (l *License) path(name string) string { return filepath.Join(l.dir, name) }

// reload re-reads the saved license and renewal and re-verifies them when
// their content changed, so a license installed by another process takes
// effect immediately.
func (l *License) reload() {
	text, err := readSmall(l.path(licenseFile))
	if err != nil {
		text = ""
	}
	if text != l.licText || l.lic == nil && l.licErr == nil && text != "" {
		l.licText, l.lic, l.licErr, l.renText, l.step = text, nil, nil, "", 0
		if text == "" {
			if err != nil && !os.IsNotExist(err) {
				l.licErr = err
			}
		} else if data, err := protocol.Unarmor(text, protocol.LabelLicense); err != nil {
			l.licErr = err
		} else if l.lic, l.licErr = protocol.Verify(l.trust, data, l.productID, l.fp); l.licErr == nil {
			l.raiseClock(l.lic.IssuedDay)
		}
	}
	if l.lic == nil {
		return
	}
	ren, _ := readSmall(l.path(renewalFile))
	if ren != l.renText {
		l.renText, l.step = ren, 0
		if c, err := protocol.ParseCode(ren); err == nil && c.Renewal != nil && l.lic.CheckRenewal(*c.Renewal) {
			l.step = c.Renewal.Step
		}
	}
}

// raiseClock moves the high-water mark to the start of a signed day: a
// clock set before a license was issued is a clock problem.
func (l *License) raiseClock(day uint16) {
	if t := protocol.EpochUnix + int64(day)*86400; t > l.high {
		l.high = t
	}
}

// clock checks the current time against the high-water mark and advances
// it. It returns the current Unix time and whether the clock is acceptable.
func (l *License) clock() (int64, bool) {
	now := l.now().Unix()
	if now < protocol.EpochUnix || now < l.high-tolerance {
		return now, false
	}
	if now > l.high {
		l.high = now
	}
	if l.high > l.saved+3600 || l.saved == 0 {
		if disk := readClock(l.clockAt); disk > l.high {
			l.high = disk
		}
		writeAtomic(l.clockAt, []byte(fmt.Sprintf("%d\n", l.high)))
		l.saved = l.high // on failure, retry only after another hour of advance
		if now < l.high-tolerance {
			return now, false
		}
	}
	return now, true
}

// Apply installs a renewal code or the contents of a .license file. It
// returns nil once the change is verified and saved, or an *Error. A license
// key returns NeedsOnline: activate it with licensekit/online.
func (l *License) Apply(input string) error {
	switch {
	case protocol.IsArmored(input, protocol.LabelLicense):
		data, err := protocol.Unarmor(input, protocol.LabelLicense)
		if err != nil {
			return newError(InvalidLicense)
		}
		return l.install(data)
	case protocol.IsArmored(input, protocol.LabelRequest):
		return newError(WrongKind)
	}
	c, err := protocol.ParseCode(input)
	if err != nil {
		return fromProtocol(err)
	}
	if c.Key != nil {
		return newError(NeedsOnline)
	}
	return l.renew(*c.Renewal)
}

// install verifies and saves a license.
func (l *License) install(data []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	lic, err := protocol.Verify(l.trust, data, l.productID, l.fp)
	if err != nil {
		return fromProtocol(err)
	}
	l.raiseClock(lic.IssuedDay)
	now, ok := l.clock()
	if !ok {
		return newError(ClockWrong)
	}
	l.reload()
	step := uint16(0) // a saved renewal still counts if it belongs to the new license's chain
	if c, err := protocol.ParseCode(l.renText); err == nil && c.Renewal != nil && lic.CheckRenewal(*c.Renewal) {
		step = c.Renewal.Step
	}
	if today, _ := protocol.Today(now); !protocol.Valid(lic.Expiry(step), today) {
		return newError(AlreadyExpired)
	}
	text := string(protocol.Armor(protocol.LabelLicense, []string{"License " + protocol.IDString(lic.ID) + " for " + l.product}, data))
	if err := writeAtomic(l.path(licenseFile), []byte(text)); err != nil {
		return &Error{Kind: StorageFailed, Message: messages[StorageFailed], err: err}
	}
	if step == 0 && l.renText != "" {
		os.Remove(l.path(renewalFile))
	}
	l.licText, l.lic, l.licErr, l.step = text, lic, nil, step
	if step == 0 {
		l.renText = ""
	}
	return nil
}

// renew applies a renewal code to the installed license.
func (l *License) renew(r protocol.Renewal) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reload()
	switch {
	case l.lic == nil:
		return newError(NeedsActivation)
	case l.lic.ExpiryDay == 0 || l.lic.Expiry(r.Step) <= l.lic.Expiry(l.step) && l.lic.CheckRenewal(r):
		return newError(AlreadyApplied)
	case !l.lic.CheckRenewal(r):
		return newError(WrongRenewal)
	}
	now, ok := l.clock()
	if !ok {
		return newError(ClockWrong)
	}
	if today, _ := protocol.Today(now); !protocol.Valid(l.lic.Expiry(r.Step), today) {
		return newError(AlreadyExpired)
	}
	text := r.String() + "\n"
	if err := writeAtomic(l.path(renewalFile), []byte(text)); err != nil {
		return &Error{Kind: StorageFailed, Message: messages[StorageFailed], err: err}
	}
	l.renText, l.step = text, r.Step
	return nil
}

// Status reports the current state. It never fails; storage problems only
// affect Message.
func (l *License) Status() Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.status()
}

func (l *License) status() Status {
	l.reload()
	s := Status{DeviceSource: "os"}
	if l.source == protocol.SourceApp {
		s.DeviceSource = "app"
	}
	now, clockOK := l.clock()
	if l.lic == nil {
		var pe *protocol.Error
		switch {
		case errors.As(l.licErr, &pe) && pe.Kind == protocol.WrongDevice:
			s.State = WrongDevice
		case l.licErr != nil && l.licText != "":
			s.State = Invalid
		default:
			s.State = NotActivated
		}
		s.Message = stateMessage(s)
		return s
	}
	v := l.lic
	expiry := v.Expiry(l.step)
	s.LicenseID = protocol.IDString(v.ID)
	s.Perpetual = expiry == 0
	s.CanDeactivate = l.ownsLicense()
	today, _ := protocol.Today(now)
	if !s.Perpetual {
		s.Expires = protocol.Date(int64(expiry))
		if clockOK {
			s.DaysLeft = int(int64(expiry) - today)
		}
	}
	switch {
	case !clockOK:
		s.State = ClockProblem
	case !protocol.Valid(expiry, today):
		s.State = Expired
	default:
		s.State = Active
		s.Entitlements = append([]string{}, v.Entitlements...)
	}
	s.Message = stateMessage(s)
	return s
}

// Has reports whether the license is Active and grants the named feature.
func (l *License) Has(entitlement string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.status().State != Active {
		return false
	}
	for _, e := range l.lic.Entitlements {
		if e == entitlement {
			return true
		}
	}
	return false
}

// RequestFile returns a suggested file name and the contents of a license
// request for a customer without internet access. It carries the license
// key's hash, never the key. The SDK does not save it.
func (l *License) RequestFile(licenseKey string) (name string, content []byte, err error) {
	key, err := protocol.ParseLicenseKey(licenseKey)
	if err != nil {
		return "", nil, fromProtocol(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := l.request(key, [32]byte{})
	if err != nil {
		return "", nil, err
	}
	content = protocol.Armor(protocol.LabelRequest, []string{
		"License request for " + l.product,
		"Send this file to your vendor. It contains no personal data and no license key.",
	}, data)
	return safeName(l.product) + " license request.txt", content, nil
}

// request returns a signed request for this computer. Callers hold l.mu.
func (l *License) request(key protocol.LicenseKey, nonce [32]byte) ([]byte, error) {
	dev, err := l.deviceKey(true)
	if err != nil {
		return nil, &Error{Kind: StorageFailed, Message: messages[StorageFailed], err: err}
	}
	q := &protocol.Request{ProductID: l.productID, Fingerprint: l.fp, Source: l.source, DeviceKey: dev.Public().(ed25519.PublicKey),
		KeyHash: key.Hash(), Nonce: nonce, Created: l.now().Unix()}
	return q.Sign(dev)
}

// deviceKey loads this installation's key, creating it when create is set.
func (l *License) deviceKey(create bool) (ed25519.PrivateKey, error) {
	if l.device != nil {
		return l.device, nil
	}
	if s, err := readSmall(l.path(deviceKeyFile)); err == nil {
		if seed, err := hex.DecodeString(strings.TrimSpace(s)); err == nil && len(seed) == ed25519.SeedSize {
			l.device = ed25519.NewKeyFromSeed(seed)
			return l.device, nil
		}
	}
	if !create {
		return nil, errors.New("no device key")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(l.path(deviceKeyFile), []byte(hex.EncodeToString(priv.Seed())+"\n")); err != nil {
		return nil, err
	}
	l.device = priv
	return priv, nil
}

// ownsLicense reports whether this installation's key is the license's
// device key, so it can sign a deactivation. Callers hold l.mu.
func (l *License) ownsLicense() bool {
	dev, err := l.deviceKey(false)
	return err == nil && l.lic != nil && dev.Public().(ed25519.PublicKey).Equal(l.lic.DeviceKey)
}

func (l *License) ops() bridge.Ops {
	return bridge.Ops{
		Product: l.product, ProductID: l.productID, ServerURL: l.server, Trust: l.trust,
		SetupRequest: func(key protocol.LicenseKey, nonce [32]byte) ([]byte, error) {
			l.mu.Lock()
			defer l.mu.Unlock()
			return l.request(key, nonce)
		},
		Install: l.install,
		Release: func(nonce [32]byte) (*protocol.Release, []byte, error) {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.reload()
			if !l.ownsLicense() {
				return nil, nil, newError(NotDeactivatable)
			}
			q := &protocol.Release{ProductID: l.productID, Fingerprint: l.fp, LicenseID: l.lic.ID, DeviceKey: l.lic.DeviceKey, Nonce: nonce}
			data, err := q.Sign(l.device)
			return q, data, err
		},
		Released: func(q *protocol.Release, receipt []byte) error {
			if err := q.CheckReceipt(l.trust, receipt); err != nil {
				return NewError(ServerUnavailable, err)
			}
			l.mu.Lock()
			defer l.mu.Unlock()
			for _, f := range []string{licenseFile, renewalFile} {
				if err := os.Remove(l.path(f)); err != nil && !os.IsNotExist(err) {
					return &Error{Kind: StorageFailed, Message: messages[StorageFailed], err: err}
				}
			}
			l.licText, l.lic, l.licErr, l.renText, l.step = "", nil, nil, "", 0
			return nil
		},
	}
}

func init() {
	bridge.Of = func(x any) bridge.Ops { return x.(*License).ops() }
}

// safeName keeps letters, digits, spaces, '-', '_' and '.' (not leading).
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '-' || r == '_' || r == '.' && b.Len() > 0 {
			b.WriteRune(r)
		}
	}
	if out := strings.TrimSpace(b.String()); out != "" {
		return out
	}
	return "app"
}
