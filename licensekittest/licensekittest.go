// Package licensekittest is a throwaway License-ZG Manager for an
// application's tests. It makes licensekit.Open trust a fresh test root for
// one product, issues license keys, license files and renewal codes, and
// serves the activation API, so tests never need real keys or a network.
//
// It works only inside `go test`.
package licensekittest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/aqobadi/licensekit"
	"github.com/aqobadi/licensekit/internal/bridge"
	"github.com/aqobadi/licensekit/protocol"
)

var (
	registryMu sync.Mutex
	registry   = map[string]*protocol.Trust{}
	hookOnce   sync.Once
)

// Terms describe a license the Issuer sells.
type Terms struct {
	Expires  time.Time // last valid day; zero means perpetual
	Features []string
}

// Issuer issues licenses for one product, like a License-ZG Manager.
type Issuer struct {
	Product string
	Now     func() time.Time // defaults to time.Now

	productID [16]byte
	signing   ed25519.PrivateKey
	cert      *protocol.Cert
	trust     *protocol.Trust

	mu     sync.Mutex
	keys   map[[32]byte]*sold
	nonces map[[32]byte]bool
	nextID uint32
}

type sold struct {
	id    uint32
	terms Terms
	seat  *seat
}

type seat struct {
	fingerprint [15]byte
	source      byte
	device      ed25519.PublicKey
	seed        [32]byte
	base, n     uint16
}

// New returns an Issuer and makes licensekit.Open trust it for product
// until the test ends. Tests that use the same product must not run in
// parallel.
func New(t testing.TB, product string) *Issuer {
	t.Helper()
	if !testing.Testing() {
		panic("licensekittest is only for tests")
	}
	pid, err := protocol.ProductID(product)
	if err != nil {
		t.Fatal(err)
	}
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	_, signing, _ := ed25519.GenerateKey(rand.Reader)
	i := &Issuer{Product: product, Now: time.Now, productID: pid, signing: signing,
		keys: map[[32]byte]*sold{}, nonces: map[[32]byte]bool{}, nextID: 0x10000}
	i.cert = &protocol.Cert{KeyNumber: 1, PublicKey: signing.Public().(ed25519.PublicKey), CreatedDay: 1}
	if err := i.cert.Sign(1, root); err != nil {
		t.Fatal(err)
	}
	i.trust = &protocol.Trust{Roots: map[uint8]ed25519.PublicKey{1: root.Public().(ed25519.PublicKey)}, Distrusted: map[uint16]bool{}}
	register(t, product, i.trust)
	return i
}

// UseBuildSetting makes licensekit.Open trust a real Manager's build setting
// (Settings → Signing) for product until the test ends, as if the test
// binary had been built with it. Use it to test against a development
// Manager.
func UseBuildSetting(t testing.TB, product, setting string) {
	t.Helper()
	if !testing.Testing() {
		panic("licensekittest is only for tests")
	}
	trust, err := protocol.ParseTrust(setting)
	if err != nil {
		t.Fatal(err)
	}
	register(t, product, trust)
}

func register(t testing.TB, product string, trust *protocol.Trust) {
	hookOnce.Do(func() {
		bridge.TestTrust = func(p string) *protocol.Trust {
			registryMu.Lock()
			defer registryMu.Unlock()
			return registry[p]
		}
	})
	registryMu.Lock()
	registry[product] = trust
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		if registry[product] == trust {
			delete(registry, product)
		}
		registryMu.Unlock()
	})
}

// Open opens the product with a temporary state directory and a fixed
// device ID unless opts sets them.
func (i *Issuer) Open(t testing.TB, opts licensekit.Options) *licensekit.License {
	t.Helper()
	if opts.StateDir == "" {
		opts.StateDir = t.TempDir()
	}
	if opts.DeviceID == "" {
		opts.DeviceID = "licensekittest-device"
	}
	l, err := licensekit.Open(i.Product, opts)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// NewKey sells a license and returns its license key.
func (i *Issuer) NewKey(terms Terms) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	var k protocol.LicenseKey
	rand.Read(k[:])
	i.nextID++
	i.keys[k.Hash()] = &sold{id: i.nextID, terms: terms}
	return k.String()
}

// Activate sells a license and installs it on lic through a request file,
// the way a customer without internet would.
func (i *Issuer) Activate(t testing.TB, lic *licensekit.License, terms Terms) (licenseKey string) {
	t.Helper()
	key := i.NewKey(terms)
	_, req, err := lic.RequestFile(key)
	if err != nil {
		t.Fatal(err)
	}
	file, err := i.LicenseFile(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := lic.Apply(string(file)); err != nil {
		t.Fatal(err)
	}
	return key
}

// LicenseFile answers a request file with a .license file.
func (i *Issuer) LicenseFile(requestFile []byte) ([]byte, error) {
	data, err := protocol.Unarmor(string(requestFile), protocol.LabelRequest)
	if err != nil {
		return nil, err
	}
	q, err := protocol.ParseRequest(data)
	if err != nil {
		return nil, err
	}
	lic, code := i.setup(q)
	if code != "" {
		return nil, errors.New(code)
	}
	return protocol.Armor(protocol.LabelLicense, []string{"Test license"}, lic), nil
}

// RenewalCode returns the renewal code that moves the license of key to
// expire on the given day. The key must be set up on a computer.
func (i *Issuer) RenewalCode(licenseKey string, expires time.Time) (string, error) {
	k, err := protocol.ParseLicenseKey(licenseKey)
	if err != nil {
		return "", err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	s := i.keys[k.Hash()]
	if s == nil || s.seat == nil {
		return "", errors.New("licensekittest: the key is not set up on a computer")
	}
	day := protocol.DayOf(expires)
	if day <= int64(s.seat.base) || day > int64(s.seat.base)+int64(s.seat.n) {
		return "", errors.New("licensekittest: expiry outside the renewal chain")
	}
	step := uint16(day - int64(s.seat.base))
	ctx := protocol.ChainContext{ProductID: i.productID, Fingerprint: s.seat.fingerprint, LicenseID: s.id}
	return protocol.Renewal{Step: step, Value: ctx.Value(s.seat.seed, s.seat.n, step)}.String(), nil
}

// setup assigns the key's seat to the requesting computer and signs its
// license. It returns an API error code on failure.
func (i *Issuer) setup(q *protocol.Request) ([]byte, string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	s := i.keys[q.KeyHash]
	if s == nil || q.ProductID != i.productID {
		return nil, protocol.ErrInvalidKey
	}
	today := uint16(protocol.DayOf(i.Now()))
	if s.seat != nil && s.seat.fingerprint != q.Fingerprint {
		return nil, protocol.ErrInUse
	}
	if s.seat == nil {
		s.seat = &seat{fingerprint: q.Fingerprint, base: today, n: protocol.ChainLength(today)}
		rand.Read(s.seat.seed[:])
	}
	s.seat.source, s.seat.device = q.Source, q.DeviceKey
	features := append([]string(nil), s.terms.Features...)
	sort.Strings(features)
	l := &protocol.License{ProductID: i.productID, Fingerprint: q.Fingerprint, Source: q.Source, DeviceKey: q.DeviceKey, ID: s.id,
		IssuedDay: today, Entitlements: features}
	if !s.terms.Expires.IsZero() {
		l.ExpiryDay = uint16(max(protocol.DayOf(s.terms.Expires), int64(s.seat.base)))
		l.ChainBase, l.ChainLength = s.seat.base, s.seat.n
		l.Lock = l.Chain().Lock(s.seat.seed, s.seat.n)
	}
	data, err := l.Sign(i.cert, i.signing)
	if err != nil {
		return nil, protocol.ErrUnavailable
	}
	return data, ""
}

// Server serves the activation API until the test ends and returns its
// address for licensekit.Options.ServerURL.
func (i *Issuer) Server(t testing.TB) string {
	t.Helper()
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	fail := func(w http.ResponseWriter, code string) {
		reply(w, http.StatusBadRequest, protocol.APIError{Code: code, Message: code})
	}
	useNonce := func(n [32]byte) bool {
		i.mu.Lock()
		defer i.mu.Unlock()
		ok := i.nonces[n]
		delete(i.nonces, n)
		return ok
	}
	mux.HandleFunc("POST "+protocol.PathChallenge, func(w http.ResponseWriter, r *http.Request) {
		var n [32]byte
		rand.Read(n[:])
		i.mu.Lock()
		i.nonces[n] = true
		i.mu.Unlock()
		reply(w, http.StatusOK, protocol.ChallengeResponse{Nonce: n[:]})
	})
	mux.HandleFunc("POST "+protocol.PathSetup, func(w http.ResponseWriter, r *http.Request) {
		var in protocol.SetupRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, protocol.ErrBadRequest)
			return
		}
		q, err := protocol.ParseRequest(in.Request)
		key, kerr := protocol.ParseLicenseKey(in.LicenseKey)
		switch {
		case err != nil || kerr != nil || key.Hash() != q.KeyHash:
			fail(w, protocol.ErrInvalidKey)
			return
		case !useNonce(q.Nonce):
			fail(w, protocol.ErrChallenge)
			return
		}
		lic, code := i.setup(q)
		if code != "" {
			fail(w, code)
			return
		}
		reply(w, http.StatusOK, protocol.SetupResponse{License: lic})
	})
	mux.HandleFunc("POST "+protocol.PathRelease, func(w http.ResponseWriter, r *http.Request) {
		var in protocol.ReleaseRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			fail(w, protocol.ErrBadRequest)
			return
		}
		q, err := protocol.ParseRelease(in.Release)
		if err != nil || !useNonce(q.Nonce) {
			fail(w, protocol.ErrChallenge)
			return
		}
		i.mu.Lock()
		var found *sold
		for _, s := range i.keys {
			if s.id == q.LicenseID && s.seat != nil && s.seat.fingerprint == q.Fingerprint && s.seat.device.Equal(q.DeviceKey) {
				found = s
			}
		}
		if found != nil {
			found.seat = nil
		}
		i.mu.Unlock()
		if found == nil {
			fail(w, protocol.ErrNotSetUp)
			return
		}
		reply(w, http.StatusOK, protocol.ReleaseResponse{Receipt: q.Receipt(i.cert, i.signing)})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// SeatHolder reports the fingerprint hash of the computer a key is set up
// on, or "" if none (for assertions in tests).
func (i *Issuer) SeatHolder(licenseKey string) string {
	k, err := protocol.ParseLicenseKey(licenseKey)
	if err != nil {
		return ""
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if s := i.keys[k.Hash()]; s != nil && s.seat != nil {
		h := sha256.Sum256(s.seat.fingerprint[:])
		return protocol.Base32(h[:5])
	}
	return ""
}
