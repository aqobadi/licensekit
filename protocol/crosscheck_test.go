package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// TestIndependentCrossCheck signs random licenses and renewal codes and
// verifies them with the independent Python verifier, written only from the
// spec.
func TestIndependentCrossCheck(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	const n = 300
	var in strings.Builder
	enc := json.NewEncoder(&in)
	features := []string{"export", "sync", "reports", "api", "a", "z9_-"}
	for i := 0; i < n; i++ {
		_, root, _ := ed25519.GenerateKey(rand.Reader)
		_, signing, _ := ed25519.GenerateKey(rand.Reader)
		_, device, _ := ed25519.GenerateKey(rand.Reader)
		rootNum := uint8(mrand.IntN(255) + 1)
		cert := &Cert{KeyNumber: uint16(mrand.IntN(65535) + 1), PublicKey: signing.Public().(ed25519.PublicKey), CreatedDay: uint16(mrand.IntN(65536))}
		cert.Sign(rootNum, root)
		slug := fmt.Sprintf("app-%d", i)
		pid, _ := ProductID(slug)
		var fp [15]byte
		var seed [32]byte
		rand.Read(fp[:])
		rand.Read(seed[:])
		base := uint16(mrand.IntN(30000))
		l := &License{ProductID: pid, Fingerprint: fp, Source: SourceApp, DeviceKey: device.Public().(ed25519.PublicKey),
			ID: uint32(mrand.IntN(MaxLicenseID) + 1), IssuedDay: base, ExpiryDay: base + uint16(mrand.IntN(400)),
			ChainBase: base, ChainLength: ChainLength(base)}
		for _, f := range features {
			if mrand.IntN(2) == 0 {
				l.Entitlements = append(l.Entitlements, f)
			}
		}
		l.Lock = l.Chain().Lock(seed, l.ChainLength)
		data, err := l.Sign(cert, signing)
		if err != nil {
			t.Fatal(err)
		}
		step := uint16(mrand.IntN(int(l.ChainLength)) + 1)
		r := Renewal{Step: step, Value: l.Chain().Value(seed, l.ChainLength, step)}
		trust := &Trust{Roots: map[uint8]ed25519.PublicKey{rootNum: root.Public().(ed25519.PublicKey)}}
		ents := append([]string{}, l.Entitlements...)
		sort.Strings(ents)
		enc.Encode(map[string]any{"trust": trust.String(), "product": slug, "fingerprint": hex.EncodeToString(fp[:]),
			"license": hex.EncodeToString(data), "renewal": r.String(), "expiry": l.Expiry(step), "entitlements": ents})
	}
	cmd := exec.Command(py, "-I", "../spec/verify.py", "check")
	cmd.Stdin = strings.NewReader(in.String())
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), fmt.Sprintf("%d licenses ok", n)) {
		t.Fatalf("independent verifier: %v\n%s", err, out)
	}
}
