package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// Spec §13 test vectors: development keys that never sign real licenses.
func seed(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

var (
	vecRoot    = ed25519.NewKeyFromSeed(seed("zurvan test root 1"))
	vecSigning = ed25519.NewKeyFromSeed(seed("zurvan test signing key 1"))
	vecDevice  = ed25519.NewKeyFromSeed(seed("zurvan test device"))
	vecMachine = []byte("0123456789abcdef0123456789abcdef")
	vecChain   = func() (s [32]byte) { copy(s[:], seed("zurvan test chain seed")); return }()
	vecKey     = func() (k LicenseKey) { copy(k[:], seed("zurvan test license key")); return }()
)

const (
	vecProduct  = "b0c28bfd19208068fca6a422351a8327"
	vecFP       = "908ec2f8d6b1c098cd88f3b3b9b4ae"
	vecKeyText  = "47E6-R5Q1-6VC8-KBJT-3YHP-XCK0"
	vecKeyHash  = "0fae3a48032b7f19f2e275ab31a25197fc123af7c4363efed66e5ed8b8f41f4c"
	vecCert     = "41000114e7414e5a1f5a65fab8a778f212d0b90b4d02d90b084b5f05c2236e3c2f177009d80101936885a2d9d82f68f1ed4b3a57d2b167060b1eddebffb8fb439be9bba4efe75635538a89de92ad2282a57fc3191075ec137576400e2320cb6d34e52b4f3e0a02"
	vecLock     = "a65587dd3e3cadc7b1a4"
	vecLicense  = "31b0c28bfd19208068fca6a422351a8327908ec2f8d6b1c098cd88f3b3b9b4ae018114065e613f6976cb6647e4515c69de07452a4e798ae120c076c61672e4ef7c5a3c9109d80b4309d84756a65587dd3e3cadc7b1a402066578706f72740473796e631742aa0f9ab80f0550d301d82764ae3939f88678c5d17d201d1475111b295b283bcfe6f4d0d9b4c12b346f80b7564b47a0d6e7233a7128f9913c55dc27c76a0f006741000114e7414e5a1f5a65fab8a778f212d0b90b4d02d90b084b5f05c2236e3c2f177009d80101936885a2d9d82f68f1ed4b3a57d2b167060b1eddebffb8fb439be9bba4efe75635538a89de92ad2282a57fc3191075ec137576400e2320cb6d34e52b4f3e0a02"
	vecRenewal  = "481D-H145-4JQW-E5FZ-Z5RC-YSQJ"
	vecRequest  = "51b0c28bfd19208068fca6a422351a8327908ec2f8d6b1c098cd88f3b3b9b4ae018114065e613f6976cb6647e4515c69de07452a4e798ae120c076c61672e4ef7c0fae3a48032b7f19f2e275ab31a25197fc123af7c4363efed66e5ed8b8f41f4c0000000000000000000000000000000000000000000000000000000000000000000000006afd86c0bebe9e76dda44c5f876dcd316f72634dfb6ac1287d981ff72a2e8ec700372981903371fe92b3f78bd112900348b270a9816b0004e5da238f1f079ad04685a301"
	vecTrust    = "r1:951a9e4c7e3defb28c5ee9033f60866b8ab55e7a7656917b626db610551e2ff5"
	vecRenewDay = 2883 + 365
)

func kindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return 0
}

func vecTrustT(t testing.TB) *Trust {
	t.Helper()
	tr, err := ParseTrust(vecTrust)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func vecIDs(t testing.TB) ([16]byte, [15]byte) {
	t.Helper()
	pid, err := ProductID("example-app")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Fingerprint(pid, SourceOS, vecMachine)
	if err != nil {
		t.Fatal(err)
	}
	return pid, fp
}

func vecCertT() *Cert {
	c := &Cert{KeyNumber: 1, PublicKey: vecSigning.Public().(ed25519.PublicKey), CreatedDay: 2520}
	c.Sign(1, vecRoot)
	return c
}

func vecLicenseT(t testing.TB) *License {
	pid, fp := vecIDs(t)
	l := &License{ProductID: pid, Fingerprint: fp, Source: SourceOS, DeviceKey: vecDevice.Public().(ed25519.PublicKey), ID: 0x5a3c91,
		IssuedDay: 2520, ExpiryDay: 2883, ChainBase: 2520, ChainLength: ChainLength(2520), Entitlements: []string{"sync", "export"}}
	l.Lock = l.Chain().Lock(vecChain, l.ChainLength)
	return l
}

func TestSpecVectors(t *testing.T) {
	pid, fp := vecIDs(t)
	check := func(name, got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
	}
	check("product", hex.EncodeToString(pid[:]), vecProduct)
	check("fingerprint", hex.EncodeToString(fp[:]), vecFP)
	check("license key", vecKey.String(), vecKeyText)
	h := vecKey.Hash()
	check("key hash", hex.EncodeToString(h[:]), vecKeyHash)
	check("cert", hex.EncodeToString(vecCertT().Marshal()), vecCert)
	l := vecLicenseT(t)
	check("lock", hex.EncodeToString(l.Lock[:]), vecLock)
	lb, err := l.Sign(vecCertT(), vecSigning)
	if err != nil {
		t.Fatal(err)
	}
	check("license", hex.EncodeToString(lb), vecLicense)
	step := uint16(vecRenewDay - 2520)
	r := Renewal{Step: step, Value: l.Chain().Value(vecChain, l.ChainLength, step)}
	check("renewal", r.String(), vecRenewal)
	q := &Request{ProductID: pid, Fingerprint: fp, Source: SourceOS, DeviceKey: vecDevice.Public().(ed25519.PublicKey), KeyHash: vecKey.Hash(), Created: 1795000000}
	qb, _ := q.Sign(vecDevice)
	check("request", hex.EncodeToString(qb), vecRequest)
	check("trust", vecTrustT(t).String(), vecTrust)

	// The device side of the vectors.
	data, _ := hex.DecodeString(vecLicense)
	got, err := Verify(vecTrustT(t), data, pid, fp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Entitlements, ",") != "export,sync" || got.Expiry(0) != 2883 {
		t.Fatalf("%+v", got)
	}
	c, err := ParseCode(strings.ToLower(strings.ReplaceAll(vecRenewal, "-", " ")))
	if err != nil || c.Renewal == nil || !got.CheckRenewal(*c.Renewal) || got.Expiry(c.Renewal.Step) != vecRenewDay {
		t.Fatalf("renewal: %v %+v", err, c)
	}
	k, err := ParseLicenseKey(vecKeyText)
	if err != nil || k != vecKey {
		t.Fatalf("key: %v", err)
	}
}

func TestCodeErrors(t *testing.T) {
	cases := []struct {
		in    string
		kind  Kind
		group int
	}{
		{"", Empty, 0},
		{"  -  ", Empty, 0},
		{"47E6-R5Q1-6VC8", Incomplete, 0},
		{vecKeyText + "-0000", TooLong, 0},
		{"47E6-R5Q1-6VU8-KBJT-3YHP-XCK0", BadCharacter, 3},
		{"47E6-R5Q1-6VC8-KBJT-3YHP-XCK1", Typo, 6},
		{"47E6-R5Q1-6VC8-KBJT-4YHP-XCK0", Typo, 5},
	}
	for _, c := range cases {
		_, err := ParseCode(c.in)
		var e *Error
		if !errors.As(err, &e) || e.Kind != c.kind || e.Group != c.group {
			t.Errorf("%q: got %+v, want %v group %d", c.in, err, c.kind, c.group)
		}
	}
	// Every single-character typo is detected, and its group named.
	norm, _ := Normalize(vecRenewal)
	located := 0
	for i := range norm {
		for _, r := range Alphabet {
			if byte(r) == norm[i] {
				continue
			}
			bad := norm[:i] + string(r) + norm[i+1:]
			_, err := ParseCode(bad)
			var e *Error
			if !errors.As(err, &e) || e.Kind != Typo {
				t.Fatalf("typo at %d not detected: %v", i, err)
			}
			if e.Group == i/4+1 {
				located++
			} else if e.Group != 0 {
				t.Fatalf("typo at %d located in group %d", i, e.Group)
			}
		}
	}
	if located < 24*31*9/10 {
		t.Fatalf("only %d of %d typos located", located, 24*31)
	}
	// Separators, case, O/I/L and comment lines are accepted.
	if _, err := ParseCode("# from the vendor\n\u2003" + strings.ToLower(vecKeyText) + "\u2011\n"); err != nil {
		t.Fatal(err)
	}
	// An unknown format byte with a valid CRC.
	b := appendCRC(append([]byte{0x23}, make([]byte, 12)...))
	if _, err := ParseCode(encode(b)); kindOf(err) != UnsupportedFormat {
		t.Fatalf("got %v", err)
	}
	// A renewal code is not a license key.
	if _, err := ParseLicenseKey(vecRenewal); kindOf(err) != UnsupportedFormat {
		t.Fatalf("got %v", err)
	}
}

func TestLicenseRejections(t *testing.T) {
	pid, fp := vecIDs(t)
	tr := vecTrustT(t)
	data, _ := hex.DecodeString(vecLicense)
	other, _ := ProductID("other-app")
	if _, err := Verify(tr, data, other, fp); kindOf(err) != WrongProduct {
		t.Errorf("wrong product: %v", err)
	}
	fp2 := fp
	fp2[0] ^= 1
	if _, err := Verify(tr, data, pid, fp2); kindOf(err) != WrongDevice {
		t.Errorf("wrong device: %v", err)
	}
	// Every flipped bit in the signed part or the certificate is rejected.
	for i := range data {
		for bit := 0; bit < 8; bit++ {
			bad := bytes.Clone(data)
			bad[i] ^= 1 << bit
			if _, err := Verify(tr, bad, pid, fp); err == nil {
				t.Fatalf("byte %d bit %d accepted", i, bit)
			}
		}
	}
	if _, err := Verify(tr, data[:len(data)-1], pid, fp); err == nil {
		t.Fatal("truncated license accepted")
	}
	if _, err := Verify(tr, append(bytes.Clone(data), 0), pid, fp); err == nil {
		t.Fatal("trailing byte accepted")
	}
	// An untrusted root, a distrusted signing key, and a key signed by nobody trusted.
	other1, _ := ParseTrust("r2:" + vecTrust[3:])
	if _, err := Verify(other1, data, pid, fp); kindOf(err) != Untrusted {
		t.Errorf("other root number: %v", err)
	}
	dis, _ := ParseTrust(vecTrust + ",-s1")
	if _, err := Verify(dis, data, pid, fp); kindOf(err) != Untrusted {
		t.Errorf("distrusted key: %v", err)
	}
	_, rogue, _ := ed25519.GenerateKey(nil)
	c := &Cert{KeyNumber: 1, PublicKey: rogue.Public().(ed25519.PublicKey), CreatedDay: 1}
	c.Sign(1, rogue)
	l := vecLicenseT(t)
	rb, err := l.Sign(c, rogue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tr, rb, pid, fp); kindOf(err) != Untrusted {
		t.Errorf("self-signed cert: %v", err)
	}
	// Signing refuses a key that does not match its certificate.
	if _, err := vecLicenseT(t).Sign(vecCertT(), rogue); err == nil {
		t.Error("mismatched key signed")
	}
}

func TestRenewalChain(t *testing.T) {
	l := vecLicenseT(t)
	ch := l.Chain()
	for _, k := range []uint16{1, 2, 363, 18261, 18262} {
		v := ch.Value(vecChain, l.ChainLength, k)
		if !l.CheckRenewal(Renewal{Step: k, Value: v}) {
			t.Fatalf("step %d rejected", k)
		}
		v[0] ^= 1
		if l.CheckRenewal(Renewal{Step: k, Value: v}) {
			t.Fatalf("altered step %d accepted", k)
		}
	}
	v := ch.Value(vecChain, l.ChainLength, 100)
	if l.CheckRenewal(Renewal{Step: 101, Value: v}) || l.CheckRenewal(Renewal{Step: 99, Value: v}) {
		t.Fatal("value accepted at another step")
	}
	if l.CheckRenewal(Renewal{Step: l.ChainLength + 1, Value: v}) {
		t.Fatal("step beyond the chain accepted")
	}
	other := l.Chain()
	other.LicenseID++
	if other.Check(l.Lock, l.ChainLength, 100, v) {
		t.Fatal("value accepted for another license")
	}
	if l.Expiry(10) != 2883 || l.Expiry(400) != 2920 {
		t.Fatalf("expiry %d %d", l.Expiry(10), l.Expiry(400))
	}
	if ChainLength(60000) != 5535 || ChainLength(100) != ChainDays {
		t.Fatal("chain length")
	}
}

func TestPerpetualLicense(t *testing.T) {
	pid, fp := vecIDs(t)
	l := &License{ProductID: pid, Fingerprint: fp, Source: SourceApp, DeviceKey: vecDevice.Public().(ed25519.PublicKey), ID: 7, IssuedDay: 2520}
	b, err := l.Sign(vecCertT(), vecSigning)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(vecTrustT(t), b, pid, fp)
	if err != nil || got.Expiry(0) != 0 || got.CheckRenewal(Renewal{Step: 1}) {
		t.Fatalf("%v %+v", err, got)
	}
	// A perpetual license cannot carry a chain, and a dated one needs one.
	l.ChainLength = 5
	if _, err := l.Sign(vecCertT(), vecSigning); err == nil {
		t.Fatal("perpetual license with a chain signed")
	}
}

func TestRequestAndRelease(t *testing.T) {
	data, _ := hex.DecodeString(vecRequest)
	q, err := ParseRequest(data)
	if err != nil || q.KeyHash != vecKey.Hash() || q.Created != 1795000000 {
		t.Fatalf("%v %+v", err, q)
	}
	for i := range data {
		bad := bytes.Clone(data)
		bad[i] ^= 0x40
		if _, err := ParseRequest(bad); err == nil {
			t.Fatalf("byte %d accepted", i)
		}
	}
	pid, fp := vecIDs(t)
	rel := &Release{ProductID: pid, Fingerprint: fp, LicenseID: 0x5a3c91, DeviceKey: vecDevice.Public().(ed25519.PublicKey)}
	rel.Nonce[0] = 9
	rb, err := rel.Sign(vecDevice)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRelease(rb)
	if err != nil || got.LicenseID != rel.LicenseID || got.Nonce != rel.Nonce {
		t.Fatalf("%v %+v", err, got)
	}
	receipt := got.Receipt(vecCertT(), vecSigning)
	if err := rel.CheckReceipt(vecTrustT(t), receipt); err != nil {
		t.Fatal(err)
	}
	rel.Nonce[0] = 8
	if err := rel.CheckReceipt(vecTrustT(t), receipt); err == nil {
		t.Fatal("receipt for another nonce accepted")
	}
	if _, err := (&Request{DeviceKey: vecDevice.Public().(ed25519.PublicKey)}).Sign(vecSigning); err == nil {
		t.Fatal("request signed with a key it does not name")
	}
}

func TestTrustParsing(t *testing.T) {
	good := vecTrust + ",r2:" + strings.Repeat("ab", 32) + ",-s3,-s1,url=https://activate.example.com/,product=example-app"
	tr, err := ParseTrust(" " + strings.ReplaceAll(good, ",", " , ") + " ")
	if err != nil {
		t.Fatal(err)
	}
	if tr.ServerURL != "https://activate.example.com" || tr.Product != "example-app" || !tr.Distrusted[3] || len(tr.Roots) != 2 {
		t.Fatalf("%+v", tr)
	}
	if again, _ := ParseTrust(tr.String()); again.String() != tr.String() {
		t.Fatal("canonical form does not round-trip")
	}
	for _, bad := range []string{"", "-s1", "r1:abcd", "r0:" + strings.Repeat("ab", 32), "r1:" + strings.Repeat("AB", 32),
		vecTrust + "," + vecTrust, "x1", vecTrust + ",url=http://example.com", vecTrust + ",-s0",
		vecTrust + ",product=", vecTrust + ",product=Example App", vecTrust + ",product=example-app,product=other-app",
		vecTrust + ",r2:" + strings.Repeat("ab", 32) + ",r3:" + strings.Repeat("ac", 32) + ",r4:" + strings.Repeat("ad", 32) + ",r5:" + strings.Repeat("ae", 32)} {
		if _, err := ParseTrust(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, ok := range []string{"https://a.example.com", "https://a.example.com:8443/base", "http://localhost:47820", "http://127.0.0.1", "http://[::1]:80"} {
		if err := CheckServerURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ftp://a", "http://example.com", "https://", "https://a?b", "https://u@a", "https://a b", "http://localhost.evil.com"} {
		if err := CheckServerURL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestArmorAndWork(t *testing.T) {
	data := bytes.Repeat([]byte{1, 2, 3}, 100)
	text := string(Armor(LabelLicense, []string{"Example  App\nlicense"}, data))
	if !strings.HasPrefix(text, "# Example App license\n") || !IsArmored(text, LabelLicense) || IsArmored(text, LabelRequest) {
		t.Fatal(text)
	}
	got, err := Unarmor("pasted:\r\n"+strings.ReplaceAll(text, "\n", "\r\n  "), LabelLicense)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("%v", err)
	}
	if _, err := Unarmor(text, LabelRequest); err == nil {
		t.Fatal("wrong label accepted")
	}
	if _, err := Unarmor(strings.Replace(text, "AQID", "AQI*", 1), LabelLicense); err == nil {
		t.Fatal("bad base64 accepted")
	}
	var nonce [32]byte
	n := uint64(0)
	for WorkBits(nonce, n) < 8 {
		n++
	}
	if WorkBits(nonce, n) < 8 {
		t.Fatal("work")
	}
}

func TestSlugsAndDays(t *testing.T) {
	for _, s := range []string{"gozar", "moro-ai", "app2"} {
		if !ValidSlug(s) {
			t.Errorf("%s rejected", s)
		}
	}
	for _, s := range []string{"", "ab", "Gozar", "2app", "moro-", "moro_ai", strings.Repeat("a", 41)} {
		if ValidSlug(s) {
			t.Errorf("%q accepted", s)
		}
	}
	d := func(s string) int64 { tm, _ := time.Parse("2006-01-02", s); return DayOf(tm) }
	for _, c := range [][3]string{{"2026-01-31", "1", "2026-02-28"}, {"2026-01-15", "12", "2027-01-14"}, {"2024-02-29", "12", "2025-02-28"}} {
		m := map[string]int{"1": 1, "12": 12}[c[1]]
		if got := Date(ExpiryDay(d(c[0]), m)).Format("2006-01-02"); got != c[2] {
			t.Errorf("%v: %s", c, got)
		}
	}
	if _, ok := Today(EpochUnix - 1); ok {
		t.Fatal("before epoch")
	}
}

func FuzzParse(f *testing.F) {
	lic, _ := hex.DecodeString(vecLicense)
	req, _ := hex.DecodeString(vecRequest)
	f.Add(lic)
	f.Add(req)
	f.Add([]byte(vecRenewal))
	f.Add(Armor(LabelLicense, nil, lic))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseCode(string(b))
		ParseLicense(b)
		ParseRequest(b)
		ParseRelease(b)
		ParseCert(b)
		Unarmor(string(b), LabelLicense)
		ParseTrust(string(b))
	})
}
