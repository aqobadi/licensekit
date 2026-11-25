// Package online activates and deactivates a licensekit license through the
// License-ZG activation API. It is the only SDK package that uses the
// network, and only when the customer enters a license key or deactivates.
// After setup the app works offline; renewals are typed codes.
package online

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/aqobadi/licensekit"
	"github.com/aqobadi/licensekit/internal/bridge"
	"github.com/aqobadi/licensekit/protocol"
)

// maxWork caps the proof-of-work a server may ask for (about a second).
const maxWork = 24

var client = &http.Client{Timeout: 30 * time.Second}

// userAgent names the LicenseKit release the app was built with, e.g.
// "licensekit/v0.1.0", from Go's build information.
var userAgent = func() string {
	v := "devel"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/aqobadi/licensekit" && d.Version != "" && d.Version != "(devel)" {
				v = d.Version
			}
		}
	}
	return "licensekit/" + v
}()

// Enter handles whatever a customer types or pastes on the License page: a
// license key activates online; a renewal code or license file is applied
// offline. It returns nil on success or a *licensekit.Error.
func Enter(ctx context.Context, lic *licensekit.License, input string) error {
	if c, err := protocol.ParseCode(input); err == nil && c.Key != nil {
		return Activate(ctx, lic, input)
	}
	return lic.Apply(input)
}

// Activate sets up this computer with a license key: it fetches a signed
// license from the activation server and saves it.
func Activate(ctx context.Context, lic *licensekit.License, licenseKey string) error {
	key, err := protocol.ParseLicenseKey(licenseKey)
	if err != nil {
		return lic.Apply(licenseKey) // reports the typo or format problem
	}
	ops := bridge.Of(lic)
	nonce, counter, err := challenge(ctx, ops)
	if err != nil {
		return err
	}
	req, err := ops.SetupRequest(key, nonce)
	if err != nil {
		return err
	}
	var out protocol.SetupResponse
	if err := post(ctx, ops, protocol.PathSetup, protocol.SetupRequest{LicenseKey: key.String(), Request: req, Counter: counter}, &out); err != nil {
		return err
	}
	return ops.Install(out.License)
}

// Deactivate gives this computer's license back so the license key can set
// up another computer. It removes the local license only after the server
// confirms with a signed receipt.
func Deactivate(ctx context.Context, lic *licensekit.License) error {
	ops := bridge.Of(lic)
	nonce, counter, err := challenge(ctx, ops)
	if err != nil {
		return err
	}
	rel, data, err := ops.Release(nonce)
	if err != nil {
		return err
	}
	var out protocol.ReleaseResponse
	if err := post(ctx, ops, protocol.PathRelease, protocol.ReleaseRequest{Release: data, Counter: counter}, &out); err != nil {
		return err
	}
	return ops.Released(rel, out.Receipt)
}

// challenge fetches a nonce and does the proof of work it asks for.
func challenge(ctx context.Context, ops bridge.Ops) ([32]byte, uint64, error) {
	var nonce [32]byte
	var ch protocol.ChallengeResponse
	if err := post(ctx, ops, protocol.PathChallenge, struct{}{}, &ch); err != nil {
		return nonce, 0, err
	}
	if len(ch.Nonce) != 32 || ch.Work < 0 || ch.Work > maxWork {
		return nonce, 0, licensekit.NewError(licensekit.ServerUnavailable, errors.New("malformed challenge"))
	}
	copy(nonce[:], ch.Nonce)
	var counter uint64
	for ch.Work > 0 && protocol.WorkBits(nonce, counter) < ch.Work {
		if counter%4096 == 0 && ctx.Err() != nil {
			return nonce, 0, licensekit.NewError(licensekit.Offline, ctx.Err())
		}
		counter++
	}
	return nonce, counter, nil
}

var errorKinds = map[string]licensekit.Kind{
	protocol.ErrInvalidKey:     licensekit.KeyNotValid,
	protocol.ErrInUse:          licensekit.KeyInUse,
	protocol.ErrMovesExhausted: licensekit.MovesExhausted,
	protocol.ErrExpired:        licensekit.LicenseExpired,
	protocol.ErrCanceled:       licensekit.LicenseCanceled,
	protocol.ErrNotSetUp:       licensekit.NotDeactivatable,
	protocol.ErrRateLimited:    licensekit.RateLimited,
}

func post(ctx context.Context, ops bridge.Ops, path string, in, out any) error {
	if ops.ServerURL == "" {
		e := licensekit.NewError(licensekit.Offline, errors.New("no activation server configured"))
		e.Message = "Online activation isn't available for this app. Save a request file and send it to us."
		return e
	}
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ops.ServerURL+path, bytes.NewReader(body))
	if err != nil {
		return licensekit.NewError(licensekit.Offline, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent+" ("+ops.Product+")")
	resp, err := client.Do(req)
	if err != nil {
		return licensekit.NewError(licensekit.Offline, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return licensekit.NewError(licensekit.Offline, err)
	}
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(data, out); err != nil {
			return licensekit.NewError(licensekit.ServerUnavailable, err)
		}
		return nil
	}
	var apiErr protocol.APIError
	json.Unmarshal(data, &apiErr)
	if k, ok := errorKinds[apiErr.Code]; ok {
		return licensekit.NewError(k, errors.New(apiErr.Code))
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return licensekit.NewError(licensekit.RateLimited, nil)
	}
	return licensekit.NewError(licensekit.ServerUnavailable, errors.New(resp.Status+" "+apiErr.Code))
}
