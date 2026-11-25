# LicenseKit

License checks for License-ZG apps (Gozar, Moro AI and future products).
Standard library only, Go 1.27.4+, Linux/macOS/Windows.

Customers type one short key once, online, and the app then works offline:

```text
Vendor sends a license key     47E6-R5Q1-6VC8-KBJT-3YHP-XCK0      the app activates over the internet, once
Vendor sends a renewal code    481D-H145-4JQW-E5FZ-Z5RC-YSQJ      typed in the app, works offline
No internet at setup?          the app saves a request file → the vendor answers with a .license file
Moving to another computer?    "Deactivate this computer" (online), then the same key on the new one
```

For a complete walkthrough, see the [developer integration guide](INTEGRATION.md).
To delegate the implementation, copy the [coding-agent prompt](INTEGRATION-PROMPT.md).

## Quick start

1. Install a pinned release that supports product build values.
   Versions and their changes: [CHANGELOG](CHANGELOG.md).
2. Open licensing for the product identified by the build and mount the ready-made License page:

```go
import (
    "github.com/aqobadi/licensekit"
    "github.com/aqobadi/licensekit/licenseui"
)

lic, err := licensekit.Open("", licensekit.Options{})
if err != nil { /* *licensekit.Error: show err.Message; Kind tells you why */ }

mux.Handle("/settings/license/", http.StripPrefix("/settings/license",
    requireAdmin(licenseui.Handler(lic, licenseui.Options{Name: "Moro AI"}))))

if lic.Status().State != licensekit.Active { /* pause licensed work */ }
if lic.Has("export") { /* a separately sold feature */ }
```

3. Set `LICENSEKIT_BUILD` once in your CI (value from the product page in the Manager), never in code.
   GitHub Actions, Docker and Coolify examples: [INTEGRATION.md §2](INTEGRATION.md#2-set-licensekit_build-once-in-your-ci-not-in-code).
   To run the app on your computer, export it plus `GOFLAGS` and use plain `go run`:

   ```sh
   export LICENSEKIT_BUILD='r1:…,url=…,product=example-app'
   export GOFLAGS="-ldflags=-X=github.com/aqobadi/licensekit.build=$LICENSEKIT_BUILD"
   ```

```sh
go build -ldflags "-X github.com/aqobadi/licensekit.build=$LICENSEKIT_BUILD" ./...
```

That's all. There is no bundle file, no key in your code and no CLI. A build without the setting opens
with `NotConfigured` ("This build of the app has no licensing configuration"), so it can't ship by accident.

## The API

| Call | Use |
|---|---|
| `licensekit.Open("", opts)` | Once at startup; keep the `*License` (safe for concurrent use) |
| `lic.Status()` | `State`, `Expires`, `DaysLeft`, `Perpetual`, `Entitlements`, `CanDeactivate`, `Message` |
| `lic.Has("key")` | A feature is licensed and the license is `Active` |
| `lic.Apply(text)` | A renewal code or `.license` file contents (offline) |
| `lic.RequestFile(licenseKey)` | The request file for a computer without internet |
| `online.Enter(ctx, lic, text)` | What the customer typed: a license key activates online, anything else is `Apply` |
| `online.Deactivate(ctx, lic)` | Give the license back so the key can set up another computer |
| `licenseui.Handler(lic, opts)` | All of the above as a page (no JavaScript; works under a strict CSP) |
| `licensekittest.New(t, "")` | A throwaway issuer and activation server for your tests |

Full contract: [API.md](API.md).

## What your app decides

The SDK reports; your app enforces. Recommended policy:

| `Status().State` | Suggested behavior |
|---|---|
| `Active` | Full access. If `!Perpetual && DaysLeft <= 30`, show a renewal reminder (the License page does). |
| `NotActivated` | Point an administrator to the License page. |
| `Expired` | Block licensed work; keep the user's data readable and exportable. A renewal code restores it. |
| `WrongDevice` | The saved license belongs to another computer: activate this one with the license key. |
| `ClockProblem` | Ask the user to correct the date and time. |
| `Invalid` | The build no longer trusts the saved license: activate again with the license key. |

## Where the license is stored

Per user by default (`~/.local/share`, `~/Library/Application Support`, `%LOCALAPPDATA%` under
`licensekit/<slug>`). Servers and installers pass `Options.StateDir`. The directory holds the license, the
latest renewal code, this installation's device key and the clock check.

## Containers and servers

Inside Linux containers the SDK refuses the image's machine-id (every container from the image would share
it) and `Open` returns `DeviceUnavailable`. Supply `Options.DeviceID`: a stable, unique value per installation
(8–256 bytes), for example a random ID stored in a mounted volume, and keep `StateDir` on the same volume.
Anyone who copies that value and the state can reuse the license; that is the trade-off of containers.

## The activation server address

The build setting includes the Manager's activation address. It can change without a new build:
`Options.ServerURL` or the `LICENSEKIT_SERVER_URL` environment variable override it. That is safe: a wrong
or fake server can only fail, never produce a license this build accepts.

## Honest limits

LicenseKit stops sharing and tampering short of patching your binary: licenses are Ed25519-signed by a key
your roots certify, for this product and this computer; saved state is re-verified on every start; renewal
codes work only on the computer they were made for; a clock set back by more than 48 hours, or before the
license was issued, is flagged. Offline software can't stop someone who patches the binary, keeps the clock
frozen before the expiry, or clones a whole disk or VM. A computer that never goes online again keeps its
license until its current expiry, even if it was released or the license canceled; it can't be renewed.
See [SECURITY.md](SECURITY.md).

## Protocol

The formats are specified independently of Go in [PROTOCOL.md](PROTOCOL.md),
with test vectors and an independent Python verifier (`spec/verify.py`).
