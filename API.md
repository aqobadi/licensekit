# LicenseKit SDK API

Module `github.com/aqobadi/licensekit`, Go 1.27.4+, standard library only.

| Package | Network | Purpose |
|---|---|---|
| `licensekit` | **None** (`make offline-check`) | Open, status, features, renewal codes, license files, request files |
| `licensekit/online` | `net/http`, only on activate/deactivate | Online setup with a license key; deactivation |
| `licenseui` | `net/http` server side | The drop-in License page |
| `licensekittest` | test only | Throwaway issuer and activation server |
| `protocol` | None | The formats in [PROTOCOL.md](PROTOCOL.md) |

## 1. Core API

```go
package licensekit

// Open prepares licensing and re-verifies any saved license. Pass an empty
// product to use the product from the build setting. An explicit slug must
// match if the build setting includes one. It fails only for build, developer or
// environment problems: NotConfigured, BadProduct, DeviceUnavailable, StorageFailed.
func Open(product string, opts Options) (*License, error)

type Options struct {
    StateDir  string // default: per-user app data dir /licensekit/<product>
    DeviceID  string // 8–256 bytes; containers and servers without a stable OS identity
    ServerURL string // overrides the build's activation address (also LICENSEKIT_SERVER_URL)
}

func (l *License) Status() Status
func (l *License) Has(feature string) bool                     // Active and the feature is licensed
func (l *License) Apply(input string) error                     // renewal code or .license file contents
func (l *License) RequestFile(licenseKey string) (name string, content []byte, err error)

type Status struct {
    State         State     // NotActivated, Active, Expired, WrongDevice, ClockProblem, Invalid
    LicenseID     string    // "B8Y92"
    DeviceSource  string    // "os" or "app"
    Expires       time.Time // last valid day, UTC midnight; zero if perpetual or none
    Perpetual     bool
    DaysLeft      int
    Entitlements  []string  // sorted; empty unless Active
    CanDeactivate bool      // this installation holds the license's device key
    Message       string    // customer-safe English
}

type Error struct { Kind Kind; Group int; Message string }
```

The trusted roots come only from the build:
`-ldflags "-X github.com/aqobadi/licensekit.build=<build setting>"`. The variable is
unexported; nothing at run time can change it.

`Kind` values: input (`Empty`, `BadCharacter`, `Incomplete`, `TooLong`, `Typo`, `UnsupportedFormat`,
`WrongKind`), licenses and renewals (`InvalidLicense`, `OtherComputer`, `WrongRenewal`,
`NeedsActivation`, `AlreadyApplied`, `AlreadyExpired`, `ClockWrong`, `StorageFailed`, `NeedsOnline`),
online (`Offline`, `KeyNotValid`, `KeyInUse`, `MovesExhausted`, `LicenseExpired`, `LicenseCanceled`,
`NotDeactivatable`, `RateLimited`, `ServerUnavailable`) and `Open` only (`NotConfigured`,
`BadProduct`, `DeviceUnavailable`). Every kind has a default customer-safe message.

## 2. Behavior

| Call | Behavior |
|---|---|
| `Open` | Derives the product ID and fingerprint ([PROTOCOL §3](PROTOCOL.md)), resolves the server address, creates a missing state directory (0700) without changing an existing one's mode, and loads the saved license, renewal and clock without trusting them. Never writes a license. |
| `Status` | Re-reads the saved files when their content changed (other processes), re-verifies, re-checks the clock and expiry. Never fails. |
| `Apply` | A `.license` file: verified (§6.3), refused if already expired, saved atomically; a saved renewal stays applied only if it belongs to the new license's chain. A renewal code: needs an installed license and must extend it (`AlreadyApplied` otherwise). A license key: `NeedsOnline`. A request file: `WrongKind`. Failed input never changes saved state. |
| `RequestFile` | Signs a request with the device key (created on first use) and a zero nonce. It carries the key's hash, never the key. The SDK does not save it. |
| `online.Enter` | A license key → `online.Activate`; anything else → `Apply`. |
| `online.Activate` | Challenge (and proof of work if asked, at most 24 bits) → signed request → license → `Apply`. Network failure: `Offline`. |
| `online.Deactivate` | Challenge → signed release → receipt verified against the build's roots → deletes the license and renewal. |

## 3. licenseui

`licenseui.Handler(lic, licenseui.Options{Name, Support}) http.Handler` serves `GET /`, `POST /`
(actions `enter`, `file`, `request`, `deactivate`) and `GET /licenseui.css`. Mount it with
`http.StripPrefix` behind the app's admin authentication. It wraps itself in
`http.CrossOriginProtection`, limits uploads to 64 KiB, uses no JavaScript and no inline styles.

## 4. licensekittest

```go
iss := licensekittest.New(t, "")            // trust a throwaway root for this product in this test
lic := iss.Open(t, licensekit.Options{ServerURL: iss.Server(t)})
key := iss.NewKey(licensekittest.Terms{Expires: t1, Features: []string{"export"}})
iss.Activate(t, lic, terms)                          // via a request file
code, _ := iss.RenewalCode(key, t2)
licensekittest.UseBuildSetting(t, "", setting) // trust a real development Manager instead
```

It panics outside `go test`. Tests that use the same product must not run in parallel.

## 5. Example: command-line app

See [`examples/cli`](examples/cli/main.go): `activate KEY`, `apply CODE|FILE`,
`request KEY FILE`, `deactivate`, and the status otherwise.
