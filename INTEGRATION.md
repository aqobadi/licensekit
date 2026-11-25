# Integrate LicenseKit into a Go app

LicenseKit lets a Go app enforce product- and computer-bound licenses. The customer enters a short license key once; the app activates online and then works offline. Renewals are short codes typed offline. A computer without internet uses a request file and a `.license` file instead. Staff do everything in License-ZG Manager.

Use Go **1.27.4 or newer**. LicenseKit supports Linux, macOS and Windows and uses only the Go standard library. The core package makes no network calls; only `licensekit/online` and `licensekit/licenseui` use the network, and only when someone activates or deactivates.

## 1. Add the dependency

Use a released version (see the [CHANGELOG](CHANGELOG.md)). From the consuming app's module:

```sh
go get github.com/aqobadi/licensekit@v0.1.1
```

The repository is public, so no token or `GOPRIVATE` setting is needed.

## 2. Set LICENSEKIT_BUILD (once, in your CI, not in code)

The License-ZG Manager shows the value under **Settings → Signing → LICENSEKIT_BUILD**. It holds only
public keys and the activation address, so it isn't secret. The app gets it **when it is built**:

```sh
go build -ldflags "-X github.com/aqobadi/licensekit.build=$LICENSEKIT_BUILD" ./cmd/yourapp
```

Where `LICENSEKIT_BUILD` lives depends on what builds your app. Set it **once** there.

### GitHub Actions

1. In the app's repository: **Settings → Secrets and variables → Actions → Variables → New repository
   variable**. Name `LICENSEKIT_BUILD`, value copied from the Manager. (A *variable*, not a secret: it
   isn't sensitive, and a variable stays readable.)
2. In the workflow that builds the app:

```yaml
      - run: go build -ldflags "-X github.com/aqobadi/licensekit.build=${{ vars.LICENSEKIT_BUILD }}" -o app ./cmd/yourapp
```

If the build already has `-ldflags` (for example a version), add the `-X …` inside the same quotes.

### Docker (any CI, Coolify, Compose)

Pass it as a build argument, never as a runtime `ENV`:

```dockerfile
FROM golang:1.27 AS build
ARG LICENSEKIT_BUILD
WORKDIR /src
COPY . .
RUN test -n "$LICENSEKIT_BUILD" && \
    go build -ldflags "-X github.com/aqobadi/licensekit.build=${LICENSEKIT_BUILD}" -o /out/app ./cmd/yourapp
```

- **GitHub Actions** building the image: `docker build --build-arg LICENSEKIT_BUILD="${{ vars.LICENSEKIT_BUILD }}" .`
  (or `build-args: LICENSEKIT_BUILD=${{ vars.LICENSEKIT_BUILD }}` with `docker/build-push-action`).
- **Coolify:** add the environment variable `LICENSEKIT_BUILD` to the application and tick
  **Available at Buildtime**; Coolify passes it as a build argument.
- **Docker Compose:** `build: { args: { LICENSEKIT_BUILD: ${LICENSEKIT_BUILD} } }`, with the value in the
  build machine's `.env`.

The `test -n` line makes the image build fail if the variable is missing.

### On your computer (local runs and tests)

Set two environment variables in your shell; plain `go run` and `go build` then pick the value up through
Go's own `GOFLAGS`:

```sh
export LICENSEKIT_BUILD='r1:…,r2:…,url=https://activate.example.com'   # value from the Manager
export GOFLAGS="-ldflags=-X=github.com/aqobadi/licensekit.build=$LICENSEKIT_BUILD"

go run ./cmd/yourapp        # licensing is configured
```

On Windows PowerShell:

```powershell
$env:LICENSEKIT_BUILD = 'r1:…,r2:…,url=https://activate.example.com'
$env:GOFLAGS = "-ldflags=-X=github.com/aqobadi/licensekit.build=$env:LICENSEKIT_BUILD"
```

Notes:

- If the project's own command passes `-ldflags` (a Makefile, a script, `go run -ldflags …`), that
  replaces the one in `GOFLAGS`. Add the `-X` there instead, for example in a Makefile:
  `LDFLAGS += -X github.com/aqobadi/licensekit.build=$(LICENSEKIT_BUILD)`; `make` reads the environment.
- Keep the two lines in a git-ignored `.env`/`.envrc` file or your shell profile, not in the repository.
  `go env -w GOFLAGS=…` also works, but applies to every Go project on the machine.
- **Testing against a local Manager:** run it (`license-zg serve --local DIR`, or `make dev` in the
  Manager's repository), create its signing identity, and copy *its* `LICENSEKIT_BUILD`
  (`url=http://127.0.0.1:47820`). Licenses from your production Manager don't work in such a build, and
  the other way round. That is intended.
- **Automated tests** need none of this: `licensekittest` gives each test its own keys and server (§6).
- Setting `LICENSEKIT_BUILD` alone, without `GOFLAGS` or `-ldflags`, changes nothing: the app never reads
  it at run time (see below).

### Checking it

A build without the value still runs, but `Open` returns `NotConfigured` ("This build of the app has no
licensing configuration"), so a missing variable is obvious on the first start.

### Why at build time

Whoever chooses the trusted keys chooses who can make licenses. If an app read `LICENSEKIT_BUILD` when it
**starts**, anyone running the app could set it to their own keys and sign their own licenses. Baked in
at build time, it can only be changed by rebuilding or patching the binary.

## 3. Open the license once

```go
lic, err := licensekit.Open("moro-ai", licensekit.Options{})
```

The first argument is the product's **slug**, shown on the product page in the Manager. Keep the returned `*licensekit.License` for the life of the process; it is safe across goroutines. Handle an `Open` error before using the license: use `errors.As` with `*licensekit.Error` and show its `Message`. A missing activation is not an error; it is `Status().State == licensekit.NotActivated`.

The default storage is per OS user and product. For a server, a container or a shared installation, pass `Options.StateDir` on persistent storage that the service account can write. In a container or an environment without a stable OS identity, also supply a stable, unique `Options.DeviceID` (8–256 bytes), persisted with the state directory and different for each installation. For a local web app, the machine or container running the Go process is the licensed computer.

## 4. Add the License page

For web apps, mount the ready-made page behind the app's administrator authentication:

```go
mux.Handle("/settings/license/", http.StripPrefix("/settings/license",
    requireAdmin(licenseui.Handler(lic, licenseui.Options{Name: "Moro AI", Support: "Email support@example.com"}))))
```

It offers: enter a license key (activates online) or a renewal code (offline) in one box; open a `.license` file; save a request file when there is no internet; and deactivate this computer. It rejects cross-origin form posts, needs no JavaScript and serves its own stylesheet, so it works under a strict Content-Security-Policy. The app's own authentication decides who can open it.

For apps without a web UI, use the same three calls:

| User action | Call |
|---|---|
| Enter a license key or renewal code | `online.Enter(ctx, lic, text)` |
| Open a `.license` file | `lic.Apply(string(contents))` (read at most 64 KiB) |
| No internet: save a request file | `name, content, err := lic.RequestFile(licenseKey)` |
| Move to another computer | `online.Deactivate(ctx, lic)` |

Show `*licensekit.Error.Message` on failure; it says, for example, "There's a typo in group 3." Keep license keys, codes and file contents out of logs.

## 5. Enforce access where work runs

- Check `lic.Status().State == licensekit.Active` for work covered by the license, including background jobs and service endpoints.
- Check `lic.Has("export")` for separately sold features. The keys are listed on the product page.
- Keep the License page, recovery and the user's own data reachable when licensed work is blocked.
- Read `Status()` when needed; it reflects renewals made by another process immediately. Remind the user when `!Perpetual && DaysLeft <= 30`. A fixed expiry is valid through the stated UTC day.

## 6. Test it

`licensekittest` is a throwaway issuer and activation server, so tests need no real keys and no network:

```go
func TestLicensedExport(t *testing.T) {
    iss := licensekittest.New(t, "moro-ai")
    lic := iss.Open(t, licensekit.Options{ServerURL: iss.Server(t)})
    key := iss.NewKey(licensekittest.Terms{Expires: time.Now().AddDate(1, 0, 0), Features: []string{"export"}})
    if err := online.Enter(context.Background(), lic, key); err != nil {
        t.Fatal(err)
    }
    // … exercise the app with lic …
}
```

`iss.Activate(t, lic, terms)` installs a license through a request file; `iss.RenewalCode(key, expires)` makes renewal codes. To test against a real development Manager, call `licensekittest.UseBuildSetting(t, "moro-ai", setting)`.

Before release, check on each target OS or container: activation online, a request-file activation, access after a restart, a renewal code, deactivation and activation on another computer, and the messages for an invalid key. See [SECURITY.md](SECURITY.md) for the limits of offline enforcement.

[CLI example](examples/cli) · [Web example](examples/web) · [SDK API reference](API.md) · [Copy-paste coding-agent prompt](INTEGRATION-PROMPT.md)
