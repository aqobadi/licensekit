# Integrate LicenseKit into a Go app

LicenseKit lets a Go app enforce product- and computer-bound licenses. The customer enters a short license key once; the app activates online and then works offline. Renewals are short codes typed offline. A computer without internet uses a request file and a `.license` file instead. Staff do everything in License-ZG Manager.

Use Go **1.27.4 or newer**. LicenseKit supports Linux, macOS and Windows and uses only the Go standard library. The core package makes no network calls; only `licensekit/online` and `licensekit/licenseui` use the network, and only when someone activates or deactivates.

## 1. Add the dependency

Use a released version (see the [CHANGELOG](CHANGELOG.md)). From the consuming app's module:

```sh
go get github.com/aqobadi/licensekit@v0.1.1
```

The repository is public, so no token or `GOPRIVATE` setting is needed.

## 2. Set the build setting (once, outside the code)

In the Manager, an admin opens **Settings → Signing → App build setting** and copies the value. It holds only public keys and the activation address, so it is safe in CI settings and Dockerfiles. Every build of the app passes it to the linker:

```sh
# CI variable or .env for builds:
LICENSEKIT_BUILD='r1:4435…5d19,r2:9a1f…88e0,url=https://activate.example.com'

go build -ldflags "-X github.com/aqobadi/licensekit.build=$LICENSEKIT_BUILD" ./cmd/yourapp
```

If the build already uses `-ldflags` (for example for a version), add the `-X` to the same `-ldflags` string. In a Dockerfile, pass it as a build argument. Without the setting, `Open` returns `NotConfigured` and the app shows "This build of the app has no licensing configuration", so a misconfigured build is obvious.

Why the build, and not a runtime environment variable or a file: whoever chooses the trusted keys chooses who can make licenses. A customer who could set them would trust their own key and sign their own license. Only the binary you build and ship is out of their reach.

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
