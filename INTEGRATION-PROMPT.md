# Coding-agent prompt for a LicenseKit integration

Copy the block into your coding agent in the consuming app's repository. Fill in what you know; the agent infers routine choices from the app and flags anything that needs an owner decision.

```text
Integrate License-ZG LicenseKit into this Go application and verify it through the app's normal entry points.

Project details
- LicenseKit version (a release with product build values):
- Features to protect and their keys (leave empty if the license grants the whole app):
- Target environments (native OS, local web app, container, or server):
- Product policy for access to existing data when licensed work is unavailable:
- What customers see for support (leave empty for "contact us"):

Read README.md, INTEGRATION.md and API.md in the public repository
github.com/aqobadi/licensekit at that version, and use the SDK source and examples as the
reference. Inspect this application's layout, Go toolchain, build scripts, Dockerfile, startup, UI,
background jobs and tests before choosing integration points.

The app needs only the SDK. There is no bundle file to embed, no key to put in code, and no CLI.
1. go get github.com/aqobadi/licensekit@<version> (Go 1.27.4 or later).
2. Call licensekit.Open("", licensekit.Options{...}) once in the process that does the
   licensed work, and reuse the returned *License. Handle Open errors with errors.As on
   *licensekit.Error and show its Message. For servers and containers, set Options.StateDir on
   persistent storage and a stable, unique Options.DeviceID per installation, persisted with it.
   Say which OS account owns the state.
3. Wire the build setting into every build, never into code: add
   -X github.com/aqobadi/licensekit.build=$LICENSEKIT_BUILD to the existing -ldflags
   in the Makefile, scripts, CI and Dockerfile (as a build argument). LICENSEKIT_BUILD comes from
   the product page in the Manager; the owner supplies it in the build
   environment. Do not read trust from runtime environment variables or files.
   For local runs, make plain `go run`/`go build` work when the developer exports LICENSEKIT_BUILD
   and GOFLAGS="-ldflags=-X=github.com/aqobadi/licensekit.build=$LICENSEKIT_BUILD" (INTEGRATION.md §2,
   "On your computer"). If the project passes its own -ldflags (Makefile, scripts), append
   -X github.com/aqobadi/licensekit.build=$(LICENSEKIT_BUILD) there so `make run` reads the variable.
   Add a git-ignored .env/.envrc example (no real value) and document both lines in the app's README.
   Automated tests use licensekittest and need no LICENSEKIT_BUILD.
4. Give administrators the License page. For a web app, mount
   licenseui.Handler(lic, licenseui.Options{Name: "<product name>", Support: "<support text>"})
   under the app's existing administrator authentication with http.StripPrefix. For other apps,
   build the same flow with online.Enter (license key or renewal code), lic.Apply (.license file
   contents, bounded to 64 KiB), lic.RequestFile (no internet) and online.Deactivate (move).
   Keep license keys, codes and file contents out of logs.
5. Enforce access where work runs: lic.Status().State == licensekit.Active for licensed work,
   including background jobs and service endpoints; lic.Has("<key>") for separately sold features.
   Keep the License page, recovery and the user's own data reachable when work is blocked, per the
   product policy. Show a renewal reminder when !Perpetual && DaysLeft <= 30 (the License page does).
6. Test with licensekittest (no real keys, no network): licensekittest.New(t, "") with
   iss.Server(t) for online activation, iss.Activate for file activation, iss.RenewalCode for
   renewals. Cover: not activated, online activation, request-file activation, restart, renewal,
   expiry, deactivation and activation on another computer, invalid and mistyped keys, enabled and
   disabled features. Run the app's normal build and tests, and one build with a real build setting
   from a development Manager if one is available.

Deliver working code, the License page, the build wiring, and a short integration note listing
where access is enforced, where state is stored, which build variable must be set, and what the
owner must provide before release. Report commands and results truthfully and list anything not
verified (for example native macOS or Windows, or a real container deployment).
```

[Developer integration guide](INTEGRATION.md)
