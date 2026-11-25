# Changelog

LicenseKit follows semantic versioning; install a release with
`go get github.com/aqobadi/licensekit@vX.Y.Z`. Before 1.0, a minor release may change the API; the notes say so.

## Unreleased

- `Open("", opts)` gets its product identity from `LICENSEKIT_BUILD`. Explicit slugs and legacy build values remain supported.
- INTEGRATION.md §2 "On your computer": run apps locally by exporting `LICENSEKIT_BUILD` and `GOFLAGS`; the agent prompt covers it too.
- INTEGRATION.md §2: where to set `LICENSEKIT_BUILD` in GitHub Actions, Docker, Coolify and Compose.
- The "not configured" error names `LICENSEKIT_BUILD`; shorter texts on the License page.

## v0.1.1 — 2026-11-25

First public release. (v0.1.0 was an internal version under an older module path; it isn't available here.)

- `licensekit.Open(slug, opts)`, `Status`, `Has`, `Apply` (renewal codes and `.license` files) and
  `RequestFile` (for computers without internet). No network access in the core package.
- Trust from one build setting: `-ldflags "-X github.com/aqobadi/licensekit.build=…"`. A build without it
  reports `NotConfigured`.
- `online`: activate with a 24-character license key, deactivate to move to another computer.
- `licenseui`: a drop-in License page (no JavaScript, cross-origin protected).
- `licensekittest`: a throwaway issuer and activation server for tests.
- Protocol v2 ([PROTOCOL.md](PROTOCOL.md)) with test vectors and an independent Python verifier.
