# Rules for this repository

`github.com/aqobadi/licensekit` is the **public** LicenseKit SDK: Go, standard library only,
Go 1.27.4+. Start with [README.md](README.md); the formats are in [PROTOCOL.md](PROTOCOL.md) and the
API in [API.md](API.md).

## This repository is public

**Never add anything secret or sensitive**, in code, tests, docs, examples, file names or commit
messages:

- private keys, seeds, passphrases, tokens, passwords or `.age`, `.pem`, `.key`, `.env` files;
- the build setting of a real Manager, or real license keys, renewal codes, license or request files;
- customer, staff or company data: names, email addresses, domains, host names, server addresses;
- links to private repositories, internal documents or internal tickets;
- compiled binaries, databases, backups or logs.

Use `example.com`, `example-app` and the published test vectors instead. `make public-check` (run by
the publishing workflow) rejects the patterns it can recognize; it can't recognize everything, so check
each change yourself.

The design needs no secrets in this repository: apps receive only public root keys, through their
build (see README), and private keys never leave the License-ZG Manager.

## How changes arrive

This repository is published one way, as snapshots, from the maintainers' upstream repository. Changes
made here directly are overwritten by the next snapshot. Report problems as GitHub issues; report
security problems privately (see [SECURITY.md](SECURITY.md)).

## Engineering rules

- The core package and `protocol` never import `net` or `net/*`; only `online` and `licenseui` may.
- `protocol` is the only implementation of the formats. A change to a signed format needs a new format
  byte and updates to PROTOCOL.md, `spec/verify.py` and the test vectors together.
- Trust comes only from the build setting. Never add a runtime way (environment, file, network, UI) to
  add or replace trusted keys.
- `go vet ./...`, `go test ./...` and `python3 -I spec/verify.py vectors` must pass. Every change updates
  [CHANGELOG.md](CHANGELOG.md).
