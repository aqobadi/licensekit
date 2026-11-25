# Security

## What LicenseKit guarantees (on an unmodified app build)

- **Licenses can't be forged.** A license is Ed25519-signed by a signing key that the app's trusted roots
  certify. The roots come only from the app's build; nothing at run time can add one.
- **A license works on one product and one computer.** The product and the computer's fingerprint are
  signed; a renewal code is bound to the computer it was made for.
- **Saved state can't be edited into a better license.** Everything saved is re-verified on every load.
- **The activation server can't be impersonated.** A fake server can't produce a license or receipt the
  app accepts; it can only fail.
- **No secret lives in this SDK or in apps.** Publishing this code doesn't weaken it.

## Honest limits

- Patching the app's binary bypasses every check (true of all offline licensing).
- Expiry holds only against an honest clock. A clock moved back more than 48 hours, or before the
  license was issued, is detected; a clock held still is not.
- A computer that never goes online again keeps its license until its current expiry, even after the
  vendor releases it or cancels the license. It can't be renewed.
- A faithful disk or VM clone shares the license. In containers, copying the `DeviceID` and the state
  directory together shares it too.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on this repository. Don't
open a public issue for security problems.
