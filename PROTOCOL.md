# LicenseKit protocol v2 (normative)

This document is the normative specification of the License-ZG licensing protocol v2. Two
implementations exist: `protocol` (Go) and `spec/verify.py` (Python, written from this
document only). Both reproduce §13.

All integers are unsigned and big-endian. `‖` is concatenation. `SHA-256` is FIPS 180-4; Ed25519
is RFC 8032 (pure Ed25519, cofactorless verification, `S < L`, canonical `R`; Go's
`crypto/ed25519` meets this). Day numbers count UTC days since 2020-01-01 (`day = (unix − 1577836800) div 86400`).

## 1. Objects

| Object | Made by | Secret? | Travels |
|---|---|---|---|
| Root key (Ed25519), number 1–255 | Manager, once; replaced only on loss | **Yes**: offline recovery files only | Public half in the build setting (§2) |
| Signing key (Ed25519), number 1–65535 | Manager; replaceable any time | **Yes**: on the Manager, age-encrypted | Public half inside its certificate (§6.1) |
| Manager secret (32 bytes) | Manager, once | **Yes** | Never. License keys and chain seeds are derived from it (not normative) |
| Build setting | Manager | No | Compiled into each app build |
| License key (§5.1) | Manager | Yes, to its owner | To the customer; typed once |
| License (§6.2) | Manager | No | Online setup response or `.license` file |
| Renewal code (§5.2) | Manager | No (useless elsewhere) | To the customer; typed |
| Request (§8.1), release (§8.2), receipt (§8.3) | App / Manager | No | Activation API or request file |

**Trust rule.** An app trusts exactly the roots in its build setting. No runtime input (environment,
file, network, UI) can add, remove or replace a root or a distrust entry. Replacing them means
building the app again, which is binary modification for an attacker and out of scope.

## 2. Build setting (trust)

A comma-separated list, whitespace around items ignored:

| Item | Meaning |
|---|---|
| `r<N>:<64 lowercase hex>` | Root `N` (1–255) with this Ed25519 public key. 1 to 4 roots, numbers unique. |
| `-s<N>` | Signing key `N` (1–65535) is distrusted. |
| `url=<address>` | Default activation API address: `https://host[:port][/path]`, or `http://` only for `localhost`, `127.0.0.1` or `[::1]`. No query, fragment, user info, spaces or commas. |

Any other item is an error. The canonical form lists roots by number, then distrust entries by
number, then `url=`. Example: `r1:951a…2ff5,r2:…,-s3,url=https://activate.example.com`.

Go apps receive it with `-ldflags "-X github.com/aqobadi/licensekit.build=<setting>"`.
The activation address may be overridden at run time (option or `LICENSEKIT_SERVER_URL`); that is
safe because every result is verified against the roots.

## 3. Product and device

```text
product_id  = SHA-256("ZURVAN/PRODUCT/1\0" ‖ slug)[0..16)
fingerprint = SHA-256("ZURVAN/DEVICE/1\0" ‖ product_id ‖ source ‖ identity)[0..15)
```

`slug` is 3–40 ASCII characters `^[a-z][a-z0-9-]{1,38}[a-z0-9]$`. `source` is one byte:

| `source` | `identity` |
|---|---|
| `0x01` OS machine identifier | ASCII of the normalized identifier below |
| `0x02` application-supplied `DeviceID` | UTF-8 bytes exactly as supplied, 8–256 bytes |

| OS | Read | Normalize and validate |
|---|---|---|
| Linux | `/etc/machine-id`, else `/var/lib/dbus/machine-id` (at most 4 KiB) | Trim ASCII whitespace, lowercase; exactly 32 hex digits, not all zero (`uninitialized` is rejected) |
| macOS | `IOPlatformUUID` of `IOPlatformExpertDevice` (`ioreg`, 5 s timeout, 1 MiB cap) | Lowercase; 8-4-4-4-12 hex UUID, not all zero |
| Windows | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, 64-bit view | Trim, lowercase; 8-4-4-4-12 hex UUID, not all zero |
| Other | — | Unsupported: the app must supply a `DeviceID` |

On Linux the OS identifier is refused inside a detected container (`/.dockerenv`,
`/run/.containerenv`, `/run/systemd/container`, `KUBERNETES_SERVICE_HOST` or `container` set, or
`/proc/1/cgroup` naming docker, kubepods, containerd, lxc or libpod); the app must supply a
`DeviceID`. There is no fallback to host names, MAC addresses or random values.

## 4. Text encoding of typed codes

**Alphabet** (Crockford Base32, value = index): `0123456789ABCDEFGHJKMNPQRSTVWXYZ`.

**Encode:** read the bytes as one MSB-first bit string, emit 5 bits per character (pad the last
with zero bits), and show groups of four joined by `-`.

**Decode:**

1. Reject input over 65,536 bytes or not valid UTF-8.
2. Split into lines at LF or CR; drop every line whose first character, after the step-3 code points, is `#`.
3. Remove only these code points: U+0009, U+000A, U+000D, U+0020, U+002D (`-`), U+00A0,
   U+2002–U+200D, U+202F, U+2060, U+FEFF, U+2010–U+2015, U+2212.
4. Map `a`–`z` to upper case, then `O`→`0`, `I`→`1`, `L`→`1`.
5. Every remaining character must be in the alphabet, else `BadCharacter` with group `floor(index/4)+1`.
   Nothing left: `Empty`.
6. Exactly **24** characters, else `Incomplete` (shorter) or `TooLong`.
7. Decode to 15 bytes (no pad bits). Check `crc16(bytes[0..13)) == bytes[13..15)`, else `Typo`.
8. `bytes[0]` must be `0x21` or `0x22`, else `UnsupportedFormat`.

**CRC-16/XMODEM:** polynomial 0x1021, initial 0, no reflection, no final XOR (`binascii.crc_hqx(b, 0)`;
check value for `123456789` is `0x31C3`).

### 4.1 Typo location (recommended)

After a CRC failure, try every single-character substitution (31 per position). If exactly one
position yields a valid CRC, report `Typo` with its group; otherwise `Typo` without a group. Never
auto-correct.

## 5. Typed codes (15 bytes, 24 characters)

### 5.1 License key

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `0x21` |
| 1 | 12 | `secret` (96 bits) |
| 13 | 2 | CRC |

`key_hash = SHA-256("ZURVAN/LICENSE-KEY/1\0" ‖ secret)`. The Manager stores only `key_hash`.
Request files carry only `key_hash`.

### 5.2 Renewal code

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `0x22` |
| 1 | 2 | `step` (1–65535; 0 is malformed) |
| 3 | 10 | `value` = `x_step` of the license's chain (§7) |
| 13 | 2 | CRC |

## 6. Certificates and licenses

### 6.1 Certificate (format `0x41`)

| Field | Size |
|---|---|
| format `0x41` | 1 |
| `key_number` (1–65535) | 2 |
| `public_key` | 32 |
| `created_day` | 2 |
| `count` (1–4) | 1 |
| `count` × (`root` (1–255, unique) ‖ `signature`) | 65 each |

Each root signs `"ZURVAN/CERT/1\0" ‖ bytes[0..37)` (format through `created_day`).
A certificate is **trusted** when `key_number` is not distrusted and at least one signature by a
root in the build setting verifies. Certificates do not expire.

### 6.2 License (format `0x31`)

| Field | Size |
|---|---|
| format `0x31` | 1 |
| `product_id` | 16 |
| `fingerprint` | 15 |
| `source` | 1 |
| `device_key` (Ed25519 public key of the installation, §8) | 32 |
| `license_id` (1 – 16,777,215) | 3 |
| `issued_day` | 2 |
| `expiry_day` (0 = perpetual) | 2 |
| `chain_base` | 2 |
| `chain_length` | 2 |
| `lock` | 10 |
| `n` (0–16) | 1 |
| `n` × (`len` (1–32) ‖ entitlement key `^[a-z][a-z0-9_-]{0,31}$`), strictly ascending | |
| `signature` | 64 |
| `cert_len` | 2 |
| certificate (§6.1) | `cert_len` |

`signature` is the certificate's key signing `"ZURVAN/LICENSE/2\0" ‖ ` every byte before it.
Constraints: `expiry_day = 0` exactly when `chain_length = 0`; `chain_base + chain_length ≤ 65535`;
a dated license has `expiry_day ≥ chain_base`. Trailing bytes are malformed.

### 6.3 Verification (device)

In order, first failure wins: decode (`Malformed`/`UnsupportedFormat`); the license signature
verifies with the attached certificate's key (`BadSignature`); the certificate is trusted (§6.1,
`Untrusted`); `product_id` equals the app's (`WrongProduct`); `fingerprint` equals this computer's
(`WrongDevice`). Then validity in time (§11).

The **effective expiry** with an applied renewal step `k` (0 if none) is `0` for perpetual licenses,
else `max(expiry_day, chain_base + k)`.

### 6.4 Signing (Manager)

The Manager signs with its active signing key and **self-verifies** every license with §6.3 against
its current build setting before it leaves. `issued_day` is the Manager's current day. A new seat
starts a chain with `chain_base = issued_day` and `chain_length = min(18262, 65535 − chain_base)`.

## 7. Renewal chain

```text
ctx      = product_id ‖ fingerprint ‖ license_id(3)
x_N      = SHA-256("ZURVAN/RENEW-SEED/1\0" ‖ seed)[0..10)               N = chain_length, seed: 32 secret bytes
x_(i-1)  = SHA-256("ZURVAN/RENEW/1\0" ‖ ctx ‖ i(2) ‖ x_i)[0..10)        for i = N … 1
lock     = x_0
```

### 7.1 Issuing (Manager)

To move a license's expiry to day `E` (`chain_base < E ≤ chain_base + chain_length`), the renewal
code carries `step = E − chain_base` and `value = x_step`.

### 7.2 Checking (device)

Accept when `1 ≤ step ≤ chain_length` and hashing `value` down from `i = step` to `1` gives `lock`.
A device always re-checks a saved renewal against `lock` when it loads it. A code whose effective
expiry is not later than the current one changes nothing (`AlreadyApplied`).

Forging a later step requires an 80-bit preimage of one step function, which mixes in the product,
computer, license and step number.

## 8. Messages between apps and the Manager

Each installation has an Ed25519 **device key**, created on first use and kept in its state directory.

### 8.1 Request (format `0x51`)

`0x51 ‖ product_id(16) ‖ fingerprint(15) ‖ source(1) ‖ device_key(32) ‖ key_hash(32) ‖ nonce(32) ‖ created(8)`
followed by the device key's signature over `"ZURVAN/REQUEST/1\0" ‖ ` those bytes (64).
`nonce` is the activation API challenge (§10) or all zero in a request file. `created` is the device's
Unix time (informational).

### 8.2 Release (format `0x52`)

`0x52 ‖ product_id(16) ‖ fingerprint(15) ‖ license_id(3) ‖ device_key(32) ‖ nonce(32)` followed by the device
key's signature over `"ZURVAN/RELEASE/1\0" ‖ ` those bytes (64). The Manager accepts it only when
`device_key` is the key recorded for the license's current seat on that computer.

### 8.3 Receipt (format `0x53`)

`0x53 ‖ signature(64) ‖ cert_len(2) ‖ certificate`, where a trusted signing key signs
`"ZURVAN/RELEASED/1\0" ‖ product_id ‖ fingerprint ‖ license_id(3) ‖ nonce`. The app deletes its
license only after the receipt verifies.

## 9. Files

Licenses and requests travel as text blocks that survive email and chat:

```text
# optional comment lines
-----BEGIN ZURVAN LICENSE-----            (or ZURVAN LICENSE REQUEST)
Base64 (RFC 4648 standard alphabet, with padding), 64 characters per line
-----END ZURVAN LICENSE-----
```

Readers ignore text before and after the block, and whitespace inside it. Input over 64 KiB is rejected.

## 10. Activation API

HTTPS, `POST`, JSON bodies of at most 8 KiB, `[]byte` fields in Base64. Paths are relative to the
activation address.

| Path | Request | 200 response |
|---|---|---|
| `/api/v1/challenge` | `{}` | `{"nonce": 32 bytes, "work": bits}` |
| `/api/v1/setup` | `{"license_key": text, "request": §8.1 with the nonce, "counter": n}` | `{"license": §6.2}` |
| `/api/v1/deactivate` | `{"release": §8.2 with the nonce, "counter": n}` | `{"receipt": §8.3}` |

Every other response is `{"error": code, "message": text}` with code `invalid_key`, `in_use`,
`moves_exhausted`, `license_expired`, `license_canceled`, `not_set_up`, `bad_challenge`,
`rate_limited`, `unavailable` or `bad_request`. `invalid_key` covers an unknown key, a key for
another product and a malformed request alike.

### 10.1 Server rules

A nonce is single-use and expires after 5 minutes. `setup` requires
`SHA-256("ZURVAN/LICENSE-KEY/1\0" ‖ secret(license_key)) = request.key_hash` and a valid request
signature. Limits are per client address and per key hash; repeated failures for one key lock it
for an hour.

### 10.2 Proof of work

When `work > 0`, the client finds `counter` such that
`SHA-256("ZURVAN/POW/1\0" ‖ nonce ‖ counter(8))` starts with at least `work` zero bits. Clients
refuse `work > 24`.

## 11. Device state and time

The state directory holds `license` (the §9 file), `renewal` (the latest applied code),
`device.key` (hex seed of the device key, mode 0600) and `clock`. Files are written atomically
(temporary file, fsync, rename, fsync of the directory where supported); symlinks, FIFOs and devices
are refused; saved state is never trusted and is re-verified on every load. A license whose
effective expiry has already passed is refused when installed (`AlreadyExpired`).

- `now < 1577836800` → `ClockProblem`. `today = (now − 1577836800) div 86400`.
- A license is valid while `today ≤ effective expiry` (or always, if perpetual).
- **Clock high-water `H`** (Unix seconds, saved in `clock`, never decreases): if `now < H − 172800`
  (48 hours) → `ClockProblem`; else `H = max(H, now)`, persisted when it advances by more than an
  hour. Loading a license raises `H` to the start of its `issued_day`.
- If the state directory is read-only, the license is still honored, `clock` moves to the per-user
  directory, and installing returns `StorageFailed`.

What this does not stop: a clock held before the expiry, deleting `clock`, restoring a snapshot,
or patching the binary (see [SECURITY.md](SECURITY.md)).

## 12. Versioning

Format bytes identify each object and version. A new layout gets a new format byte; verifiers
reject unknown formats (`UnsupportedFormat`: "update the app"). Domain tags change with any change
to a signed message. Replacing the signing key changes no format: new keys reach apps inside their
certificates. Protocol v1 (bundle files, 32-character request codes, 120-character activation codes)
was never released and is not supported.

## 13. Test vectors (development keys; never used for real licenses)

```text
root 1 seed       SHA-256("zurvan test root 1")
signing key seed  SHA-256("zurvan test signing key 1")     key number 1, certificate created_day 2520
device key seed   SHA-256("zurvan test device")
build setting     r1:951a9e4c7e3defb28c5ee9033f60866b8ab55e7a7656917b626db610551e2ff5
product slug      example-app      → product_id b0c28bfd19208068fca6a422351a8327
machine id        0123456789abcdef0123456789abcdef (source 0x01)
fingerprint       908ec2f8d6b1c098cd88f3b3b9b4ae
license key       secret = SHA-256("zurvan test license key")[0..12)
                  47E6-R5Q1-6VC8-KBJT-3YHP-XCK0
key hash          0fae3a48032b7f19f2e275ab31a25197fc123af7c4363efed66e5ed8b8f41f4c
certificate       41000114e7414e5a1f5a65fab8a778f212d0b90b4d02d90b084b5f05c2236e3c2f177009d80101936885a2d9d82f68f1ed4b
                  3a57d2b167060b1eddebffb8fb439be9bba4efe75635538a89de92ad2282a57fc3191075ec137576400e2320cb6d34e52b4f3e0a02
license           id 0x5a3c91, issued 2520, expiry 2883, chain base 2520, length 18262, entitlements sync, export
chain seed        SHA-256("zurvan test chain seed")         → lock a65587dd3e3cadc7b1a4
license bytes     31b0c28bfd19208068fca6a422351a8327908ec2f8d6b1c098cd88f3b3b9b4ae018114065e613f6976cb6647e4515c69de07
                  452a4e798ae120c076c61672e4ef7c5a3c9109d80b4309d84756a65587dd3e3cadc7b1a402066578706f72740473796e6317
                  42aa0f9ab80f0550d301d82764ae3939f88678c5d17d201d1475111b295b283bcfe6f4d0d9b4c12b346f80b7564b47a0d6e7
                  233a7128f9913c55dc27c76a0f006741000114e7414e5a1f5a65fab8a778f212d0b90b4d02d90b084b5f05c2236e3c2f1770
                  09d80101936885a2d9d82f68f1ed4b3a57d2b167060b1eddebffb8fb439be9bba4efe75635538a89de92ad2282a57fc31910
                  75ec137576400e2320cb6d34e52b4f3e0a02
renewal code      to day 3248 (step 728): 481D-H145-4JQW-E5FZ-Z5RC-YSQJ
request           with key hash above, zero nonce, created 1795000000:
                  51b0c28bfd19208068fca6a422351a8327908ec2f8d6b1c098cd88f3b3b9b4ae018114065e613f6976cb6647e4515c69de07
                  452a4e798ae120c076c61672e4ef7c0fae3a48032b7f19f2e275ab31a25197fc123af7c4363efed66e5ed8b8f41f4c0000
                  000000000000000000000000000000000000000000000000000000000000000000006afd86c0bebe9e76dda44c5f876dcd31
                  6f72634dfb6ac1287d981ff72a2e8ec700372981903371fe92b3f78bd112900348b270a9816b0004e5da238f1f079ad0468
                  5a301
```

Negative cases (every flipped bit, truncation, trailing data, wrong product and device, untrusted and
distrusted keys, every typo position, renewal steps and values off by one, perpetual licenses, clock
rollback) are Go tests in `protocol` and the module root. `spec/verify.py vectors` reproduces
every value above from this document alone; `TestIndependentCrossCheck` feeds it 300 random Go-signed
licenses with renewal codes.
