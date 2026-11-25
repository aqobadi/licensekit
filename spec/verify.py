#!/usr/bin/env python3
"""Independent verifier for the License-ZG licensing protocol v2.

Written only from PROTOCOL.md, with no Go code. Uses the Python
standard library and the RFC 8032 section 6 reference Ed25519 code.

  python3 -I spec/verify.py vectors   reproduce and check the spec section 13 vectors
  python3 -I spec/verify.py check     read JSON lines from stdin and verify each:
      {"trust": str, "product": slug, "fingerprint": hex, "license": hex,
       "renewal": code, "expiry": n, "entitlements": [str]}
"""
import base64
import binascii
import hashlib
import json
import sys

# ---- RFC 8032 section 6 reference Ed25519 (verbatim logic) ----
p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
modp_sqrt_m1 = pow(2, (p - 1) // 4, p)
G_y = 4 * pow(5, p - 2, p) % p


def sha512(s):
    return hashlib.sha512(s).digest()


def point_add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % p, (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F, G * H, F * G, E * H)


def point_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q


def point_equal(P, Q):
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    return (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


G_x = recover_x(G_y, 0)
G = (G_x, G_y, 1, G_x * G_y % p)


def point_compress(P):
    zinv = pow(P[2], p - 2, p)
    x, y = P[0] * zinv % p, P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def point_decompress(s):
    if len(s) != 32:
        raise ValueError("bad point")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def secret_expand(secret):
    h = sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return (a, h[32:])


def secret_to_public(secret):
    a, _ = secret_expand(secret)
    return point_compress(point_mul(a, G))


def sha512_modq(s):
    return int.from_bytes(sha512(s), "little") % L


def sign(secret, msg):
    a, prefix = secret_expand(secret)
    A = point_compress(point_mul(a, G))
    r = sha512_modq(prefix + msg)
    Rs = point_compress(point_mul(r, G))
    h = sha512_modq(Rs + A + msg)
    s = (r + h * a) % L
    return Rs + int.to_bytes(s, 32, "little")


def verify(public, msg, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    A = point_decompress(public)
    if not A:
        return False
    Rs = signature[:32]
    R = point_decompress(Rs)
    if not R:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = sha512_modq(Rs + public + msg)
    sB = point_mul(s, G)
    hA = point_mul(h, A)
    return point_equal(sB, point_add(R, hA))


# ---- Spec section 4: text encoding ----
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
IGNORED = set("\t\n\r -") | {chr(c) for c in [0xA0, 0x202F, 0x2060, 0xFEFF, 0x2212]} \
    | {chr(c) for c in range(0x2002, 0x200E)} | {chr(c) for c in range(0x2010, 0x2016)}


def encode(b):
    bits = "".join(f"{x:08b}" for x in b)
    bits += "0" * (-len(bits) % 5)
    return "".join(ALPHABET[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def group(s):
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def normalize(text):
    out = []
    for line in text.replace("\r", "\n").split("\n"):
        if line.lstrip("".join(IGNORED)).startswith("#"):
            continue
        for ch in line:
            if ch in IGNORED:
                continue
            ch = ch.upper() if "a" <= ch <= "z" else ch
            ch = {"O": "0", "I": "1", "L": "1"}.get(ch, ch)
            if ch not in ALPHABET:
                raise ValueError("BadCharacter")
            out.append(ch)
    return "".join(out)


def decode(chars, nbytes):
    bits = "".join(f"{ALPHABET.index(c):05b}" for c in chars)
    if len(bits) != nbytes * 8:
        raise ValueError("length")
    data = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    if binascii.crc_hqx(data[:-2], 0) != int.from_bytes(data[-2:], "big"):
        raise ValueError("Typo")
    return data


def with_crc(b):
    return b + binascii.crc_hqx(b, 0).to_bytes(2, "big")


# ---- Spec section 3: product and device ----
def sha256(b):
    return hashlib.sha256(b).digest()


def product_id(slug):
    return sha256(b"ZURVAN/PRODUCT/1\0" + slug.encode())[:16]


def fingerprint(pid, source, identity):
    return sha256(b"ZURVAN/DEVICE/1\0" + pid + bytes([source]) + identity)[:15]


# ---- Spec section 5: typed codes ----
def license_key(secret):
    return group(encode(with_crc(b"\x21" + secret)))


def key_hash(secret):
    return sha256(b"ZURVAN/LICENSE-KEY/1\0" + secret)


def renewal_code(step, value):
    return group(encode(with_crc(b"\x22" + step.to_bytes(2, "big") + value)))


def parse_code(text):
    chars = normalize(text)
    if len(chars) != 24:
        raise ValueError("length")
    data = decode(chars, 15)
    if data[0] == 0x21:
        return ("key", data[1:13])
    if data[0] == 0x22:
        step = int.from_bytes(data[1:3], "big")
        if step == 0:
            raise ValueError("Malformed")
        return ("renewal", step, data[3:13])
    raise ValueError("UnsupportedFormat")


# ---- Spec section 2: trust ----
def parse_trust(text):
    roots, distrusted = {}, set()
    for item in [i.strip() for i in text.split(",") if i.strip()]:
        if item.startswith("url="):
            continue
        if item.startswith("-s"):
            distrusted.add(int(item[2:]))
        elif item.startswith("r"):
            num, key = item[1:].split(":")
            roots[int(num)] = bytes.fromhex(key)
        else:
            raise ValueError("trust item " + item)
    return roots, distrusted


# ---- Spec section 6: certificates and licenses ----
class Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def take(self, n):
        if self.i + n > len(self.b):
            raise ValueError("short")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def u(self, n):
        return int.from_bytes(self.take(n), "big")


def cert_body(number, public, created):
    return b"\x41" + number.to_bytes(2, "big") + public + created.to_bytes(2, "big")


def make_cert(number, public, created, roots):
    """roots: list of (root number, root seed)."""
    body = cert_body(number, public, created)
    out = body + bytes([len(roots)])
    for n, seed in roots:
        out += bytes([n]) + sign(seed, b"ZURVAN/CERT/1\0" + body)
    return out


def check_cert(roots, distrusted, data):
    r = Reader(data)
    if r.u(1) != 0x41:
        raise ValueError("UnsupportedFormat")
    number, public, created = r.u(2), r.take(32), r.u(2)
    count = r.u(1)
    sigs = [(r.u(1), r.take(64)) for _ in range(count)]
    if r.i != len(data) or not 1 <= count <= 4 or number == 0:
        raise ValueError("Malformed")
    if number in distrusted:
        raise ValueError("Untrusted")
    body = cert_body(number, public, created)
    if not any(n in roots and verify(roots[n], b"ZURVAN/CERT/1\0" + body, s) for n, s in sigs):
        raise ValueError("Untrusted")
    return public


def chain_step(pid, fp, lid, i, x):
    return sha256(b"ZURVAN/RENEW/1\0" + pid + fp + lid.to_bytes(3, "big") + i.to_bytes(2, "big") + x)[:10]


def chain_value(seed, pid, fp, lid, n, k):
    x = sha256(b"ZURVAN/RENEW-SEED/1\0" + seed)[:10]
    for i in range(n, k, -1):
        x = chain_step(pid, fp, lid, i, x)
    return x


def license_body(f):
    b = b"\x31" + f["product"] + f["fingerprint"] + bytes([f["source"]]) + f["device_key"]
    b += f["id"].to_bytes(3, "big")
    for k in ("issued", "expiry", "chain_base", "chain_length"):
        b += f[k].to_bytes(2, "big")
    b += f["lock"] + bytes([len(f["entitlements"])])
    for e in sorted(f["entitlements"]):
        b += bytes([len(e)]) + e.encode()
    return b


def make_license(f, signing_seed, cert):
    body = license_body(f)
    return body + sign(signing_seed, b"ZURVAN/LICENSE/2\0" + body) + len(cert).to_bytes(2, "big") + cert


def verify_license(roots, distrusted, data, pid, fp):
    r = Reader(data)
    if r.u(1) != 0x31:
        raise ValueError("UnsupportedFormat")
    f = {"product": r.take(16), "fingerprint": r.take(15), "source": r.u(1), "device_key": r.take(32), "id": r.u(3),
         "issued": r.u(2), "expiry": r.u(2), "chain_base": r.u(2), "chain_length": r.u(2), "lock": r.take(10)}
    f["entitlements"] = [r.take(r.u(1)).decode() for _ in range(r.u(1))]
    body = data[:r.i]
    sig = r.take(64)
    cert = r.take(r.u(2))
    if r.i != len(data):
        raise ValueError("Malformed")
    if f["entitlements"] != sorted(set(f["entitlements"])) or (f["expiry"] == 0) != (f["chain_length"] == 0):
        raise ValueError("Malformed")
    public = check_cert(roots, distrusted, cert)
    if not verify(public, b"ZURVAN/LICENSE/2\0" + body, sig):
        raise ValueError("BadSignature")
    if f["product"] != pid:
        raise ValueError("WrongProduct")
    if f["fingerprint"] != fp:
        raise ValueError("WrongDevice")
    return f


def renewed_expiry(f, step, value):
    """Spec section 7.2: hash the value down step times; it must reach the lock."""
    if not 1 <= step <= f["chain_length"]:
        raise ValueError("WrongRenewal")
    x = value
    for i in range(step, 0, -1):
        x = chain_step(f["product"], f["fingerprint"], f["id"], i, x)
    if x != f["lock"]:
        raise ValueError("WrongRenewal")
    return max(f["expiry"], f["chain_base"] + step)


# ---- Spec section 8: requests ----
def make_request(pid, fp, source, device_seed, khash, nonce, created):
    body = b"\x51" + pid + fp + bytes([source]) + secret_to_public(device_seed) + khash + nonce + created.to_bytes(8, "big")
    return body + sign(device_seed, b"ZURVAN/REQUEST/1\0" + body)


# ---- Spec section 13: vectors (copied from the spec) ----
V = {
    "product": "b0c28bfd19208068fca6a422351a8327",
    "fingerprint": "908ec2f8d6b1c098cd88f3b3b9b4ae",
    "key": "47E6-R5Q1-6VC8-KBJT-3YHP-XCK0",
    "key_hash": "0fae3a48032b7f19f2e275ab31a25197fc123af7c4363efed66e5ed8b8f41f4c",
    "cert": "41000114e7414e5a1f5a65fab8a778f212d0b90b4d02d90b084b5f05c2236e3c2f177009d80101936885a2d9d82f68f1ed4b"
            "3a57d2b167060b1eddebffb8fb439be9bba4efe75635538a89de92ad2282a57fc3191075ec137576400e2320cb6d34e52b4f3e0a02",
    "lock": "a65587dd3e3cadc7b1a4",
    "license": "31b0c28bfd19208068fca6a422351a8327908ec2f8d6b1c098cd88f3b3b9b4ae018114065e613f6976cb6647e4515c69de07"
               "452a4e798ae120c076c61672e4ef7c5a3c9109d80b4309d84756a65587dd3e3cadc7b1a402066578706f72740473796e6317"
               "42aa0f9ab80f0550d301d82764ae3939f88678c5d17d201d1475111b295b283bcfe6f4d0d9b4c12b346f80b7564b47a0d6e7"
               "233a7128f9913c55dc27c76a0f006741000114e7414e5a1f5a65fab8a778f212d0b90b4d02d90b084b5f05c2236e3c2f1770"
               "09d80101936885a2d9d82f68f1ed4b3a57d2b167060b1eddebffb8fb439be9bba4efe75635538a89de92ad2282a57fc31910"
               "75ec137576400e2320cb6d34e52b4f3e0a02",
    "renewal": "481D-H145-4JQW-E5FZ-Z5RC-YSQJ",
    "request": "51b0c28bfd19208068fca6a422351a8327908ec2f8d6b1c098cd88f3b3b9b4ae018114065e613f6976cb6647e4515c69de07"
               "452a4e798ae120c076c61672e4ef7c0fae3a48032b7f19f2e275ab31a25197fc123af7c4363efed66e5ed8b8f41f4c0000"
               "000000000000000000000000000000000000000000000000000000000000000000006afd86c0bebe9e76dda44c5f876dcd31"
               "6f72634dfb6ac1287d981ff72a2e8ec700372981903371fe92b3f78bd112900348b270a9816b0004e5da238f1f079ad0468"
               "5a301",
    "trust": "r1:951a9e4c7e3defb28c5ee9033f60866b8ab55e7a7656917b626db610551e2ff5",
}


def check_vectors():
    seed = lambda s: sha256(s.encode())
    root, signing, device = seed("zurvan test root 1"), seed("zurvan test signing key 1"), seed("zurvan test device")
    pid = product_id("example-app")
    fp = fingerprint(pid, 1, b"0123456789abcdef0123456789abcdef")
    secret = seed("zurvan test license key")[:12]
    assert pid.hex() == V["product"], pid.hex()
    assert fp.hex() == V["fingerprint"], fp.hex()
    assert license_key(secret) == V["key"]
    assert key_hash(secret).hex() == V["key_hash"]
    assert "r1:" + secret_to_public(root).hex() == V["trust"]
    cert = make_cert(1, secret_to_public(signing), 2520, [(1, root)])
    assert cert.hex() == V["cert"]
    lid, base, n = 0x5A3C91, 2520, 18262
    chain_seed = seed("zurvan test chain seed")
    lock = chain_value(chain_seed, pid, fp, lid, n, 0)
    assert lock.hex() == V["lock"]
    f = {"product": pid, "fingerprint": fp, "source": 1, "device_key": secret_to_public(device), "id": lid, "issued": 2520,
         "expiry": 2883, "chain_base": base, "chain_length": n, "lock": lock, "entitlements": ["sync", "export"]}
    lic = make_license(f, signing, cert)
    assert lic.hex() == V["license"]
    step = 2883 + 365 - base
    assert renewal_code(step, chain_value(chain_seed, pid, fp, lid, n, step)) == V["renewal"]
    assert make_request(pid, fp, 1, device, key_hash(secret), bytes(32), 1795000000).hex() == V["request"]
    # The device side, from the documented bytes alone.
    roots, distrusted = parse_trust(V["trust"])
    got = verify_license(roots, distrusted, bytes.fromhex(V["license"]), pid, fp)
    assert got["entitlements"] == ["export", "sync"] and got["expiry"] == 2883
    kind, step, value = parse_code(V["renewal"].lower().replace("-", " "))
    assert kind == "renewal" and renewed_expiry(got, step, value) == 2883 + 365
    for bad, why in ((lambda: verify_license(roots, {1}, bytes.fromhex(V["license"]), pid, fp), "Untrusted"),
                     (lambda: verify_license(roots, distrusted, bytes.fromhex(V["license"]), product_id("other-app"), fp), "WrongProduct"),
                     (lambda: renewed_expiry(got, step + 1, value), "WrongRenewal")):
        try:
            bad()
            raise AssertionError("accepted: " + why)
        except ValueError as e:
            assert str(e) == why, (str(e), why)
    print("spec vectors: ok")


def check_stream():
    n = 0
    for line in sys.stdin:
        c = json.loads(line)
        roots, distrusted = parse_trust(c["trust"])
        fp = bytes.fromhex(c["fingerprint"])
        f = verify_license(roots, distrusted, bytes.fromhex(c["license"]), product_id(c["product"]), fp)
        kind, step, value = parse_code(c["renewal"])
        assert kind == "renewal" and renewed_expiry(f, step, value) == c["expiry"], line
        assert f["entitlements"] == c["entitlements"], line
        n += 1
    print(f"{n} licenses ok")


if __name__ == "__main__":
    {"vectors": check_vectors, "check": check_stream}[sys.argv[1] if len(sys.argv) > 1 else "vectors"]()
