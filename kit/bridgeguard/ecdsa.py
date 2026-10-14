import hashlib
import hmac

from .keccak import keccak256

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def _nonce(d, z):
    x = d.to_bytes(32, "big")
    h = (z % N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, "big")
        if 1 <= t < N:
            return t
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def address(private_key):
    d = int.from_bytes(private_key, "big")
    if not 1 <= d < N:
        raise ValueError("private key out of range")
    x, y = _mul(d, G)
    return "0x" + keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:].hex()


def sign_digest(private_key, digest):
    d = int.from_bytes(private_key, "big")
    if not 1 <= d < N or len(digest) != 32:
        raise ValueError("invalid input")
    z = int.from_bytes(digest, "big")
    k = _nonce(d, z)
    rx, ry = _mul(k, G)
    r = rx % N
    s = pow(k, -1, N) * (z + r * d) % N
    if r == 0 or s == 0:
        raise ValueError("degenerate signature")
    recid = (ry & 1) | (2 if rx >= N else 0)
    if s > N // 2:
        s = N - s
        recid ^= 1
    if rx >= N:
        raise ValueError("degenerate recovery identifier")
    pub = _mul(d, G)
    if not _verify(pub, z, r, s) or _recover(z, r, s, recid & 1) != pub:
        raise ValueError("signature self check failed")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + (recid & 1)])


def _recover(z, r, s, parity):
    x = r
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y) % P != y2:
        return None
    if y & 1 != parity:
        y = P - y
    rinv = pow(r, -1, N)
    sr = _mul(s * rinv % N, (x, y))
    zg = _mul((-z * rinv) % N, G)
    return _add(sr, zg)


def _verify(pub, z, r, s):
    if not (1 <= r < N and 1 <= s < N):
        return False
    w = pow(s, -1, N)
    pt = _add(_mul(z * w % N, G), _mul(r * w % N, pub))
    return pt is not None and pt[0] % N == r
