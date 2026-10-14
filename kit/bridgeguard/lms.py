import hashlib
import hmac
import struct

D_PBLC = 0x8080
D_MESG = 0x8181
D_LEAF = 0x8282
D_INTR = 0x8383

LMOTS = {
    1: (32, 1, 265, 7),
    2: (32, 2, 133, 6),
    3: (32, 4, 67, 4),
    4: (32, 8, 34, 0),
}

LMS = {
    5: (32, 5),
    6: (32, 10),
    7: (32, 15),
    8: (32, 20),
    9: (32, 25),
}


class LMSError(ValueError):
    pass


def u32(x):
    return struct.pack(">I", x)


def u16(x):
    return struct.pack(">H", x)


def u8(x):
    return struct.pack(">B", x)


def H(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def coef(s, i, w):
    return ((1 << w) - 1) & (s[(i * w) // 8] >> (8 - (w * (i % (8 // w)) + w)))


def cksm(s, n, w, ls):
    total = 0
    for i in range((n * 8) // w):
        total += (1 << w) - 1 - coef(s, i, w)
    return u16((total << ls) & 0xFFFF)


def ots_candidate(ots_type, ident, q, message, c, y):
    n, w, p, ls = LMOTS[ots_type]
    qs = u32(q)
    big_q = H(ident, qs, u16(D_MESG), c, message)
    qc = big_q + cksm(big_q, n, w, ls)
    z = []
    top = (1 << w) - 1
    for i in range(p):
        a = coef(qc, i, w)
        tmp = y[i]
        for j in range(a, top):
            tmp = H(ident, qs, u16(i), u8(j), tmp)
        z.append(tmp)
    return H(ident, qs, u16(D_PBLC), *z)


def parse_public_key(pub):
    if len(pub) < 8:
        raise LMSError("public key too short")
    lms_type, ots_type = struct.unpack(">II", pub[:8])
    if lms_type not in LMS or ots_type not in LMOTS:
        raise LMSError("unsupported parameter set")
    m, _ = LMS[lms_type]
    if len(pub) != 8 + 16 + m:
        raise LMSError("public key length")
    return lms_type, ots_type, pub[8:24], pub[24:24 + m]


def signature_length(lms_type, ots_type):
    n, _, p, _ = LMOTS[ots_type]
    m, h = LMS[lms_type]
    return 4 + 4 + n + p * n + 4 + h * m


def parse_signature(sig, expect_lms=None, expect_ots=None):
    if len(sig) < 8:
        raise LMSError("signature too short")
    q, ots_type = struct.unpack(">II", sig[:8])
    if ots_type not in LMOTS or (expect_ots is not None and ots_type != expect_ots):
        raise LMSError("ots type")
    n, _, p, _ = LMOTS[ots_type]
    off = 8
    c = sig[off:off + n]
    off += n
    y = [sig[off + i * n: off + (i + 1) * n] for i in range(p)]
    off += p * n
    if len(sig) < off + 4:
        raise LMSError("signature truncated")
    (lms_type,) = struct.unpack(">I", sig[off:off + 4])
    off += 4
    if lms_type not in LMS or (expect_lms is not None and lms_type != expect_lms):
        raise LMSError("lms type")
    m, h = LMS[lms_type]
    if len(sig) != off + h * m:
        raise LMSError("signature length")
    if q >= (1 << h):
        raise LMSError("leaf index")
    path = [sig[off + i * m: off + (i + 1) * m] for i in range(h)]
    return q, ots_type, c, y, lms_type, path


def verify(pub, message, sig):
    try:
        lms_type, ots_type, ident, root = parse_public_key(pub)
        q, _, c, y, _, path = parse_signature(sig, lms_type, ots_type)
    except LMSError:
        return False
    _, h = LMS[lms_type]
    kc = ots_candidate(ots_type, ident, q, message, c, y)
    node = (1 << h) + q
    tmp = H(ident, u32(node), u16(D_LEAF), kc)
    i = 0
    while node > 1:
        if node & 1:
            tmp = H(ident, u32(node // 2), u16(D_INTR), path[i], tmp)
        else:
            tmp = H(ident, u32(node // 2), u16(D_INTR), tmp, path[i])
        node //= 2
        i += 1
    return hmac.compare_digest(tmp, root)


def leaf_index(sig):
    return struct.unpack(">I", sig[:4])[0]


class PrivateKey:
    def __init__(self, lms_type, ots_type, ident, seed):
        if lms_type not in LMS or ots_type not in LMOTS:
            raise LMSError("unsupported parameter set")
        if len(ident) != 16 or len(seed) != 32:
            raise LMSError("identifier or seed length")
        self.lms_type = lms_type
        self.ots_type = ots_type
        self.ident = ident
        self.seed = seed
        self._nodes = None

    @property
    def height(self):
        return LMS[self.lms_type][1]

    @property
    def capacity(self):
        return 1 << self.height

    def _x(self, q, i):
        return H(self.ident, u32(q), u16(i), u8(0xFF), self.seed)

    def _ots_public(self, q):
        _, w, p, _ = LMOTS[self.ots_type]
        qs = u32(q)
        top = (1 << w) - 1
        ys = []
        for i in range(p):
            tmp = self._x(q, i)
            for j in range(top):
                tmp = H(self.ident, qs, u16(i), u8(j), tmp)
            ys.append(tmp)
        return H(self.ident, qs, u16(D_PBLC), *ys)

    def load_nodes(self, blob):
        expected = 2 * (1 << self.height) * 32
        if len(blob) != expected:
            raise LMSError("tree cache length")
        nodes = [None] + [blob[32 * i: 32 * i + 32] for i in range(1, expected // 32)]
        self._nodes = nodes
        return self

    def export_nodes(self):
        if self._nodes is None:
            self.build()
        return bytes(32) + b"".join(self._nodes[1:])

    def build(self):
        h = self.height
        leaves = 1 << h
        nodes = [None] * (2 * leaves)
        for q in range(leaves):
            r = leaves + q
            nodes[r] = H(self.ident, u32(r), u16(D_LEAF), self._ots_public(q))
        for r in range(leaves - 1, 0, -1):
            nodes[r] = H(self.ident, u32(r), u16(D_INTR), nodes[2 * r], nodes[2 * r + 1])
        self._nodes = nodes
        return self

    def public_key(self):
        if self._nodes is None:
            self.build()
        return u32(self.lms_type) + u32(self.ots_type) + self.ident + self._nodes[1]

    def check_leaf(self, q):
        if self._nodes is None:
            self.build()
        if not 0 <= q < self.capacity:
            return False
        node = (1 << self.height) + q
        tmp = H(self.ident, u32(node), u16(D_LEAF), self._ots_public(q))
        if not hmac.compare_digest(tmp, self._nodes[node]):
            return False
        while node > 1:
            if node & 1:
                tmp = H(self.ident, u32(node // 2), u16(D_INTR), self._nodes[node ^ 1], tmp)
            else:
                tmp = H(self.ident, u32(node // 2), u16(D_INTR), tmp, self._nodes[node ^ 1])
            node //= 2
        return hmac.compare_digest(tmp, self._nodes[1])

    def _sign_leaf(self, q, message, randomizer):
        if self._nodes is None:
            self.build()
        if not 0 <= q < self.capacity:
            raise LMSError("leaf index out of range")
        n, w, p, ls = LMOTS[self.ots_type]
        if len(randomizer) != n:
            raise LMSError("randomizer length")
        qs = u32(q)
        big_q = H(self.ident, qs, u16(D_MESG), randomizer, message)
        qc = big_q + cksm(big_q, n, w, ls)
        ys = []
        for i in range(p):
            a = coef(qc, i, w)
            tmp = self._x(q, i)
            for j in range(a):
                tmp = H(self.ident, qs, u16(i), u8(j), tmp)
            ys.append(tmp)
        node = (1 << self.height) + q
        path = []
        while node > 1:
            path.append(self._nodes[node ^ 1])
            node //= 2
        return qs + u32(self.ots_type) + randomizer + b"".join(ys) + u32(self.lms_type) + b"".join(path)
