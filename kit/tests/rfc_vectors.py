import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from bridgeguard import lms

results = []


def check(name, cond):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name)


for tc in (1, 2):
    vec = json.load(open(os.path.join(HERE, "vectors", f"rfc_tc{tc}.json")))
    for level, v in enumerate(vec):
        pub, msg, sig = bytes.fromhex(v["pub"]), bytes.fromhex(v["msg"]), bytes.fromhex(v["sig"])
        check(f"RFC 8554 test case {tc} level {level} verifies", lms.verify(pub, msg, sig))
        bad = bytearray(msg)
        bad[0] ^= 1
        check(f"RFC 8554 test case {tc} level {level} rejects a changed message", not lms.verify(pub, bytes(bad), sig))
        forged = bytearray(sig)
        forged[len(forged) // 2] ^= 1
        check(f"RFC 8554 test case {tc} level {level} rejects a changed signature", not lms.verify(pub, msg, bytes(forged)))

tc2 = json.load(open(os.path.join(HERE, "vectors", "rfc_tc2.json")))
sk = lms.PrivateKey(6, 3, bytes.fromhex("d08fabd4a2091ff0a8cb4ed834e74534"),
                    bytes.fromhex("558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439")).build()
check("RFC 8554 test case 2 key generation reproduces the published public key", sk.public_key().hex() == tc2[0]["pub"])
m = b"quantova bridge guard self test"
s = sk._sign_leaf(7, m, bytes(32))
check("kit signature verifies", lms.verify(sk.public_key(), m, s))
check("kit signature rejects another message", not lms.verify(sk.public_key(), m + b"x", s))
print(f"{sum(results)} of {len(results)} RFC 8554 checks passed")
sys.exit(0 if all(results) else 1)
