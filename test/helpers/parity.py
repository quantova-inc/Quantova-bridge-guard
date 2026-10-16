import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "kit"))
from bridgeguard import encoding


def h(s):
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


a = json.loads(sys.argv[1])
signers = [(x["ecdsa"], h(x["lms"]), h(x["salt"])) for x in a["signers"]]
leaves = [h(x) for x in a["leaves"]]
root, proofs = encoding.merkle(leaves)
out = {
    "root": encoding.root_digest(a["chain"], a["guard"], a["epoch"], h(a["r"])),
    "revoke": encoding.revoke_digest(a["chain"], a["guard"], a["epoch"], h(a["r"])),
    "config": encoding.config_digest(a["chain"], a["guard"], a["epoch"], signers, a["threshold"], a["mode"]),
    "layerzero": encoding.layerzero_leaf(a["eid"], a["dvn"], a["lib"], h(a["header"]), h(a["payload"]), a["confirmations"]),
    "merkle": root,
    "proof": b"".join(proofs[a["index"]]),
}
sys.stdout.write("0x" + b"".join(out[k] for k in ("root", "revoke", "config", "layerzero", "merkle", "proof")).hex())
