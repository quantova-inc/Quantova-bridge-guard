import argparse
import json
import sys

from . import ecdsa, encoding, lms, state

LMS_BY_HEIGHT = {5: 5, 10: 6, 15: 7, 20: 8}
OTS_BY_W = {1: 1, 2: 2, 4: 3, 8: 4}


def _hex(s, length=None):
    b = bytes.fromhex(s[2:] if s.startswith("0x") else s)
    if length is not None and len(b) != length:
        raise SystemExit(f"expected {length} bytes")
    return b


def _read_secret(path):
    with open(path) as f:
        return _hex(f.read().strip(), 32)


def _out(obj):
    sys.stdout.write(json.dumps(obj, indent=2) + "\n")


def _show(fields):
    sys.stderr.write("signing " + json.dumps(fields) + "\n")


def _attest(args, digest, purpose):
    result = {"signer": args.signer, "digest": "0x" + digest.hex(), "ecdsaSignature": "0x", "lmsSignature": None}
    state.check_binding(args.dir, args.chain_id, args.guard)
    if args.ecdsa_key_file:
        result["ecdsaSignature"] = "0x" + ecdsa.sign_digest(_read_secret(args.ecdsa_key_file), digest).hex()
    result["lmsSignature"] = "0x" + state.sign(args.dir, digest, purpose, args.onchain_next_leaf).hex()
    _out(result)


def _signer_args(p):
    p.add_argument("--dir", required=True)
    p.add_argument("--signer", type=int, required=True)
    p.add_argument("--ecdsa-key-file")
    p.add_argument("--onchain-next-leaf", type=int, required=True)
    p.add_argument("--chain-id", type=int, required=True)
    p.add_argument("--guard", required=True)
    p.add_argument("--epoch", type=int, required=True)


def _load_signers(path):
    with open(path) as f:
        return [(x["ecdsa"], _hex(x["lmsPublicKey"])) for x in json.load(f)]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="bridgeguard")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen")
    g.add_argument("--dir", required=True)
    g.add_argument("--height", type=int, choices=sorted(LMS_BY_HEIGHT), default=15)
    g.add_argument("--winternitz", type=int, choices=sorted(OTS_BY_W), default=4)
    g.add_argument("--reserve", type=int, default=state.DEFAULT_RESERVE)
    g.add_argument("--chain-id", type=int, required=True)
    g.add_argument("--guard", required=True)

    s = sub.add_parser("status")
    s.add_argument("--dir", required=True)

    rt = sub.add_parser("retire")
    rt.add_argument("--dir", required=True)
    rt.add_argument("--reason", required=True)

    rb = sub.add_parser("rebind")
    rb.add_argument("--dir", required=True)
    rb.add_argument("--onchain-next-leaf", type=int, required=True)
    rb.add_argument("--issued-upper-bound", type=int)

    ar = sub.add_parser("attest-root")
    _signer_args(ar)
    ar.add_argument("--root", required=True)

    av = sub.add_parser("attest-revoke")
    _signer_args(av)
    av.add_argument("--root", required=True)

    ac = sub.add_parser("attest-config")
    _signer_args(ac)
    ac.add_argument("--signers", required=True)
    ac.add_argument("--threshold", type=int, required=True)
    ac.add_argument("--mode", type=int, choices=[0, 1], required=True)

    m = sub.add_parser("merkle")
    m.add_argument("--leaves", required=True)

    lz = sub.add_parser("leaf-layerzero")
    lz.add_argument("--eid", type=int, required=True)
    lz.add_argument("--dvn", required=True)
    lz.add_argument("--receive-lib", required=True)
    lz.add_argument("--header", required=True)
    lz.add_argument("--payload-hash", required=True)
    lz.add_argument("--confirmations", type=int, required=True)

    v = sub.add_parser("verify")
    v.add_argument("--public-key", required=True)
    v.add_argument("--message", required=True)
    v.add_argument("--signature", required=True)

    ad = sub.add_parser("ecdsa-address")
    ad.add_argument("--key-file", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "keygen":
        pub = state.generate(
            args.dir, LMS_BY_HEIGHT[args.height], OTS_BY_W[args.winternitz], args.reserve,
            chain_id=args.chain_id, guard=args.guard,
        )
        _out({"public_key": "0x" + pub.hex(), "key_hash": state.key_hash(pub), "capacity": 1 << args.height, "reserve": args.reserve})
    elif args.cmd == "status":
        st = state.status(args.dir)
        st["public_key"] = "0x" + st["public_key"]
        _out(st)
    elif args.cmd == "retire":
        state.retire(args.dir, args.reason)
        _out({"retired": True})
    elif args.cmd == "rebind":
        _out({"rebound": True, "next": state.rebind(args.dir, args.onchain_next_leaf, args.issued_upper_bound)})
    elif args.cmd == "attest-root":
        root = _hex(args.root, 32)
        _show({"purpose": "approve root", "chain_id": args.chain_id, "guard": args.guard, "epoch": args.epoch, "root": args.root})
        _attest(args, encoding.root_digest(args.chain_id, args.guard, args.epoch, root), state.PURPOSE_ROOT)
    elif args.cmd == "attest-revoke":
        root = _hex(args.root, 32)
        _show({"purpose": "revoke root", "chain_id": args.chain_id, "guard": args.guard, "epoch": args.epoch, "root": args.root})
        _attest(args, encoding.revoke_digest(args.chain_id, args.guard, args.epoch, root), state.PURPOSE_REVOKE)
    elif args.cmd == "attest-config":
        try:
            signers = _load_signers(args.signers)
            encoding.validate_config(signers, args.threshold, args.mode, args.chain_id, args.guard)
            d = encoding.config_digest(args.chain_id, args.guard, args.epoch, signers, args.threshold, args.mode)
        except (ValueError, KeyError, TypeError) as e:
            raise SystemExit(f"refusing to sign an invalid configuration, {e}")
        _show({
            "purpose": "reconfigure", "chain_id": args.chain_id, "guard": args.guard, "epoch": args.epoch,
            "signers": [{"ecdsa": a, "lms": "0x" + k.hex()} for a, k in signers], "threshold": args.threshold, "mode": args.mode,
        })
        _attest(args, d, state.PURPOSE_CONFIG)
    elif args.cmd == "merkle":
        with open(args.leaves) as f:
            leaves = [_hex(x, 32) for x in json.load(f)]
        root, proofs = encoding.merkle(leaves)
        _out({
            "root": "0x" + root.hex(),
            "leaves": ["0x" + x.hex() for x in leaves],
            "proofs": [{"index": i, "proof": ["0x" + p.hex() for p in pr]} for i, pr in enumerate(proofs)],
        })
    elif args.cmd == "leaf-layerzero":
        leaf = encoding.layerzero_leaf(
            args.eid, args.dvn, args.receive_lib, _hex(args.header), _hex(args.payload_hash, 32), args.confirmations
        )
        _out({"leaf": "0x" + leaf.hex()})
    elif args.cmd == "verify":
        ok = lms.verify(_hex(args.public_key), _hex(args.message), _hex(args.signature))
        _out({"valid": ok})
        return 0 if ok else 1
    elif args.cmd == "ecdsa-address":
        _out({"address": ecdsa.address(_read_secret(args.key_file))})
    return 0


if __name__ == "__main__":
    sys.exit(main())
