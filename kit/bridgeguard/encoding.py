from .keccak import keccak256

ROOT_TAG = keccak256(b"QUANTOVA_BRIDGE_GUARD_ROOT_V1")
CONFIG_TAG = keccak256(b"QUANTOVA_BRIDGE_GUARD_CONFIG_V1")
LAYERZERO_TAG = keccak256(b"QUANTOVA_BRIDGE_GUARD_LAYERZERO_V1")


def word(v, bits=256):
    if not isinstance(v, int) or isinstance(v, bool) or v < 0 or v >= 1 << bits:
        raise ValueError("integer out of range")
    return v.to_bytes(32, "big")


def b32(v):
    if not isinstance(v, (bytes, bytearray)) or len(v) != 32:
        raise ValueError("expected 32 bytes")
    return bytes(v)


def addr(a):
    a = a[2:] if a.startswith("0x") else a
    b = bytes.fromhex(a)
    if len(b) != 20:
        raise ValueError("address length")
    return b.rjust(32, b"\x00")


def dynamic_bytes(b):
    pad = (32 - len(b) % 32) % 32
    return word(len(b)) + b + b"\x00" * pad


def encode_signers(signers):
    n = len(signers)
    tuples = []
    for ecdsa_address, lms_public_key in signers:
        tuples.append(addr(ecdsa_address) + word(64) + dynamic_bytes(bytes(lms_public_key)))
    offsets = []
    off = 32 * n
    for t in tuples:
        offsets.append(word(off))
        off += len(t)
    return word(32) + word(n) + b"".join(offsets) + b"".join(tuples)


REVOKE_TAG = keccak256(b"QUANTOVA_BRIDGE_GUARD_REVOKE_V1")


def root_digest(chain_id, guard, epoch, root):
    return keccak256(ROOT_TAG + word(chain_id) + addr(guard) + word(epoch, 64) + b32(root))


def revoke_digest(chain_id, guard, epoch, root):
    return keccak256(REVOKE_TAG + word(chain_id) + addr(guard) + word(epoch, 64) + b32(root))


def config_digest(chain_id, guard, epoch, signers, threshold, mode):
    return keccak256(
        CONFIG_TAG + word(chain_id) + addr(guard) + word(epoch, 64) + keccak256(encode_signers(signers)) + word(threshold)
        + word(mode, 8)
    )


def layerzero_leaf(local_eid, dvn, receive_lib, packet_header, payload_hash, confirmations):
    if len(packet_header) != 81 or packet_header[0] != 1 or int.from_bytes(packet_header[45:49], "big") != local_eid:
        raise ValueError("packet header is not addressed to this endpoint")
    return keccak256(
        LAYERZERO_TAG + word(local_eid, 32) + addr(dvn) + addr(receive_lib) + keccak256(packet_header) + b32(payload_hash)
        + word(confirmations, 64)
    )


def leaf_hash(leaf):
    return keccak256(b"\x00" + b32(leaf))


def node_hash(left, right):
    return keccak256(b"\x01" + left + right)


def merkle(leaves):
    if not leaves:
        raise ValueError("no leaves")
    depth = max(0, (len(leaves) - 1).bit_length())
    level = [leaf_hash(x) for x in leaves] + [bytes(32)] * ((1 << depth) - len(leaves))
    levels = [level]
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    proofs = []
    for idx in range(len(leaves)):
        path = []
        j = idx
        for lv in levels[:-1]:
            path.append(lv[j ^ 1])
            j >>= 1
        proofs.append(path)
    return levels[-1][0], proofs


GAS_BUDGET = 14_000_000
CALLDATA_BUDGET = 120_000
ROTATION_GAS_BUDGET = 16_000_000
ROTATION_GAS_PER_SIGNER = 90_000
_EXECUTION = {1: 290_000, 2: 235_000, 3: 360_000, 4: 2_500_000}
_HEIGHT = {5: 5, 6: 10, 7: 15, 8: 20, 9: 25}
_P = {1: 265, 2: 133, 3: 67, 4: 34}


def attestation_cost(public_key):
    if len(public_key) != 56:
        return 0, 0
    lms_type = int.from_bytes(public_key[0:4], "big")
    ots_type = int.from_bytes(public_key[4:8], "big")
    if lms_type not in _HEIGHT or ots_type not in _P:
        return 0, 0
    length = 44 + 32 * _P[ots_type] + 32 * _HEIGHT[lms_type]
    size = length + 65 + 7 * 32
    gas = _EXECUTION[ots_type] + 300 * _HEIGHT[lms_type] + 16 * size + 70_000
    return gas, size


def validate_config(signers, threshold, mode):
    n = len(signers)
    if n == 0 or threshold > n or threshold * 2 <= n:
        raise ValueError("threshold must be a strict majority of the signer set")
    worst_gas = 0
    worst_size = 0
    seen_keys = set()
    seen_ecdsa = set()
    for ecdsa_address, public_key in signers:
        gas, size = attestation_cost(public_key)
        if gas == 0:
            raise ValueError("unsupported or malformed LMS public key")
        worst_gas = max(worst_gas, gas)
        worst_size = max(worst_size, size)
        if public_key in seen_keys:
            raise ValueError("duplicate LMS public key")
        seen_keys.add(public_key)
        if mode == 0:
            a = addr(ecdsa_address)
            if a == bytes(32):
                raise ValueError("hybrid mode needs a nonzero ECDSA address for every signer")
            if a in seen_ecdsa:
                raise ValueError("duplicate ECDSA address")
            seen_ecdsa.add(a)
    if (
        threshold * worst_gas > GAS_BUDGET or threshold * worst_size > CALLDATA_BUDGET
        or threshold * worst_gas + n * ROTATION_GAS_PER_SIGNER > ROTATION_GAS_BUDGET
    ):
        raise ValueError("configuration exceeds the gas or transaction size budget")
