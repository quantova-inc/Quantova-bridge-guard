import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys

from . import encoding, lms
from .keccak import keccak256

KEY_FILE = "key.json"
STATE_FILE = "state.json"
TREE_FILE = "tree.bin"
LOCK_FILE = "lock"
JOURNAL_FILE = "journal.log"
RETIRED_FILE = "retired"
DEFAULT_RESERVE = 16
MAX_HEIGHT_TYPE = 8
REBIND_GAP = 64

NETWORK_FILESYSTEMS = {
    "nfs", "nfs4", "smbfs", "cifs", "smb3", "afpfs", "webdav", "davfs", "sshfs", "fuse.sshfs", "9p", "ceph",
    "glusterfs", "fuse.glusterfs", "lustre", "gpfs", "ncpfs", "fuse.rclone", "fuse.s3fs", "fuse.gcsfuse",
}

PURPOSE_ROOT = "root"
PURPOSE_REVOKE = "revoke"
PURPOSE_CONFIG = "config"


class StateError(RuntimeError):
    pass


def _full_sync(fd):
    if sys.platform == "darwin" and hasattr(fcntl, "F_FULLFSYNC"):
        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
    else:
        os.fsync(fd)


def _sync_directory(directory):
    dfd = os.open(directory, os.O_RDONLY)
    try:
        _full_sync(dfd)
    finally:
        os.close(dfd)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:
            raise StateError("short write")
        view = view[n:]


def _has_acl(path):
    path = os.path.abspath(path)
    if sys.platform == "darwin":
        r = subprocess.run(["/bin/ls", "-led", path], capture_output=True, text=True)
        if r.returncode != 0:
            raise StateError("unable to inspect access control lists")
        return any(line.strip().split(" ")[0].rstrip(":").isdigit() for line in r.stdout.splitlines()[1:])
    if sys.platform.startswith("linux"):
        try:
            names = os.listxattr(path, follow_symlinks=False)
        except OSError as e:
            raise StateError("unable to inspect access control lists") from e
        return any(n in ("system.posix_acl_access", "system.posix_acl_default", "system.nfs4_acl") for n in names)
    if os.environ.get("BRIDGEGUARD_ALLOW_UNCHECKED_ACL") == "1":
        return False
    raise StateError("access control lists cannot be checked on this platform")


def _darwin_mounts(text):
    for line in text.splitlines():
        m = re.match(r"^.+? on (.+) \(([^,)]+)", line)
        if m:
            yield m.group(1), m.group(2).strip()


def _linux_mounts(text):
    for line in text.splitlines():
        left, _, right = line.partition(" - ")
        fields = left.split()
        if len(fields) >= 5 and right:
            yield fields[4].replace("\\040", " "), right.split()[0]


def _deepest(real, mounts):
    best, kind = None, None
    for point, fs in mounts:
        if _inside(real, point) and (best is None or len(point) >= len(best)):
            best, kind = point, fs
    return kind


def _filesystem_type(path):
    real = os.path.realpath(path)
    if sys.platform == "darwin":
        r = subprocess.run(["/sbin/mount"], capture_output=True, text=True)
        if r.returncode != 0:
            raise StateError("unable to inspect file systems")
        kind = _deepest(real, _darwin_mounts(r.stdout))
    elif sys.platform.startswith("linux"):
        try:
            with open("/proc/self/mountinfo") as f:
                kind = _deepest(real, _linux_mounts(f.read()))
        except OSError as e:
            raise StateError("unable to inspect file systems") from e
    elif os.environ.get("BRIDGEGUARD_ALLOW_UNCHECKED_ACL") == "1":
        return "unchecked"
    else:
        raise StateError("file systems cannot be checked on this platform")
    if kind is None:
        raise StateError("unable to determine the file system of " + path)
    return kind


def _check_local(path):
    kind = _filesystem_type(path)
    if kind in NETWORK_FILESYSTEMS or kind.startswith("nfs"):
        raise StateError(f"{path} is on a {kind} network file system, where locks are not reliable, use local storage")


def _check_private(path, want_dir):
    st = os.lstat(path)
    if want_dir and not stat.S_ISDIR(st.st_mode):
        raise StateError(f"{path} is not a directory")
    if not want_dir and not stat.S_ISREG(st.st_mode):
        raise StateError(f"{path} is not a regular file")
    if st.st_uid != os.getuid():
        raise StateError(f"{path} is not owned by this user")
    if st.st_mode & 0o077:
        raise StateError(f"{path} must not be accessible by group or others")
    if _has_acl(path):
        raise StateError(f"{path} must not carry an access control list")


def _check_directory(directory):
    _check_private(directory, True)
    _check_local(directory)
    for name in os.listdir(directory):
        if name.startswith(".") and name.endswith(".tmp"):
            continue
        try:
            _check_private(os.path.join(directory, name), False)
        except FileNotFoundError:
            continue


def _write_atomic(directory, name, data):
    path = os.path.join(directory, name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    tmp = os.path.join(directory, f".{name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, flags, 0o600)
    try:
        try:
            _write_all(fd, data)
            _full_sync(fd)
        finally:
            os.close(fd)
        if os.path.getsize(tmp) != len(data):
            raise StateError("incomplete write")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    _sync_directory(directory)


def _read(directory, name, binary=False):
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise StateError(f"{name} has unsafe ownership or permissions")
        data = f.read()
    return data if binary else json.loads(data)


def _fingerprint(directory):
    st = os.stat(directory)
    return hashlib.sha256(f"inode|{st.st_ino}".encode()).hexdigest()


def key_hash(public_key):
    return "0x" + keccak256(public_key).hex()


def _inside(path, parent):
    return os.path.commonpath([path, parent]) == parent


def _hwm_directory(key_directory):
    d = os.environ.get("BRIDGEGUARD_HWM_DIR")
    if not d:
        raise StateError("BRIDGEGUARD_HWM_DIR must name a high water mark directory on storage separate from the key")
    if not os.path.isabs(d):
        raise StateError("BRIDGEGUARD_HWM_DIR must be an absolute path")
    real = os.path.realpath(d)
    key_real = os.path.realpath(key_directory)
    if _inside(real, key_real) or _inside(key_real, real):
        raise StateError("the high water mark directory must be outside the key directory")
    os.makedirs(d, mode=0o700, exist_ok=True)
    _check_private(d, True)
    _check_local(d)
    return d


def _hwm_name(public_key):
    return hashlib.sha256(public_key).hexdigest()


def _hwm_read(key_directory, public_key):
    d = _hwm_directory(key_directory)
    path = os.path.join(d, _hwm_name(public_key))
    if not os.path.exists(path):
        return None
    _check_private(path, False)
    return int(_read(d, _hwm_name(public_key))["next"])


def _hwm_write(key_directory, public_key, value):
    current = _hwm_read(key_directory, public_key)
    if current is not None and int(value) < current:
        raise StateError("the high water mark never moves backwards")
    _write_atomic(_hwm_directory(key_directory), _hwm_name(public_key), json.dumps({"next": int(value)}).encode())


def _journal_max(directory):
    path = os.path.join(directory, JOURNAL_FILE)
    if not os.path.exists(path):
        return -1
    data = _read(directory, JOURNAL_FILE, binary=True).decode()
    lines = data.split("\n")
    highest = -1
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            highest = max(highest, int(json.loads(line)["leaf"]))
        except (ValueError, KeyError, TypeError) as e:
            if i == len(lines) - 1:
                continue
            raise StateError("journal is damaged before its final line, inspect it before signing") from e
    return highest


class _Lock:
    def __init__(self, directory, name=LOCK_FILE):
        self.path = os.path.join(directory, name)

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def generate(directory, lms_type, ots_type, reserve=DEFAULT_RESERVE, *, chain_id, guard):
    if lms_type > MAX_HEIGHT_TYPE:
        raise StateError("tree heights above 20 need a native key generator")
    _hwm_directory(directory)
    os.makedirs(directory, mode=0o700, exist_ok=False)
    _check_private(directory, True)
    with _Lock(directory):
        if os.path.exists(os.path.join(directory, KEY_FILE)):
            raise StateError("key already exists in this directory")
        ident = encoding.identifier_tag(chain_id, guard) + secrets.token_bytes(8)
        seed = secrets.token_bytes(32)
        randomizer_key = secrets.token_bytes(32)
        sk = lms.PrivateKey(lms_type, ots_type, ident, seed).build()
        if not 0 <= reserve < sk.capacity // 2:
            raise StateError("reserve must be below half the key capacity")
        pub = sk.public_key()
        with _Lock(_hwm_directory(directory), _hwm_name(pub) + ".lock"):
            if _hwm_read(directory, pub) is not None:
                raise StateError("a high water mark already exists for this key")
            _write_atomic(directory, TREE_FILE, sk.export_nodes())
            key = {
                "lms_type": lms_type, "ots_type": ots_type, "ident": ident.hex(), "seed": seed.hex(),
                "randomizer_key": randomizer_key.hex(), "public_key": pub.hex(),
                "chain_id": int(chain_id), "guard": "0x" + encoding.addr(guard)[12:].hex(),
            }
            _write_atomic(directory, KEY_FILE, json.dumps(key).encode())
            st = {"next": 0, "public_key": pub.hex(), "reserve": reserve, "fingerprint": _fingerprint(directory)}
            _write_atomic(directory, STATE_FILE, json.dumps(st).encode())
            _hwm_write(directory, pub, 0)
    return pub


def check_binding(directory, chain_id, guard):
    _check_directory(directory)
    key = _read(directory, KEY_FILE)
    ident = bytes.fromhex(key["ident"])
    if ident[:8] != encoding.identifier_tag(chain_id, guard):
        raise StateError("key is bound to another guard or chain, refusing to sign")


def _load(directory):
    _check_directory(directory)
    k = _read(directory, KEY_FILE)
    sk = lms.PrivateKey(k["lms_type"], k["ots_type"], bytes.fromhex(k["ident"]), bytes.fromhex(k["seed"]))
    if os.path.exists(os.path.join(directory, TREE_FILE)):
        sk.load_nodes(_read(directory, TREE_FILE, binary=True))
    if sk.public_key().hex() != k["public_key"]:
        raise StateError("tree cache does not match key")
    if "randomizer_key" not in k:
        raise StateError("key file has no randomizer key, generate a new key")
    sk.randomizer_key = bytes.fromhex(k["randomizer_key"])
    if len(sk.randomizer_key) != 32 or sk.randomizer_key == sk.seed:
        raise StateError("randomizer key is malformed")
    return sk


def _load_state(directory, sk):
    st = _read(directory, STATE_FILE)
    if st["public_key"] != sk.public_key().hex():
        raise StateError("state does not match key")
    return st


def status(directory):
    sk = _load(directory)
    st = _load_state(directory, sk)
    pub = sk.public_key()
    return {
        "next": st["next"],
        "capacity": sk.capacity,
        "remaining": sk.capacity - st["next"],
        "reserve": st["reserve"],
        "high_water_mark": _hwm_read(directory, pub),
        "highest_journal_leaf": _journal_max(directory),
        "bound_to_this_directory": st["fingerprint"] == _fingerprint(directory),
        "retired": os.path.exists(os.path.join(directory, RETIRED_FILE)),
        "public_key": st["public_key"],
        "key_hash": key_hash(pub),
    }


def _check_counter(sk, onchain_next_leaf):
    if onchain_next_leaf is None:
        raise StateError("the on chain leaf counter is required")
    value = int(onchain_next_leaf)
    if value < 0 or value > sk.capacity:
        raise StateError("the on chain leaf counter is outside the key capacity, check the key hash and the guard")
    return value


def retire(directory, reason):
    _check_directory(directory)
    with _Lock(directory):
        _write_atomic(directory, RETIRED_FILE, (reason.strip() + "\n").encode())
        sk = _load(directory)
        pub = sk.public_key()
        with _Lock(_hwm_directory(directory), _hwm_name(pub) + ".lock"):
            current = _hwm_read(directory, pub)
            if current is None or current < sk.capacity:
                _hwm_write(directory, pub, sk.capacity)


def rebind(directory, onchain_next_leaf, issued_upper_bound=None):
    _check_directory(directory)
    with _Lock(directory):
        if os.path.exists(os.path.join(directory, RETIRED_FILE)):
            raise StateError("a retired key cannot be rebound")
        sk = _load(directory)
        st = _load_state(directory, sk)
        onchain = _check_counter(sk, onchain_next_leaf)
        pub = sk.public_key()
        with _Lock(_hwm_directory(directory), _hwm_name(pub) + ".lock"):
            hwm = _hwm_read(directory, pub)
            if hwm is not None and hwm >= sk.capacity:
                raise StateError("a retired key cannot be rebound")
            if hwm is None and issued_upper_bound is None:
                raise StateError(
                    "high water mark missing, retire this key or rebind with an upper bound on issued leaves "
                    "taken from the aggregator and watcher logs"
                )
            bound = 0
            if issued_upper_bound is not None:
                bound = int(issued_upper_bound)
                if bound < 0 or bound > sk.capacity:
                    raise StateError("the issued leaf upper bound is outside the key capacity")
            target = max(int(st["next"]), onchain, _journal_max(directory) + 1, hwm or 0, bound) + REBIND_GAP
            if target >= sk.capacity:
                raise StateError("not enough leaves remain to rebind safely, rotate this key")
            _hwm_write(directory, pub, target)
            st["next"] = target
            st["fingerprint"] = _fingerprint(directory)
            _write_atomic(directory, STATE_FILE, json.dumps(st).encode())
            return target


def _randomizer(randomizer_key, q, message):
    return hmac.new(
        randomizer_key, b"QUANTOVA_BRIDGE_GUARD_RANDOMIZER_V1" + q.to_bytes(4, "big") + message, hashlib.sha256
    ).digest()


def sign(directory, message, purpose, onchain_next_leaf):
    if purpose not in (PURPOSE_ROOT, PURPOSE_REVOKE, PURPOSE_CONFIG):
        raise StateError("unknown purpose")
    if onchain_next_leaf is None:
        raise StateError("the on chain leaf counter is required")
    _check_private(directory, True)
    with _Lock(directory):
        _check_directory(directory)
        if os.path.exists(os.path.join(directory, RETIRED_FILE)):
            raise StateError("key is retired and must not sign again")
        sk = _load(directory)
        st = _load_state(directory, sk)
        pub = sk.public_key()
        onchain = _check_counter(sk, onchain_next_leaf)
        with _Lock(_hwm_directory(directory), _hwm_name(pub) + ".lock"):
            return _sign_locked(directory, sk, st, pub, onchain, message, purpose)


def _sign_locked(directory, sk, st, pub, onchain, message, purpose):
    if st["fingerprint"] != _fingerprint(directory):
        raise StateError(
            "key directory was moved, copied or restored, run rebind only if the high water mark on this host "
            "is intact, otherwise retire this key"
        )
    q = int(st["next"])
    hwm = _hwm_read(directory, pub)
    if hwm is None:
        raise StateError(
            "high water mark missing, retire this key or rebind with an upper bound on issued leaves "
            "taken from the aggregator and watcher logs"
        )
    if hwm >= sk.capacity:
        raise StateError("key is retired and must not sign again")
    if q < hwm or q <= _journal_max(directory):
        raise StateError("local state is behind the high water mark or the journal, run rebind")
    if q < onchain:
        raise StateError("local state is behind the on chain leaf counter, run rebind")
    remaining = sk.capacity - q
    if remaining <= 0:
        raise StateError("key exhausted")
    if purpose == PURPOSE_ROOT and remaining <= st["reserve"]:
        raise StateError("only reserve leaves remain, use them to rotate this key")
    if not sk.check_leaf(q):
        raise StateError("tree cache is corrupt at this leaf, no leaf was consumed")
    _hwm_write(directory, pub, q + 1)
    st["next"] = q + 1
    _write_atomic(directory, STATE_FILE, json.dumps(st).encode())
    signature = sk._sign_leaf(q, message, _randomizer(sk.randomizer_key, q, message))
    if not lms.verify(pub, message, signature):
        raise StateError("self check failed")
    journal = os.path.join(directory, JOURNAL_FILE)
    created = not os.path.exists(journal)
    jfd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        jst = os.fstat(jfd)
        if jst.st_uid != os.getuid() or jst.st_mode & 0o077:
            raise StateError("journal has unsafe ownership or permissions")
        _write_all(jfd, (json.dumps({"leaf": q, "purpose": purpose, "message": message.hex()}) + "\n").encode())
        _full_sync(jfd)
    finally:
        os.close(jfd)
    if created:
        _sync_directory(directory)
    return signature
