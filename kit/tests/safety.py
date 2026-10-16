import sys, os, json, shutil, subprocess, tempfile
base = tempfile.mkdtemp(); os.chmod(base, 0o700)
hwm = os.path.join(base, "hwm"); os.makedirs(hwm, mode=0o700)
os.environ["BRIDGEGUARD_HWM_DIR"] = hwm
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from bridgeguard import state, lms, encoding

CHAIN = 1
GUARD = "0x" + "a1" * 20

results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def expect_error(fn, contains):
    try:
        fn()
    except Exception as e:
        return contains in str(e)
    return False


digest = bytes(32)
d = os.path.join(base, "k"); state.generate(d, 5, 3, reserve=4, chain_id=CHAIN, guard=GUARD)
for i in range(28):
    state.sign(d, os.urandom(32), "root", 0)
check("root signing refused once only reserve remains", expect_error(lambda: state.sign(d, digest, "root", 0), "reserve"))
check("config signing may use reserve leaves", len(state.sign(d, digest, "config", 0)) > 0)
check("leaf counter advanced exactly", state.status(d)["next"] == 29)
check("on chain counter above capacity rejected as an input error", expect_error(lambda: state.sign(d, digest, "config", 10**9), "outside"))
check("an input error does not retire the key", not state.status(d)["retired"])

r = os.path.join(base, "restore"); state.generate(r, 6, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
state.sign(r, os.urandom(32), "root", 0)
saved_state = open(os.path.join(r, "state.json"), "rb").read()
saved_journal = open(os.path.join(r, "journal.log"), "rb").read()
state.sign(r, os.urandom(32), "root", 0)
for name, data in (("state.json", saved_state), ("journal.log", saved_journal)):
    p = os.path.join(r, name); os.chmod(p, 0o600); open(p, "wb").write(data); os.chmod(p, 0o600)
check("in place backup restore of state and journal is refused", expect_error(lambda: state.sign(r, os.urandom(32), "root", 1), "behind"))
target = state.rebind(r, 1)
check("rebind jumps past every possibly issued leaf", target >= 2 + state.REBIND_GAP)
check("signing after rebind uses a fresh leaf", lms.leaf_index(state.sign(r, os.urandom(32), "root", 2)) == target)

c = os.path.join(base, "clone"); state.generate(c, 6, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
state.sign(c, os.urandom(32), "root", 0)
c2 = os.path.join(base, "clone2"); shutil.copytree(c, c2); os.chmod(c2, 0o700)
check("copied key directory refused", expect_error(lambda: state.sign(c2, digest, "config", 1), "copied"))
state.rebind(c2, 1)
check("original refused after a clone was rebound", expect_error(lambda: state.sign(c, os.urandom(32), "root", 1), "behind"))

b = os.path.join(base, "behind"); state.generate(b, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
state.sign(b, digest, "root", 0)
check("state behind the on chain counter refused", expect_error(lambda: state.sign(b, digest, "root", 5), "behind"))
check("being behind does not retire automatically", not state.status(b)["retired"])
state.retire(b, "operator decision")
check("retired key never signs again", expect_error(lambda: state.sign(b, digest, "root", 0), "retired"))
check("retired key cannot be rebound", expect_error(lambda: state.rebind(b, 1), "retired"))

d3 = os.path.join(base, "k3"); state.generate(d3, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
tree = os.path.join(d3, "tree.bin"); blob = bytearray(open(tree, "rb").read())
blob[32 * ((1 << 5) + 0)] ^= 0xFF
os.chmod(tree, 0o600); open(tree, "wb").write(bytes(blob)); os.chmod(tree, 0o600)
check("corrupt tree cache detected", expect_error(lambda: state.sign(d3, digest, "root", 0), "corrupt"))
check("corrupt tree cache burned no leaf", json.load(open(os.path.join(d3, "state.json")))["next"] == 0)

d4 = os.path.join(base, "k4"); state.generate(d4, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD); os.chmod(d4, 0o755)
check("group or world accessible directory refused", expect_error(lambda: state.sign(d4, digest, "root", 0), "group or others"))
d5 = os.path.join(base, "k5"); state.generate(d5, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
os.rename(os.path.join(d5, "key.json"), os.path.join(base, "realkey.json")); os.symlink(os.path.join(base, "realkey.json"), os.path.join(d5, "key.json"))
check("symlinked key file refused", expect_error(lambda: state.sign(d5, digest, "root", 0), "regular file"))
if sys.platform == "darwin":
    d7 = os.path.join(base, "k7"); state.generate(d7, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
    subprocess.run(["chmod", "+a", "everyone allow add_file,delete_child", d7], check=True)
    check("directory with an access control list refused", expect_error(lambda: state.sign(d7, digest, "root", 0), "access control"))
    d9 = os.path.join(base, "k9"); state.generate(d9, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
    subprocess.run(["chmod", "+a", "everyone allow read", os.path.join(d9, "key.json")], check=True)
    check("key file with an access control list refused", expect_error(lambda: state.sign(d9, digest, "root", 0), "access control"))
    d10 = os.path.join(base, "-k"); state.generate(d10, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
    subprocess.run(["chmod", "+a", "everyone allow add_file", d10], check=True)
    check("option like directory name cannot hide an access control list", expect_error(lambda: state.sign(d10, digest, "root", 0), "access control"))
d8 = os.path.join(base, "k8"); state.generate(d8, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
check("signing without the on chain counter refused", expect_error(lambda: state.sign(d8, digest, "root", None), "required"))
sk8 = state._load(d8)
check("randomizer is deterministic per leaf and message", state._randomizer(sk8.randomizer_key, 3, digest) == state._randomizer(sk8.randomizer_key, 3, digest)
      and state._randomizer(sk8.randomizer_key, 3, digest) != state._randomizer(sk8.randomizer_key, 4, digest))
check("randomizer key is independent of the LMS seed", len(sk8.randomizer_key) == 32 and sk8.randomizer_key != sk8.seed)
pub8 = sk8.public_key()
check("high water mark never moves backwards", expect_error(lambda: state._hwm_write(d8, pub8, 0) or state._hwm_write(d8, pub8, 5) or state._hwm_write(d8, pub8, 4), "backwards"))
check("invalid configuration rejected before signing", expect_error(lambda: encoding.validate_config([("0x" + "11" * 20, b"\x00", bytes(32))], 1, 0), "malformed"))
check("minority threshold rejected before signing", expect_error(lambda: encoding.validate_config([("0x" + "11" * 20, pub8, bytes(32)), ("0x" + "22" * 20, pub8 + b"", bytes(32))], 1, 0), "majority"))
check("keygen into existing directory refused", expect_error(lambda: state.generate(d, 5, 3, chain_id=CHAIN, guard=GUARD), "exists"))
check("heights above 20 refused in pure python", expect_error(lambda: state.generate(os.path.join(base, "big"), 9, 3, chain_id=CHAIN, guard=GUARD), "native"))

saved_env = os.environ.pop("BRIDGEGUARD_HWM_DIR")
check("signing without an explicit high water mark directory refused", expect_error(lambda: state.sign(d8, digest, "root", 0), "BRIDGEGUARD_HWM_DIR"))
os.environ["BRIDGEGUARD_HWM_DIR"] = "relative/hwm"
check("relative high water mark directory refused", expect_error(lambda: state.sign(d8, digest, "root", 0), "absolute"))
os.environ["BRIDGEGUARD_HWM_DIR"] = os.path.join(d8, "hwm")
inside_sign = expect_error(lambda: state.sign(d8, digest, "root", 0), "outside")
os.environ["BRIDGEGUARD_HWM_DIR"] = os.path.join(base, "k11", "hwm")
inside_gen = expect_error(lambda: state.generate(os.path.join(base, "k11"), 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD), "outside")
os.environ["BRIDGEGUARD_HWM_DIR"] = base
parent = expect_error(lambda: state.sign(d8, digest, "root", 0), "outside")
check("high water mark inside or above the key directory refused", inside_sign and inside_gen and parent
      and not os.path.exists(os.path.join(d8, "hwm")) and not os.path.exists(os.path.join(base, "k11")))
os.environ["BRIDGEGUARD_HWM_DIR"] = saved_env

m = os.path.join(base, "lost"); state.generate(m, 6, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
for _ in range(3):
    state.sign(m, os.urandom(32), "root", 0)
pubm = bytes.fromhex(state.status(m)["public_key"])
os.unlink(os.path.join(hwm, state._hwm_name(pubm)))
check("lost high water mark refuses to sign", expect_error(lambda: state.sign(m, digest, "root", 3), "retire this key or rebind"))
check("lost high water mark refuses rebind without an issued leaf bound", expect_error(lambda: state.rebind(m, 1), "upper bound"))
target = state.rebind(m, 1, issued_upper_bound=40)
check("rebind with an issued leaf bound jumps past the bound", target >= 40 + state.REBIND_GAP and state.status(m)["high_water_mark"] == target)

t = os.path.join(base, "tomb"); state.generate(t, 6, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
state.sign(t, os.urandom(32), "root", 0)
backup = os.path.join(base, "tomb_backup"); shutil.copytree(t, backup); os.chmod(backup, 0o700)
state.retire(t, "rotated out")
check("retirement tombstone stops a backup copy from rebinding", expect_error(lambda: state.rebind(backup, 1), "retired"))
check("retirement tombstone stops a backup copy from signing", expect_error(lambda: state.sign(backup, digest, "root", 1), "retired")
      or expect_error(lambda: state.sign(backup, digest, "root", 1), "copied"))

j = os.path.join(base, "torn"); state.generate(j, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
state.sign(j, os.urandom(32), "root", 0)
jp = os.path.join(j, "journal.log")
with open(jp, "ab") as f:
    f.write(b'{"leaf": 1, "purp')
check("torn final journal line tolerated", len(state.sign(j, os.urandom(32), "root", 1)) > 0)
data = open(jp, "rb").read().replace(b'{"leaf": 1, "purp', b'{"leaf": 1, "purp\n', 1)
os.chmod(jp, 0o600); open(jp, "wb").write(data); os.chmod(jp, 0o600)
check("damaged journal line before the end refused", expect_error(lambda: state.sign(j, os.urandom(32), "root", 2), "damaged"))

import fcntl
lk = os.path.join(base, "lk"); state.generate(lk, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
pubk = bytes.fromhex(state.status(lk)["public_key"])
lfd = os.open(os.path.join(hwm, state._hwm_name(pubk) + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(lfd, fcntl.LOCK_EX)
code = (f"import sys,os;os.environ['BRIDGEGUARD_HWM_DIR']={hwm!r};sys.path.insert(0,{os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')!r});"
        f"from bridgeguard import state;state.sign({lk!r},os.urandom(32),'root',0);print('signed')")
proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
try:
    proc.wait(timeout=1.5)
    blocked = False
except subprocess.TimeoutExpired:
    blocked = True
fcntl.flock(lfd, fcntl.LOCK_UN); os.close(lfd)
out, _ = proc.communicate(timeout=30)
check("a per key lock spans every copy of the key", blocked and "signed" in out)

big = [("0x" + f"{i + 1:040x}", (5).to_bytes(4, "big") + (3).to_bytes(4, "big") + i.to_bytes(16, "big") + bytes(32), bytes(32)) for i in range(57)]
check("rotation gas rule refuses 29 of 57 W4 signers", expect_error(lambda: encoding.validate_config(big, 29, 0), "budget"))
ok = [("0x" + f"{i + 1:040x}", (8).to_bytes(4, "big") + (3).to_bytes(4, "big") + i.to_bytes(16, "big") + bytes(32), bytes(32)) for i in range(47)]
try:
    encoding.validate_config(ok, 24, 0)
    accepted = True
except ValueError:
    accepted = False
check("rotation gas rule accepts 24 of 47 W4 H20 signers", accepted)

d6 = os.path.join(base, "k6"); state.generate(d6, 6, 3, reserve=4, chain_id=CHAIN, guard=GUARD)
code = (f"import sys,os;os.environ['BRIDGEGUARD_HWM_DIR']={hwm!r};sys.path.insert(0,{os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')!r});"
        f"from bridgeguard import state;[sys.stdout.write(str(int.from_bytes(state.sign({d6!r},os.urandom(32),'root',0)[:4],'big'))+chr(10)) for _ in range(25)]")
procs = [subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True) for _ in range(8)]
leaves = []
for p in procs:
    out, _ = p.communicate(); leaves += [int(x) for x in out.split()]
check(f"8 concurrent signer processes, {len(leaves)} signatures, no duplicate leaf", len(leaves) == 200 and len(set(leaves)) == 200)
journal = [json.loads(l)["leaf"] for l in open(os.path.join(d6, "journal.log"))]
check("journal records every leaf exactly once", sorted(journal) == sorted(leaves))
nf = os.path.join(base, "nfs"); state.generate(nf, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
real_fs = state._filesystem_type
state._filesystem_type = lambda p: "nfs4" if os.path.realpath(p).startswith(os.path.realpath(nf)) else real_fs(p)
check("key directory on a network file system refused", expect_error(lambda: state.sign(nf, digest, "root", 0), "network file system"))
state._filesystem_type = lambda p: "cifs" if os.path.realpath(p).startswith(os.path.realpath(hwm)) else real_fs(p)
check("high water mark on a network file system refused", expect_error(lambda: state.sign(d8, digest, "root", 0), "network file system"))
state._filesystem_type = real_fs
mounts = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n40 22 0:50 / /srv/keys rw - nfs4 server:/export rw\n"
check("linux mount table resolves the deepest mount", state._deepest("/srv/keys/k1", state._linux_mounts(mounts)) == "nfs4"
      and state._deepest("/home/k", state._linux_mounts(mounts)) == "ext4")
check("macOS mount table resolves the deepest mount", state._deepest("/Volumes/k/a", state._darwin_mounts(
    "/dev/disk3s1 on / (apfs, local)\nhost:/x on /Volumes/k (nfs, nodev)")) == "nfs")

bd = os.path.join(base, "bound"); pub_bd = state.generate(bd, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
salt_bd = state.identifier_salt(bd)
check("key identifier is fully derived from the chain, the guard and its salt", pub_bd[8:24] == encoding.identifier_for(CHAIN, GUARD, salt_bd))
other = os.path.join(base, "bound2"); pub_other = state.generate(other, 5, 3, reserve=2, chain_id=CHAIN, guard=GUARD)
salt_other = state.identifier_salt(other)
check("every key draws its own identifier salt", salt_bd != salt_other and len(salt_bd) == 32)
check("keys for one guard keep distinct identifiers", pub_bd[8:24] != pub_other[8:24])
check("signing for the bound guard is allowed", state.check_binding(bd, CHAIN, GUARD) is None)
check("signing for another guard refused", expect_error(lambda: state.check_binding(bd, CHAIN, "0x" + "b2" * 20), "another guard"))
check("signing for another chain refused", expect_error(lambda: state.check_binding(bd, CHAIN + 1, GUARD), "another guard"))
committee = [("0x" + f"{i + 1:040x}", p, t) for i, (p, t) in enumerate(((pub_bd, salt_bd), (pub_other, salt_other)))]
try:
    encoding.validate_config(committee, 2, 0, CHAIN, GUARD)
    bound_ok = True
except ValueError:
    bound_ok = False
check("committee of keys bound to the guard validates", bound_ok)
check("committee validated for another guard refused", expect_error(lambda: encoding.validate_config(committee, 2, 0, CHAIN, "0x" + "b2" * 20), "not bound"))
dup = bytearray(pub_other); dup[8:24] = pub_bd[8:24]; dup[24] ^= 1
check("committee with a duplicate identifier refused", expect_error(lambda: encoding.validate_config([committee[0], ("0x" + "02" * 20, bytes(dup), salt_bd)], 2, 0, CHAIN, GUARD), "duplicate LMS identifier"))
check("a key presented with another salt refused", expect_error(lambda: encoding.validate_config([committee[0], (committee[1][0], pub_other, salt_bd)], 2, 0, CHAIN, GUARD), "not bound"))
check("a key whose identifier shares only a prefix refused", expect_error(lambda: encoding.validate_config([committee[0], (committee[1][0], bytes(pub_other[:16]) + bytes(8) + bytes(pub_other[24:]), salt_other)], 2, 0, CHAIN, GUARD), "not bound"))

ok = sum(1 for _, r in results if r)
print(f"{ok} of {len(results)} kit safety checks passed")
shutil.rmtree(base, ignore_errors=True)
sys.exit(0 if ok == len(results) else 1)
