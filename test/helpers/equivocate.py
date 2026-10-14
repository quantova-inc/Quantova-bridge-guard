import sys, os, json, secrets
os.environ.setdefault("BRIDGEGUARD_HWM_DIR", os.path.join(os.environ.get("TMPDIR", "/tmp"), "bridgeguard-test-hwm"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "kit"))
from bridgeguard import state
d, a, b, q = sys.argv[1], bytes.fromhex(sys.argv[2][2:]), bytes.fromhex(sys.argv[3][2:]), int(sys.argv[4])
sk = state._load(d)
sa = sk._sign_leaf(q, a, secrets.token_bytes(32))
sb = sk._sign_leaf(q, b, secrets.token_bytes(32))
sys.stdout.write("0x" + (sa.hex()) + (sb.hex()))
