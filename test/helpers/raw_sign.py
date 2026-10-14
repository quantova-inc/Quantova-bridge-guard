import sys, os, json
os.environ.setdefault("BRIDGEGUARD_HWM_DIR", os.path.join(os.environ.get("TMPDIR", "/tmp"), "bridgeguard-test-hwm"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "kit"))
from bridgeguard import state
d, digest = sys.argv[1], bytes.fromhex(sys.argv[2][2:])
purpose = sys.argv[3] if len(sys.argv) > 3 else "config"
sys.stdout.write("0x" + state.sign(d, digest, purpose, 0).hex())
