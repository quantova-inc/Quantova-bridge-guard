import os
import platform
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from bridgeguard import lms, state

base = tempfile.mkdtemp()
os.chmod(base, 0o700)
os.environ["BRIDGEGUARD_HWM_DIR"] = os.path.join(base, "hwm")
print(f"python {platform.python_version()} on {platform.system()} {platform.machine()}")
print("parameters        keygen s   sign ms   verify ms   signature bytes")
for height, lms_type in ((5, 5), (10, 6)):
    for w, ots in ((1, 1), (2, 2), (4, 3), (8, 4)):
        d = os.path.join(base, f"h{height}w{w}")
        t = time.perf_counter()
        pub = state.generate(d, lms_type, ots, reserve=2)
        keygen = time.perf_counter() - t
        signs, verifies = [], []
        for k in range(8):
            m = os.urandom(32)
            t = time.perf_counter()
            sig = state.sign(d, m, "config", k)
            signs.append(time.perf_counter() - t)
            t = time.perf_counter()
            assert lms.verify(pub, m, sig)
            verifies.append(time.perf_counter() - t)
        print(f"H{height:<2} W{w}            {keygen:8.2f}  {1000 * sum(signs) / 8:8.1f}  {1000 * sum(verifies) / 8:10.1f}   {len(sig):>15}")
shutil.rmtree(base, ignore_errors=True)
