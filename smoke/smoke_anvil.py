import json, os, secrets, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
KIT = os.path.join(REPO, "test", "helpers", "kit.sh")
RPC = "http://127.0.0.1:8547"
DEPLOYER = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
CHAIN = 31337
LOCAL_DOMAIN = 31337
LZ_EID = 30110


def run(cmd, cwd=REPO):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"command failed {' '.join(cmd[:4])}\n{r.stderr[-2000:]}")
    return r.stdout.strip()


def kit(*args):
    return json.loads(run([KIT, *args]))


def cast_call(addr, sig, *args):
    return run(["cast", "call", "--rpc-url", RPC, addr, sig, *args])


def cast_send(addr, sig, *args):
    out = run(["cast", "send", "--json", "--rpc-url", RPC, "--private-key", DEPLOYER, addr, sig, *args])
    rcpt = json.loads(out)
    if rcpt["status"] not in ("0x1", 1):
        raise SystemExit(f"transaction reverted {sig}")
    return int(rcpt["gasUsed"], 16)


def create(path, *args):
    cmd = ["forge", "create", "--json", "--broadcast", "--rpc-url", RPC, "--private-key", DEPLOYER, path]
    if args:
        cmd += ["--constructor-args", *args]
    return json.loads(run(cmd))["deployedTo"]


report = []


def step(name, ok, extra=""):
    report.append((name, ok, extra))
    print(("PASS " if ok else "FAIL ") + name + (f"  {extra}" if extra else ""), flush=True)
    if not ok:
        raise SystemExit(1)


os.environ["BRIDGEGUARD_HWM_DIR"] = tempfile.mkdtemp(prefix="bridgeguard-smoke-hwm")
anvil = subprocess.Popen(["anvil", "--port", "8547", "--silent", "--hardfork", "prague"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            run(["cast", "block-number", "--rpc-url", RPC])
            break
        except SystemExit:
            time.sleep(0.2)
    bal = int(run(["cast", "balance", "--rpc-url", RPC, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]))
    step("local Ethereum node running with funded test account", bal > 0, f"{bal / 1e18:.0f} test ETH")

    work = tempfile.mkdtemp()
    os.chmod(work, 0o700)
    signers = []
    for i in range(4):
        kd = os.path.join(work, f"signer{i}")
        pub = kit("keygen", "--dir", kd, "--height", "10", "--winternitz", "4", "--reserve", "8")["public_key"]
        ek = os.path.join(work, f"ecdsa{i}.key")
        fd = os.open(ek, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, secrets.token_hex(32).encode())
        os.close(fd)
        addr = kit("ecdsa-address", "--key-file", ek)["address"]
        signers.append({"dir": kd, "pub": pub, "ecdsa_file": ek, "addr": addr})
    step("four signer keys generated", True, "LMS SHA256 M32 H10 with LMOTS W4, plus secp256k1")

    signer_arg = "[" + ",".join(f"({s['addr']},{s['pub']})" for s in signers) + "]"
    guard = create("src/BridgeGuard.sol:BridgeGuard", signer_arg, "3", "0", "60")
    step("BridgeGuard deployed", True, guard)
    uln = create("test/BridgeGuard.t.sol:MockReceiveUln")
    sendlib = create("test/BridgeGuard.t.sol:MockSendLib")
    endpoint = create("test/BridgeGuard.t.sol:MockEndpoint")
    dvn = create(
        "src/adapters/LayerZeroQuantumDVN.sol:LayerZeroQuantumDVN", guard, endpoint, str(LZ_EID), sendlib, "[30101]",
        "0x000000000000000000000000000000000000bEEF", "1000"
    )
    step("LayerZero verifier deployed", True, dvn)

    messages = [run(["cast", "keccak", f"transfer {n}"]) for n in range(3)]
    header = "0x01" + f"{9:016x}" + f"{30101:08x}" + "00" * 31 + "11" + f"{LZ_EID:08x}" + "00" * 31 + "22"
    payload = "0x" + secrets.token_hex(32)
    lz_leaf = kit("leaf-layerzero", "--eid", str(LZ_EID), "--dvn", dvn, "--receive-lib", uln, "--header", header,
                  "--payload-hash", payload, "--confirmations", "12")["leaf"]
    leaves = messages + [lz_leaf]
    lf = os.path.join(work, "leaves.json")
    json.dump(leaves, open(lf, "w"))
    tree = kit("merkle", "--leaves", lf)
    root = tree["root"]
    onchain_leaf = cast_call(dvn, "leafFor(address,bytes,bytes32,uint64)(bytes32)", uln, header, payload, "12")
    step("kit leaves match the contracts", onchain_leaf == lz_leaf, f"{len(leaves)} messages in one batch")

    def attest(kind, idx, *extra):
        s = signers[idx]
        epoch = cast_call(guard, "epoch()(uint64)")
        nxt = cast_call(guard, "nextLeafOf(uint256)(uint256)", str(idx)).split()[0]
        out = kit(kind, "--dir", s["dir"], "--signer", str(idx), "--ecdsa-key-file", s["ecdsa_file"], "--onchain-next-leaf", nxt,
                  "--chain-id", str(CHAIN), "--guard", guard, "--epoch", epoch, *extra)
        return f"({idx},{out['ecdsaSignature']},{out['lmsSignature']})"

    atts = "[" + ",".join(attest("attest-root", i, "--root", root) for i in (0, 1, 2)) + "]"
    gas = cast_send(guard, "approveRoot(bytes32,(uint256,bytes,bytes)[])", root, atts)
    early = cast_call(guard, "isApproved(bytes32)(bool)", root)
    run(["cast", "rpc", "--rpc-url", RPC, "evm_increaseTime", "61"])
    run(["cast", "rpc", "--rpc-url", RPC, "evm_mine"])
    approved = cast_call(guard, "isApproved(bytes32)(bool)", root)
    step("batch approved by 3 of 4 hybrid post quantum attestations after the minimum root age",
         early == "false" and approved == "true", f"{gas} gas")

    before = [cast_call(guard, "nextLeafOf(uint256)(uint256)", str(i)) for i in range(4)] + [cast_call(guard, "rootApprovedAt(bytes32)(uint64)", root)]
    cast_send(guard, "approveRoot(bytes32,(uint256,bytes,bytes)[])", root, atts)
    after = [cast_call(guard, "nextLeafOf(uint256)(uint256)", str(i)) for i in range(4)] + [cast_call(guard, "rootApprovedAt(bytes32)(uint64)", root)]
    other = subprocess.run(["cast", "send", "--rpc-url", RPC, "--private-key", DEPLOYER, guard,
                            "approveRoot(bytes32,(uint256,bytes,bytes)[])", "0x" + "ee" * 32, atts], cwd=REPO, capture_output=True, text=True)
    step("replayed attestations change nothing and cannot approve another root", before == after and other.returncode != 0)

    proof0 = "[" + ",".join(tree["proofs"][0]["proof"]) + "]"
    included = cast_call(guard, "isIncluded(bytes32,bytes32,uint256,bytes32[])(bool)", root, messages[0], "0", proof0)
    forged = cast_call(guard, "isIncluded(bytes32,bytes32,uint256,bytes32[])(bool)", root, messages[1], "0", proof0)
    step("message accepted by its inclusion proof and a forged message refused", included == "true" and forged == "false")

    gas = cast_send(dvn, "submit(address,bytes,bytes32,uint64,bytes32,uint256,bytes32[])", uln, header, payload, "12", root, "3",
                    "[" + ",".join(tree["proofs"][3]["proof"]) + "]")
    step("LayerZero packet verified and forwarded to the receive library", cast_call(uln, "calls()(uint256)") == "1", f"{gas} gas")

    ratts = "[" + ",".join(attest("attest-revoke", i, "--root", root) for i in (1, 2, 3)) + "]"
    gas = cast_send(guard, "revokeRoot(bytes32,(uint256,bytes,bytes)[])", root, ratts)
    step("batch revoked by quorum", cast_call(guard, "isApproved(bytes32)(bool)", root) == "false", f"{gas} gas")

    sj = os.path.join(work, "signers.json")
    json.dump([{"ecdsa": s["addr"], "lmsPublicKey": s["pub"]} for s in signers], open(sj, "w"))
    proof = attest("attest-config", 3, "--signers", sj, "--threshold", "3", "--mode", "1")
    pgas = cast_send(guard, "provePossession((address,bytes)[],uint256,uint8,uint256,(uint256,bytes,bytes))", signer_arg, "3", "1", "3", proof)
    q = "[" + ",".join(attest("attest-config", i, "--signers", sj, "--threshold", "3", "--mode", "1") for i in (0, 1, 2)) + "]"
    gas = cast_send(guard, "reconfigure((address,bytes)[],uint256,uint8,(uint256,bytes,bytes)[])", signer_arg, "3", "1", q)
    gas = f"{pgas} gas for the new member proof, {gas}"
    step("committee rotated to post quantum only mode with proof of possession",
         cast_call(guard, "mode()(uint8)") == "1" and cast_call(guard, "epoch()(uint64)") == "2", f"{gas} gas")

    root2 = "0x" + secrets.token_hex(32)
    epoch = cast_call(guard, "epoch()(uint64)")
    atts2 = []
    for i in (0, 2, 3):
        s = signers[i]
        nxt = cast_call(guard, "nextLeafOf(uint256)(uint256)", str(i)).split()[0]
        out = kit("attest-root", "--dir", s["dir"], "--signer", str(i), "--onchain-next-leaf", nxt, "--chain-id", str(CHAIN),
                  "--guard", guard, "--epoch", epoch, "--root", root2)
        atts2.append(f"({i},0x,{out['lmsSignature']})")
    gas = cast_send(guard, "approveRoot(bytes32,(uint256,bytes,bytes)[])", root2, "[" + ",".join(atts2) + "]")
    run(["cast", "rpc", "--rpc-url", RPC, "evm_increaseTime", "61"])
    run(["cast", "rpc", "--rpc-url", RPC, "evm_mine"])
    step("post quantum only approval after rotation", cast_call(guard, "isApproved(bytes32)(bool)", root2) == "true", f"{gas} gas")
    print(f"\n{sum(1 for _, ok, _ in report if ok)} of {len(report)} live steps passed on a local Ethereum node")
finally:
    anvil.terminate()
