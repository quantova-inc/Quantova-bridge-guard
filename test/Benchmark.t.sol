// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BridgeGuard} from "../src/BridgeGuard.sol";
import {LMSVerifier} from "../src/LMSVerifier.sol";
import {LayerZeroQuantumDVN} from "../src/adapters/LayerZeroQuantumDVN.sol";
import {IEndpointInbound} from "../src/interfaces/ILayerZeroDVN.sol";
import {IBridgeGuard} from "../src/interfaces/IBridgeGuard.sol";
import {MockReceiveUln, MockEndpoint} from "./BridgeGuard.t.sol";

contract VerifyHarness {
    function run(bytes memory pub, bytes memory message, bytes memory sig)
        external
        view
        returns (bool ok, uint256 used)
    {
        uint256 g = gasleft();
        ok = LMSVerifier.verify(pub, message, sig);
        used = g - gasleft();
    }
}

contract BenchmarkTest is Test {
    string constant KIT = "test/helpers/kit.sh";
    string base;
    uint256 keys;

    function _ffi(string memory cmd) internal returns (bytes memory) {
        string[] memory c = new string[](3);
        c[0] = "sh";
        c[1] = "-c";
        c[2] = cmd;
        return vm.ffi(c);
    }

    function _dir(uint256 i) internal view returns (string memory) {
        return string.concat(base, "/b", vm.toString(i));
    }

    function _key(uint256 height, uint256 w) internal returns (uint256 i, bytes memory pub) {
        if (bytes(base).length == 0) base = string(_ffi("d=$(mktemp -d) && chmod 700 $d && printf %s $d"));
        i = keys++;
        string memory out = string(
            _ffi(
                string.concat(
                    KIT,
                    " keygen --dir ",
                    _dir(i),
                    " --height ",
                    vm.toString(height),
                    " --winternitz ",
                    vm.toString(w),
                    " --reserve 2"
                )
            )
        );
        pub = vm.parseJsonBytes(out, ".public_key");
    }

    function _sign(uint256 i, bytes32 digest) internal returns (bytes memory) {
        string[] memory c = new string[](4);
        c[0] = "python3";
        c[1] = "test/helpers/raw_sign.py";
        c[2] = _dir(i);
        c[3] = vm.toString(digest);
        return vm.ffi(c);
    }

    function _ecdsa(uint256 i, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 1, d);
        return abi.encodePacked(r, s, v);
    }

    function test_bench_lms_verification() public {
        VerifyHarness h = new VerifyHarness();
        uint256[4] memory ws = [uint256(1), 2, 4, 8];
        uint256[2] memory hs = [uint256(5), 10];
        for (uint256 a = 0; a < 2; a++) {
            for (uint256 b = 0; b < 4; b++) {
                (uint256 i, bytes memory pub) = _key(hs[a], ws[b]);
                uint256 lo = type(uint256).max;
                uint256 hi;
                uint256 total;
                uint256 len;
                for (uint256 k = 0; k < 16; k++) {
                    bytes32 m = keccak256(abi.encode(a, b, k));
                    bytes memory sig = _sign(i, m);
                    (bool ok, uint256 used) = h.run(pub, abi.encodePacked(m), sig);
                    assertTrue(ok);
                    if (used < lo) lo = used;
                    if (used > hi) hi = used;
                    total += used;
                    len = sig.length;
                }
                string memory tag = string.concat("bench lms H", vm.toString(hs[a]), " W", vm.toString(ws[b]));
                emit log_named_uint(string.concat(tag, " min gas"), lo);
                emit log_named_uint(string.concat(tag, " mean gas"), total / 16);
                emit log_named_uint(string.concat(tag, " max gas"), hi);
                emit log_named_uint(string.concat(tag, " signature bytes"), len);
            }
        }
    }

    function _committee(uint256 n, uint256 first) internal returns (BridgeGuard.Signer[] memory s) {
        s = new BridgeGuard.Signer[](n);
        for (uint256 k = 0; k < n; k++) {
            (uint256 i, bytes memory pub) = _key(10, 4);
            assertEq(i, first + k);
            s[k] = BridgeGuard.Signer(vm.addr(i + 1), pub);
        }
    }

    function _attest(BridgeGuard g, bytes32 d, uint256 t, uint256 first, bool hybrid)
        internal
        returns (BridgeGuard.Attestation[] memory a)
    {
        a = new BridgeGuard.Attestation[](t);
        for (uint256 k = 0; k < t; k++) {
            a[k] = BridgeGuard.Attestation(k, hybrid ? _ecdsa(first + k, d) : bytes(""), _sign(first + k, d));
        }
        g;
    }

    function test_bench_committee_actions() public {
        uint256[4] memory ns = [uint256(3), 4, 7, 10];
        for (uint256 c = 0; c < 4; c++) {
            uint256 n = ns[c];
            uint256 t = n / 2 + 1;
            uint256 first = keys;
            BridgeGuard.Signer[] memory s = _committee(n, first);
            BridgeGuard g = new BridgeGuard(s, t, BridgeGuard.Mode.Hybrid, 60);
            string memory label = string.concat(vm.toString(t), " of ", vm.toString(n), " hybrid H10 W4");
            bytes32 root = keccak256(abi.encode("bench", n));
            BridgeGuard.Attestation[] memory a = _attest(g, g.rootDigest(root), t, first, true);
            uint256 before = gasleft();
            g.approveRoot(root, a);
            emit log_named_uint(string.concat("bench approve ", label, " gas"), before - gasleft());
            emit log_named_uint(
                string.concat("bench approve ", label, " calldata bytes"),
                abi.encodeCall(g.approveRoot, (root, a)).length
            );
            a = _attest(g, g.revokeDigest(root), t, first, true);
            before = gasleft();
            g.revokeRoot(root, a);
            emit log_named_uint(string.concat("bench revoke ", label, " gas"), before - gasleft());
            bytes32 cd = g.configDigest(s, t, BridgeGuard.Mode.PostQuantum);
            a = _attest(g, cd, t, first, true);
            before = gasleft();
            g.reconfigure(s, t, BridgeGuard.Mode.PostQuantum, a);
            emit log_named_uint(string.concat("bench rotate to post quantum ", label, " gas"), before - gasleft());
            root = keccak256(abi.encode("bench pq", n));
            a = _attest(g, g.rootDigest(root), t, first, false);
            before = gasleft();
            g.approveRoot(root, a);
            emit log_named_uint(
                string.concat("bench approve ", vm.toString(t), " of ", vm.toString(n), " post quantum H10 W4 gas"),
                before - gasleft()
            );
        }
    }

    function test_bench_possession_and_equivocation() public {
        uint256 first = keys;
        BridgeGuard.Signer[] memory s = _committee(3, first);
        BridgeGuard g = new BridgeGuard(s, 2, BridgeGuard.Mode.Hybrid, 60);
        bytes32 cd = g.configDigest(s, 2, BridgeGuard.Mode.Hybrid);
        BridgeGuard.Attestation memory p = BridgeGuard.Attestation(2, _ecdsa(first + 2, cd), _sign(first + 2, cd));
        uint256 before = gasleft();
        g.provePossession(s, 2, BridgeGuard.Mode.Hybrid, 2, p);
        emit log_named_uint("bench prove possession H10 W4 hybrid gas", before - gasleft());
        string[] memory c = new string[](6);
        c[0] = "python3";
        c[1] = "test/helpers/equivocate.py";
        c[2] = _dir(first);
        c[3] = vm.toString(keccak256("a"));
        c[4] = vm.toString(keccak256("b"));
        c[5] = "900";
        bytes memory both = vm.ffi(c);
        uint256 half = both.length / 2;
        bytes memory sa = new bytes(half);
        bytes memory sb = new bytes(half);
        for (uint256 i = 0; i < half; i++) {
            sa[i] = both[i];
            sb[i] = both[i + half];
        }
        before = gasleft();
        g.reportEquivocation(s[0].lmsPublicKey, keccak256("a"), sa, keccak256("b"), sb);
        emit log_named_uint("bench report equivocation H10 W4 gas", before - gasleft());
        assertTrue(g.frozenKey(keccak256(s[0].lmsPublicKey)));
    }

    function test_bench_message_acceptance() public {
        uint256 first = keys;
        BridgeGuard.Signer[] memory s = _committee(3, first);
        BridgeGuard g = new BridgeGuard(s, 2, BridgeGuard.Mode.Hybrid, 60);
        MockReceiveUln uln = new MockReceiveUln();
        MockEndpoint ep = new MockEndpoint();
        uint32[] memory dsts = new uint32[](1);
        dsts[0] = 30101;
        LayerZeroQuantumDVN dvn = new LayerZeroQuantumDVN(
            IBridgeGuard(address(g)),
            IEndpointInbound(address(ep)),
            30110,
            address(0x5E),
            dsts,
            payable(address(0xBEEF)),
            0
        );
        uint256 count = 256;
        bytes32[] memory level = new bytes32[](count);
        bytes32 messageLeaf = keccak256("bench message");
        bytes memory header = abi.encodePacked(
            uint8(1), uint64(5), uint32(30101), bytes32(uint256(1)), uint32(30110), bytes32(uint256(2))
        );
        level[0] = g.leafHash(messageLeaf);
        level[1] = g.leafHash(dvn.leafFor(address(uln), header, keccak256("payload"), 15));
        for (uint256 i = 2; i < count; i++) {
            level[i] = g.leafHash(keccak256(abi.encode(i)));
        }
        bytes32[] memory p0 = new bytes32[](8);
        bytes32[] memory p1 = new bytes32[](8);
        for (uint256 d = 0; d < 8; d++) {
            p0[d] = level[(0 >> d) ^ 1];
            p1[d] = level[(1 >> d) ^ 1];
            bytes32[] memory next = new bytes32[](level.length / 2);
            for (uint256 i = 0; i < next.length; i++) {
                next[i] = keccak256(abi.encodePacked(bytes1(0x01), level[2 * i], level[2 * i + 1]));
            }
            level = next;
        }
        bytes32 root = level[0];
        g.approveRoot(root, _attest(g, g.rootDigest(root), 2, first, true));
        vm.warp(vm.getBlockTimestamp() + 60);
        uint256 before = gasleft();
        assertTrue(g.isIncluded(root, messageLeaf, 0, p0));
        emit log_named_uint("bench inclusion check, batch of 256 gas", before - gasleft());
        before = gasleft();
        dvn.submit(address(uln), header, keccak256("payload"), 15, root, 1, p1);
        emit log_named_uint("bench layerzero submit with proof, batch of 256 gas", before - gasleft());
    }
}
