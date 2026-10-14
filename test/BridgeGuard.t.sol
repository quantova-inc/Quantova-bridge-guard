// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BridgeGuard} from "../src/BridgeGuard.sol";
import {LayerZeroQuantumDVN} from "../src/adapters/LayerZeroQuantumDVN.sol";
import {ILayerZeroDVN, IEndpointInbound} from "../src/interfaces/ILayerZeroDVN.sol";
import {IBridgeGuard} from "../src/interfaces/IBridgeGuard.sol";

contract MockReceiveUln {
    struct Verification {
        bool submitted;
        uint64 confirmations;
    }

    mapping(bytes32 => mapping(bytes32 => mapping(address => Verification))) public hashLookup;
    address public lastCaller;
    bytes32 public lastPayload;
    uint64 public lastConfirmations;
    uint256 public calls;

    function verify(bytes calldata h, bytes32 p, uint64 c) external {
        hashLookup[keccak256(h)][p][msg.sender] = Verification(true, c);
        lastCaller = msg.sender;
        lastPayload = p;
        lastConfirmations = c;
        calls++;
    }

    function commit(bytes calldata h, bytes32 p, address dvn) external {
        delete hashLookup[keccak256(h)][p][dvn];
    }
}

contract MockEndpoint {
    mapping(address => mapping(uint32 => mapping(bytes32 => mapping(uint64 => bytes32)))) public inboundPayloadHash;

    function set(address r, uint32 e, bytes32 s, uint64 n, bytes32 h) external {
        inboundPayloadHash[r][e][s][n] = h;
    }
}

contract MockSendLib {
    address public lastTo;
    uint256 public lastAmount;
    address public lastCaller;

    function withdrawFee(address to, uint256 amount) external {
        lastCaller = msg.sender;
        lastTo = to;
        lastAmount = amount;
    }
}

contract BridgeGuardTest is Test {
    string constant KIT = "test/helpers/kit.sh";
    uint256 constant N = 4;
    string base;
    uint256[N] ecdsaKeys;
    bytes[N] pubs;
    BridgeGuard guard;
    uint256 savedChainId;

    function _ffi(string memory cmd) internal returns (string memory) {
        string[] memory c = new string[](3);
        c[0] = "sh";
        c[1] = "-c";
        c[2] = cmd;
        return string(vm.ffi(c));
    }

    function _dir(uint256 i) internal view returns (string memory) {
        return string.concat(base, "/k", vm.toString(i));
    }

    function _lms(uint256 i, bytes32 digest) internal returns (bytes memory) {
        string[] memory c = new string[](4);
        c[0] = "python3";
        c[1] = "test/helpers/raw_sign.py";
        c[2] = _dir(i);
        c[3] = vm.toString(digest);
        return vm.ffi(c);
    }

    function _ecdsa(uint256 i, bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecdsaKeys[i], digest);
        return abi.encodePacked(r, s, v);
    }

    function _signers() internal view returns (BridgeGuard.Signer[] memory s) {
        s = new BridgeGuard.Signer[](N);
        for (uint256 i = 0; i < N; i++) {
            s[i] = BridgeGuard.Signer(vm.addr(ecdsaKeys[i]), pubs[i]);
        }
    }

    function _attest(bytes32 digest, uint256[] memory who, bool withEcdsa)
        internal
        returns (BridgeGuard.Attestation[] memory a)
    {
        a = new BridgeGuard.Attestation[](who.length);
        for (uint256 k = 0; k < who.length; k++) {
            a[k] = BridgeGuard.Attestation(who[k], withEcdsa ? _ecdsa(who[k], digest) : bytes(""), _lms(who[k], digest));
        }
    }

    function _prove(BridgeGuard.Signer[] memory s, uint256 t, BridgeGuard.Mode m, uint256 i, bool withEcdsa) internal {
        bytes32 cd = guard.configDigest(s, t, m);
        BridgeGuard.Attestation memory p =
            BridgeGuard.Attestation(i, withEcdsa ? _ecdsa(i, cd) : bytes(""), _lms(i, cd));
        guard.provePossession(s, t, m, i, p);
    }

    function _lmsAt(string memory dir, bytes32 digest) internal returns (bytes memory) {
        string[] memory c = new string[](4);
        c[0] = "python3";
        c[1] = "test/helpers/raw_sign.py";
        c[2] = dir;
        c[3] = vm.toString(digest);
        return vm.ffi(c);
    }

    function _newKey(string memory name) internal returns (string memory dir, bytes memory pub) {
        dir = string.concat(base, "/", name);
        pub = vm.parseJsonBytes(
            _ffi(string.concat(KIT, " keygen --dir ", dir, " --height 10 --winternitz 4 --reserve 4")), ".public_key"
        );
    }

    function _ids(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory r) {
        r = new uint256[](3);
        r[0] = a;
        r[1] = b;
        r[2] = c;
    }

    function setUp() public {
        base = _ffi("d=$(mktemp -d) && chmod 700 $d && printf %s $d");
        for (uint256 i = 0; i < N; i++) {
            ecdsaKeys[i] = uint256(keccak256(abi.encode("ecdsa", i)))
                % 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140 + 1;
            string memory out =
                _ffi(string.concat(KIT, " keygen --dir ", _dir(i), " --height 10 --winternitz 4 --reserve 4"));
            pubs[i] = vm.parseJsonBytes(out, ".public_key");
        }
        guard = new BridgeGuard(_signers(), 3, BridgeGuard.Mode.Hybrid, 60);
    }

    function test_quorum_hybrid_approves_root() public {
        bytes32 root = keccak256("root-1");
        guard.approveRoot(root, _attest(guard.rootDigest(root), _ids(0, 1, 3), true));
        vm.warp(vm.getBlockTimestamp() + 60);
        assertTrue(guard.isApproved(root));
        assertGt(guard.nextLeafOf(0), 0);
    }

    function test_below_threshold_reverts() public {
        bytes32 root = keccak256("root-2");
        uint256[] memory two = new uint256[](2);
        two[0] = 0;
        two[1] = 2;
        BridgeGuard.Attestation[] memory a = _attest(guard.rootDigest(root), two, true);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.QuorumNotReached.selector, 2, 3));
        guard.approveRoot(root, a);
    }

    function test_duplicate_and_unordered_signers_rejected() public {
        bytes32 root = keccak256("root-3");
        BridgeGuard.Attestation[] memory a = _attest(guard.rootDigest(root), _ids(0, 1, 2), true);
        BridgeGuard.Attestation memory keep = a[2];
        a[2] = a[1];
        vm.expectRevert(BridgeGuard.UnorderedAttestation.selector);
        guard.approveRoot(root, a);
        a[2] = a[0];
        a[0] = keep;
        vm.expectRevert(BridgeGuard.UnorderedAttestation.selector);
        guard.approveRoot(root, a);
    }

    function test_classical_signature_failures_rejected() public {
        bytes32 root = keccak256("root-5");
        bytes32 d = guard.rootDigest(root);
        BridgeGuard.Attestation[] memory a = _attest(d, _ids(0, 1, 2), true);
        a[1].ecdsaSignature = _ecdsa(3, d);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidClassicalSignature.selector, 1));
        guard.approveRoot(root, a);
        a[1].ecdsaSignature = "";
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidClassicalSignature.selector, 1));
        guard.approveRoot(root, a);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ecdsaKeys[1], d);
        uint256 n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
        a[1].ecdsaSignature = abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidClassicalSignature.selector, 1));
        guard.approveRoot(root, a);
        a[1].ecdsaSignature = abi.encodePacked(r, s, v - 27);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidClassicalSignature.selector, 1));
        guard.approveRoot(root, a);
    }

    function test_post_quantum_signature_for_other_digest_rejected() public {
        bytes32 root = keccak256("root-8");
        BridgeGuard.Attestation[] memory a = _attest(guard.rootDigest(root), _ids(0, 1, 2), true);
        a[2].lmsSignature = _lms(2, keccak256("something else"));
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidPostQuantumSignature.selector, 2));
        guard.approveRoot(root, a);
    }

    function test_cross_contract_and_cross_chain_replay_rejected() public {
        BridgeGuard other = new BridgeGuard(_signers(), 3, BridgeGuard.Mode.Hybrid, 60);
        bytes32 root = keccak256("root-9");
        BridgeGuard.Attestation[] memory a = _attest(guard.rootDigest(root), _ids(0, 1, 2), true);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidPostQuantumSignature.selector, 0));
        other.approveRoot(root, a);
        savedChainId = block.chainid;
        vm.chainId(savedChainId + 1);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidPostQuantumSignature.selector, 0));
        guard.approveRoot(root, a);
        vm.chainId(savedChainId);
        guard.approveRoot(root, a);
        vm.warp(vm.getBlockTimestamp() + 60);
        assertTrue(guard.isApproved(root));
    }

    function test_attestation_replay_changes_nothing() public {
        bytes32 root = keccak256("root-10");
        bytes32 d = guard.rootDigest(root);
        BridgeGuard.Attestation[] memory a = _attest(d, _ids(0, 1, 2), true);
        guard.approveRoot(root, a);
        vm.warp(vm.getBlockTimestamp() + 60);
        uint64 at = guard.rootApprovedAt(root);
        uint256 next0 = guard.nextLeafOf(0);
        vm.warp(vm.getBlockTimestamp() + 100);
        guard.approveRoot(root, a);
        vm.warp(vm.getBlockTimestamp() + 60);
        assertEq(guard.rootApprovedAt(root), at);
        assertEq(guard.nextLeafOf(0), next0);
        assertFalse(guard.frozenKey(keccak256(pubs[0])));
        bytes memory good = a[1].ecdsaSignature;
        a[1].ecdsaSignature = _ecdsa(3, d);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidClassicalSignature.selector, 1));
        guard.approveRoot(root, a);
        a[1].ecdsaSignature = good;
        bytes32 other = keccak256("root-10b");
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.QuorumNotReached.selector, 0, 3));
        guard.approveRoot(other, a);
    }

    function test_out_of_order_landing_and_revocation_after_later_approval() public {
        bytes32 bad = keccak256("bad root");
        guard.approveRoot(bad, _attest(guard.rootDigest(bad), _ids(0, 1, 2), true));
        vm.warp(vm.getBlockTimestamp() + 60);
        BridgeGuard.Attestation[] memory revoke = _attest(guard.revokeDigest(bad), _ids(0, 1, 2), true);
        bytes32 routine = keccak256("routine root signed later");
        BridgeGuard.Attestation[] memory later = _attest(guard.rootDigest(routine), _ids(0, 1, 2), true);
        guard.approveRoot(routine, later);
        vm.warp(vm.getBlockTimestamp() + 60);
        guard.revokeRoot(bad, revoke);
        assertFalse(guard.isApproved(bad));
        assertTrue(guard.isApproved(routine));
        bytes32 r1 = keccak256("first signed");
        bytes32 r2 = keccak256("second signed");
        BridgeGuard.Attestation[] memory a1 = _attest(guard.rootDigest(r1), _ids(1, 2, 3), true);
        BridgeGuard.Attestation[] memory a2 = _attest(guard.rootDigest(r2), _ids(1, 2, 3), true);
        guard.approveRoot(r2, a2);
        vm.warp(vm.getBlockTimestamp() + 60);
        guard.approveRoot(r1, a1);
        vm.warp(vm.getBlockTimestamp() + 60);
        assertTrue(guard.isApproved(r1) && guard.isApproved(r2));
        BridgeGuard.Attestation[] memory again = _attest(guard.rootDigest(bad), _ids(0, 1, 2), true);
        vm.expectRevert(BridgeGuard.RootIsRevoked.selector);
        guard.approveRoot(bad, again);
    }

    function _equivocate(uint256 signer, bytes32 a, bytes32 b, uint256 q)
        internal
        returns (bytes memory sa, bytes memory sb)
    {
        string[] memory c = new string[](6);
        c[0] = "python3";
        c[1] = "test/helpers/equivocate.py";
        c[2] = _dir(signer);
        c[3] = vm.toString(a);
        c[4] = vm.toString(b);
        c[5] = vm.toString(q);
        bytes memory both = vm.ffi(c);
        uint256 half = both.length / 2;
        sa = new bytes(half);
        sb = new bytes(half);
        for (uint256 i = 0; i < half; i++) {
            sa[i] = both[i];
            sb[i] = both[i + half];
        }
    }

    function test_reused_leaf_cannot_approve_second_root() public {
        bytes32 rootA = keccak256("honest");
        bytes32 rootB = keccak256("attacker chosen");
        (bytes memory sa, bytes memory sb) = _equivocate(1, guard.rootDigest(rootA), guard.rootDigest(rootB), 1000);
        BridgeGuard.Attestation[] memory a = _attest(guard.rootDigest(rootA), _ids(0, 1, 2), true);
        a[1].lmsSignature = sa;
        guard.approveRoot(rootA, a);
        vm.warp(vm.getBlockTimestamp() + 60);
        BridgeGuard.Attestation[] memory b = _attest(guard.rootDigest(rootB), _ids(0, 1, 2), true);
        b[1].lmsSignature = sb;
        uint256 next0 = guard.nextLeafOf(0);
        uint256 leaf0 = uint256(uint32(bytes4(b[0].lmsSignature)));
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.EquivocationDetected.selector, 1, 1000));
        guard.approveRoot(rootB, b);
        assertFalse(guard.isApproved(rootB));
        assertFalse(guard.isLeafUsed(pubs[0], leaf0));
        assertEq(guard.nextLeafOf(0), next0);
        guard.reportEquivocation(pubs[1], guard.rootDigest(rootA), sa, guard.rootDigest(rootB), sb);
        assertTrue(guard.frozenKey(keccak256(pubs[1])));
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.QuorumNotReached.selector, 2, 3));
        guard.approveRoot(rootB, b);
        BridgeGuard.Attestation[] memory c = new BridgeGuard.Attestation[](3);
        c[0] = b[0];
        c[1] = b[2];
        c[2] = _attest(guard.rootDigest(rootB), _one(3), true)[0];
        guard.approveRoot(rootB, c);
        vm.warp(vm.getBlockTimestamp() + 60);
        assertTrue(guard.isApproved(rootB));
        assertTrue(guard.isLeafUsed(pubs[0], leaf0));
    }

    function test_member_poison_cannot_fake_a_successful_revocation() public {
        bytes32 root = keccak256("root-poison");
        guard.approveRoot(root, _attest(guard.rootDigest(root), _ids(0, 1, 2), true));
        vm.warp(vm.getBlockTimestamp() + 60);
        BridgeGuard.Signer[] memory fake = new BridgeGuard.Signer[](1);
        fake[0] = BridgeGuard.Signer(address(0), pubs[1]);
        bytes32 fd = guard.configDigest(fake, 1, BridgeGuard.Mode.PostQuantum);
        bytes32 rd = guard.revokeDigest(root);
        (bytes memory honest, bytes memory poison) = _equivocate(1, rd, fd, 700);
        guard.provePossession(fake, 1, BridgeGuard.Mode.PostQuantum, 0, BridgeGuard.Attestation(0, "", poison));
        BridgeGuard.Attestation[] memory r = _attest(rd, _ids(0, 1, 2), true);
        r[1].lmsSignature = honest;
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.EquivocationDetected.selector, 1, 700));
        guard.revokeRoot(root, r);
        assertTrue(guard.isApproved(root));
        guard.reportEquivocation(pubs[1], rd, honest, fd, poison);
        BridgeGuard.Attestation[] memory r2 = new BridgeGuard.Attestation[](3);
        r2[0] = r[0];
        r2[1] = r[2];
        r2[2] = _attest(rd, _one(3), true)[0];
        guard.revokeRoot(root, r2);
        assertFalse(guard.isApproved(root));
    }

    function _one(uint256 a) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = a;
    }

    function test_front_run_possession_cannot_block_rotation() public {
        BridgeGuard.Signer[] memory s = _signers();
        bytes32 cd = guard.configDigest(s, 3, BridgeGuard.Mode.Hybrid);
        BridgeGuard.Attestation[] memory q = _attest(cd, _ids(0, 1, 2), true);
        for (uint256 k = 0; k < 3; k++) {
            guard.provePossession(s, 3, BridgeGuard.Mode.Hybrid, k, q[k]);
        }
        _prove(s, 3, BridgeGuard.Mode.Hybrid, 3, true);
        guard.reconfigure(s, 3, BridgeGuard.Mode.Hybrid, q);
        assertEq(guard.epoch(), 2);
        for (uint256 k = 0; k < 3; k++) {
            assertFalse(guard.frozenKey(keccak256(pubs[k])));
        }
    }

    function test_possession_with_reused_leaf_freezes() public {
        BridgeGuard.Signer[] memory s = _signers();
        bytes32 cd = guard.configDigest(s, 3, BridgeGuard.Mode.Hybrid);
        bytes32 root = keccak256("root-pp");
        (bytes memory sa, bytes memory sb) = _equivocate(2, guard.rootDigest(root), cd, 600);
        BridgeGuard.Attestation[] memory a = _attest(guard.rootDigest(root), _ids(0, 1, 2), true);
        a[2].lmsSignature = sa;
        guard.approveRoot(root, a);
        vm.warp(vm.getBlockTimestamp() + 60);
        guard.provePossession(s, 3, BridgeGuard.Mode.Hybrid, 2, BridgeGuard.Attestation(2, _ecdsa(2, cd), sb));
        assertTrue(guard.frozenKey(keccak256(pubs[2])));
        assertFalse(guard.possessionProven(cd, keccak256(pubs[2])));
    }

    function test_rotation_reverts_when_new_set_contains_key_frozen_in_same_call() public {
        BridgeGuard.Signer[] memory s = _signers();
        bytes32 cd = guard.configDigest(s, 3, BridgeGuard.Mode.Hybrid);
        bytes32 root = keccak256("root-ab");
        (bytes memory sa, bytes memory sb) = _equivocate(3, guard.rootDigest(root), cd, 500);
        BridgeGuard.Attestation[] memory a = _attest(guard.rootDigest(root), _ids(1, 2, 3), true);
        a[2].lmsSignature = sa;
        guard.approveRoot(root, a);
        vm.warp(vm.getBlockTimestamp() + 60);
        BridgeGuard.Attestation[] memory q = new BridgeGuard.Attestation[](4);
        BridgeGuard.Attestation[] memory fresh = _attest(cd, _ids(0, 1, 2), true);
        q[0] = fresh[0];
        q[1] = fresh[1];
        q[2] = fresh[2];
        q[3] = BridgeGuard.Attestation(3, _ecdsa(3, cd), sb);
        uint256 next0 = guard.nextLeafOf(0);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.EquivocationDetected.selector, 3, 500));
        guard.reconfigure(s, 3, BridgeGuard.Mode.Hybrid, q);
        assertEq(guard.epoch(), 1);
        assertEq(guard.nextLeafOf(0), next0);
    }

    function test_equivocation_freezes_and_frozen_signer_is_skipped() public {
        bytes32 a = keccak256("digest-a");
        bytes32 b = keccak256("digest-b");
        (bytes memory sa, bytes memory sb) = _equivocate(1, a, b, 900);
        vm.expectRevert(BridgeGuard.NotEquivocation.selector);
        guard.reportEquivocation(pubs[1], a, sa, a, sa);
        vm.expectRevert(BridgeGuard.NotEquivocation.selector);
        guard.reportEquivocation(pubs[0], a, sa, b, sb);
        guard.reportEquivocation(pubs[1], a, sa, b, sb);
        assertTrue(guard.frozenKey(keccak256(pubs[1])));
        bytes32 root = keccak256("root-12");
        BridgeGuard.Attestation[] memory att = _attest(guard.rootDigest(root), _ids(0, 1, 2), true);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.QuorumNotReached.selector, 2, 3));
        guard.approveRoot(root, att);
        guard.approveRoot(root, _attest(guard.rootDigest(root), _ids(0, 2, 3), true));
        vm.warp(vm.getBlockTimestamp() + 60);
        assertTrue(guard.isApproved(root));
    }

    function test_distinct_leaves_are_not_equivocation() public {
        bytes32 a = keccak256("digest-a");
        bytes32 b = keccak256("digest-b");
        bytes memory sa = _lms(2, a);
        bytes memory sb = _lms(2, b);
        vm.expectRevert(BridgeGuard.NotEquivocation.selector);
        guard.reportEquivocation(pubs[2], a, sa, b, sb);
    }

    function _signersJson(BridgeGuard.Signer[] memory s) internal pure returns (string memory j) {
        j = "[";
        for (uint256 i = 0; i < s.length; i++) {
            j = string.concat(
                j,
                i == 0 ? "" : ",",
                "{\"ecdsa\":\"",
                vm.toString(s[i].ecdsa),
                "\",\"lmsPublicKey\":\"",
                vm.toString(s[i].lmsPublicKey),
                "\"}"
            );
        }
        j = string.concat(j, "]");
    }

    function test_reconfigure_with_possession_and_epoch_replay() public {
        bytes32 root = keccak256("root-11");
        BridgeGuard.Attestation[] memory stale = _attest(guard.rootDigest(root), _ids(0, 1, 2), true);
        (string memory newDir, bytes memory newPub) = _newKey("joiner");
        BridgeGuard.Signer[] memory s = _signers();
        s[3] = BridgeGuard.Signer(address(0), newPub);
        bytes32 cd = guard.configDigest(s, 3, BridgeGuard.Mode.PostQuantum);
        string memory out = _ffi(
            string.concat(
                "f=$(mktemp) && printf '%s' '",
                _signersJson(s),
                "' > $f && ",
                KIT,
                " attest-config --dir ",
                newDir,
                " --onchain-next-leaf 0 --signer 3 --chain-id ",
                vm.toString(block.chainid),
                " --guard ",
                vm.toString(address(guard)),
                " --epoch ",
                vm.toString(uint256(guard.epoch())),
                " --signers $f --threshold 3 --mode 1 2>/dev/null"
            )
        );
        assertEq(vm.parseJsonBytes32(out, ".digest"), cd);
        BridgeGuard.Attestation[] memory q = _attest(cd, _ids(0, 1, 2), true);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.MissingPossessionProof.selector, 3));
        guard.reconfigure(s, 3, BridgeGuard.Mode.PostQuantum, q);
        guard.provePossession(
            s,
            3,
            BridgeGuard.Mode.PostQuantum,
            3,
            BridgeGuard.Attestation(3, "", vm.parseJsonBytes(out, ".lmsSignature"))
        );
        guard.reconfigure(s, 3, BridgeGuard.Mode.PostQuantum, q);
        assertEq(uint256(guard.mode()), uint256(BridgeGuard.Mode.PostQuantum));
        assertEq(guard.epoch(), 2);
        assertEq(keccak256(guard.signerAt(3).lmsPublicKey), keccak256(newPub));
        vm.expectRevert();
        guard.approveRoot(root, stale);
        bytes32 rd = guard.rootDigest(root);
        BridgeGuard.Attestation[] memory a = new BridgeGuard.Attestation[](3);
        a[0] = BridgeGuard.Attestation(0, "", _lms(0, rd));
        a[1] = BridgeGuard.Attestation(2, "", _lms(2, rd));
        a[2] = BridgeGuard.Attestation(3, "", _lmsAt(newDir, rd));
        guard.approveRoot(root, a);
        vm.warp(vm.getBlockTimestamp() + 60);
        assertTrue(guard.isApproved(root));
    }

    function test_offline_member_is_retained_without_a_fresh_proof() public {
        BridgeGuard.Signer[] memory s = _signers();
        bytes32 cd = guard.configDigest(s, 3, BridgeGuard.Mode.Hybrid);
        guard.reconfigure(s, 3, BridgeGuard.Mode.Hybrid, _attest(cd, _ids(0, 1, 2), true));
        assertEq(guard.epoch(), 2);
        assertEq(guard.signerAt(3).ecdsa, vm.addr(ecdsaKeys[3]));
    }

    function test_retained_member_with_new_classical_key_needs_proof() public {
        BridgeGuard.Signer[] memory s = _signers();
        s[3].ecdsa = vm.addr(0xC0FFEE);
        bytes32 cd = guard.configDigest(s, 3, BridgeGuard.Mode.Hybrid);
        BridgeGuard.Attestation[] memory q = _attest(cd, _ids(0, 1, 2), true);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.MissingPossessionProof.selector, 3));
        guard.reconfigure(s, 3, BridgeGuard.Mode.Hybrid, q);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(0xC0FFEE, cd);
        guard.provePossession(
            s, 3, BridgeGuard.Mode.Hybrid, 3, BridgeGuard.Attestation(3, abi.encodePacked(r, sg, v), _lms(3, cd))
        );
        guard.reconfigure(s, 3, BridgeGuard.Mode.Hybrid, q);
        assertEq(guard.signerAt(3).ecdsa, vm.addr(0xC0FFEE));
    }

    function test_live_signer_count_tracks_freezes() public {
        assertEq(guard.liveSignerCount(), 4);
        (bytes memory sa, bytes memory sb) = _equivocate(2, keccak256("x"), keccak256("y"), 810);
        guard.reportEquivocation(pubs[2], keccak256("x"), sa, keccak256("y"), sb);
        assertEq(guard.liveSignerCount(), 3);
    }

    function test_minimum_root_age_floor() public {
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(_signers(), 3, BridgeGuard.Mode.Hybrid, 59);
        assertEq(new BridgeGuard(_signers(), 3, BridgeGuard.Mode.Hybrid, 60).minimumRootAge(), 60);
    }

    function test_proof_depth_is_bounded() public view {
        bytes32[] memory deep = new bytes32[](65);
        assertEq(guard.computeRoot(keccak256("leaf"), 0, deep), bytes32(0));
        bytes32[] memory big = new bytes32[](256);
        assertEq(guard.computeRoot(keccak256("leaf"), 1 << 255, big), bytes32(0));
        bytes32[] memory ok = new bytes32[](64);
        assertTrue(guard.computeRoot(keccak256("leaf"), 0, ok) != bytes32(0));
    }

    function test_possession_by_wrong_key_rejected() public {
        BridgeGuard.Signer[] memory s = _signers();
        bytes32 cd = guard.configDigest(s, 3, BridgeGuard.Mode.Hybrid);
        BridgeGuard.Attestation memory p = BridgeGuard.Attestation(3, _ecdsa(3, cd), _lms(2, cd));
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidPostQuantumSignature.selector, 3));
        guard.provePossession(s, 3, BridgeGuard.Mode.Hybrid, 3, p);
        p = BridgeGuard.Attestation(3, _ecdsa(2, cd), _lms(3, cd));
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidClassicalSignature.selector, 3));
        guard.provePossession(s, 3, BridgeGuard.Mode.Hybrid, 3, p);
    }

    function test_frozen_key_cannot_be_reintroduced() public {
        (bytes memory sa, bytes memory sb) = _equivocate(2, keccak256("x"), keccak256("y"), 800);
        guard.reportEquivocation(pubs[2], keccak256("x"), sa, keccak256("y"), sb);
        BridgeGuard.Signer[] memory s = _signers();
        bytes32 cd = guard.configDigest(s, 3, BridgeGuard.Mode.Hybrid);
        BridgeGuard.Attestation memory p = BridgeGuard.Attestation(2, _ecdsa(2, cd), _lms(2, cd));
        vm.expectRevert(BridgeGuard.FrozenKey.selector);
        guard.provePossession(s, 3, BridgeGuard.Mode.Hybrid, 2, p);
        BridgeGuard.Attestation[] memory q = _attest(cd, _ids(0, 1, 3), true);
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        guard.reconfigure(s, 3, BridgeGuard.Mode.Hybrid, q);
    }

    function test_reconfigure_requires_quorum() public {
        BridgeGuard.Signer[] memory s = _signers();
        bytes32 cd = guard.configDigest(s, 3, BridgeGuard.Mode.PostQuantum);
        uint256[] memory two = new uint256[](2);
        two[0] = 0;
        two[1] = 1;
        BridgeGuard.Attestation[] memory a = _attest(cd, two, true);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.QuorumNotReached.selector, 2, 3));
        guard.reconfigure(s, 3, BridgeGuard.Mode.PostQuantum, a);
    }

    function test_invalid_configurations_rejected() public {
        BridgeGuard.Signer[] memory s = _signers();
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(s, 2, BridgeGuard.Mode.Hybrid, 60);
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(s, 5, BridgeGuard.Mode.Hybrid, 60);
        s[1].lmsPublicKey = s[0].lmsPublicKey;
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(s, 3, BridgeGuard.Mode.Hybrid, 60);
        s = _signers();
        s[2].ecdsa = s[0].ecdsa;
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(s, 3, BridgeGuard.Mode.Hybrid, 60);
        s = _signers();
        s[3].lmsPublicKey = hex"00";
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(s, 3, BridgeGuard.Mode.Hybrid, 60);
    }

    function _fakeSigners(uint256 n, uint32 lmsType, uint32 otsType)
        internal
        pure
        returns (BridgeGuard.Signer[] memory s)
    {
        s = new BridgeGuard.Signer[](n);
        for (uint256 i = 0; i < n; i++) {
            s[i] = BridgeGuard.Signer(
                address(uint160(i + 1)),
                abi.encodePacked(lmsType, otsType, bytes16(keccak256(abi.encode(i))), keccak256(abi.encode("k", i)))
            );
        }
    }

    function test_gas_and_size_budget_rejects_unexecutable_configuration() public {
        new BridgeGuard(_fakeSigners(9, 8, 4), 5, BridgeGuard.Mode.Hybrid, 60);
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(_fakeSigners(11, 8, 4), 6, BridgeGuard.Mode.Hybrid, 60);
        new BridgeGuard(_fakeSigners(23, 9, 1), 12, BridgeGuard.Mode.Hybrid, 60);
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(_fakeSigners(25, 9, 1), 13, BridgeGuard.Mode.Hybrid, 60);
        new BridgeGuard(_fakeSigners(47, 8, 3), 24, BridgeGuard.Mode.Hybrid, 60);
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(_fakeSigners(49, 8, 3), 25, BridgeGuard.Mode.Hybrid, 60);
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(_fakeSigners(57, 5, 3), 29, BridgeGuard.Mode.Hybrid, 60);
        new BridgeGuard(_fakeSigners(49, 5, 2), 25, BridgeGuard.Mode.Hybrid, 60);
        BridgeGuard.Signer[] memory s = _signers();
        bytes memory bad = bytes.concat(s[0].lmsPublicKey);
        bad[3] = 0x0a;
        s[0].lmsPublicKey = bad;
        vm.expectRevert(BridgeGuard.InvalidConfiguration.selector);
        new BridgeGuard(s, 3, BridgeGuard.Mode.Hybrid, 60);
    }

    function test_revocation_by_quorum() public {
        bytes32 root = keccak256("root-r");
        guard.approveRoot(root, _attest(guard.rootDigest(root), _ids(0, 1, 2), true));
        vm.warp(vm.getBlockTimestamp() + 60);
        assertTrue(guard.isApproved(root));
        BridgeGuard.Attestation[] memory wrong = _attest(guard.rootDigest(root), _ids(0, 1, 3), true);
        vm.expectRevert(abi.encodeWithSelector(BridgeGuard.InvalidPostQuantumSignature.selector, 0));
        guard.revokeRoot(root, wrong);
        guard.revokeRoot(root, _attest(guard.revokeDigest(root), _ids(1, 2, 3), true));
        assertFalse(guard.isApproved(root));
        bytes32[] memory empty = new bytes32[](0);
        assertFalse(guard.isIncluded(root, keccak256("x"), 0, empty));
    }

    function test_minimum_root_age_enforced() public {
        BridgeGuard delayed = new BridgeGuard(_signers(), 3, BridgeGuard.Mode.Hybrid, 3600);
        bytes32 leaf = keccak256("message");
        bytes32 root = delayed.leafHash(leaf);
        delayed.approveRoot(root, _attest(delayed.rootDigest(root), _ids(0, 1, 2), true));
        bytes32[] memory empty = new bytes32[](0);
        assertFalse(delayed.isIncluded(root, leaf, 0, empty));
        vm.warp(vm.getBlockTimestamp() + 3599);
        assertFalse(delayed.isIncluded(root, leaf, 0, empty));
        vm.warp(vm.getBlockTimestamp() + 1);
        assertTrue(delayed.isIncluded(root, leaf, 0, empty));
    }

    function _merkle(bytes32[] memory leaves) internal returns (bytes32 root, string memory out) {
        string memory j = "[";
        for (uint256 i = 0; i < leaves.length; i++) {
            j = string.concat(j, i == 0 ? "\"" : ",\"", vm.toString(leaves[i]), "\"");
        }
        out = _ffi(string.concat("f=$(mktemp) && printf '%s' '", j, "]' > $f && ", KIT, " merkle --leaves $f"));
        root = vm.parseJsonBytes32(out, ".root");
    }

    function _approveViaKit(bytes32 root) internal {
        BridgeGuard.Attestation[] memory a = new BridgeGuard.Attestation[](3);
        for (uint256 k = 0; k < 3; k++) {
            string memory out = _ffi(
                string.concat(
                    KIT,
                    " attest-root --dir ",
                    _dir(k),
                    " --onchain-next-leaf ",
                    vm.toString(guard.nextLeafOf(k)),
                    " --signer ",
                    vm.toString(k),
                    " --chain-id ",
                    vm.toString(block.chainid),
                    " --guard ",
                    vm.toString(address(guard)),
                    " --epoch ",
                    vm.toString(uint256(guard.epoch())),
                    " --root ",
                    vm.toString(root),
                    " 2>/dev/null"
                )
            );
            assertEq(vm.parseJsonBytes32(out, ".digest"), guard.rootDigest(root));
            a[k] =
                BridgeGuard.Attestation(k, _ecdsa(k, guard.rootDigest(root)), vm.parseJsonBytes(out, ".lmsSignature"));
        }
        guard.approveRoot(root, a);
        vm.warp(vm.getBlockTimestamp() + 60);
    }

    function test_merkle_inclusion_matches_kit() public {
        bytes32[] memory leaves = new bytes32[](5);
        for (uint256 i = 0; i < 5; i++) {
            leaves[i] = keccak256(abi.encode("leaf", i));
        }
        (bytes32 root, string memory out) = _merkle(leaves);
        _approveViaKit(root);
        for (uint256 i = 0; i < 5; i++) {
            bytes32[] memory proof = vm.parseJsonBytes32Array(out, string.concat(".proofs[", vm.toString(i), "].proof"));
            assertTrue(guard.isIncluded(root, leaves[i], i, proof));
            assertFalse(guard.isIncluded(root, leaves[i], i ^ 1, proof));
            assertFalse(guard.isIncluded(root, leaves[i], i + 8, proof));
            assertFalse(guard.isIncluded(root, keccak256("other"), i, proof));
        }
    }

    function test_internal_node_cannot_pose_as_leaf() public {
        bytes32[] memory leaves = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            leaves[i] = keccak256(abi.encode("leaf", i));
        }
        (bytes32 root, string memory out) = _merkle(leaves);
        _approveViaKit(root);
        bytes32[] memory p = vm.parseJsonBytes32Array(out, ".proofs[0].proof");
        bytes32 internalNode = keccak256(abi.encodePacked(bytes1(0x01), guard.leafHash(leaves[0]), p[0]));
        bytes32[] memory shortProof = new bytes32[](1);
        shortProof[0] = p[1];
        assertFalse(guard.isIncluded(root, internalNode, 0, shortProof));
    }

    function testFuzz_forged_proofs_rejected(bytes32 leaf, uint256 index, bytes32 sibling) public view {
        bytes32 la = keccak256("a");
        bytes32 lb = keccak256("b");
        bytes32 root = keccak256(abi.encodePacked(bytes1(0x01), guard.leafHash(la), guard.leafHash(lb)));
        vm.assume(leaf != la && leaf != lb);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        assertTrue(guard.computeRoot(leaf, index, proof) != root);
    }

    function _lzHeader(uint8 version, uint32 dstEid) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                version, uint64(5), uint32(30101), bytes32(uint256(0x111)), dstEid, bytes32(uint256(0x222))
            );
    }

    MockReceiveUln lzUln;
    MockEndpoint lzEndpoint;
    MockSendLib lzSendLib;
    LayerZeroQuantumDVN lzDvn;
    bytes lzHeaderBytes;
    bytes32 lzPayload;
    bytes32 lzRoot;
    string lzTree;

    function _lzSetup() internal {
        lzUln = new MockReceiveUln();
        lzEndpoint = new MockEndpoint();
        lzSendLib = new MockSendLib();
        uint32[] memory dsts = new uint32[](1);
        dsts[0] = 30101;
        lzDvn = new LayerZeroQuantumDVN(
            IBridgeGuard(address(guard)),
            IEndpointInbound(address(lzEndpoint)),
            30110,
            address(lzSendLib),
            dsts,
            payable(address(0xBEEF)),
            1234
        );
        lzHeaderBytes = _lzHeader(1, 30110);
        lzPayload = keccak256("payload");
        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] = lzDvn.leafFor(address(lzUln), lzHeaderBytes, lzPayload, 15);
        leaves[1] = lzDvn.leafFor(address(lzUln), lzHeaderBytes, lzPayload, 20);
        leaves[2] = lzDvn.leafFor(address(lzUln), lzHeaderBytes, keccak256("zero"), 0);
        string memory kl = _ffi(
            string.concat(
                KIT,
                " leaf-layerzero --eid 30110 --dvn ",
                vm.toString(address(lzDvn)),
                " --receive-lib ",
                vm.toString(address(lzUln)),
                " --header ",
                vm.toString(lzHeaderBytes),
                " --payload-hash ",
                vm.toString(lzPayload),
                " --confirmations 15"
            )
        );
        assertEq(vm.parseJsonBytes32(kl, ".leaf"), leaves[0]);
        (lzRoot, lzTree) = _merkle(leaves);
        _approveViaKit(lzRoot);
    }

    function _lzProof(uint256 i) internal view returns (bytes32[] memory) {
        return vm.parseJsonBytes32Array(lzTree, string.concat(".proofs[", vm.toString(i), "].proof"));
    }

    function test_layerzero_dvn_end_to_end() public {
        _lzSetup();
        uint32[] memory dsts = new uint32[](1);
        dsts[0] = 30101;
        LayerZeroQuantumDVN other = new LayerZeroQuantumDVN(
            IBridgeGuard(address(guard)),
            IEndpointInbound(address(lzEndpoint)),
            30110,
            address(lzSendLib),
            dsts,
            payable(address(0xBEEF)),
            1234
        );
        vm.expectRevert(LayerZeroQuantumDVN.NotAttested.selector);
        lzDvn.submit(address(lzUln), lzHeaderBytes, keccak256("tampered"), 15, lzRoot, 0, _lzProof(0));
        vm.expectRevert(LayerZeroQuantumDVN.NotAttested.selector);
        other.submit(address(lzUln), lzHeaderBytes, lzPayload, 15, lzRoot, 0, _lzProof(0));
        lzDvn.submit(address(lzUln), lzHeaderBytes, lzPayload, 20, lzRoot, 1, _lzProof(1));
        vm.expectRevert(LayerZeroQuantumDVN.AlreadyDelivered.selector);
        lzDvn.submit(address(lzUln), lzHeaderBytes, lzPayload, 15, lzRoot, 0, _lzProof(0));
        vm.expectRevert(LayerZeroQuantumDVN.AlreadyDelivered.selector);
        lzDvn.submit(address(lzUln), lzHeaderBytes, lzPayload, 20, lzRoot, 1, _lzProof(1));
        assertEq(lzUln.calls(), 1);
        assertEq(lzUln.lastCaller(), address(lzDvn));
        assertEq(lzUln.lastConfirmations(), 20);
        vm.expectRevert(LayerZeroQuantumDVN.MalformedHeader.selector);
        lzDvn.leafFor(address(lzUln), _lzHeader(1, 1), lzPayload, 15);
        vm.expectRevert(LayerZeroQuantumDVN.MalformedHeader.selector);
        lzDvn.leafFor(address(lzUln), _lzHeader(2, 30110), lzPayload, 15);
    }

    function _nilify() internal {
        lzEndpoint.set(address(0x222), 30101, bytes32(uint256(0x111)), 5, bytes32(type(uint256).max));
    }

    function test_layerzero_nilify_replay_blocked_and_zero_confirmations() public {
        _lzSetup();
        lzDvn.submit(address(lzUln), lzHeaderBytes, lzPayload, 20, lzRoot, 1, _lzProof(1));
        lzUln.commit(lzHeaderBytes, lzPayload, address(lzDvn));
        _nilify();
        vm.expectRevert(LayerZeroQuantumDVN.Nilified.selector);
        lzDvn.submit(address(lzUln), lzHeaderBytes, lzPayload, 20, lzRoot, 1, _lzProof(1));
        assertEq(lzUln.calls(), 1);
        vm.prank(address(0x222));
        lzDvn.submit(address(lzUln), lzHeaderBytes, lzPayload, 20, lzRoot, 1, _lzProof(1));
        assertEq(lzUln.calls(), 2);
        lzEndpoint.set(address(0x222), 30101, bytes32(uint256(0x111)), 5, lzPayload);
        lzDvn.submit(address(lzUln), lzHeaderBytes, keccak256("zero"), 0, lzRoot, 2, _lzProof(2));
        assertEq(lzUln.calls(), 3);
        vm.expectRevert(LayerZeroQuantumDVN.AlreadyDelivered.selector);
        lzDvn.submit(address(lzUln), lzHeaderBytes, keccak256("zero"), 0, lzRoot, 2, _lzProof(2));
    }

    function test_layerzero_nilify_holds_when_another_verifier_committed() public {
        _lzSetup();
        lzEndpoint.set(address(0x222), 30101, bytes32(uint256(0x111)), 5, lzPayload);
        _nilify();
        vm.expectRevert(LayerZeroQuantumDVN.Nilified.selector);
        lzDvn.submit(address(lzUln), lzHeaderBytes, lzPayload, 15, lzRoot, 0, _lzProof(0));
        vm.expectRevert(LayerZeroQuantumDVN.Nilified.selector);
        lzDvn.submit(address(lzUln), lzHeaderBytes, lzPayload, 20, lzRoot, 1, _lzProof(1));
        assertEq(lzUln.calls(), 0);
    }

    function test_layerzero_confirmation_upgrade_before_commit() public {
        _lzSetup();
        lzDvn.submit(address(lzUln), lzHeaderBytes, lzPayload, 15, lzRoot, 0, _lzProof(0));
        lzDvn.submit(address(lzUln), lzHeaderBytes, lzPayload, 20, lzRoot, 1, _lzProof(1));
        assertEq(lzUln.calls(), 2);
        assertEq(lzUln.lastConfirmations(), 20);
    }

    function test_layerzero_jobs_fees_and_construction() public {
        _lzSetup();
        ILayerZeroDVN.AssignJobParam memory job =
            ILayerZeroDVN.AssignJobParam(30101, lzHeaderBytes, lzPayload, 15, address(this));
        vm.expectRevert(LayerZeroQuantumDVN.UnauthorizedSendLib.selector);
        lzDvn.assignJob(job, "");
        vm.prank(address(lzSendLib));
        assertEq(lzDvn.assignJob(job, ""), 1234);
        job.dstEid = 999;
        vm.prank(address(lzSendLib));
        vm.expectRevert(abi.encodeWithSelector(LayerZeroQuantumDVN.UnsupportedDestination.selector, 999));
        lzDvn.assignJob(job, "");
        assertEq(lzDvn.getFee(30101, 1, address(0), ""), 1234);
        vm.expectRevert(LayerZeroQuantumDVN.Unauthorized.selector);
        lzDvn.withdrawFromLibrary(77);
        vm.expectRevert(LayerZeroQuantumDVN.Unauthorized.selector);
        lzDvn.sweep();
        vm.deal(address(lzDvn), 5 ether);
        vm.prank(address(0xBEEF));
        lzDvn.sweep();
        assertEq(address(0xBEEF).balance, 5 ether);
        vm.prank(address(0xBEEF));
        lzDvn.withdrawFromLibrary(77);
        assertEq(lzSendLib.lastTo(), address(0xBEEF));
        assertEq(lzSendLib.lastAmount(), 77);
        assertEq(lzSendLib.lastCaller(), address(lzDvn));
        uint32[] memory dsts = new uint32[](1);
        vm.expectRevert(LayerZeroQuantumDVN.ZeroAddress.selector);
        new LayerZeroQuantumDVN(
            IBridgeGuard(address(guard)),
            IEndpointInbound(address(lzEndpoint)),
            30110,
            address(0),
            dsts,
            payable(address(0xBEEF)),
            1
        );
    }

    function test_gas_approve_root_three_hybrid() public {
        bytes32 root = keccak256("gas");
        BridgeGuard.Attestation[] memory a = _attest(guard.rootDigest(root), _ids(0, 1, 2), true);
        uint256 g = gasleft();
        guard.approveRoot(root, a);
        vm.warp(vm.getBlockTimestamp() + 60);
        emit log_named_uint("approveRoot gas, 3 hybrid signers, LMS H10 W4", g - gasleft());
    }
}
