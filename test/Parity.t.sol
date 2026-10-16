// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BridgeGuard} from "../src/BridgeGuard.sol";
import {LayerZeroQuantumDVN} from "../src/adapters/LayerZeroQuantumDVN.sol";
import {IEndpointInbound} from "../src/interfaces/ILayerZeroDVN.sol";
import {IBridgeGuard} from "../src/interfaces/IBridgeGuard.sol";

contract ParityTest is Test {
    BridgeGuard guard;
    LayerZeroQuantumDVN dvn;
    bytes32 seed;

    function _rand() internal returns (bytes32) {
        seed = keccak256(abi.encode(seed));
        return seed;
    }

    function _signers(uint256 n) internal returns (BridgeGuard.Signer[] memory s) {
        s = new BridgeGuard.Signer[](n);
        for (uint256 i = 0; i < n; i++) {
            s[i] = BridgeGuard.Signer(
                address(uint160(uint256(_rand()))),
                abi.encodePacked(uint32(6), uint32(3), bytes16(_rand()), _rand()),
                _rand()
            );
        }
    }

    function setUp() public {
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        BridgeGuard.Signer[] memory bound = new BridgeGuard.Signer[](3);
        for (uint256 i = 0; i < 3; i++) {
            bytes32 salt = _rand();
            bytes16 identifier = bytes16(keccak256(abi.encode(block.chainid, predicted, salt)));
            bound[i] = BridgeGuard.Signer(
                address(uint160(i + 1)), abi.encodePacked(uint32(6), uint32(3), identifier, _rand()), salt
            );
        }
        guard = new BridgeGuard(bound, 2, BridgeGuard.Mode.Hybrid, 60);
        assertEq(address(guard), predicted);
        uint32[] memory dsts = new uint32[](1);
        dsts[0] = 30101;
        dvn = new LayerZeroQuantumDVN(
            IBridgeGuard(address(guard)),
            IEndpointInbound(address(0xE0)),
            30110,
            address(0x5E),
            dsts,
            payable(address(0xBEEF)),
            0
        );
    }

    function _json(BridgeGuard.Signer[] memory s) internal pure returns (string memory j) {
        j = "[";
        for (uint256 i = 0; i < s.length; i++) {
            j = string.concat(
                j,
                i == 0 ? "" : ",",
                "{\"ecdsa\":\"",
                vm.toString(s[i].ecdsa),
                "\",\"lms\":\"",
                vm.toString(s[i].lmsPublicKey),
                "\",\"salt\":\"",
                vm.toString(s[i].identifierSalt),
                "\"}"
            );
        }
        j = string.concat(j, "]");
    }

    function _leavesJson(bytes32[] memory l) internal pure returns (string memory j) {
        j = "[";
        for (uint256 i = 0; i < l.length; i++) {
            j = string.concat(j, i == 0 ? "\"" : ",\"", vm.toString(l[i]), "\"");
        }
        j = string.concat(j, "]");
    }

    function _merkle(bytes32[] memory l, uint256 index) internal view returns (bytes32 root, bytes32[] memory proof) {
        uint256 depth;
        while ((uint256(1) << depth) < l.length) depth++;
        bytes32[] memory level = new bytes32[](uint256(1) << depth);
        for (uint256 i = 0; i < l.length; i++) {
            level[i] = guard.leafHash(l[i]);
        }
        proof = new bytes32[](depth);
        uint256 j = index;
        for (uint256 d = 0; d < depth; d++) {
            proof[d] = level[j ^ 1];
            bytes32[] memory next = new bytes32[](level.length / 2);
            for (uint256 i = 0; i < next.length; i++) {
                next[i] = keccak256(abi.encodePacked(bytes1(0x01), level[2 * i], level[2 * i + 1]));
            }
            level = next;
            j >>= 1;
        }
        root = level[0];
        assertEq(guard.computeRoot(l[index], index, proof), root);
    }

    function test_solidity_and_kit_encodings_agree() public {
        for (uint256 round = 0; round < 24; round++) {
            seed = keccak256(abi.encode("parity", round));
            uint256 n = 1 + uint256(_rand()) % 5;
            BridgeGuard.Signer[] memory s = _signers(n);
            uint256 t = n / 2 + 1;
            BridgeGuard.Mode m = uint256(_rand()) % 2 == 0 ? BridgeGuard.Mode.Hybrid : BridgeGuard.Mode.PostQuantum;
            bytes32 r = _rand();
            bytes memory header =
                abi.encodePacked(uint8(1), uint64(round), uint32(30101), _rand(), uint32(30110), _rand());
            bytes32 payload = _rand();
            uint64 conf = uint64(uint256(_rand()) % 100);
            uint256 count = 1 + uint256(_rand()) % 9;
            bytes32[] memory l = new bytes32[](count);
            for (uint256 i = 0; i < count; i++) {
                l[i] = _rand();
            }
            uint256 index = uint256(_rand()) % count;
            string memory args = string.concat(
                "{\"chain\":",
                vm.toString(block.chainid),
                ",\"guard\":\"",
                vm.toString(address(guard)),
                "\",\"epoch\":1,\"r\":\"",
                vm.toString(r),
                "\",\"signers\":",
                _json(s),
                ",\"threshold\":",
                vm.toString(t),
                ",\"mode\":",
                vm.toString(uint256(m))
            );
            args = string.concat(
                args,
                ",\"eid\":30110,\"dvn\":\"",
                vm.toString(address(dvn)),
                "\",\"lib\":\"",
                vm.toString(address(0x11B))
            );
            args = string.concat(
                args,
                "\",\"header\":\"",
                vm.toString(header),
                "\",\"payload\":\"",
                vm.toString(payload),
                "\",\"confirmations\":",
                vm.toString(uint256(conf)),
                ",\"leaves\":",
                _leavesJson(l),
                ",\"index\":",
                vm.toString(index),
                "}"
            );
            string[] memory c = new string[](3);
            c[0] = "python3";
            c[1] = "test/helpers/parity.py";
            c[2] = args;
            bytes memory kit = vm.ffi(c);
            (bytes32 root, bytes32[] memory proof) = _merkle(l, index);
            bytes memory expected = abi.encodePacked(
                guard.rootDigest(r),
                guard.revokeDigest(r),
                guard.configDigest(s, t, m),
                dvn.leafFor(address(0x11B), header, payload, conf),
                root
            );
            expected = bytes.concat(expected, abi.encodePacked(proof));
            assertEq(keccak256(kit), keccak256(expected));
        }
    }
}
