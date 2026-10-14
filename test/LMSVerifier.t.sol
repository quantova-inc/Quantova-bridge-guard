// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {LMSVerifier} from "../src/LMSVerifier.sol";

contract LMSHarness {
    function verify(bytes memory p, bytes memory m, bytes memory s) external view returns (bool) {
        return LMSVerifier.verify(p, m, s);
    }
}

contract LMSVerifierTest is Test {
    LMSHarness h;
    string kitJson;

    function setUp() public {
        h = new LMSHarness();
        kitJson = vm.readFile("test/vectors/kit.json");
    }

    function _kit(uint256 i) internal view returns (bytes memory p, bytes memory m, bytes memory s) {
        string memory k = string.concat(".[", vm.toString(i), "]");
        p = vm.parseJsonBytes(kitJson, string.concat(k, ".pub"));
        m = vm.parseJsonBytes(kitJson, string.concat(k, ".msg"));
        s = vm.parseJsonBytes(kitJson, string.concat(k, ".sig"));
    }

    function _rfc(string memory file, uint256 i)
        internal
        view
        returns (bytes memory p, bytes memory m, bytes memory s)
    {
        string memory j = vm.readFile(file);
        string memory k = string.concat(".[", vm.toString(i), "]");
        p = vm.parseJsonBytes(j, string.concat(k, ".pub"));
        m = vm.parseJsonBytes(j, string.concat(k, ".msg"));
        s = vm.parseJsonBytes(j, string.concat(k, ".sig"));
    }

    function test_rfc8554_case1() public view {
        for (uint256 i = 0; i < 2; i++) {
            (bytes memory p, bytes memory m, bytes memory s) = _rfc("test/vectors/rfc_tc1.json", i);
            assertTrue(h.verify(p, m, s));
            m[0] = m[0] ^ 0x01;
            assertFalse(h.verify(p, m, s));
        }
    }

    function test_rfc8554_case2() public view {
        for (uint256 i = 0; i < 2; i++) {
            (bytes memory p, bytes memory m, bytes memory s) = _rfc("test/vectors/rfc_tc2.json", i);
            assertTrue(h.verify(p, m, s));
            m[m.length - 1] = m[m.length - 1] ^ 0x80;
            assertFalse(h.verify(p, m, s));
        }
    }

    function test_all_parameter_sets_accept_valid() public view {
        for (uint256 i = 0; i < 28; i++) {
            (bytes memory p, bytes memory m, bytes memory s) = _kit(i);
            assertTrue(h.verify(p, m, s), vm.toString(i));
        }
    }

    function test_gas_profile() public view {
        for (uint256 i = 0; i < 28; i += 4) {
            (bytes memory p, bytes memory m, bytes memory s) = _kit(i);
            uint256 g = gasleft();
            bool ok = h.verify(p, m, s);
            uint256 used = g - gasleft();
            assertTrue(ok);
            console.log(
                string.concat("lms ", vm.toString(uint32(bytes4(p)))),
                uint32(bytes4(bytes.concat(p[4], p[5], p[6], p[7]))),
                used,
                s.length
            );
        }
    }

    function testFuzz_signature_bitflip_rejected(uint256 vec, uint256 pos, uint8 bit) public view {
        (bytes memory p, bytes memory m, bytes memory s) = _kit(vec % 28);
        pos = pos % s.length;
        s[pos] = s[pos] ^ bytes1(uint8(1) << (bit % 8));
        assertFalse(h.verify(p, m, s));
    }

    function testFuzz_publickey_bitflip_rejected(uint256 vec, uint256 pos, uint8 bit) public view {
        (bytes memory p, bytes memory m, bytes memory s) = _kit(vec % 28);
        pos = pos % p.length;
        p[pos] = p[pos] ^ bytes1(uint8(1) << (bit % 8));
        assertFalse(h.verify(p, m, s));
    }

    function testFuzz_message_bitflip_rejected(uint256 vec, uint256 pos, uint8 bit) public view {
        (bytes memory p, bytes memory m, bytes memory s) = _kit(vec % 28);
        pos = pos % m.length;
        m[pos] = m[pos] ^ bytes1(uint8(1) << (bit % 8));
        assertFalse(h.verify(p, m, s));
    }

    function testFuzz_wrong_length_rejected(uint256 vec, uint8 cut, bool extend) public view {
        (bytes memory p, bytes memory m, bytes memory s) = _kit(vec % 28);
        uint256 delta = uint256(cut) % 64 + 1;
        bytes memory t;
        if (extend) {
            t = bytes.concat(s, new bytes(delta));
        } else {
            t = new bytes(s.length - delta);
            for (uint256 i = 0; i < t.length; i++) {
                t[i] = s[i];
            }
        }
        assertFalse(h.verify(p, m, t));
    }

    function testFuzz_random_signature_rejected(bytes32 seed) public view {
        (bytes memory p, bytes memory m, bytes memory s) = _kit(uint256(seed) % 28);
        for (uint256 i = 8; i < s.length; i++) {
            s[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i)))));
        }
        assertFalse(h.verify(p, m, s));
    }

    function test_cross_key_rejected() public view {
        (bytes memory p0,,) = _kit(8);
        (, bytes memory m1, bytes memory s1) = _kit(12);
        assertFalse(h.verify(p0, m1, s1));
    }

    function test_empty_and_short_inputs_rejected() public view {
        (bytes memory p, bytes memory m, bytes memory s) = _kit(8);
        assertFalse(h.verify(p, m, ""));
        assertFalse(h.verify("", m, s));
        assertFalse(h.verify(p, m, hex"00000000"));
        assertFalse(h.verify(p, "", s));
    }

    function test_leaf_out_of_range_rejected() public view {
        (bytes memory p, bytes memory m, bytes memory s) = _kit(0);
        s[0] = 0x00;
        s[1] = 0x00;
        s[2] = 0x00;
        s[3] = 0x20;
        assertFalse(h.verify(p, m, s));
        s[0] = 0xff;
        s[1] = 0xff;
        s[2] = 0xff;
        s[3] = 0xff;
        assertFalse(h.verify(p, m, s));
    }

    function test_unsupported_types_rejected() public view {
        (bytes memory p, bytes memory m, bytes memory s) = _kit(8);
        bytes memory q = bytes.concat(p);
        q[3] = 0x0a;
        assertFalse(h.verify(q, m, s));
        q = bytes.concat(p);
        q[7] = 0x05;
        assertFalse(h.verify(q, m, s));
    }
}
