// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

library LMSVerifier {
    uint256 internal constant PUBLIC_KEY_LENGTH = 56;

    /// Returns the Winternitz width, chain count and checksum shift of an LMOTS type
    function otsParameters(uint32 otsType) internal pure returns (uint256 w, uint256 p, uint256 ls) {
        if (otsType == 1) return (1, 265, 7);
        if (otsType == 2) return (2, 133, 6);
        if (otsType == 3) return (4, 67, 4);
        if (otsType == 4) return (8, 34, 0);
        return (0, 0, 0);
    }

    /// Returns the Merkle tree height of an LMS type
    function treeHeight(uint32 lmsType) internal pure returns (uint256) {
        if (lmsType == 5) return 5;
        if (lmsType == 6) return 10;
        if (lmsType == 7) return 15;
        if (lmsType == 8) return 20;
        if (lmsType == 9) return 25;
        return 0;
    }

    /// Returns the byte length of an LMS signature for a parameter set
    function signatureLength(uint32 lmsType, uint32 otsType) internal pure returns (uint256) {
        (, uint256 p,) = otsParameters(otsType);
        uint256 h = treeHeight(lmsType);
        if (p == 0 || h == 0) return 0;
        return 44 + 32 * p + 32 * h;
    }

    /// Reads the LMS leaf index from a signature
    function leafIndex(bytes memory sig) internal pure returns (uint32 q) {
        if (sig.length < 4) return type(uint32).max;
        assembly {
            q := shr(224, mload(add(sig, 32)))
        }
    }

    /// Reads a big endian 32 bit word
    function _u32(bytes memory b, uint256 offset) private pure returns (uint32 v) {
        assembly {
            v := shr(224, mload(add(add(b, 32), offset)))
        }
    }

    /// Reads a 32 byte word
    function _word(bytes memory b, uint256 offset) private pure returns (bytes32 v) {
        assembly {
            v := mload(add(add(b, 32), offset))
        }
    }

    /// Verifies an RFC 8554 LMS signature over a message
    function verify(bytes memory publicKey, bytes memory message, bytes memory sig) internal view returns (bool) {
        if (publicKey.length != PUBLIC_KEY_LENGTH || sig.length < 8) return false;
        uint32 lmsType = _u32(publicKey, 0);
        uint32 otsType = _u32(publicKey, 4);
        uint256 h = treeHeight(lmsType);
        (uint256 w, uint256 p, uint256 ls) = otsParameters(otsType);
        if (h == 0 || w == 0) return false;
        if (sig.length != 44 + 32 * p + 32 * h) return false;
        if (_u32(sig, 4) != otsType) return false;
        if (_u32(sig, 40 + 32 * p) != lmsType) return false;
        uint256 q = _u32(sig, 0);
        if (q >> h != 0) return false;
        bytes16 ident = bytes16(_word(publicKey, 8));
        bytes32 kc = _candidate(ident, q, message, sig, w, p, ls);
        return _climb(ident, q, h, kc, sig, 44 + 32 * p) == _word(publicKey, 24);
    }

    /// Climbs the LMS authentication path from the leaf to the root
    function _climb(bytes16 ident, uint256 q, uint256 h, bytes32 kc, bytes memory sig, uint256 pathOffset)
        private
        pure
        returns (bytes32 tmp)
    {
        uint256 node = (1 << h) + q;
        tmp = sha256(abi.encodePacked(ident, uint32(node), uint16(0x8282), kc));
        for (uint256 i = 0; node > 1; i++) {
            bytes32 sibling = _word(sig, pathOffset + 32 * i);
            if (node & 1 == 1) {
                tmp = sha256(abi.encodePacked(ident, uint32(node >> 1), uint16(0x8383), sibling, tmp));
            } else {
                tmp = sha256(abi.encodePacked(ident, uint32(node >> 1), uint16(0x8383), tmp, sibling));
            }
            node >>= 1;
        }
    }

    /// Completes the LMOTS hash chains into the candidate one time public key
    function _candidate(
        bytes16 ident,
        uint256 q,
        bytes memory message,
        bytes memory sig,
        uint256 w,
        uint256 p,
        uint256 ls
    ) private view returns (bytes32 kc) {
        bytes32 c = _word(sig, 8);
        bytes32 bigQ = sha256(abi.encodePacked(ident, uint32(q), uint16(0x8181), c, message));
        uint256 top = (1 << w) - 1;
        uint256 sum;
        for (uint256 i = 0; i < 256 / w; i++) {
            sum += top - ((uint256(bigQ) >> (256 - w * (i + 1))) & top);
        }
        bytes memory qc = abi.encodePacked(bigQ, uint16(sum << ls), bytes30(0));
        bytes memory kbuf = new bytes(22 + 32 * p);
        bool ok = true;
        assembly {
            let kp := add(kbuf, 32)
            mstore(kp, ident)
            mstore(add(kp, 16), shl(224, q))
            mstore8(add(kp, 20), 0x80)
            mstore8(add(kp, 21), 0x80)
            let buf := mload(0x40)
            mstore(0x40, add(buf, 96))
            mstore(buf, ident)
            mstore(add(buf, 16), shl(224, q))
            let qcp := add(qc, 32)
            let yp := add(add(sig, 32), 40)
            let perByte := div(8, w)
            for { let i := 0 } lt(i, p) { i := add(i, 1) } {
                let byteVal := shr(248, mload(add(qcp, div(mul(i, w), 8))))
                let shift := sub(8, add(mul(w, mod(i, perByte)), w))
                let a := and(shr(shift, byteVal), top)
                mstore8(add(buf, 20), shr(8, i))
                mstore8(add(buf, 21), and(i, 0xff))
                mstore(add(buf, 23), mload(add(yp, mul(i, 32))))
                for { let j := a } lt(j, top) { j := add(j, 1) } {
                    mstore8(add(buf, 22), j)
                    ok := and(ok, and(staticcall(gas(), 2, buf, 55, add(buf, 23), 32), eq(returndatasize(), 32)))
                }
                mstore(add(add(kp, 22), mul(i, 32)), mload(add(buf, 23)))
            }
        }
        require(ok);
        kc = sha256(kbuf);
    }
}
