// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

interface IBridgeGuard {
    /// Tells whether a batch root is approved and usable
    function isApproved(bytes32 root) external view returns (bool);

    /// Tells whether a leaf sits in an approved batch root
    function isIncluded(bytes32 root, bytes32 leaf, uint256 index, bytes32[] calldata proof)
        external
        view
        returns (bool);
}
