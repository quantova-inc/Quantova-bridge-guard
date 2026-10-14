// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

interface ILayerZeroDVN {
    struct AssignJobParam {
        uint32 dstEid;
        bytes packetHeader;
        bytes32 payloadHash;
        uint64 confirmations;
        address sender;
    }

    /// Assigns a verification job to the verifier
    function assignJob(AssignJobParam calldata param, bytes calldata options) external payable returns (uint256 fee);

    /// Quotes the fee for a verification job
    function getFee(uint32 dstEid, uint64 confirmations, address sender, bytes calldata options)
        external
        view
        returns (uint256 fee);
}

interface IReceiveUlnVerify {
    /// Records a verifier's confirmation of a packet
    function verify(bytes calldata packetHeader, bytes32 payloadHash, uint64 confirmations) external;

    /// Reads a verifier's recorded confirmation of a packet
    function hashLookup(bytes32 headerHash, bytes32 payloadHash, address dvn)
        external
        view
        returns (bool submitted, uint64 confirmations);
}

interface ISendLibFees {
    /// Withdraws accrued verifier fees
    function withdrawFee(address to, uint256 amount) external;
}

interface IEndpointInbound {
    /// Reads the payload hash the endpoint holds for an inbound nonce
    function inboundPayloadHash(address receiver, uint32 srcEid, bytes32 sender, uint64 nonce)
        external
        view
        returns (bytes32);
}
