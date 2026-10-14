// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import {ILayerZeroDVN, IReceiveUlnVerify, ISendLibFees, IEndpointInbound} from "../interfaces/ILayerZeroDVN.sol";
import {IBridgeGuard} from "../interfaces/IBridgeGuard.sol";

contract LayerZeroQuantumDVN is ILayerZeroDVN {
    bytes32 public constant LEAF_TAG = keccak256("QUANTOVA_BRIDGE_GUARD_LAYERZERO_V1");
    uint256 internal constant HEADER_LENGTH = 81;
    uint8 internal constant PACKET_VERSION = 1;
    bytes32 internal constant NIL_PAYLOAD_HASH = bytes32(type(uint256).max);

    IBridgeGuard public immutable guard;
    IEndpointInbound public immutable endpoint;
    uint32 public immutable localEid;
    address public immutable sendLib;
    address payable public immutable treasury;
    uint256 public immutable fee;

    mapping(uint32 => bool) public supportedDstEid;

    event JobAssigned(uint32 indexed dstEid, bytes32 indexed payloadHash, uint64 confirmations, address sender);
    event PacketVerified(
        address indexed receiveLib, bytes32 indexed headerHash, bytes32 indexed payloadHash, bytes32 root
    );

    error MalformedHeader();
    error NotAttested();
    error AlreadyDelivered();
    error Nilified();
    error UnauthorizedSendLib();
    error UnsupportedDestination(uint32 dstEid);
    error TransferFailed();
    error ZeroAddress();
    error Unauthorized();

    /// Fixes the guard, endpoint, send library, destinations, treasury and fee
    constructor(
        IBridgeGuard guard_,
        IEndpointInbound endpoint_,
        uint32 localEid_,
        address sendLib_,
        uint32[] memory dstEids_,
        address payable treasury_,
        uint256 fee_
    ) {
        if (
            address(guard_) == address(0) || address(endpoint_) == address(0) || sendLib_ == address(0)
                || treasury_ == address(0)
        ) revert ZeroAddress();
        guard = guard_;
        endpoint = endpoint_;
        localEid = localEid_;
        sendLib = sendLib_;
        treasury = treasury_;
        fee = fee_;
        for (uint256 i = 0; i < dstEids_.length; i++) {
            supportedDstEid[dstEids_[i]] = true;
        }
    }

    /// Binds a packet to this verifier, its receive library and confirmations
    function leafFor(address receiveLib, bytes calldata packetHeader, bytes32 payloadHash, uint64 confirmations)
        public
        view
        returns (bytes32)
    {
        if (
            packetHeader.length != HEADER_LENGTH || uint8(packetHeader[0]) != PACKET_VERSION
                || uint32(bytes4(packetHeader[45:49])) != localEid
        ) {
            revert MalformedHeader();
        }
        return keccak256(
            abi.encode(
                LEAF_TAG, localEid, address(this), receiveLib, keccak256(packetHeader), payloadHash, confirmations
            )
        );
    }

    /// Verifies a packet against an approved batch and forwards it to the receive library
    function submit(
        address receiveLib,
        bytes calldata packetHeader,
        bytes32 payloadHash,
        uint64 confirmations,
        bytes32 root,
        uint256 index,
        bytes32[] calldata proof
    ) external {
        bytes32 leaf = leafFor(receiveLib, packetHeader, payloadHash, confirmations);
        if (!guard.isIncluded(root, leaf, index, proof)) revert NotAttested();
        bytes32 headerHash = keccak256(packetHeader);
        address receiver = address(uint160(uint256(bytes32(packetHeader[49:81]))));
        bytes32 inbound = endpoint.inboundPayloadHash(
            receiver,
            uint32(bytes4(packetHeader[9:13])),
            bytes32(packetHeader[13:45]),
            uint64(bytes8(packetHeader[1:9]))
        );
        if (inbound == NIL_PAYLOAD_HASH && msg.sender != receiver) revert Nilified();
        (bool submitted, uint64 current) =
            IReceiveUlnVerify(receiveLib).hashLookup(headerHash, payloadHash, address(this));
        if (submitted && current >= confirmations) revert AlreadyDelivered();
        emit PacketVerified(receiveLib, headerHash, payloadHash, root);
        IReceiveUlnVerify(receiveLib).verify(packetHeader, payloadHash, confirmations);
    }

    /// Accepts a verification job from the send library
    function assignJob(AssignJobParam calldata param, bytes calldata) external payable returns (uint256) {
        if (msg.sender != sendLib) revert UnauthorizedSendLib();
        if (!supportedDstEid[param.dstEid]) revert UnsupportedDestination(param.dstEid);
        emit JobAssigned(param.dstEid, param.payloadHash, param.confirmations, param.sender);
        return fee;
    }

    /// Quotes the verification fee for a destination
    function getFee(uint32 dstEid, uint64, address, bytes calldata) external view returns (uint256) {
        if (!supportedDstEid[dstEid]) revert UnsupportedDestination(dstEid);
        return fee;
    }

    /// Moves accrued fees from the send library to the treasury
    function withdrawFromLibrary(uint256 amount) external {
        if (msg.sender != treasury) revert Unauthorized();
        ISendLibFees(sendLib).withdrawFee(treasury, amount);
    }

    /// Sends any ether held here to the treasury
    function sweep() external {
        if (msg.sender != treasury) revert Unauthorized();
        (bool ok,) = treasury.call{value: address(this).balance}("");
        if (!ok) revert TransferFailed();
    }
}
