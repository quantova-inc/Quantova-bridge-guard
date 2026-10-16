// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.24;

import {LMSVerifier} from "./LMSVerifier.sol";
import {IBridgeGuard} from "./interfaces/IBridgeGuard.sol";

contract BridgeGuard is IBridgeGuard {
    enum Mode {
        Hybrid,
        PostQuantum
    }

    struct Signer {
        address ecdsa;
        bytes lmsPublicKey;
        bytes32 identifierSalt;
    }

    struct Attestation {
        uint256 signer;
        bytes ecdsaSignature;
        bytes lmsSignature;
    }

    struct Tally {
        bool reached;
        bool froze;
        uint256 frozenSigner;
        uint256 frozenLeaf;
        uint256 valid;
        bytes32[] keys;
        uint256[] leaves;
        bytes32[] records;
    }

    enum Outcome {
        Skipped,
        Frozen,
        Fresh,
        Repeat
    }

    bytes32 public constant ROOT_TAG = keccak256("ERC8443_ROOT_V1");
    bytes32 public constant REVOKE_TAG = keccak256("ERC8443_REVOKE_V1");
    bytes32 public constant CONFIG_TAG = keccak256("ERC8443_CONFIG_V1");
    bytes1 internal constant LEAF_PREFIX = 0x00;
    bytes1 internal constant NODE_PREFIX = 0x01;
    uint256 internal constant SECP256K1_HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 public constant GAS_BUDGET = 14_000_000;
    uint256 public constant CALLDATA_BUDGET = 120_000;
    uint256 public constant ROTATION_GAS_BUDGET = 16_000_000;
    uint64 public constant MINIMUM_ROOT_AGE_FLOOR = 60;
    uint256 public constant MAX_PROOF_DEPTH = 64;
    uint256 public constant ROTATION_GAS_PER_SIGNER = 90_000;
    uint256 internal constant ATTESTATION_ENCODING_OVERHEAD = 65 + 7 * 32;
    uint256 internal constant STORAGE_COST_PER_ATTESTATION = 70_000;
    bytes32 internal constant SHA256_ABC = 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad;
    bytes32 public constant LLA = "16121994";

    uint64 public immutable minimumRootAge;

    Signer[] internal _signers;
    uint256 public threshold;
    Mode public mode;
    uint64 public epoch;

    mapping(bytes32 => uint64) public rootApprovedAt;
    mapping(bytes32 => bool) public rootRevoked;
    mapping(bytes32 => bool) public frozenKey;
    mapping(bytes32 => uint256) public nextLeaf;
    mapping(bytes32 => mapping(uint256 => bytes32)) public leafSignature;
    mapping(bytes32 => mapping(bytes32 => bool)) public possessionProven;

    event RootApproved(bytes32 indexed root, uint64 indexed epoch, uint256 signatures);
    event RootRevoked(bytes32 indexed root, uint64 indexed epoch, uint256 signatures);
    event ConfigurationChanged(uint64 indexed epoch, uint256 signers, uint256 threshold, Mode mode);
    event PossessionProven(bytes32 indexed configDigest, bytes32 indexed lmsKeyHash);
    event LeafConsumed(bytes32 indexed lmsKeyHash, uint256 indexed leaf, bytes32 record);
    event SignerFrozen(bytes32 indexed lmsKeyHash, uint256 leaf, bytes32 recordA, bytes32 recordB);

    error InvalidConfiguration();
    error UnsupportedPlatform();
    error UnorderedAttestation();
    error UnknownSigner(uint256 index);
    error InvalidPostQuantumSignature(uint256 index);
    error InvalidClassicalSignature(uint256 index);
    error RootIsRevoked();
    error QuorumNotReached(uint256 valid, uint256 required);
    error MissingPossessionProof(uint256 index);
    error FrozenKey();
    error NotEquivocation();
    error EquivocationDetected(uint256 signer, uint256 leaf);

    /// Runs a SHA 256 known answer test and installs the first committee
    constructor(Signer[] memory signers_, uint256 threshold_, Mode mode_, uint64 minimumRootAge_) {
        if (sha256("abc") != SHA256_ABC) revert UnsupportedPlatform();
        if (minimumRootAge_ < MINIMUM_ROOT_AGE_FLOOR) revert InvalidConfiguration();
        minimumRootAge = minimumRootAge_;
        _configure(signers_, threshold_, mode_);
    }

    /// Derives the LMS identifier a key must carry on this guard and chain for a given salt
    function identifierFor(bytes32 salt) public view returns (bytes16) {
        return bytes16(keccak256(abi.encode(block.chainid, address(this), salt)));
    }

    /// Returns the number of committee members
    function signerCount() external view returns (uint256) {
        return _signers.length;
    }

    /// Returns the ECDSA address and LMS public key of one member
    function signerAt(uint256 index) external view returns (Signer memory) {
        return _signers[index];
    }

    /// Counts members whose keys are not frozen
    function liveSignerCount() public view returns (uint256 live) {
        for (uint256 i = 0; i < _signers.length; i++) {
            if (!frozenKey[keccak256(_signers[i].lmsPublicKey)]) live++;
        }
    }

    /// Returns one past the highest LMS leaf recorded for a member
    function nextLeafOf(uint256 index) external view returns (uint256) {
        return nextLeaf[keccak256(_signers[index].lmsPublicKey)];
    }

    /// Tells whether an LMS leaf of a key has already signed
    function isLeafUsed(bytes calldata lmsPublicKey, uint256 leaf) external view returns (bool) {
        return leafSignature[keccak256(lmsPublicKey)][leaf] != bytes32(0);
    }

    /// Binds a batch root to this chain, guard and epoch for approval
    function rootDigest(bytes32 root) public view returns (bytes32) {
        return keccak256(abi.encode(ROOT_TAG, block.chainid, address(this), epoch, root));
    }

    /// Binds a batch root to this chain, guard and epoch for revocation
    function revokeDigest(bytes32 root) public view returns (bytes32) {
        return keccak256(abi.encode(REVOKE_TAG, block.chainid, address(this), epoch, root));
    }

    /// Binds a new committee to this chain, guard and epoch
    function configDigest(Signer[] calldata signers_, uint256 threshold_, Mode mode_) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                CONFIG_TAG, block.chainid, address(this), epoch, keccak256(abi.encode(signers_)), threshold_, mode_
            )
        );
    }

    /// Approves a batch root once a strict majority of LMS attestations verify
    function approveRoot(bytes32 root, Attestation[] calldata attestations) external {
        if (rootRevoked[root]) revert RootIsRevoked();
        Tally memory t = _quorum(rootDigest(root), attestations);
        _commit(t);
        if (rootApprovedAt[root] == 0) rootApprovedAt[root] = uint64(block.timestamp);
        emit RootApproved(root, epoch, t.valid);
    }

    /// Revokes a batch root once a strict majority of LMS attestations verify
    function revokeRoot(bytes32 root, Attestation[] calldata attestations) external {
        Tally memory t = _quorum(revokeDigest(root), attestations);
        _commit(t);
        rootRevoked[root] = true;
        emit RootRevoked(root, epoch, t.valid);
    }

    /// Records a new member's LMS signature over the committee digest as proof it holds the key
    function provePossession(
        Signer[] calldata signers_,
        uint256 threshold_,
        Mode mode_,
        uint256 index,
        Attestation calldata proof
    ) external {
        if (index >= signers_.length || proof.signer != index) revert MissingPossessionProof(index);
        bytes32 digest = configDigest(signers_, threshold_, mode_);
        bytes calldata pub = signers_[index].lmsPublicKey;
        bytes32 keyHash = keccak256(pub);
        if (frozenKey[keyHash]) revert FrozenKey();
        if (!LMSVerifier.verify(pub, abi.encodePacked(digest), proof.lmsSignature)) {
            revert InvalidPostQuantumSignature(index);
        }
        uint256 q = LMSVerifier.leafIndex(proof.lmsSignature);
        bytes32 record = _record(digest, proof.lmsSignature);
        bytes32 recorded = leafSignature[keyHash][q];
        if (recorded != bytes32(0) && recorded != record) {
            _freeze(keyHash, q, recorded, record);
            return;
        }
        if (mode_ == Mode.Hybrid && _recover(digest, proof.ecdsaSignature) != signers_[index].ecdsa) {
            revert InvalidClassicalSignature(index);
        }
        if (recorded == bytes32(0)) _markLeaf(keyHash, q, record);
        possessionProven[digest][keyHash] = true;
        emit PossessionProven(digest, keyHash);
    }

    /// Rotates the committee once the current majority signs the new configuration
    function reconfigure(
        Signer[] calldata signers_,
        uint256 threshold_,
        Mode mode_,
        Attestation[] calldata attestations
    ) external {
        bytes32 digest = configDigest(signers_, threshold_, mode_);
        Tally memory t = _quorum(digest, attestations);
        if (t.froze) {
            for (uint256 i = 0; i < signers_.length; i++) {
                if (frozenKey[keccak256(signers_[i].lmsPublicKey)]) {
                    revert EquivocationDetected(t.frozenSigner, t.frozenLeaf);
                }
            }
        }
        uint256 current = _signers.length;
        bytes32[] memory currentKeys = new bytes32[](current);
        for (uint256 k = 0; k < current; k++) {
            currentKeys[k] = keccak256(_signers[k].lmsPublicKey);
        }
        for (uint256 i = 0; i < signers_.length; i++) {
            bytes32 keyHash = keccak256(signers_[i].lmsPublicKey);
            if (possessionProven[digest][keyHash]) continue;
            bool proven;
            for (uint256 k = 0; k < current; k++) {
                if (currentKeys[k] == keyHash) {
                    proven = mode_ != Mode.Hybrid || (mode == Mode.Hybrid && _signers[k].ecdsa == signers_[i].ecdsa);
                    break;
                }
            }
            if (!proven) revert MissingPossessionProof(i);
        }
        _commit(t);
        delete _signers;
        _configure(signers_, threshold_, mode_);
    }

    /// Tells whether a root is approved, unrevoked and past the minimum root age
    function isApproved(bytes32 root) public view override returns (bool) {
        uint64 at = rootApprovedAt[root];
        return at != 0 && !rootRevoked[root] && block.timestamp >= uint256(at) + minimumRootAge;
    }

    /// Hashes a leaf with a prefix that separates leaves from internal nodes
    function leafHash(bytes32 leaf) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(LEAF_PREFIX, leaf));
    }

    /// Folds a Merkle proof into a root, or returns zero for an oversized proof
    function computeRoot(bytes32 leaf, uint256 index, bytes32[] calldata proof) public pure returns (bytes32 node) {
        if (proof.length > MAX_PROOF_DEPTH || index >> proof.length != 0) return bytes32(0);
        node = leafHash(leaf);
        for (uint256 i = 0; i < proof.length; i++) {
            if ((index >> i) & 1 == 1) {
                node = keccak256(abi.encodePacked(NODE_PREFIX, proof[i], node));
            } else {
                node = keccak256(abi.encodePacked(NODE_PREFIX, node, proof[i]));
            }
        }
    }

    /// Tells whether a leaf sits in an approved batch root
    function isIncluded(bytes32 root, bytes32 leaf, uint256 index, bytes32[] calldata proof)
        external
        view
        override
        returns (bool)
    {
        return root != bytes32(0) && isApproved(root) && computeRoot(leaf, index, proof) == root;
    }

    /// Freezes a key that signed two digests with one LMS leaf
    function reportEquivocation(
        bytes calldata lmsPublicKey,
        bytes32 digestA,
        bytes calldata lmsSignatureA,
        bytes32 digestB,
        bytes calldata lmsSignatureB
    ) external {
        uint256 leaf = LMSVerifier.leafIndex(lmsSignatureA);
        if (
            keccak256(lmsSignatureA) == keccak256(lmsSignatureB) || leaf != LMSVerifier.leafIndex(lmsSignatureB)
                || !LMSVerifier.verify(lmsPublicKey, abi.encodePacked(digestA), lmsSignatureA)
                || !LMSVerifier.verify(lmsPublicKey, abi.encodePacked(digestB), lmsSignatureB)
        ) revert NotEquivocation();
        _freeze(keccak256(lmsPublicKey), leaf, _record(digestA, lmsSignatureA), _record(digestB, lmsSignatureB));
    }

    /// Counts valid attestations and reverts unless the threshold is reached
    function _quorum(bytes32 digest, Attestation[] calldata attestations) internal returns (Tally memory t) {
        uint256 count = attestations.length;
        t.keys = new bytes32[](count);
        t.leaves = new uint256[](count);
        t.records = new bytes32[](count);
        uint256 previous;
        for (uint256 k = 0; k < count; k++) {
            Attestation calldata a = attestations[k];
            if (k > 0 && a.signer <= previous) revert UnorderedAttestation();
            previous = a.signer;
            (Outcome outcome, bytes32 keyHash, uint256 q, bytes32 record) = _check(digest, a);
            if (outcome == Outcome.Frozen && !t.froze) {
                t.froze = true;
                t.frozenSigner = a.signer;
                t.frozenLeaf = q;
            }
            if (outcome == Outcome.Skipped || outcome == Outcome.Frozen) continue;
            t.keys[t.valid] = keyHash;
            if (outcome == Outcome.Fresh) {
                t.leaves[t.valid] = q;
                t.records[t.valid] = record;
            }
            t.valid++;
        }
        t.reached = t.valid >= threshold;
        if (!t.reached) {
            if (t.froze) revert EquivocationDetected(t.frozenSigner, t.frozenLeaf);
            revert QuorumNotReached(t.valid, threshold);
        }
    }

    /// Classifies one attestation as fresh, repeated, skipped or equivocating
    function _check(bytes32 digest, Attestation calldata a)
        internal
        returns (Outcome outcome, bytes32 keyHash, uint256 q, bytes32 record)
    {
        if (a.signer >= _signers.length) revert UnknownSigner(a.signer);
        Signer storage s = _signers[a.signer];
        bytes memory pub = s.lmsPublicKey;
        keyHash = keccak256(pub);
        if (frozenKey[keyHash]) return (Outcome.Skipped, keyHash, 0, 0);
        q = LMSVerifier.leafIndex(a.lmsSignature);
        record = _record(digest, a.lmsSignature);
        bytes32 recorded = leafSignature[keyHash][q];
        if (recorded != bytes32(0) && recorded != record) {
            if (!LMSVerifier.verify(pub, abi.encodePacked(digest), a.lmsSignature)) {
                return (Outcome.Skipped, keyHash, q, 0);
            }
            _freeze(keyHash, q, recorded, record);
            return (Outcome.Frozen, keyHash, q, 0);
        }
        if (recorded == bytes32(0) && !LMSVerifier.verify(pub, abi.encodePacked(digest), a.lmsSignature)) {
            revert InvalidPostQuantumSignature(a.signer);
        }
        if (mode == Mode.Hybrid && _recover(digest, a.ecdsaSignature) != s.ecdsa) {
            revert InvalidClassicalSignature(a.signer);
        }
        outcome = recorded == bytes32(0) ? Outcome.Fresh : Outcome.Repeat;
    }

    /// Records the LMS leaves of a successful action
    function _commit(Tally memory t) internal {
        for (uint256 k = 0; k < t.valid; k++) {
            if (t.records[k] != bytes32(0)) _markLeaf(t.keys[k], t.leaves[k], t.records[k]);
        }
    }

    /// Hashes a digest with an LMS signature into the record stored for its leaf
    function _record(bytes32 digest, bytes calldata lmsSignature) internal pure returns (bytes32) {
        return keccak256(abi.encode(digest, keccak256(lmsSignature)));
    }

    /// Freezes an LMS key after proven leaf reuse
    function _freeze(bytes32 keyHash, uint256 leaf, bytes32 recordA, bytes32 recordB) internal {
        frozenKey[keyHash] = true;
        emit SignerFrozen(keyHash, leaf, recordA, recordB);
    }

    /// Stores the record for a used LMS leaf and advances the leaf counter
    function _markLeaf(bytes32 keyHash, uint256 q, bytes32 record) internal {
        leafSignature[keyHash][q] = record;
        if (q + 1 > nextLeaf[keyHash]) nextLeaf[keyHash] = q + 1;
        emit LeafConsumed(keyHash, q, record);
    }

    /// Validates and installs a committee within the gas and calldata budgets
    function _configure(Signer[] memory signers_, uint256 threshold_, Mode mode_) internal {
        uint256 n = signers_.length;
        if (n == 0 || threshold_ > n || threshold_ * 2 <= n) revert InvalidConfiguration();
        uint256 worstGas;
        uint256 worstBytes;
        for (uint256 i = 0; i < n; i++) {
            Signer memory s = signers_[i];
            if (s.lmsPublicKey.length != LMSVerifier.PUBLIC_KEY_LENGTH) revert InvalidConfiguration();
            bytes16 identifier = _identifier(s.lmsPublicKey);
            if (identifier != identifierFor(s.identifierSalt)) revert InvalidConfiguration();
            (uint256 gasCost, uint256 bytesCost) = _attestationCost(s.lmsPublicKey);
            if (gasCost == 0) revert InvalidConfiguration();
            if (gasCost > worstGas) worstGas = gasCost;
            if (bytesCost > worstBytes) worstBytes = bytesCost;
            if (frozenKey[keccak256(s.lmsPublicKey)]) revert InvalidConfiguration();
            if (mode_ == Mode.Hybrid && s.ecdsa == address(0)) revert InvalidConfiguration();
            for (uint256 j = 0; j < i; j++) {
                if (keccak256(signers_[j].lmsPublicKey) == keccak256(s.lmsPublicKey)) revert InvalidConfiguration();
                if (_identifier(signers_[j].lmsPublicKey) == identifier) revert InvalidConfiguration();
                if (mode_ == Mode.Hybrid && signers_[j].ecdsa == s.ecdsa) revert InvalidConfiguration();
            }
            _signers.push(s);
        }
        if (
            threshold_ * worstGas > GAS_BUDGET || threshold_ * worstBytes > CALLDATA_BUDGET
                || threshold_ * worstGas + n * ROTATION_GAS_PER_SIGNER > ROTATION_GAS_BUDGET
        ) revert InvalidConfiguration();
        threshold = threshold_;
        mode = mode_;
        epoch += 1;
        emit ConfigurationChanged(epoch, n, threshold_, mode_);
    }

    /// Reads the LMS identifier I from a public key
    function _identifier(bytes memory pub) internal pure returns (bytes16) {
        bytes32 word;
        assembly {
            word := mload(add(pub, 40))
        }
        return bytes16(word);
    }

    /// Estimates the worst case gas and calldata of one attestation for a key
    function _attestationCost(bytes memory pub) internal pure returns (uint256 gasCost, uint256 bytesCost) {
        uint32 lmsType;
        uint32 otsType;
        assembly {
            lmsType := shr(224, mload(add(pub, 32)))
            otsType := shr(224, mload(add(pub, 36)))
        }
        uint256 length = LMSVerifier.signatureLength(lmsType, otsType);
        if (length == 0) return (0, 0);
        uint256 execution;
        if (otsType == 1) execution = 290_000;
        else if (otsType == 2) execution = 235_000;
        else if (otsType == 3) execution = 360_000;
        else execution = 2_500_000;
        execution += 300 * LMSVerifier.treeHeight(lmsType);
        bytesCost = length + ATTESTATION_ENCODING_OVERHEAD;
        gasCost = execution + 16 * bytesCost + STORAGE_COST_PER_ATTESTATION;
    }

    /// Recovers a low s secp256k1 signer from a digest
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (uint256(s) > SECP256K1_HALF_N || (v != 27 && v != 28)) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
