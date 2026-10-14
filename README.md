# Quantova Bridge Guard

**The post quantum shield for bridges on Ethereum.**

Quantova is the first to issue an open source post quantum protection layer for the bridges that move value on Ethereum. Quantova Bridge Guard lets an existing bridge require hash based signatures that a quantum computer cannot forge before it accepts any cross chain message, without replacing the bridge and without a pause in service.

Built and owned by Quantova Inc, www.quantova.org, the team behind the Qstamp SDK family, qstamp.org.

Copyright 2026 Quantova Inc. Owned by Quantova Inc and dual licensed under the Apache License, Version 2.0 and the MIT License, at your option. Quantova is a trademark of Quantova Inc.

Quantova Bridge Guard is a protection layer for third party bridges that operate on Ethereum. It is not a bridge, it never holds or moves assets, and it is not a Quantova bridge. It is independent work of Quantova Inc and is not affiliated with or endorsed by the Ethereum Foundation or LayerZero.

## What Quantova has built

| Component | Location | Role |
|---|---|---|
| LMS verifier | `src/LMSVerifier.sol` | Verifies RFC 8554 hash based signatures on chain through the SHA 256 precompile |
| Guard core | `src/BridgeGuard.sol` | Approves and revokes batches of cross chain messages by a quorum of post quantum signatures, rotates its committee, and freezes any key that is misused |
| Bridge interface | `src/interfaces/IBridgeGuard.sol` | The two calls any bridge on Ethereum makes to accept a message, `isApproved` and `isIncluded` |
| LayerZero shield | `src/adapters/LayerZeroQuantumDVN.sol` | A decentralized verifier network contract that any LayerZero V2 application can require |
| Signer kit | `kit/bridgeguard` | A standard library Python signer that generates keys, signs batches and protects the one time key state |

## Why bridges need a shield

Bridges on Ethereum are secured today by committees that sign with secp256k1 ECDSA or BLS12 381. Shor's algorithm recovers the private key behind any such public key in polynomial time on a fault tolerant quantum computer. With a recovered committee key an adversary can attest to messages that never happened and release assets on the destination chain. Committee public keys are published on chain, so they are exposed long before such a machine exists. A bridge is only as strong as the signatures that guard it, and every asset it carries inherits that weakness.

## How the shield works

1. Committee members observe messages on the source chain and collect them into a Merkle tree.
2. Each member signs the tree root with an LMS key as specified in RFC 8554, using the SHA 256 parameter sets with 32 byte outputs listed in NIST SP 800 208. In hybrid mode each member also signs with ECDSA, so the shield is at least as strong as the stronger of the two during migration.
3. Anyone submits the signatures to `BridgeGuard.approveRoot`. The root is approved only when a strict majority of distinct, unfrozen members sign it.
4. Each message is then delivered through the bridge with an inclusion proof against the approved root. The bridge refuses any message that is not included in an approved root.
5. The committee can revoke a root at any time, an optional minimum root age gives time to act before a root becomes usable, and the committee rotates to post quantum only mode through a quorum signed reconfiguration.

Post quantum verification is paid once per batch, not once per message, so once its batch of 256 is approved a single message costs about 7k gas for the inclusion check, or about 129k gas through the LayerZero verifier including the receive library call.

The shield works at the message layer, so every asset a protected bridge carries is covered with no per asset code. Native ETH, ERC 20 tokens, NFTs, bridged token representations and arbitrary contract calls are all protected by the same check.

## How it plugs into a bridge

```
source chain event
      |
committee signs the batch root with LMS, plus ECDSA in hybrid mode
      |
BridgeGuard.approveRoot on the destination chain
      |
bridge receive path   →  BridgeGuard.isIncluded(root, leaf, index, proof)  →  message released
LayerZero ReceiveUln302  ←  LayerZeroQuantumDVN.submit  →  commit and lzReceive
```

**Any bridge.** A bridge calls `isIncluded` on the guard with the message leaf, its index and its Merkle proof before it releases a message, and refuses the message when the call returns false. The leaf must bind a domain tag for the bridge, the destination, the bridge endpoint and the full message. During migration the bridge keeps its existing verification and requires both.

**LayerZero.** `LayerZeroQuantumDVN` implements the verifier interface used by the LayerZero V2 send and receive libraries. An application adds its address to the required or optional verifiers in its ULN configuration through `setConfig` on the endpoint. Any party with an inclusion proof can then call `submit`, which checks the approved root and forwards the verification to the receive library. It reads the endpoint state, so a packet that the application nilifies can be verified again only by that application. Fees accrue in the send library and only the treasury can withdraw or sweep them.

## How bridge developers adopt it

1. **Add the dependency.** In a Foundry project run `forge install quantova-inc/Quantova-bridge-guard` and import the adapters, or deploy the contracts from this repository as they are.
2. **Generate committee keys.** Fix the guard address first, through CREATE2 or a known deployer nonce. Each committee member then runs the signer kit on its own host with the chain identifier and that guard address, and publishes its LMS public key and ECDSA address.
3. **Deploy the guard.** Deploy `BridgeGuard` with the signer list, a strict majority threshold, hybrid mode and a minimum root age.
4. **Deploy the shield for your bridge.** Add the `isIncluded` check to the bridge receive path, or deploy `LayerZeroQuantumDVN` with the guard, the endpoint, the local endpoint identifier, the send library, the supported destinations, a treasury and a fee.
5. **Run it alongside your current security.** Add the shield next to your existing module or verifiers, so nothing is lost if either side fails. Test the full path on a testnet.
6. **Merge into your main branch.** Open a pull request in your own repository that adds the dependency, the deployment scripts and the configuration change. Review it, audit it under your own process, and merge it into your main branch when your maintainers approve.
7. **Complete the migration.** Once every committee member has proven possession of its post quantum key, reconfigure the guard to post quantum only mode, and the bridge no longer depends on any signature that a quantum computer can break.

Deployment with Foundry looks like this.

```
forge create src/BridgeGuard.sol:BridgeGuard --constructor-args "[(0xECDSA1,0xLMSKEY1),(0xECDSA2,0xLMSKEY2),(0xECDSA3,0xLMSKEY3)]" 2 0 3600
forge create src/adapters/LayerZeroQuantumDVN.sol:LayerZeroQuantumDVN --constructor-args 0xGUARD 0xENDPOINT 30101 0xSENDLIB "[30110]" 0xTREASURY 0
```

## Security properties

| Property | Mechanism |
|---|---|
| Unforgeability against quantum adversaries | LMS with SHA 256, about 128 bit security against Grover search |
| No replay across chains, guards or epochs | Every digest binds a domain tag, the chain identifier, the guard address and the configuration epoch |
| One time key safety on chain | Every used leaf of every key is recorded with a hash of the digest and the signature, in any arrival order, and is bound to that digest forever |
| Evidence of key misuse | Two valid signatures at one leaf freeze the key for anyone who submits them to `reportEquivocation`, and a second valid signature met during an action that still reaches the threshold freezes the key in that action |
| All or nothing actions | An approval, revocation or rotation either takes full effect or reverts. When an equivocating member costs the quorum, the call reverts with `EquivocationDetected` naming that member and leaf, honest members keep their signatures, and the action succeeds once the key is frozen or left out |
| Proof of possession | Every new member signs the configuration digest. An identical recorded attestation counts again for the same digest, so a member's proof of possession for a configuration is also its vote for that configuration, and publishing it early cannot block a rotation |
| Revocation | A quorum can revoke an approved root, and every root waits a minimum root age of at least 60 seconds, set per deployment, before any message can use it |
| Key binding | The first eight bytes of every LMS identifier I equal the first eight bytes of keccak256 over the chain identifier and the guard address, and the last eight bytes are random per key. The guard rejects keys bound elsewhere and committees with a duplicate identifier, so each key serves exactly one guard on one chain |
| Membership | Members kept in a rotation need no fresh signature, so an offline honest member is retained. New members, and members whose classical key changes, must prove possession |
| Fail safe halt | If misuse freezes so many keys that fewer live members remain than the threshold, the guard stops approving anything. `liveSignerCount` exposes the margin, and recovery is a new guard and shield that the application selects |
| Executability | A committee is accepted only when its worst case approval fits 14M gas and 120 KB of attestation data, and its threshold cost plus 90k gas per member fits 16M gas. Rotation to a committee no larger than the current one is therefore always executable, and the largest growth rotations measured stay far below the EIP 7825 cap of 16,777,216 gas per transaction |
| Platform check | The constructor runs a SHA 256 known answer test against the precompile |

## Parameter sets and cost

LMOTS W4 is the recommended default. Measured execution cost per signature on the EVM.

| LMOTS | Gas per signature | Signature size |
|---|---|---|
| W1 | 226k to 240k | 8.7 to 9.3 KB |
| W2 | 152k to 170k | 4.5 to 5.1 KB |
| W4 | 185k to 224k | 2.3 to 2.9 KB |
| W8 | 1.06M to 1.58M | 1.3 to 1.9 KB |

Execution gas measured with LMS H10 and LMOTS W4.

| Committee | Approve, hybrid | Approve, post quantum | Revoke | Rotate |
|---|---|---|---|---|
| 2 of 3 | 549k | 504k | 550k | 787k |
| 3 of 4 | 849k | 758k | 781k | 1.14M |
| 4 of 7 | 1.13M | 1.00M | 1.01M | 1.62M |
| 6 of 10 | 1.69M | 1.47M | 1.54M | 2.49M |

A proof of possession costs about 279k gas and an equivocation report about 456k gas. The full benchmark and smoke test report is in `benchmarks`.

The largest committees accepted, written as threshold of members.

| LMOTS | H5 | H10 | H15 | H20 | H25 |
|---|---|---|---|---|---|
| W1 | 13 of 25 | 13 of 25 | 12 of 23 | 12 of 23 | 12 of 23 |
| W2 | 25 of 49 | 24 of 47 | 23 of 45 | 22 of 43 | 22 of 43 |
| W4 | 24 of 47 | 24 of 47 | 24 of 47 | 24 of 47 | 24 of 47 |
| W8 | 5 of 9 | 5 of 9 | 5 of 9 | 5 of 9 | 5 of 9 |

The worst case rotations at these limits, growing a committee to its maximum with every key new, measured 11.5M gas for W4, 12.6M gas for W2 and 8.7M gas for W1 at height 5.

## Signer kit

The `kit` directory contains a standard library Python signer for committee members. It generates LMS keys, signs only semantically constructed digests for root approval, revocation and reconfiguration, and protects the one time key state.

```
export BRIDGEGUARD_HWM_DIR=/var/lib/bridgeguard/hwm
python3 -m bridgeguard keygen --dir signer --height 20 --winternitz 4 --chain-id 1 --guard 0xGUARD
python3 -m bridgeguard attest-root --dir signer --signer 0 --chain-id 1 --guard 0xGUARD --epoch 1 --root 0xROOT --onchain-next-leaf 0
python3 -m bridgeguard attest-config --dir signer --signer 0 --chain-id 1 --guard 0xGUARD --epoch 1 --signers signers.json --threshold 3 --mode 1 --onchain-next-leaf 4
python3 -m bridgeguard rebind --dir signer --onchain-next-leaf 9 --issued-upper-bound 40
```

Every signing command needs the environment variable `BRIDGEGUARD_HWM_DIR`, an absolute path to a high water mark directory on storage separate from the key directory. Before it releases a signature the kit holds a lock for the key that spans every copy of the key on the host, advances a monotonic high water mark that never moves backwards, and reserves the leaf in the key state, both on durable storage. It refuses to sign when the key state is behind the high water mark, the signing journal or the on chain leaf counter. It refuses directories accessible by other users or carrying an access control list, refuses symbolic links, verifies every leaf before reserving it, keeps reserve leaves for revocation and reconfiguration, and validates every configuration against the contract rules before signing it. Keys are generated bound to one chain and one guard, and the kit refuses any signing request for another chain or guard before it touches leaf state.

A key directory that was moved or copied must be rebound with `rebind`, which jumps past every leaf the high water mark, the journal and the chain have seen. When the high water mark is lost, `rebind` also needs an upper bound on issued leaves taken from the aggregator and watcher logs, otherwise the key must be retired. `retire` writes a tombstone into the high water mark, so no copy of a retired key can sign or be rebound on that host.

The LMS randomizer is derived deterministically with HMAC SHA 256 under a dedicated randomizer key generated with the private key, bound to the leaf and the message. A signer that is rolled back and asked to sign the same digest again produces the identical signature, which the guard counts once. RFC 8554 permits any unpredictable process for the randomizer, while NIST SP 800 208 asks for an approved random bit generator, so deployments that require strict SP 800 208 conformance should generate the randomizer inside a validated module.

## Operational requirements

An LMS key is stateful. Each key signs at most 2 to the power of its tree height times. Run exactly one signer host per key on a local file system. Never back up, restore, copy or clone a key directory. A key that must be restored is retired and replaced through reconfiguration. Keep keys and the high water mark off storage that can be snapshotted, replicated or rolled back. The high water mark protects against restoring the key directory alone, not against rolling back a whole host, so prefer a hardware security module with a monotonic counter where one is available. Height 5 keys are for testing, since they have too few leaves to rebind. The pure Python kit generates heights up to 20.

The kit refuses key and high water mark directories on network file systems such as NFS and SMB, where file locks are not reliable. A block level clone, a virtual machine snapshot or a disk image keeps the directory inode, so the kit cannot tell a clone from the original, and two live clones of one key would reuse leaves. Never run a cloned signer host. Pass the on chain leaf counter to every signing command. Run a watcher that submits any two signatures from one leaf to `reportEquivocation` on every guard that lists the key, and a relayer that retries an action without the named member after `EquivocationDetected`. Monitor remaining leaves and rotate keys before the reserve is reached. Roots approved by an earlier committee remain valid until revoked, so revoke them when a committee is rotated for cause. Recovery after a halt is a new guard at a new address, which needs fresh keys for every member. Size each committee so that members minus threshold covers the keys that could be lost or frozen at the same time.

## Scope of protection

The shield makes forged attestations infeasible for a quantum adversary. It does not make the source chain, the bridge contracts, the governance keys of a bridge, or the accounts of its users post quantum. Committee members attest to what they observe on the source chain, so the guarantee holds for messages that genuinely occurred there. Keccak 256 is used for digests and Merkle trees and rests on hash assumptions with about 128 bit preimage security against Grover search.

## Verification

The LMS verifier reproduces the RFC 8554 Appendix F test vectors, including key generation for test case 2, and agrees with the reference implementation across every supported parameter set. Fuzzing rejects every single bit change to signatures, public keys and messages. The contracts, the adapters and the signer kit have passed five rounds of internal adversarial review and a security audit by NioLabs that found no critical and no high severity issues. Every finding is resolved or answered in the audit report. Bridges should still review and test the integration under their own process before they secure production value with it.

## Authorship stamp

`BridgeGuard` carries the constant `LLA`, holding `16121994`. It is the Quantova Inc authorship stamp, compiled into the deployed bytecode so every deployment carries it. It is read only and takes no part in verification.

## Testing

```
git submodule update --init
FOUNDRY_PROFILE=local forge test
python3 kit/tests/rfc_vectors.py
python3 kit/tests/safety.py
python3 smoke/smoke_anvil.py
```

The contract suite covers the quorum, rotation, freezing, replay binding, the LayerZero verifier and fuzzed Merkle proofs, checks the RFC 8554 vectors, and proves byte for byte agreement between the contracts and the signer kit. The kit suite covers leaf safety under crashes, copies, restores, clones, concurrent signers, access control lists and network file systems. The smoke test deploys everything on a local Ethereum node and runs approval, message acceptance by inclusion proof, LayerZero delivery, revocation and rotation. Continuous integration runs all of them on every push.

## Ethereum standard

Quantova Inc has proposed this shield to the Ethereum organisation as the standard Quantum Bridge Shield, in pull request 2071 of the ethereum/ERCs repository, https://github.com/ethereum/ERCs/pull/2071. The standard fixes the digests, the Merkle construction, the quorum and freeze rules and the guard interface, so any bridge on Ethereum can adopt the same shield.

## Audit and benchmarks

The security audit by NioLabs is in `audits`. The benchmark and smoke test report by Quantova Inc is in `benchmarks`.

## Building

```
forge build
```

The contracts target Solidity 0.8.28 with the IR pipeline and the Cancun EVM. The signer kit needs Python 3.10 or later and no third party packages.

## Contact

Quantova Inc, www.quantova.org. Qstamp SDK family, qstamp.org.
