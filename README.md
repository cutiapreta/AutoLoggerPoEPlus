# AutoLoggerPoEPlus - Tamper-Proof Proof-of-Existence Logger
### Overview

`AutoLoggerPoEPlus` is an enhanced Proof-of-Existence (PoE) smart contract that securely logs digital content hashes on-chain. It provides tamper-proof, gasless, and fork-safe logging with full EIP-712 compliance.
This contract serves as a drop-in upgrade to the original `AutoLoggerPoE` and introduces critical improvements such as gasless signature-based logging, chain-aware digest recomputation, and domain introspection.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Features

### Backward Compatibility

- Maintains the same public API as the original contract (`log`, `logBatch`, `exists`, `getProof`, `verifyTag`, `computeDigest`)
- Compatible event signatures for smooth integration with existing `indexers`

### Gasless Logging (EIP-712 + ERC-1271)

- Allows users to sign off-chain messages (via `logWithSig`) and delegate submission to any relayer
- Accepts both EOA signatures and smart contract signatures compliant with ERC-1271
- Includes replay protection using per-user nonces

### Fork-Safe Digest

- Correctly recomputes the EIP-712 digest using the provided `chainId`, ensuring digest verification remains valid even after a chain fork

### Domain Introspection

- Implements EIP-5267 support via OpenZeppelin’s EIP712
- Exposes `domainSeparatorAt(chainId)` to reconstruct domain separators for historical verification

### Security Enhancements

- Prevents excessively long tags to mitigate gas-bloating and potential DoS risks
- Uses OpenZeppelin’s `ReentrancyGuard` to prevent reentrancy attacks
- Explicitly rejects ETH transfers via `receive()` and `fallback()` to avoid accidental fund deposits
  
--------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Architecture

**Core Data Structure**

```solidity
struct Proof {
    address user;       // Owner of the proof
    uint64 blockNumber; // Block when logged
    uint64 timestamp;   // Timestamp at logging
    uint64 chainId;     // Chain ID (fork-safe)
    bytes32 tagHash;    // Keccak256 hash of tag
    bytes32 digest;     // EIP-712-style digest
}
```
each `dataHash` maps to a unique `Proof`, ensuring immutability and non-replayability

--------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Core Functionalities

**1. `log(bytes32 dataHash, string tag)`**

Records a proof of existence for the given data hash and tag.
Ensures:

- Each `dataHash` is logged only once
- Tag length is `≤ MAX_TAG_BYTES (256)`
- Emits a detailed `ProofLogged` event

```solidity
function log(bytes32 dataHash, string calldata tag) external nonReentrant returns (bytes32 digest)
```

**2. `logBatch(bytes32[] dataHashes, string[] tags)`**

Gas-efficient batch logging for multiple proofs in a single transaction
Validates input length equality and applies the same safety checks as `log()`

```solidity
function logBatch(bytes32[] calldata dataHashes, string[] calldata tags)
    external
    nonReentrant
    returns (bytes32[] memory digests)
```

**3. `logWithSig(...)` - Gasless Meta-Transaction**

Allows off-chain signed proof submissions via relayers
Uses EIP-712 structured data signing with replay-protected nonces

```solidity
function logWithSig(
    bytes32 dataHash,
    string calldata tag,
    address user,
    uint256 deadline,
    bytes calldata signature
) external nonReentrant returns (bytes32 digest)
```

Workflow:

- User signs an EIP-712 message off-chain
- Relayer submits it on-chain via `logWithSig()`
- Contract verifies:
   - Signature validity (`SignatureChecker.isValidSignatureNow`)
   - Nonce uniqueness
   - Deadline validity (`block.timestamp <= deadline`)
- Emits both:
   - `ProofLogged`
   - `ProofRelayed` (if relayed by a third party)

**4. `exists(bytes32 dataHash)`**

Checks if a proof has been logged for a given hash

```solidity
function exists(bytes32 dataHash) external view returns (bool)
```

**5. `getProof(bytes32 dataHash)`**

Retrieves full proof metadata for a given hash
Reverts if no proof exists

```solidity
function getProof(bytes32 dataHash) external view returns (Proof memory)
```

**6. `verifyTag(bytes32 dataHash, string tag)`**

Validates whether a given tag corresponds to the stored tag hash

```solidity
function verifyTag(bytes32 dataHash, string calldata tag) external view returns (bool)
```

**7. `computeDigest(...)` - Fork-Safe Digest Rebuilder**

Recomputes the EIP-712 digest for given proof parameters and a specific `chainId`
Useful for verifying proofs after chain forks

```solidity
function computeDigest(
    bytes32 dataHash,
    string calldata tag,
    address user,
    uint256 blockNumber,
    uint256 timestamp,
    uint256 chainId
) external view returns (bytes32)
```

**8. `domainSeparator()` / `domainSeparatorAt(chainId)`**

Returns current or historical EIP-712 domain separators

```
function domainSeparator() external view returns (bytes32)
function domainSeparatorAt(uint256 chainId) external view returns (bytes32)
```

-------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Events

- `ProofLogged(bytes32 dataHash, bytes32 digest, address user, bytes32 tagHash, string tag, uint256 blockNumber, uint256 timestamp, uint256 chainId)`
     - Emitted whenever a proof is logged
- `ProofRelayed(bytes32 dataHash, address user, address relayer)`
     - Emitted when a third-party relayer submits a user’s signed proof
 
-------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Error Definitions

- `AlreadyLogged(bytes32 dataHash)`
   - Data already logged
- `LengthMismatch()`
   - Array length mismatch in `logBatch`
- `NoETH()`
   - Reverts on ETH transfer
- `TagTooLong(uint256 length)`
   - Tag exceeds max byte length
- `DeadlineExpired(uint256 deadline)`
   - Signature deadline exceeded
- `BadSignature()`
   - Invalid EIP-712 or ERC-1271 signature

-------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Security Considerations

**1. Reentrancy Protection:** All mutating functions use `nonReentrant`

**2. Signature Validation:** Uses `SignatureChecker` (supports EOAs + ERC-1271)

**3. Fork Safety:** Digest recomputation honors the supplied `chainId`

**4. Gas Efficiency:** Batching minimizes repeated domain recomputation

**5. Event Safety:** Tags capped to prevent excessive gas use

-------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Use Cases

**1. Digital Timestamping:** Prove file or message existence at a given block

**2. Off-Chain Signing dApps:** Gasless proof submission by relayers

**3. Auditable Metadata:** Integrate with notarization or IP attribution systems

**4. Decentralized Identity:** Record and verify EIP-712 structured claims

-------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Integration Example

```solidity
bytes32 fileHash = keccak256(abi.encodePacked(fileData));
autoLogger.log(fileHash, "ProjectReport2025");
```

- Or via relayer:

```solidity
// Off-chain: user signs message with EIP-712
// On-chain: relayer submits it
autoLogger.logWithSig(fileHash, "ResearchNote", user, deadline, signature);
```
