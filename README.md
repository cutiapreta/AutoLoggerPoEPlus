# AutoLoggerPoEPlus - Tamper-Proof Proof-of-Existence Logger
### Overview

`AutoLoggerPoEPlus` is an enhanced Proof-of-Existence (PoE) smart contract that securely logs digital content hashes on-chain. It provides tamper-proof, gasless, and fork-safe logging with full EIP-712 compliance.
This contract serves as a drop-in upgrade to the original `AutoLoggerPoE` and introduces critical improvements such as gasless signature-based logging, chain-aware digest recomputation, and domain introspection.

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


# Architecture

Explicitly rejects ETH transfers via receive() and fallback() to avoid accidental fund deposits.
