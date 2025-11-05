// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title AutoLoggerPoEPlus — Tamper‑proof Proof‑of‑Existence logger with gasless signing & fork‑safe digest
/// @notice
///  - Drop‑in compatible with your original API (log, logBatch, exists, getProof, verifyTag, computeDigest)
///  - Adds gasless `logWithSig` using EIP‑712 + ERC‑1271 (smart wallet) verification
///  - Fixes a subtle fork mismatch: `computeDigest` now recomputes the digest with the *provided* chainId
///  - Adds EIP‑5267 domain introspection via OZ EIP712 and exposes domainSeparatorAt(chainId)
///  - Adds a safety guard for overly long tags to avoid bloated events
contract AutoLoggerPoEPlus is EIP712, ReentrancyGuard {
    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------
    error AlreadyLogged(bytes32 dataHash);
    error LengthMismatch();
    error NoETH();
    error TagTooLong(uint256 length);
    error DeadlineExpired(uint256 deadline);
    error BadSignature();

    // ---------------------------------------------------------------------
    // Public constants / metadata (kept for compatibility)
    // ---------------------------------------------------------------------
    string public constant NAME = "AutoLoggerPoE";
    string public constant VERSION = "1";

    // Typehash for EIP‑712 domain
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    // Typehash for the logged proof struct — identical to the original
    bytes32 public constant PROOF_TYPEHASH =
        keccak256("Proof(bytes32 dataHash,bytes32 tagHash,address user,uint256 blockNumber,uint256 timestamp,uint256 chainId)");

    // Typehash for off‑chain authorization of a log call (gasless meta‑tx)
    // Note: signing domain is this contract’s EIP‑712 domain (chain‑bound by design)
    bytes32 public constant LOG_REQUEST_TYPEHASH =
        keccak256("LogRequest(bytes32 dataHash,bytes32 tagHash,address user,uint256 nonce,uint256 deadline)");

    // Upper bound for tag length emitted in events (kept conservative to cap gas/DoS risk)
    uint256 public constant MAX_TAG_BYTES = 256;

    // ---------------------------------------------------------------------
    // Stored proof structure (compact layout) — identical to the original
    // ---------------------------------------------------------------------
    struct Proof {
        address user;       // 20 bytes
        uint64 blockNumber; // 8 bytes
        uint64 timestamp;   // 8 bytes
        uint64 chainId;     // 8 bytes
        bytes32 tagHash;    // 32 bytes
        bytes32 digest;     // 32 bytes (EIP‑712‑style digest)
    }

    // Each dataHash can be logged exactly once
    mapping(bytes32 => Proof) private _proofs;

    // Nonces for gasless signing per user (EIP‑2612‑style)
    mapping(address => uint256) public nonces;

    // ---------------------------------------------------------------------
    // Events (same primary event as original to keep indexers compatible)
    // ---------------------------------------------------------------------
    event ProofLogged(
        bytes32 indexed dataHash,
        bytes32 indexed digest,
        address indexed user,
        bytes32 tagHash,
        string tag,
        uint256 blockNumber_,
        uint256 timestamp_,
        uint256 chainId_
    );

    /// @dev Extra signal when a relayer submits on behalf of user
    event ProofRelayed(bytes32 indexed dataHash, address indexed user, address indexed relayer);

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------
    constructor() EIP712(NAME, VERSION) {}

    // ---------------------------------------------------------------------
    // Internal: domain helpers
    // ---------------------------------------------------------------------
    /// @dev Rebuild the separator for an *arbitrary* chainId (used to recompute historical digests)
    function _domainSeparatorV4For(uint256 chainId_) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(_EIP712Name())),
                keccak256(bytes(_EIP712Version())),
                chainId_,
                address(this)
            )
        );
    }

    /// @dev Typed‑data hash using a custom separator (fork‑safe recomputation)
    function _hashTypedDataV4For(bytes32 structHash, uint256 chainId_) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4For(chainId_), structHash));
    }

    // ---------------------------------------------------------------------
    // Core: log a single hash with an optional tag (duplicate‑proof)
    // ---------------------------------------------------------------------
    function log(bytes32 dataHash, string calldata tag) external nonReentrant returns (bytes32 digest) {
        if (_proofs[dataHash].user != address(0)) revert AlreadyLogged(dataHash);

        uint256 tagLen = bytes(tag).length;
        if (tagLen > MAX_TAG_BYTES) revert TagTooLong(tagLen);

        // Compute canonical tag hash for storage and typed data
        bytes32 tagHash = keccak256(bytes(tag));

        // Snapshot the immutable context at log time
        uint64 bn = uint64(block.number);
        uint64 ts = uint64(block.timestamp);
        uint64 cid = uint64(block.chainid);

        // Compute EIP‑712‑style digest (domain separated for the *current* chainId)
        bytes32 structHash = keccak256(
            abi.encode(
                PROOF_TYPEHASH,
                dataHash,
                tagHash,
                msg.sender,
                uint256(bn),
                uint256(ts),
                uint256(cid)
            )
        );
        digest = _hashTypedDataV4For(structHash, cid);

        // Store compact proof
        _proofs[dataHash] = Proof({
            user: msg.sender,
            blockNumber: bn,
            timestamp: ts,
            chainId: cid,
            tagHash: tagHash,
            digest: digest
        });

        // Emit a rich event for easy indexing & independent verification
        emit ProofLogged(
            dataHash,
            digest,
            msg.sender,
            tagHash,
            tag,
            uint256(bn),
            uint256(ts),
            uint256(cid)
        );
    }

    // ---------------------------------------------------------------------
    // Batch logging (gas‑efficient for multiple entries)
    // ---------------------------------------------------------------------
    function logBatch(bytes32[] calldata dataHashes, string[] calldata tags)
        external
        nonReentrant
        returns (bytes32[] memory digests)
    {
        if (dataHashes.length != tags.length) revert LengthMismatch();

        digests = new bytes32[](dataHashes.length);

        // Snapshot block context once for consistency across the batch
        uint64 bn = uint64(block.number);
        uint64 ts = uint64(block.timestamp);
        uint64 cid = uint64(block.chainid);

        for (uint256 i = 0; i < dataHashes.length; ) {
            bytes32 h = dataHashes[i];
            if (_proofs[h].user != address(0)) revert AlreadyLogged(h);

            uint256 tagLen = bytes(tags[i]).length;
            if (tagLen > MAX_TAG_BYTES) revert TagTooLong(tagLen);

            bytes32 tagHash = keccak256(bytes(tags[i]));

            bytes32 structHash = keccak256(
                abi.encode(
                    PROOF_TYPEHASH,
                    h,
                    tagHash,
                    msg.sender,
                    uint256(bn),
                    uint256(ts),
                    uint256(cid)
                )
            );

            bytes32 d = _hashTypedDataV4For(structHash, cid);

            _proofs[h] = Proof({
                user: msg.sender,
                blockNumber: bn,
                timestamp: ts,
                chainId: cid,
                tagHash: tagHash,
                digest: d
            });

            emit ProofLogged(
                h,
                d,
                msg.sender,
                tagHash,
                tags[i],
                uint256(bn),
                uint256(ts),
                uint256(cid)
            );

            digests[i] = d;

            unchecked { ++i; }
        }
    }

    // ---------------------------------------------------------------------
    // Gasless meta‑tx: authorize a log off‑chain, any relayer may submit it
    // ---------------------------------------------------------------------
    /// @notice Log a proof authorized by `user` via an EIP‑712 signature (EOA or ERC‑1271 smart wallet)
    /// @param dataHash Keccak/SHA‑256 digest of the original content (as bytes32)
    /// @param tag      Short human‑friendly label
    /// @param user     Address that owns the proof (will be stored and emitted as user)
    /// @param deadline Signature deadline (unix time). Must be >= block.timestamp
    /// @param signature EIP‑712 signature over LOG_REQUEST_TYPEHASH
    /// @return digest  EIP‑712‑style domain‑separated digest for this proof entry
    function logWithSig(
        bytes32 dataHash,
        string calldata tag,
        address user,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant returns (bytes32 digest) {
        if (_proofs[dataHash].user != address(0)) revert AlreadyLogged(dataHash);

        uint256 tagLen = bytes(tag).length;
        if (tagLen > MAX_TAG_BYTES) revert TagTooLong(tagLen);
        if (block.timestamp > deadline) revert DeadlineExpired(deadline);

        bytes32 tagHash = keccak256(bytes(tag));
        uint256 nonce = nonces[user]++;

        // User signs a chain‑bound request authorizing the log
        bytes32 reqHash = keccak256(abi.encode(
            LOG_REQUEST_TYPEHASH,
            dataHash,
            tagHash,
            user,
            nonce,
            deadline
        ));
        bytes32 reqDigest = _hashTypedDataV4(reqHash);

        // Accept EOAs and ERC‑1271 smart‑contract wallets
        if (!SignatureChecker.isValidSignatureNow(user, reqDigest, signature)) {
            revert BadSignature();
        }

        // Snapshot block context and compute final Proof digest
        uint64 bn = uint64(block.number);
        uint64 ts = uint64(block.timestamp);
        uint64 cid = uint64(block.chainid);

        bytes32 structHash = keccak256(
            abi.encode(
                PROOF_TYPEHASH,
                dataHash,
                tagHash,
                user,
                uint256(bn),
                uint256(ts),
                uint256(cid)
            )
        );
        digest = _hashTypedDataV4For(structHash, cid);

        _proofs[dataHash] = Proof({
            user: user,
            blockNumber: bn,
            timestamp: ts,
            chainId: cid,
            tagHash: tagHash,
            digest: digest
        });

        emit ProofLogged(
            dataHash,
            digest,
            user,
            tagHash,
            tag,
            uint256(bn),
            uint256(ts),
            uint256(cid)
        );

        if (msg.sender != user) {
            emit ProofRelayed(dataHash, user, msg.sender);
        }
    }

    // ---------------------------------------------------------------------
    // Views: existence + retrieval + verification helpers
    // ---------------------------------------------------------------------
    function exists(bytes32 dataHash) external view returns (bool) {
        return _proofs[dataHash].user != address(0);
    }

    function getProof(bytes32 dataHash) external view returns (Proof memory p) {
        p = _proofs[dataHash];
        require(p.user != address(0), "Proof: not found");
    }

    function verifyTag(bytes32 dataHash, string calldata tag) external view returns (bool) {
        Proof storage p = _proofs[dataHash];
        if (p.user == address(0)) return false;
        return p.tagHash == keccak256(bytes(tag));
    }

    /// @notice Recomputes the canonical EIP‑712‑style digest for *given inputs*.
    /// @dev Unlike many implementations, this function recomputes the digest using the provided chainId
    ///      to remain valid even if the current chainId has changed since the proof was logged (fork‑safe)
    function computeDigest(
        bytes32 dataHash,
        string calldata tag,
        address user,
        uint256 blockNumber_,
        uint256 timestamp_,
        uint256 chainId_
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                PROOF_TYPEHASH,
                dataHash,
                keccak256(bytes(tag)),
                user,
                blockNumber_,
                timestamp_,
                chainId_
            )
        );
        return _hashTypedDataV4For(structHash, chainId_);
    }

    /// @notice Returns the EIP‑712 domain separator currently in use
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Returns what the domain separator *would have been* for a given chainId (for historical recomputation)
    function domainSeparatorAt(uint256 chainId_) external view returns (bytes32) {
        return _domainSeparatorV4For(chainId_);
    }

    // ---------------------------------------------------------------------
    // ETH handling: no funds allowed (explicitly non‑payable surface)
    // ---------------------------------------------------------------------
    receive() external payable { revert NoETH(); }
    fallback() external payable { revert NoETH(); }
}
