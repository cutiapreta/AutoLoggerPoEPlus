// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title AutoLoggerPoEPlus — Tamper‑proof Proof‑of‑Existence logger with gasless signing & fork‑safe digest
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
    bytes32 public constant PROOF_TYPEHASH = keccak256(
        "Proof(bytes32 dataHash,bytes32 tagHash,address user,uint256 blockNumber,uint256 timestamp,uint256 chainId)"
    );

    // Typehash for off‑chain authorization of a log call (gasless meta‑tx)
    bytes32 public constant LOG_REQUEST_TYPEHASH =
        keccak256("LogRequest(bytes32 dataHash,bytes32 tagHash,address user,uint256 nonce,uint256 deadline)");

    uint256 public constant MAX_TAG_BYTES = 256;

    // ---------------------------------------------------------------------
    // Stored proof structure (compact layout) — identical to the original
    // ---------------------------------------------------------------------
    struct Proof {
        address user; // 20 bytes
        uint64 blockNumber; // 8 bytes
        uint64 timestamp; // 8 bytes
        uint64 chainId; // 8 bytes
        bytes32 tagHash; // 32 bytes
        bytes32 digest; // 32 bytes (EIP‑712‑style digest)
    }

    mapping(bytes32 => Proof) private _proofs;
    mapping(address => uint256) public nonces;

    // ---------------------------------------------------------------------
    // Events
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

    event ProofRelayed(bytes32 indexed dataHash, address indexed user, address indexed relayer);

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------
    constructor() EIP712(NAME, VERSION) {}

    // ---------------------------------------------------------------------
    // Internal: domain helpers
    // ---------------------------------------------------------------------
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

        bytes32 tagHash = keccak256(bytes(tag));
        uint64 bn = uint64(block.number);
        uint64 ts = uint64(block.timestamp);
        uint64 cid = uint64(block.chainid);

        bytes32 structHash = keccak256(
            abi.encode(PROOF_TYPEHASH, dataHash, tagHash, msg.sender, uint256(bn), uint256(ts), uint256(cid))
        );
        digest = _hashTypedDataV4For(structHash, cid);

        _proofs[dataHash] =
            Proof({user: msg.sender, blockNumber: bn, timestamp: ts, chainId: cid, tagHash: tagHash, digest: digest});

        emit ProofLogged(dataHash, digest, msg.sender, tagHash, tag, uint256(bn), uint256(ts), uint256(cid));
    }

    // ---------------------------------------------------------------------
    // Batch logging
    // ---------------------------------------------------------------------
    function logBatch(bytes32[] calldata dataHashes, string[] calldata tags)
        external
        nonReentrant
        returns (bytes32[] memory digests)
    {
        if (dataHashes.length != tags.length) revert LengthMismatch();
        digests = new bytes32[](dataHashes.length);

        uint64 bn = uint64(block.number);
        uint64 ts = uint64(block.timestamp);
        uint64 cid = uint64(block.chainid);

        for (uint256 i = 0; i < dataHashes.length;) {
            bytes32 h = dataHashes[i];
            if (_proofs[h].user != address(0)) revert AlreadyLogged(h);

            uint256 tagLen = bytes(tags[i]).length;
            if (tagLen > MAX_TAG_BYTES) revert TagTooLong(tagLen);

            bytes32 tagHash = keccak256(bytes(tags[i]));

            bytes32 structHash =
                keccak256(abi.encode(PROOF_TYPEHASH, h, tagHash, msg.sender, uint256(bn), uint256(ts), uint256(cid)));
            bytes32 d = _hashTypedDataV4For(structHash, cid);

            _proofs[h] =
                Proof({user: msg.sender, blockNumber: bn, timestamp: ts, chainId: cid, tagHash: tagHash, digest: d});

            emit ProofLogged(h, d, msg.sender, tagHash, tags[i], uint256(bn), uint256(ts), uint256(cid));
            digests[i] = d;

            unchecked {
                ++i;
            }
        }
    }

    // ---------------------------------------------------------------------
    // Gasless meta‑tx
    // ---------------------------------------------------------------------
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

        bytes32 reqHash = keccak256(abi.encode(LOG_REQUEST_TYPEHASH, dataHash, tagHash, user, nonce, deadline));
        bytes32 reqDigest = _hashTypedDataV4(reqHash);

        if (!SignatureChecker.isValidSignatureNow(user, reqDigest, signature)) revert BadSignature();

        uint64 bn = uint64(block.number);
        uint64 ts = uint64(block.timestamp);
        uint64 cid = uint64(block.chainid);

        bytes32 structHash =
            keccak256(abi.encode(PROOF_TYPEHASH, dataHash, tagHash, user, uint256(bn), uint256(ts), uint256(cid)));
        digest = _hashTypedDataV4For(structHash, cid);

        _proofs[dataHash] =
            Proof({user: user, blockNumber: bn, timestamp: ts, chainId: cid, tagHash: tagHash, digest: digest});

        emit ProofLogged(dataHash, digest, user, tagHash, tag, uint256(bn), uint256(ts), uint256(cid));
        if (msg.sender != user) emit ProofRelayed(dataHash, user, msg.sender);
    }

    // ---------------------------------------------------------------------
    // Views
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

    function computeDigest(
        bytes32 dataHash,
        string calldata tag,
        address user,
        uint256 blockNumber_,
        uint256 timestamp_,
        uint256 chainId_
    ) external view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(PROOF_TYPEHASH, dataHash, keccak256(bytes(tag)), user, blockNumber_, timestamp_, chainId_)
        );
        return _hashTypedDataV4For(structHash, chainId_);
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function domainSeparatorAt(uint256 chainId_) external view returns (bytes32) {
        return _domainSeparatorV4For(chainId_);
    }

    // ---------------------------------------------------------------------
    // ETH handling
    // ---------------------------------------------------------------------
    receive() external payable {
        revert NoETH();
    }

    fallback() external payable {
        revert NoETH();
    }
}
