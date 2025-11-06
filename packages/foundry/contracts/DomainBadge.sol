// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title DomainBadge - Non-transferable ERC-1155 badge proving control of an email domain
/// @notice Mint is authorized by an off-chain issuer via EIP-712 signature. Token id = uint256(domainHash).
contract DomainBadge is ERC1155, EIP712, Ownable, Pausable {
    using ECDSA for bytes32;

    /// @dev Emitted on successful mint.
    event Minted(address indexed wallet, bytes32 indexed domainHash, bytes32 hCommit);
    /// @dev Emitted on revoke (burn).
    event Revoked(address indexed wallet, bytes32 indexed domainHash);
    /// @dev Emitted when issuer is updated.
    event IssuerUpdated(address indexed newIssuer);

    /// @dev Issuer address whose EIP-712 signatures are accepted.
    address public issuer;

    /// @dev Prevents replay of authorizations per wallet+nonce.
    mapping(address => mapping(uint256 => bool)) public nonceUsed;

    /// @dev Optional commitment per wallet+domainHash (stores H = sha256(L)).
    mapping(address => mapping(bytes32 => bytes32)) public hCommitOf;

    /// @dev keccak256("MintAuthorization(address wallet,bytes32 domainHash,bytes32 hCommit,uint256 nonce,uint64 expiresAt)")
    bytes32 public constant MINT_AUTH_TYPEHASH = 0x2f2b9d9985f1fd8763c8b7e1d4e02b8a0ecb23f6b6d20e845f806e3d3dbe9d6a;

    struct MintAuthorization {
        address wallet;
        bytes32 domainHash; // keccak256(lowercase(domain))
        bytes32 hCommit;    // sha256(padded L) commitment
        uint256 nonce;      // anti-replay per wallet
        uint64 expiresAt;   // unix seconds
    }

    constructor(address _issuer, address _owner)
        ERC1155("")
        EIP712("DomainBadgeIssuer", "1")
        Ownable(_owner)
    {
        issuer = _issuer;
        emit IssuerUpdated(_issuer);
    }

    function setIssuer(address _issuer) external onlyOwner {
        issuer = _issuer;
        emit IssuerUpdated(_issuer);
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    /// @notice Mint or update badge for (wallet, domainHash) using issuer-signed auth.
    function mintWithAuth(MintAuthorization calldata auth, bytes calldata signature) external whenNotPaused {
        require(block.timestamp <= auth.expiresAt, "auth expired");
        require(auth.wallet != address(0), "bad wallet");

        // Verify signature
        bytes32 structHash = keccak256(abi.encode(
            MINT_AUTH_TYPEHASH,
            auth.wallet,
            auth.domainHash,
            auth.hCommit,
            auth.nonce,
            auth.expiresAt
        ));
        bytes32 digest = _hashTypedDataV4(structHash);
        address recovered = ECDSA.recover(digest, signature);
        require(recovered == issuer, "bad issuer sig");

        // Anti-replay per wallet
        require(!nonceUsed[auth.wallet][auth.nonce], "nonce used");
        nonceUsed[auth.wallet][auth.nonce] = true;

        uint256 tokenId = uint256(auth.domainHash);

        // Mint if not owned yet, else no-op balance but update commitment
        if (balanceOf(auth.wallet, tokenId) == 0) {
            _mint(auth.wallet, tokenId, 1, "");
        }

        // Store/update commitment
        hCommitOf[auth.wallet][auth.domainHash] = auth.hCommit;

        emit Minted(auth.wallet, auth.domainHash, auth.hCommit);
    }

    /// @notice Holder can revoke their own badge for a domain.
    function revoke(bytes32 domainHash) external whenNotPaused {
        uint256 tokenId = uint256(domainHash);
        require(balanceOf(msg.sender, tokenId) > 0, "no badge");
        _burn(msg.sender, tokenId, 1);
        delete hCommitOf[msg.sender][domainHash];
        emit Revoked(msg.sender, domainHash);
    }

    /// @notice Owner can revoke someone else's badge (e.g., abuse or DMCA).
    function revokeFor(address wallet, bytes32 domainHash) external onlyOwner {
        uint256 tokenId = uint256(domainHash);
        require(balanceOf(wallet, tokenId) > 0, "no badge");
        _burn(wallet, tokenId, 1);
        delete hCommitOf[wallet][domainHash];
        emit Revoked(wallet, domainHash);
    }

    /// @dev Non-transferable: block approvals and transfers.
    function setApprovalForAll(address, bool) public pure override {
        revert("SBT: approvals disabled");
    }

    function safeTransferFrom(address, address, uint256, uint256, bytes memory) public pure override {
        revert("SBT: non-transferable");
    }

    function safeBatchTransferFrom(address, address, uint256[] memory, uint256[] memory, bytes memory) public pure override {
        revert("SBT: non-transferable");
    }

    /// @notice Helper exposed for tests: compute domain token id.
    function tokenIdOf(bytes32 domainHash) external pure returns (uint256) {
        return uint256(domainHash);
    }
}
