// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IERC5564Announcer.sol";

/// @title StealthAnnouncer
/// @notice Reference implementation of the ERC-5564 Announcer contract.
/// @dev Emits announcements for recipients to detect incoming stealth transfers.
/// Stores no private data and handles no funds directly.
contract StealthAnnouncer is IERC5564Announcer {
    /// @inheritdoc IERC5564Announcer
    function announce(
        uint256 schemeId,
        address stealthAddress,
        bytes memory ephemeralPubKey,
        bytes memory metadata
    ) external override {
        require(stealthAddress != address(0), "StealthAnnouncer: stealthAddress is zero");
        require(ephemeralPubKey.length > 0, "StealthAnnouncer: ephemeralPubKey is empty");
        require(metadata.length > 0, "StealthAnnouncer: metadata must contain view tag");

        emit Announcement(
            schemeId,
            stealthAddress,
            msg.sender,
            ephemeralPubKey,
            metadata
        );
    }
}
