// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/StealthAnnouncer.sol";
import "../../contracts/StealthPayment.sol";

contract StealthContractsTest is Test {
    StealthAnnouncer public announcer;
    StealthPayment public payment;

    address public payer = address(0x1111);
    address payable public stealthRecipient = payable(address(0x2222));
    address public maliciousContract;

    uint256 public constant SCHEME_ID = 1;
    bytes public ephemeralPubKey = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    bytes public metadata = hex"42010203"; // first byte 0x42 is view tag

    event Announcement(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes metadata
    );

    event StealthPaymentSent(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed payer,
        uint256 amount,
        bytes ephemeralPubKey,
        bytes metadata
    );

    function setUp() public {
        announcer = new StealthAnnouncer();
        payment = new StealthPayment(address(announcer));
        vm.deal(payer, 10 ether);
    }

    function test_DirectAnnounce() public {
        vm.prank(payer);

        vm.expectEmit(true, true, true, true, address(announcer));
        emit Announcement(
            SCHEME_ID,
            stealthRecipient,
            payer,
            ephemeralPubKey,
            metadata
        );

        announcer.announce(SCHEME_ID, stealthRecipient, ephemeralPubKey, metadata);
    }

    function test_RevertAnnounce_ZeroStealthAddress() public {
        vm.expectRevert("StealthAnnouncer: stealthAddress is zero");
        announcer.announce(SCHEME_ID, address(0), ephemeralPubKey, metadata);
    }

    function test_RevertAnnounce_EmptyEphemeralKey() public {
        vm.expectRevert("StealthAnnouncer: ephemeralPubKey is empty");
        announcer.announce(SCHEME_ID, stealthRecipient, "", metadata);
    }

    function test_RevertAnnounce_EmptyMetadata() public {
        vm.expectRevert("StealthAnnouncer: metadata must contain view tag");
        announcer.announce(SCHEME_ID, stealthRecipient, ephemeralPubKey, "");
    }

    function test_PayETH_Success() public {
        uint256 payAmount = 1 ether;
        uint256 recipientBalBefore = stealthRecipient.balance;

        vm.prank(payer);

        // Expect both the custom payment event and the standard ERC-5564 announcement
        vm.expectEmit(true, true, true, true, address(payment));
        emit StealthPaymentSent(
            SCHEME_ID,
            stealthRecipient,
            payer,
            payAmount,
            ephemeralPubKey,
            metadata
        );

        vm.expectEmit(true, true, true, true, address(announcer));
        emit Announcement(
            SCHEME_ID,
            stealthRecipient,
            address(payment),
            ephemeralPubKey,
            metadata
        );

        payment.payETH{value: payAmount}(
            SCHEME_ID,
            stealthRecipient,
            ephemeralPubKey,
            metadata
        );

        assertEq(stealthRecipient.balance, recipientBalBefore + payAmount);
        assertEq(address(payment).balance, 0);
    }

    function test_PayETH_RevertZeroAmount() public {
        vm.prank(payer);
        vm.expectRevert("StealthPayment: payment amount must be greater than zero");
        payment.payETH{value: 0}(
            SCHEME_ID,
            stealthRecipient,
            ephemeralPubKey,
            metadata
        );
    }

    function test_PayETH_RevertZeroAddress() public {
        vm.prank(payer);
        vm.expectRevert("StealthPayment: stealth address cannot be zero");
        payment.payETH{value: 1 ether}(
            SCHEME_ID,
            payable(address(0)),
            ephemeralPubKey,
            metadata
        );
    }

    function test_PayETH_RevertEmptyEphemeralKey() public {
        vm.prank(payer);
        vm.expectRevert("StealthPayment: ephemeralPubKey cannot be empty");
        payment.payETH{value: 1 ether}(
            SCHEME_ID,
            stealthRecipient,
            "",
            metadata
        );
    }

    function test_PayETH_RevertEmptyMetadata() public {
        vm.prank(payer);
        vm.expectRevert("StealthPayment: metadata must contain view tag");
        payment.payETH{value: 1 ether}(
            SCHEME_ID,
            stealthRecipient,
            ephemeralPubKey,
            ""
        );
    }

    function test_RevertDirectDeposit() public {
        vm.prank(payer);
        (bool success, ) = address(payment).call{value: 1 ether}("");
        assertFalse(success);
    }

    function test_PayETH_RevertOnReentrancy() public {
        MaliciousReentrantRecipient attacker = new MaliciousReentrantRecipient(address(payment));
        vm.deal(address(attacker), 2 ether);

        vm.prank(payer);
        // Expect revert due to reentrancy rejection during call back
        vm.expectRevert("StealthPayment: ETH transfer failed");
        payment.payETH{value: 1 ether}(
            SCHEME_ID,
            payable(address(attacker)),
            ephemeralPubKey,
            metadata
        );
    }
}

contract MaliciousReentrantRecipient {
    StealthPayment public target;
    bool private attacked;

    constructor(address _target) {
        target = StealthPayment(payable(_target));
    }

    receive() external payable {
        if (!attacked) {
            attacked = true;
            // Attempt reentrancy into payETH
            target.payETH{value: 1 ether}(
                1,
                payable(address(this)),
                hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                hex"42"
            );
        }
    }
}
