import { formatEther, parseEther } from 'viem';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  fetchAnnouncements,
  getDeployments,
  getPublicClient,
  getWalletClient
} from '../src/chain/index.js';
import { executeStealthPayment } from '../src/chain/pay.js';
import { executeWithdrawal } from '../src/chain/withdraw.js';
import {
  SCHEME_ID,
  encodeStealthMetaAddress,
  generateStealthAddress,
  generateStealthKeys,
  hexToBytes,
  recoverStealthPrivateKey,
  scanAnnouncements
} from '../src/crypto/index.js';
import type { Hex } from '../src/crypto/types.js';

describe('ERC-5564 On-Chain Workflow & Acceptance Checks (Anvil)', () => {
  const publicClient = getPublicClient();
  const payerClient = getWalletClient(
    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
  );

  let announcerAddress: Hex;
  let paymentAddress: Hex;

  beforeAll(async () => {
    const deployments = getDeployments();
    if (!deployments) {
      throw new Error('Deployments not found. Ensure contracts are deployed to Anvil.');
    }
    announcerAddress = deployments.announcer;
    paymentAddress = deployments.payment;
  });

  it('8. On-chain ephemeral-key publication: every payment produces an announcement containing the ephemeral public key and view tag', async () => {
    const recipient = generateStealthKeys();
    const recipientMeta = encodeStealthMetaAddress({
      spendingPublicKey: recipient.spending.publicKey,
      viewingPublicKey: recipient.viewing.publicKey
    });

    const paymentResult = await executeStealthPayment({
      walletClient: payerClient,
      publicClient,
      announcerAddress,
      paymentAddress,
      stealthMetaAddress: recipientMeta,
      amountEth: '0.1'
    });

    expect(paymentResult.transactionHash).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(paymentResult.ephemeralPublicKey).toMatch(/^0x[0-9a-fA-F]{66}$/);
    expect(paymentResult.viewTag).toMatch(/^0x[0-9a-fA-F]{2}$/);

    // Fetch the on-chain announcement log from the transaction block
    const announcements = await fetchAnnouncements({
      publicClient,
      announcerAddress,
      fromBlock: paymentResult.blockNumber,
      toBlock: paymentResult.blockNumber
    });

    const matchingAnnouncement = announcements.find(
      (a) => a.stealthAddress.toLowerCase() === paymentResult.stealthAddress.toLowerCase()
    );

    expect(matchingAnnouncement).toBeDefined();
    expect(matchingAnnouncement!.schemeId).toBe(SCHEME_ID);
    expect(matchingAnnouncement!.ephemeralPubKey.toLowerCase()).toBe(
      paymentResult.ephemeralPublicKey.toLowerCase()
    );

    // Verify view tag is published as the first byte of metadata
    const metadataBytes = hexToBytes(matchingAnnouncement!.metadata);
    const publishedViewTag = `0x${metadataBytes[0].toString(16).padStart(2, '0')}`;
    expect(publishedViewTag.toLowerCase()).toBe(paymentResult.viewTag.toLowerCase());
  });

  it('Full Workflow: Mira receives payments from Client A & B, scans, discovers, recovers, and withdraws', async () => {
    // 1. Mira generates keys and publishes ONE reusable meta-address
    const mira = generateStealthKeys();
    const miraMetaAddress = encodeStealthMetaAddress({
      spendingPublicKey: mira.spending.publicKey,
      viewingPublicKey: mira.viewing.publicKey
    });

    // Dave also generates keys (unrelated recipient)
    const dave = generateStealthKeys();
    const daveMetaAddress = encodeStealthMetaAddress({
      spendingPublicKey: dave.spending.publicKey,
      viewingPublicKey: dave.viewing.publicKey
    });

    const startBlock = await publicClient.getBlockNumber();

    // 2. Client A pays Mira 0.5 ETH
    const payA = await executeStealthPayment({
      walletClient: payerClient,
      publicClient,
      announcerAddress,
      paymentAddress,
      stealthMetaAddress: miraMetaAddress,
      amountEth: '0.5'
    });

    // 3. Client B pays Mira 0.8 ETH
    const payB = await executeStealthPayment({
      walletClient: payerClient,
      publicClient,
      announcerAddress,
      paymentAddress,
      stealthMetaAddress: miraMetaAddress,
      amountEth: '0.8'
    });

    // Unrelated payment: Client pays Dave 0.2 ETH
    const payDave = await executeStealthPayment({
      walletClient: payerClient,
      publicClient,
      announcerAddress,
      paymentAddress,
      stealthMetaAddress: daveMetaAddress,
      amountEth: '0.2'
    });

    const endBlock = await publicClient.getBlockNumber();

    // 4. Distinct stealth addresses
    expect(payA.stealthAddress.toLowerCase()).not.toBe(payB.stealthAddress.toLowerCase());
    expect(payA.ephemeralPublicKey.toLowerCase()).not.toBe(payB.ephemeralPublicKey.toLowerCase());

    // Both stealth addresses received ETH
    const balA = await publicClient.getBalance({ address: payA.stealthAddress });
    const balB = await publicClient.getBalance({ address: payB.stealthAddress });
    expect(balA).toBe(parseEther('0.5'));
    expect(balB).toBe(parseEther('0.8'));

    // 5. Mira scans announcements using ONLY her viewing private key and spending public key
    const announcements = await fetchAnnouncements({
      publicClient,
      announcerAddress,
      fromBlock: startBlock,
      toBlock: endBlock
    });

    const scanResult = scanAnnouncements({
      viewingPrivateKey: mira.viewing.privateKey,
      spendingPublicKey: mira.spending.publicKey,
      announcements
    });

    // 6. Mira identifies BOTH payments to her, and completely ignores Dave's payment
    expect(scanResult.matches.length).toBe(2);
    const discoveredAddresses = scanResult.matches.map((m) => m.stealthAddress.toLowerCase());
    expect(discoveredAddresses).toContain(payA.stealthAddress.toLowerCase());
    expect(discoveredAddresses).toContain(payB.stealthAddress.toLowerCase());
    expect(discoveredAddresses).not.toContain(payDave.stealthAddress.toLowerCase());

    // 7. Mira recovers spending keys ONLY during withdrawal, and transfers both balances to a cold wallet
    const miraColdWallet: Hex = '0x9999999999999999999999999999999999999999';
    const coldWalletBalBefore = await publicClient.getBalance({ address: miraColdWallet });

    // Withdraw payment A
    const recoveryA = recoverStealthPrivateKey({
      spendingPrivateKey: mira.spending.privateKey,
      viewingPrivateKey: mira.viewing.privateKey,
      ephemeralPublicKey: payA.ephemeralPublicKey,
      expectedStealthAddress: payA.stealthAddress
    });
    expect(recoveryA.stealthAddress.toLowerCase()).toBe(payA.stealthAddress.toLowerCase());

    const withdrawA = await executeWithdrawal({
      publicClient,
      stealthPrivateKey: recoveryA.stealthPrivateKey,
      toAddress: miraColdWallet
    });
    expect(withdrawA.transactionHash).toBeDefined();

    // Withdraw payment B
    const recoveryB = recoverStealthPrivateKey({
      spendingPrivateKey: mira.spending.privateKey,
      viewingPrivateKey: mira.viewing.privateKey,
      ephemeralPublicKey: payB.ephemeralPublicKey,
      expectedStealthAddress: payB.stealthAddress
    });
    expect(recoveryB.stealthAddress.toLowerCase()).toBe(payB.stealthAddress.toLowerCase());

    const withdrawB = await executeWithdrawal({
      publicClient,
      stealthPrivateKey: recoveryB.stealthPrivateKey,
      toAddress: miraColdWallet
    });
    expect(withdrawB.transactionHash).toBeDefined();

    // Verify both stealth address balances are now swept to 0
    const finalBalA = await publicClient.getBalance({ address: payA.stealthAddress });
    const finalBalB = await publicClient.getBalance({ address: payB.stealthAddress });
    expect(finalBalA).toBe(0n);
    expect(finalBalB).toBe(0n);

    // Verify Cold wallet received the net funds (minus minimal L1 gas)
    const coldWalletBalAfter = await publicClient.getBalance({ address: miraColdWallet });
    const totalNetReceived = coldWalletBalAfter - coldWalletBalBefore;
    // Expected ~ 1.3 ETH minus 2 * 21000 gas * gasPrice
    expect(totalNetReceived).toBeGreaterThan(parseEther('1.29'));
  });

  it('Edge case: Withdrawal fails when balance is zero', async () => {
    // Generate an empty stealth key with 0 ETH
    const emptyKeys = generateStealthKeys();
    const emptyMeta = encodeStealthMetaAddress({
      spendingPublicKey: emptyKeys.spending.publicKey,
      viewingPublicKey: emptyKeys.viewing.publicKey
    });
    const derivation = generateStealthAddress({ stealthMetaAddress: emptyMeta });
    const recovery = recoverStealthPrivateKey({
      spendingPrivateKey: emptyKeys.spending.privateKey,
      viewingPrivateKey: emptyKeys.viewing.privateKey,
      ephemeralPublicKey: derivation.ephemeralPublicKey
    });

    await expect(
      executeWithdrawal({
        publicClient,
        stealthPrivateKey: recovery.stealthPrivateKey,
        toAddress: '0x1234567890123456789012345678901234567890'
      })
    ).rejects.toThrow(/zero balance/);
  });

  it('Edge case: Wrong spending private key fails stealth verification', () => {
    const alice = generateStealthKeys();
    const bob = generateStealthKeys();
    const aliceMeta = encodeStealthMetaAddress({
      spendingPublicKey: alice.spending.publicKey,
      viewingPublicKey: alice.viewing.publicKey
    });
    const payAlice = generateStealthAddress({ stealthMetaAddress: aliceMeta });

    // Attempting to recover Alice's stealth key using Bob's spending private key
    expect(() =>
      recoverStealthPrivateKey({
        spendingPrivateKey: bob.spending.privateKey,
        viewingPrivateKey: alice.viewing.privateKey,
        ephemeralPublicKey: payAlice.ephemeralPublicKey,
        expectedStealthAddress: payAlice.stealthAddress
      })
    ).toThrow(/does not match expected address/);
  });
});
