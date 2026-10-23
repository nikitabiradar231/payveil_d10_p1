import { parseEther } from 'viem';
import { SCHEME_ID } from '../crypto/constants.js';
import { generateStealthAddress } from '../crypto/payer.js';
import type { Hex } from '../crypto/types.js';
import { STEALTH_ANNOUNCER_ABI, STEALTH_PAYMENT_ABI } from './abis.js';
import type { StealthPublicClient, StealthWalletClient } from './client.js';

export interface ExecuteStealthPaymentParams {
  walletClient: StealthWalletClient;
  publicClient: StealthPublicClient;
  announcerAddress: Hex;
  paymentAddress?: Hex;
  stealthMetaAddress: string;
  amountEth: string;
  ephemeralPrivateKey?: Hex;
}

export interface StealthPaymentResult {
  stealthAddress: Hex;
  ephemeralPublicKey: Hex;
  viewTag: Hex;
  metadata: Hex;
  transactionHash: Hex;
  blockNumber: bigint;
  amount: bigint;
}

/**
 * Derives a one-time stealth address and performs an on-chain payment with announcement.
 */
export async function executeStealthPayment({
  walletClient,
  publicClient,
  announcerAddress,
  paymentAddress,
  stealthMetaAddress,
  amountEth,
  ephemeralPrivateKey
}: ExecuteStealthPaymentParams): Promise<StealthPaymentResult> {
  const account = walletClient.account;
  if (!account) {
    throw new Error('Wallet client must have an active account to make payments');
  }

  const value = parseEther(amountEth);
  if (value <= 0n) {
    throw new Error('Payment amount must be greater than zero');
  }

  // 1. Payer-side stealth address derivation
  const derivation = generateStealthAddress({
    stealthMetaAddress,
    ephemeralPrivateKey
  });

  let txHash: Hex;

  if (paymentAddress) {
    // Atomic transfer + announcement via StealthPayment contract
    txHash = (await walletClient.writeContract({
      address: paymentAddress,
      abi: STEALTH_PAYMENT_ABI,
      functionName: 'payETH',
      args: [
        SCHEME_ID,
        derivation.stealthAddress,
        derivation.ephemeralPublicKey,
        derivation.metadata
      ],
      value,
      account,
      chain: null
    })) as Hex;
  } else {
    // Fallback: Direct ETH send + separate announcement
    await walletClient.sendTransaction({
      to: derivation.stealthAddress,
      value,
      account,
      chain: null
    });

    txHash = (await walletClient.writeContract({
      address: announcerAddress,
      abi: STEALTH_ANNOUNCER_ABI,
      functionName: 'announce',
      args: [
        SCHEME_ID,
        derivation.stealthAddress,
        derivation.ephemeralPublicKey,
        derivation.metadata
      ],
      account,
      chain: null
    })) as Hex;
  }

  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });

  return {
    stealthAddress: derivation.stealthAddress,
    ephemeralPublicKey: derivation.ephemeralPublicKey,
    viewTag: derivation.viewTag,
    metadata: derivation.metadata,
    transactionHash: txHash,
    blockNumber: receipt.blockNumber,
    amount: value
  };
}
