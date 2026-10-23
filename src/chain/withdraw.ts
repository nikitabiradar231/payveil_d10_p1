import { formatEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import type { Hex } from '../crypto/types.js';
import { type StealthPublicClient, getWalletClient } from './client.js';

export interface ExecuteWithdrawalParams {
  publicClient: StealthPublicClient;
  stealthPrivateKey: Hex;
  toAddress: Hex;
  rpcUrl?: string;
}

export interface WithdrawalResult {
  transactionHash: Hex;
  stealthAddress: Hex;
  destinationAddress: Hex;
  amountSent: bigint;
  amountSentEth: string;
  gasCost: bigint;
  blockNumber: bigint;
}

/**
 * Sweeps the entire balance from a recovered stealth address to a recipient-chosen destination,
 * accurately accounting for gas costs.
 */
export async function executeWithdrawal({
  publicClient,
  stealthPrivateKey,
  toAddress,
  rpcUrl
}: ExecuteWithdrawalParams): Promise<WithdrawalResult> {
  const stealthAccount = privateKeyToAccount(stealthPrivateKey);
  const stealthAddress = stealthAccount.address;

  // 1. Fetch current balance
  const balance = await publicClient.getBalance({ address: stealthAddress });
  if (balance === 0n) {
    throw new Error(`Stealth address ${stealthAddress} has zero balance`);
  }

  // 2. Compute gas costs
  const gasLimit = 21000n; // Standard native ETH transfer
  const gasPrice = await publicClient.getGasPrice();
  const gasCost = gasLimit * gasPrice;

  if (balance <= gasCost) {
    throw new Error(
      `Insufficient balance (${formatEther(balance)} ETH) to cover gas fee (${formatEther(gasCost)} ETH)`
    );
  }

  const amountToSend = balance - gasCost;

  // 3. Broadcast withdrawal transaction
  const walletClient = getWalletClient(stealthPrivateKey, rpcUrl);
  const txHash = await walletClient.sendTransaction({
    account: stealthAccount,
    to: toAddress,
    value: amountToSend,
    gas: gasLimit,
    gasPrice,
    chain: null
  });

  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });

  return {
    transactionHash: txHash,
    stealthAddress,
    destinationAddress: toAddress,
    amountSent: amountToSend,
    amountSentEth: formatEther(amountToSend),
    gasCost,
    blockNumber: receipt.blockNumber
  };
}
