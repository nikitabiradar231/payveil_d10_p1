import fs from 'node:fs';
import path from 'node:path';
import type { Hex } from '../crypto/types.js';
import { STEALTH_ANNOUNCER_ABI, STEALTH_PAYMENT_ABI } from './abis.js';
import type { StealthPublicClient, StealthWalletClient } from './client.js';
import { type DeploymentAddresses, saveDeployments } from './config.js';

function readBytecode(contractName: string): Hex {
  const artifactPath = path.resolve(process.cwd(), 'out', `${contractName}.sol`, `${contractName}.json`);
  if (!fs.existsSync(artifactPath)) {
    throw new Error(`Artifact not found at ${artifactPath}. Please run "forge build" first.`);
  }
  const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
  return artifact.bytecode.object as Hex;
}

export async function deployStealthContracts({
  publicClient,
  walletClient
}: {
  publicClient: StealthPublicClient;
  walletClient: StealthWalletClient;
}): Promise<DeploymentAddresses> {
  const account = walletClient.account;
  if (!account) {
    throw new Error('Wallet client must have an attached account to deploy contracts');
  }

  // 1. Deploy StealthAnnouncer
  const announcerBytecode = readBytecode('StealthAnnouncer');
  const announcerDeployTx = await walletClient.deployContract({
    abi: STEALTH_ANNOUNCER_ABI,
    bytecode: announcerBytecode,
    account,
    chain: null
  });

  const announcerReceipt = await publicClient.waitForTransactionReceipt({
    hash: announcerDeployTx
  });

  if (!announcerReceipt.contractAddress) {
    throw new Error('StealthAnnouncer deployment failed: no contract address in receipt');
  }
  const announcerAddress = announcerReceipt.contractAddress as Hex;

  // 2. Deploy StealthPayment
  const paymentBytecode = readBytecode('StealthPayment');
  const paymentDeployTx = await walletClient.deployContract({
    abi: STEALTH_PAYMENT_ABI,
    bytecode: paymentBytecode,
    args: [announcerAddress],
    account,
    chain: null
  });

  const paymentReceipt = await publicClient.waitForTransactionReceipt({
    hash: paymentDeployTx
  });

  if (!paymentReceipt.contractAddress) {
    throw new Error('StealthPayment deployment failed: no contract address in receipt');
  }
  const paymentAddress = paymentReceipt.contractAddress as Hex;

  const deployments: DeploymentAddresses = {
    announcer: announcerAddress,
    payment: paymentAddress,
    deployedAt: new Date().toISOString(),
    chainId: await publicClient.getChainId()
  };

  saveDeployments(deployments);
  return deployments;
}
