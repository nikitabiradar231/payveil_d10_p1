import 'dotenv/config';
import { getPublicClient, getWalletClient } from '../src/chain/client.js';
import { deployStealthContracts } from '../src/chain/deploy.js';
import type { Hex } from '../src/crypto/types.js';

async function main() {
  console.log('🚀 Deploying ERC-5564 stealth contracts to local EVM...');
  const deployerKey = (process.env.DEPLOYER_PRIVATE_KEY ||
    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80') as Hex;

  const publicClient = getPublicClient(process.env.RPC_URL);
  const walletClient = getWalletClient(deployerKey, process.env.RPC_URL);

  const deployments = await deployStealthContracts({ publicClient, walletClient });

  console.log('✅ Deployment successful!');
  console.log(`   StealthAnnouncer: ${deployments.announcer}`);
  console.log(`   StealthPayment:   ${deployments.payment}`);
  console.log(`   Chain ID:         ${deployments.chainId}`);
}

main().catch((err) => {
  console.error('❌ Deployment error:', err);
  process.exit(1);
});
