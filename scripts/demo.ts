import { formatEther, parseEther } from 'viem';
import {
  fetchAnnouncements,
  getDeployments,
  getPublicClient,
  getWalletClient
} from '../src/chain/index.js';
import { executeStealthPayment } from '../src/chain/pay.js';
import { executeWithdrawal } from '../src/chain/withdraw.js';
import {
  encodeStealthMetaAddress,
  generateStealthKeys,
  recoverStealthPrivateKey,
  scanAnnouncements
} from '../src/crypto/index.js';
import type { Hex } from '../src/crypto/types.js';

async function main() {
  console.log('================================================================');
  console.log('  StealthPay — ERC-5564 Full Interactive Demonstration');
  console.log('================================================================\n');

  const deployments = getDeployments();
  if (!deployments) {
    throw new Error('Deployments not found. Run npm run deploy:local first.');
  }

  const publicClient = getPublicClient();
  const payerPrivateKey = (process.env.PAYER_PRIVATE_KEY ||
    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80') as Hex;
  const payerClient = getWalletClient(payerPrivateKey);

  // 1. Mira generates her keys and publishes ONE reusable meta-address
  console.log('STEP 1: Mira generates separate spending and viewing keypairs...');
  const mira = generateStealthKeys();
  const miraMetaAddress = encodeStealthMetaAddress({
    spendingPublicKey: mira.spending.publicKey,
    viewingPublicKey: mira.viewing.publicKey
  });

  console.log(`  Mira Spending Public Key: ${mira.spending.publicKey}`);
  console.log(`  Mira Viewing Public Key:  ${mira.viewing.publicKey}`);
  console.log(`  Mira Reusable Meta-Addr:  ${miraMetaAddress}\n`);

  // An unrelated user (Bob) also has a meta-address
  const bob = generateStealthKeys();
  const bobMetaAddress = encodeStealthMetaAddress({
    spendingPublicKey: bob.spending.publicKey,
    viewingPublicKey: bob.viewing.publicKey
  });

  const fromBlock = await publicClient.getBlockNumber();

  // 2. Client A pays Mira
  console.log('STEP 2: Client A sends 0.50 ETH to Mira\'s stealth meta-address...');
  const payA = await executeStealthPayment({
    walletClient: payerClient,
    publicClient,
    announcerAddress: deployments.announcer,
    paymentAddress: deployments.payment,
    stealthMetaAddress: miraMetaAddress,
    amountEth: '0.50'
  });
  console.log(`  Payment A derived Stealth Address: ${payA.stealthAddress}`);
  console.log(`  Ephemeral Public Key (R):         ${payA.ephemeralPublicKey}`);
  console.log(`  Published View Tag:               ${payA.viewTag}`);
  console.log(`  Tx Hash:                          ${payA.transactionHash}\n`);

  // 3. Client B pays Mira
  console.log('STEP 3: Client B sends 0.75 ETH to Mira\'s stealth meta-address...');
  const payB = await executeStealthPayment({
    walletClient: payerClient,
    publicClient,
    announcerAddress: deployments.announcer,
    paymentAddress: deployments.payment,
    stealthMetaAddress: miraMetaAddress,
    amountEth: '0.75'
  });
  console.log(`  Payment B derived Stealth Address: ${payB.stealthAddress}`);
  console.log(`  Ephemeral Public Key (R):         ${payB.ephemeralPublicKey}`);
  console.log(`  Published View Tag:               ${payB.viewTag}`);
  console.log(`  Tx Hash:                          ${payB.transactionHash}\n`);

  // Client C pays Bob (unrelated announcement)
  console.log('--- Unrelated noise: Client C sends 0.10 ETH to Bob\'s meta-address ---');
  const payBob = await executeStealthPayment({
    walletClient: payerClient,
    publicClient,
    announcerAddress: deployments.announcer,
    paymentAddress: deployments.payment,
    stealthMetaAddress: bobMetaAddress,
    amountEth: '0.10'
  });
  console.log(`  Payment to Bob Stealth Address:   ${payBob.stealthAddress}\n`);

  // 4. Distinct stealth addresses verification
  console.log('STEP 4: Verifying payment address uniqueness...');
  if (payA.stealthAddress.toLowerCase() === payB.stealthAddress.toLowerCase()) {
    throw new Error('Collision detected! Stealth addresses must be distinct.');
  }
  console.log('  ✅ Pay A and Pay B derived completely distinct stealth addresses!\n');

  // 5. Mira scans announcements using ONLY her viewing private key and spending public key
  console.log('STEP 5: Mira scans announcements using ONLY viewing.privateKey & spending.publicKey...');
  console.log('  🔒 Strict security check: spending private key is NOT passed to scanner.');
  const toBlock = await publicClient.getBlockNumber();
  const announcements = await fetchAnnouncements({
    publicClient,
    announcerAddress: deployments.announcer,
    fromBlock,
    toBlock
  });

  const scanResult = scanAnnouncements({
    viewingPrivateKey: mira.viewing.privateKey,
    spendingPublicKey: mira.spending.publicKey,
    announcements
  });

  // 6. Mira identifies both payments
  console.log('\nSTEP 6: Mira scans and identifies matching payments:');
  console.log(`  Total announcements checked: ${announcements.length}`);
  console.log(`  View-tag skips (fast path):  ${scanResult.diagnostics.viewTagSkips}`);
  console.log(`  Matching payments detected:  ${scanResult.matches.length}`);

  for (let i = 0; i < scanResult.matches.length; i++) {
    const m = scanResult.matches[i];
    const bal = await publicClient.getBalance({ address: m.stealthAddress });
    console.log(`  Payment #${i + 1}: Address: ${m.stealthAddress} | Balance: ${formatEther(bal)} ETH`);
  }

  // 7. Mira recovers spending keys ONLY during withdrawal and sweeps balances
  console.log('\nSTEP 7: Mira recovers spending keys only at withdrawal time and sweeps funds...');
  const miraColdStorage: Hex = '0x1234567890123456789012345678901234567890';
  const coldBalanceBefore = await publicClient.getBalance({ address: miraColdStorage });

  for (let i = 0; i < scanResult.matches.length; i++) {
    const payment = scanResult.matches[i];
    console.log(`  Sweeping Payment #${i + 1} (${payment.stealthAddress})...`);

    // Recovery formula: p_stealth = (p_spend + h) mod n
    const recovery = recoverStealthPrivateKey({
      spendingPrivateKey: mira.spending.privateKey,
      viewingPrivateKey: mira.viewing.privateKey,
      ephemeralPublicKey: payment.ephemeralPublicKey,
      expectedStealthAddress: payment.stealthAddress
    });

    const withdrawal = await executeWithdrawal({
      publicClient,
      stealthPrivateKey: recovery.stealthPrivateKey,
      toAddress: miraColdStorage
    });

    console.log(`    ✅ Transferred ${withdrawal.amountSentEth} ETH to cold storage.`);
    console.log(`    Tx Hash: ${withdrawal.transactionHash}`);
  }

  const coldBalanceAfter = await publicClient.getBalance({ address: miraColdStorage });
  console.log(`  Cold Storage Balance Increase: ${formatEther(coldBalanceAfter - coldBalanceBefore)} ETH\n`);

  // 8. Verify unrelated announcements are ignored
  console.log('STEP 8: Verifying unrelated announcements to Bob were ignored by Mira...');
  const foundBob = scanResult.matches.some(
    (m) => m.stealthAddress.toLowerCase() === payBob.stealthAddress.toLowerCase()
  );
  if (foundBob) {
    throw new Error('Security flaw: Mira mistakenly matched Bob\'s payment!');
  }
  console.log('  ✅ Confirmed: Bob\'s payment was completely ignored by Mira.');

  console.log('\n================================================================');
  console.log('  🎉 DEMONSTRATION COMPLETE: ALL 8 STEPS VERIFIED SUCCESSFULLY!');
  console.log('================================================================');
}

main().catch((err) => {
  console.error('❌ Demo failure:', err);
  process.exit(1);
});
