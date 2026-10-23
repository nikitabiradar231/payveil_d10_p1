import fs from 'node:fs';
import path from 'node:path';
import { Command } from 'commander';
import { formatEther } from 'viem';
import {
  fetchAnnouncements,
  getDeployments,
  getPublicClient,
  getWalletClient
} from '../chain/index.js';
import { executeStealthPayment } from '../chain/pay.js';
import { executeWithdrawal } from '../chain/withdraw.js';
import {
  encodeStealthMetaAddress,
  recoverStealthPrivateKey,
  scanAnnouncements
} from '../crypto/index.js';
import type { Hex, ScanMatch } from '../crypto/types.js';
import {
  DEFAULT_KEYSTORE_PATH,
  createNewKeystore,
  loadKeystore
} from './keystore.js';

const SCANNED_CACHE_PATH = path.resolve(process.cwd(), '.stealthpay', 'scanned_payments.json');

function saveScannedPayments(payments: ScanMatch[]) {
  const dir = path.dirname(SCANNED_CACHE_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const serialized = JSON.stringify(
    payments,
    (_key, value) => (typeof value === 'bigint' ? value.toString() : value),
    2
  );
  fs.writeFileSync(SCANNED_CACHE_PATH, serialized, 'utf8');
}

function loadScannedPayments(): ScanMatch[] {
  if (!fs.existsSync(SCANNED_CACHE_PATH)) return [];
  try {
    const raw = JSON.parse(fs.readFileSync(SCANNED_CACHE_PATH, 'utf8'));
    return raw.map((item: any) => ({
      ...item,
      blockNumber: item.blockNumber ? BigInt(item.blockNumber) : undefined,
      amount: item.amount ? BigInt(item.amount) : undefined
    }));
  } catch {
    return [];
  }
}

export function createProgram(): Command {
  const program = new Command();

  program
    .name('stealthpay')
    .description('ERC-5564 Stealth Payments on Ethereum (Scheme 1 secp256k1)')
    .version('1.0.0');

  // Command 1: keys create
  program
    .command('keys create')
    .description('Generate a new spending & viewing key pair and save securely to local keystore')
    .option('-o, --out <path>', 'Custom keystore output path', DEFAULT_KEYSTORE_PATH)
    .action((options) => {
      try {
        const { keys, metaAddress, path: savedPath } = createNewKeystore(options.out);
        console.log('✨ Stealth keys generated successfully!');
        console.log(`📁 Keystore saved to: ${savedPath}`);
        console.log('');
        console.log('Public Keys:');
        console.log(`  Spending Public Key: ${keys.spending.publicKey}`);
        console.log(`  Viewing Public Key:  ${keys.viewing.publicKey}`);
        console.log('');
        console.log('Reusable Stealth Meta-Address:');
        console.log(`  ${metaAddress}`);
        console.log('');
        console.log('🔒 Security Notice: Private keys are stored locally with restricted permissions.');
        console.log('   The spending private key is never shared or loaded during scanning.');
      } catch (err) {
        console.error('❌ Error creating keys:', (err as Error).message);
        process.exit(1);
      }
    });

  // Command 2: meta-address
  program
    .command('meta-address')
    .description('Display your reusable ERC-5564 stealth meta-address')
    .option('-k, --keyfile <path>', 'Keystore path', DEFAULT_KEYSTORE_PATH)
    .action((options) => {
      try {
        const keys = loadKeystore(options.keyfile);
        const metaAddress = encodeStealthMetaAddress({
          spendingPublicKey: keys.spending.publicKey,
          viewingPublicKey: keys.viewing.publicKey
        });
        console.log(metaAddress);
      } catch (err) {
        console.error('❌ Error getting meta-address:', (err as Error).message);
        process.exit(1);
      }
    });

  // Command 3: pay
  program
    .command('pay')
    .description('Send an ETH payment to a stealth meta-address with an on-chain announcement')
    .requiredOption('-m, --meta-address <address>', 'Recipient stealth meta-address')
    .requiredOption('-a, --amount <eth>', 'Amount in ETH (e.g. 0.5)')
    .option('--rpc <url>', 'RPC endpoint URL')
    .option('--payer-key <key>', 'Payer private key (defaults to local Anvil account 0)')
    .action(async (options) => {
      try {
        console.log(`💸 Preparing stealth payment of ${options.amount} ETH...`);
        const deployments = getDeployments();
        if (!deployments) {
          throw new Error('Contract deployments not found. Please deploy contracts first.');
        }

        const payerPrivateKey = (options.payerKey ||
          process.env.PAYER_PRIVATE_KEY ||
          process.env.DEPLOYER_PRIVATE_KEY ||
          '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80') as Hex;

        const publicClient = getPublicClient(options.rpc);
        const walletClient = getWalletClient(payerPrivateKey, options.rpc);

        const result = await executeStealthPayment({
          walletClient,
          publicClient,
          announcerAddress: deployments.announcer,
          paymentAddress: deployments.payment,
          stealthMetaAddress: options.metaAddress,
          amountEth: options.amount
        });

        console.log('✅ Stealth payment confirmed!');
        console.log(`   Stealth Address:      ${result.stealthAddress}`);
        console.log(`   Amount:               ${options.amount} ETH`);
        console.log(`   Ephemeral Public Key: ${result.ephemeralPublicKey}`);
        console.log(`   View Tag:             ${result.viewTag}`);
        console.log(`   Transaction Hash:     ${result.transactionHash}`);
        console.log(`   Block Number:         ${result.blockNumber}`);
      } catch (err) {
        console.error('❌ Payment failed:', (err as Error).message);
        process.exit(1);
      }
    });

  // Command 4: scan
  program
    .command('scan')
    .description('Scan on-chain announcements for payments matching your viewing key')
    .option('-f, --from-block <block>', 'Starting block number', '0')
    .option('-t, --to-block <block>', 'Ending block number')
    .option('-k, --keyfile <path>', 'Keystore path', DEFAULT_KEYSTORE_PATH)
    .option('--rpc <url>', 'RPC endpoint URL')
    .action(async (options) => {
      try {
        console.log('🔍 Scanning announcements for incoming stealth payments...');
        const keys = loadKeystore(options.keyfile);
        const deployments = getDeployments();
        if (!deployments) {
          throw new Error('Contract deployments not found. Please deploy contracts first.');
        }

        const publicClient = getPublicClient(options.rpc);
        const fromBlock = BigInt(options.fromBlock);
        const toBlock = options.toBlock ? BigInt(options.toBlock) : await publicClient.getBlockNumber();

        const announcements = await fetchAnnouncements({
          publicClient,
          announcerAddress: deployments.announcer,
          fromBlock,
          toBlock
        });

        console.log(`   Fetched ${announcements.length} total announcement(s) on-chain.`);

        // SECURITY: Scan using ONLY viewing private key and spending public key!
        const scanResult = scanAnnouncements({
          viewingPrivateKey: keys.viewing.privateKey,
          spendingPublicKey: keys.spending.publicKey,
          announcements
        });

        console.log('');
        console.log(`Scan complete: ${scanResult.matches.length} matching payment(s) detected.`);
        console.log(`   View tags checked:       ${scanResult.diagnostics.viewTagChecks}`);
        console.log(`   View tag skips (fast):   ${scanResult.diagnostics.viewTagSkips}`);
        console.log(`   Full address derivations: ${scanResult.diagnostics.addressDerivations}`);

        // Fetch balances for matched payments
        for (let i = 0; i < scanResult.matches.length; i++) {
          const match = scanResult.matches[i];
          const balance = await publicClient.getBalance({ address: match.stealthAddress });
          (match as any).currentBalance = formatEther(balance);
          console.log('');
          console.log(`Payment #${i + 1}:`);
          console.log(`  Stealth Address:  ${match.stealthAddress}`);
          console.log(`  Current Balance:  ${(match as any).currentBalance} ETH`);
          console.log(`  Tx Hash:          ${match.transactionHash}`);
          console.log(`  Block Number:     ${match.blockNumber}`);
          console.log(`  View Tag:         ${match.viewTag}`);
        }

        saveScannedPayments(scanResult.matches);
      } catch (err) {
        console.error('❌ Scan error:', (err as Error).message);
        process.exit(1);
      }
    });

  // Command 5: withdraw
  program
    .command('withdraw')
    .description('Recover stealth private key and sweep funds to a recipient destination')
    .requiredOption('--to <address>', 'Destination address for swept funds')
    .option('--announcement <id>', 'Announcement index (1-based) or tx hash to withdraw')
    .option('--all', 'Withdraw all discovered payments with positive balance', false)
    .option('-k, --keyfile <path>', 'Keystore path containing spending private key', DEFAULT_KEYSTORE_PATH)
    .option('--rpc <url>', 'RPC endpoint URL')
    .action(async (options) => {
      try {
        const keys = loadKeystore(options.keyfile);
        const scanned = loadScannedPayments();
        if (scanned.length === 0) {
          throw new Error('No scanned payments found. Please run "stealthpay scan" first.');
        }

        const publicClient = getPublicClient(options.rpc);

        let targets: ScanMatch[] = [];
        if (options.all) {
          targets = scanned;
        } else if (options.announcement) {
          const index = parseInt(options.announcement, 10);
          if (!Number.isNaN(index) && index >= 1 && index <= scanned.length) {
            targets = [scanned[index - 1]];
          } else {
            const found = scanned.find((s) => s.transactionHash?.toLowerCase() === options.announcement.toLowerCase());
            if (found) targets = [found];
            else throw new Error(`Announcement "${options.announcement}" not found in scanned list.`);
          }
        } else {
          // Default to the first scanned payment
          targets = [scanned[0]];
        }

        console.log(`💳 Preparing withdrawal for ${targets.length} payment(s) to ${options.to}...`);

        for (const target of targets) {
          const balance = await publicClient.getBalance({ address: target.stealthAddress });
          if (balance === 0n) {
            console.log(`⚠️ Skipping ${target.stealthAddress}: balance is already 0 ETH.`);
            continue;
          }

          // Recover the spending key
          const recovery = recoverStealthPrivateKey({
            spendingPrivateKey: keys.spending.privateKey,
            viewingPrivateKey: keys.viewing.privateKey,
            ephemeralPublicKey: target.ephemeralPublicKey,
            expectedStealthAddress: target.stealthAddress
          });

          const withdrawal = await executeWithdrawal({
            publicClient,
            stealthPrivateKey: recovery.stealthPrivateKey,
            toAddress: options.to as Hex,
            rpcUrl: options.rpc
          });

          console.log(`✅ Swept ${withdrawal.amountSentEth} ETH from ${target.stealthAddress}`);
          console.log(`   Tx Hash: ${withdrawal.transactionHash}`);
        }
      } catch (err) {
        console.error('❌ Withdrawal error:', (err as Error).message);
        process.exit(1);
      }
    });

  // Command 6: balance
  program
    .command('balance')
    .description('Check ETH balance of an address or currently scanned stealth addresses')
    .option('-a, --address <address>', 'Address to query')
    .option('--rpc <url>', 'RPC endpoint URL')
    .action(async (options) => {
      try {
        const publicClient = getPublicClient(options.rpc);

        if (options.address) {
          const bal = await publicClient.getBalance({ address: options.address as Hex });
          console.log(`Balance of ${options.address}: ${formatEther(bal)} ETH`);
        } else {
          const scanned = loadScannedPayments();
          if (scanned.length === 0) {
            console.log('No scanned addresses found. Provide --address <addr> or run "stealthpay scan".');
            return;
          }
          console.log('Balances of scanned stealth addresses:');
          let total = 0n;
          for (const s of scanned) {
            const bal = await publicClient.getBalance({ address: s.stealthAddress });
            total += bal;
            console.log(`  ${s.stealthAddress}: ${formatEther(bal)} ETH`);
          }
          console.log(`Total across scanned addresses: ${formatEther(total)} ETH`);
        }
      } catch (err) {
        console.error('❌ Error checking balance:', (err as Error).message);
        process.exit(1);
      }
    });

  return program;
}

if (process.argv[1] && (process.argv[1].endsWith('index.ts') || process.argv[1].endsWith('stealthpay.js'))) {
  createProgram().parse(process.argv);
}
