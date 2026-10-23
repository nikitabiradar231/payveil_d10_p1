import fs from 'node:fs';
import path from 'node:path';
import { type Chain, defineChain } from 'viem';
import type { Hex } from '../crypto/types.js';

export const anvilChain: Chain = defineChain({
  id: 31337,
  name: 'Anvil Localhost',
  nativeCurrency: {
    name: 'Ether',
    symbol: 'ETH',
    decimals: 18
  },
  rpcUrls: {
    default: {
      http: [process.env.RPC_URL || 'http://127.0.0.1:8545']
    }
  }
});

export interface DeploymentAddresses {
  announcer: Hex;
  payment: Hex;
  deployedAt?: string;
  chainId: number;
}

export const DEFAULT_DEPLOYMENT_PATH = path.resolve(process.cwd(), 'deployments.json');

export function getDeployments(filePath = DEFAULT_DEPLOYMENT_PATH): DeploymentAddresses | null {
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
  } catch {
    return null;
  }
}

export function saveDeployments(
  addresses: DeploymentAddresses,
  filePath = DEFAULT_DEPLOYMENT_PATH
): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, JSON.stringify(addresses, null, 2), 'utf8');
}
