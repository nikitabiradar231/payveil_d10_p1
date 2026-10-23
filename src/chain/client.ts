import {
  type Account,
  type Chain,
  type PublicClient,
  type Transport,
  type WalletClient,
  createPublicClient,
  createWalletClient,
  http
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import type { Hex } from '../crypto/types.js';
import { anvilChain } from './config.js';

export type StealthPublicClient = PublicClient<Transport, Chain>;
export type StealthWalletClient = WalletClient<Transport, Chain, Account>;

export function getPublicClient(rpcUrl?: string): StealthPublicClient {
  return createPublicClient({
    chain: anvilChain,
    transport: http(rpcUrl || anvilChain.rpcUrls.default.http[0], {
      retryCount: 3,
      retryDelay: 1000
    })
  });
}

export function getWalletClient(privateKey: Hex, rpcUrl?: string): StealthWalletClient {
  const account = privateKeyToAccount(privateKey);
  return createWalletClient({
    account,
    chain: anvilChain,
    transport: http(rpcUrl || anvilChain.rpcUrls.default.http[0])
  });
}

export { privateKeyToAccount };
