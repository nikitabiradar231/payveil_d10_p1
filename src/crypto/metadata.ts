import { getAddress } from 'viem';
import type { Hex } from './types.js';
import { hexToBytes } from './utils.js';

export const ETH_METADATA_FUNCTION_IDENTIFIER = '0xeeeeeeee' as const;
export const ETH_TOKEN_ADDRESS = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE' as const;

export interface ParsedMetadata {
  viewTag: Hex;
  functionIdentifier?: Hex;
  tokenAddress?: Hex;
  amount?: bigint;
  raw: Hex;
}

export interface BuildEthMetadataParams {
  viewTag: Hex;
  amount: bigint;
}

/**
 * Builds standard ERC-5564 recommended metadata for native ETH transfers:
 * - Byte 1: view tag (1 byte)
 * - Bytes 2-5: function identifier 0xeeeeeeee (4 bytes)
 * - Bytes 6-25: token address 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE (20 bytes)
 * - Bytes 26-57: amount uint256 (32 bytes big-endian)
 * Total: 57 bytes (114 hex chars + 0x)
 */
export function buildMetadataForETH({ viewTag, amount }: BuildEthMetadataParams): Hex {
  const cleanTag = viewTag.startsWith('0x') ? viewTag.slice(2) : viewTag;
  if (cleanTag.length !== 2 || !/^[0-9a-fA-F]{2}$/.test(cleanTag)) {
    throw new Error(`View tag must be exactly 1 byte hex (e.g. 0x42), got: ${viewTag}`);
  }
  if (amount < 0n) {
    throw new Error('Metadata ETH amount cannot be negative');
  }

  const tagHex = cleanTag.toLowerCase();
  const funcId = 'eeeeeeee';
  const tokenHex = ETH_TOKEN_ADDRESS.slice(2).toLowerCase();
  const amountHex = amount.toString(16).padStart(64, '0');

  return `0x${tagHex}${funcId}${tokenHex}${amountHex}` as Hex;
}

/**
 * Parses ERC-5564 announcement metadata:
 * - Always extracts the view tag from byte 0.
 * - If 57 bytes, extracts functionIdentifier, tokenAddress, and amount.
 */
export function parseMetadata(metadataHex: string): ParsedMetadata {
  if (typeof metadataHex !== 'string' || metadataHex.trim().length === 0) {
    throw new Error('Metadata must be a non-empty hex string');
  }
  const clean = metadataHex.startsWith('0x') ? metadataHex.slice(2) : metadataHex;
  if (clean.length === 0 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error(`Invalid metadata hex string: ${metadataHex}`);
  }

  const bytes = hexToBytes(`0x${clean}`);
  const viewTag: Hex = `0x${bytes[0].toString(16).padStart(2, '0')}`;
  const raw: Hex = `0x${clean.toLowerCase()}`;

  // If standard 57-byte ETH or token metadata
  if (bytes.length === 57) {
    const funcId: Hex = `0x${clean.slice(2, 10).toLowerCase()}`;
    const tokenAddr: Hex = getAddress(`0x${clean.slice(10, 50)}`) as Hex;
    const amountHex = clean.slice(50, 114);
    const amount = BigInt(`0x${amountHex}`);

    return {
      viewTag,
      functionIdentifier: funcId,
      tokenAddress: tokenAddr,
      amount,
      raw
    };
  }

  return {
    viewTag,
    raw
  };
}
