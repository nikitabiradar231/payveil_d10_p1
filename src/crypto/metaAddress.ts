import {
  COMPRESSED_PUBKEY_BYTE_LENGTH,
  DEFAULT_CHAIN,
  META_ADDRESS_PREFIX,
  UNCOMPRESSED_PUBKEY_BYTE_LENGTH
} from './constants.js';
import type { Hex, StealthMetaAddressComponents } from './types.js';
import { bytesToHex, hexToBytes, validateAndParsePoint } from './utils.js';

/**
 * Encodes spending and viewing public keys into an ERC-5564 stealth meta-address URI.
 * Format: `st:<chain>:0x<spendingPublicKey><viewingPublicKey>`
 */
export function encodeStealthMetaAddress({
  spendingPublicKey,
  viewingPublicKey,
  chain = DEFAULT_CHAIN
}: {
  spendingPublicKey: Hex | string;
  viewingPublicKey: Hex | string;
  chain?: string;
}): string {
  // Validate both public keys
  const spendPoint = validateAndParsePoint(spendingPublicKey);
  const viewPoint = validateAndParsePoint(viewingPublicKey);

  // Use compressed 33-byte representation as canonical standard
  const spendHex = bytesToHex(spendPoint.toRawBytes(true)).slice(2);
  const viewHex = bytesToHex(viewPoint.toRawBytes(true)).slice(2);

  return `${META_ADDRESS_PREFIX}${chain}:0x${spendHex}${viewHex}`;
}

/**
 * Parses an ERC-5564 stealth meta-address string into spending and viewing public keys.
 * Accepts:
 * - `st:<chain>:0x...`
 * - `st:<chain>:...`
 * - `0x...`
 */
export function parseStealthMetaAddress(metaAddress: string): StealthMetaAddressComponents {
  if (typeof metaAddress !== 'string' || metaAddress.trim().length === 0) {
    throw new Error('Stealth meta-address must be a non-empty string');
  }

  let chain = DEFAULT_CHAIN;
  let keyPayload = metaAddress.trim();

  if (keyPayload.startsWith(META_ADDRESS_PREFIX)) {
    const afterPrefix = keyPayload.slice(META_ADDRESS_PREFIX.length);
    const colonIndex = afterPrefix.indexOf(':');
    if (colonIndex === -1) {
      throw new Error(`Malformed stealth meta-address URI: missing chain delimiter in "${metaAddress}"`);
    }
    chain = afterPrefix.slice(0, colonIndex);
    keyPayload = afterPrefix.slice(colonIndex + 1);
  }

  if (keyPayload.startsWith('0x') || keyPayload.startsWith('0X')) {
    keyPayload = keyPayload.slice(2);
  }

  // Validate hex characters
  if (!/^[0-9a-fA-F]+$/.test(keyPayload)) {
    throw new Error('Stealth meta-address payload contains non-hexadecimal characters');
  }

  const totalBytes = keyPayload.length / 2;

  let keyLength: number;
  if (totalBytes === COMPRESSED_PUBKEY_BYTE_LENGTH * 2) {
    // Both are 33-byte compressed keys
    keyLength = COMPRESSED_PUBKEY_BYTE_LENGTH;
  } else if (totalBytes === UNCOMPRESSED_PUBKEY_BYTE_LENGTH * 2) {
    // Both are 65-byte uncompressed keys
    keyLength = UNCOMPRESSED_PUBKEY_BYTE_LENGTH;
  } else {
    throw new Error(
      `Invalid stealth meta-address length: ${totalBytes} bytes. Expected ${COMPRESSED_PUBKEY_BYTE_LENGTH * 2} bytes (compressed) or ${UNCOMPRESSED_PUBKEY_BYTE_LENGTH * 2} bytes (uncompressed).`
    );
  }

  const spendHexPart = keyPayload.slice(0, keyLength * 2);
  const viewHexPart = keyPayload.slice(keyLength * 2);

  const spendingPublicKey: Hex = `0x${spendHexPart}`;
  const viewingPublicKey: Hex = `0x${viewHexPart}`;

  // Rigorously validate both curve points
  validateAndParsePoint(spendingPublicKey);
  validateAndParsePoint(viewingPublicKey);

  return {
    spendingPublicKey,
    viewingPublicKey,
    chain
  };
}
