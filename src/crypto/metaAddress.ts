import {
  COMPRESSED_PUBKEY_BYTE_LENGTH,
  DEFAULT_CHAIN,
  META_ADDRESS_PREFIX,
  UNCOMPRESSED_PUBKEY_BYTE_LENGTH
} from './constants.js';
import type { Hex, StealthMetaAddressComponents } from './types.js';
import { bytesToHex, validateAndParsePoint } from './utils.js';

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
 * Conforms strictly to ERC-5564 specification:
 * - A stealth meta-address of length n uses the same key for spending and viewing.
 * - A stealth meta-address of length 2n uses the first n bytes for spending and last n bytes for viewing.
 *
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

  let spendingPublicKey: Hex;
  let viewingPublicKey: Hex;

  if (totalBytes === COMPRESSED_PUBKEY_BYTE_LENGTH * 2) {
    // Dual key (compressed): 33 bytes spend + 33 bytes view
    const spendHex = keyPayload.slice(0, COMPRESSED_PUBKEY_BYTE_LENGTH * 2);
    const viewHex = keyPayload.slice(COMPRESSED_PUBKEY_BYTE_LENGTH * 2);
    spendingPublicKey = `0x${spendHex}`;
    viewingPublicKey = `0x${viewHex}`;
  } else if (totalBytes === UNCOMPRESSED_PUBKEY_BYTE_LENGTH * 2) {
    // Dual key (uncompressed): 65 bytes spend + 65 bytes view
    const spendHex = keyPayload.slice(0, UNCOMPRESSED_PUBKEY_BYTE_LENGTH * 2);
    const viewHex = keyPayload.slice(UNCOMPRESSED_PUBKEY_BYTE_LENGTH * 2);
    spendingPublicKey = `0x${spendHex}`;
    viewingPublicKey = `0x${viewHex}`;
  } else if (totalBytes === COMPRESSED_PUBKEY_BYTE_LENGTH) {
    // Single key (compressed): same key for spending and viewing (ERC-5564 spec)
    spendingPublicKey = `0x${keyPayload}`;
    viewingPublicKey = `0x${keyPayload}`;
  } else if (totalBytes === UNCOMPRESSED_PUBKEY_BYTE_LENGTH) {
    // Single key (uncompressed): same key for spending and viewing (ERC-5564 spec)
    spendingPublicKey = `0x${keyPayload}`;
    viewingPublicKey = `0x${keyPayload}`;
  } else {
    throw new Error(
      `Invalid stealth meta-address length: ${totalBytes} bytes. Expected 33/65 bytes (single key) or 66/130 bytes (dual key).`
    );
  }

  // Rigorously validate both curve points
  validateAndParsePoint(spendingPublicKey);
  validateAndParsePoint(viewingPublicKey);

  return {
    spendingPublicKey,
    viewingPublicKey,
    chain
  };
}
