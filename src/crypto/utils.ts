import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { getAddress } from 'viem';
import { CURVE_ORDER } from './constants.js';
import type { Hex } from './types.js';

/**
 * Converts a Uint8Array to a 0x-prefixed hex string.
 */
export function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}`;
}

/**
 * Converts a hex string (with or without 0x prefix) to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error(`Invalid hex string length: ${hex}`);
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`Invalid hex character in ${hex}`);
    }
    bytes[i] = byte;
  }
  return bytes;
}

/**
 * Converts a BigInt to a 32-byte 0x-prefixed hex string.
 */
export function bigIntToHex32(value: bigint): Hex {
  const hex = value.toString(16).padStart(64, '0');
  return `0x${hex}`;
}

/**
 * Converts a byte array to a BigInt (big-endian).
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

/**
 * Generates cryptographically secure random bytes using web standard CSPRNG.
 */
export function secureRandomBytes(length: number): Uint8Array {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    throw new Error('Cryptographically secure random number generator is not available');
  }
  const buffer = new Uint8Array(length);
  globalThis.crypto.getRandomValues(buffer);
  return buffer;
}

/**
 * Validates that a private key scalar d satisfies 1 <= d < n.
 */
export function validateScalar(scalar: bigint): void {
  if (scalar <= 0n || scalar >= CURVE_ORDER) {
    throw new Error('Scalar out of valid secp256k1 range [1, n-1]');
  }
}

/**
 * Parses and validates that a hex public key is a valid non-infinity point on secp256k1.
 */
export function validateAndParsePoint(pubKeyHex: string): typeof secp256k1.ProjectivePoint.prototype {
  const bytes = hexToBytes(pubKeyHex);
  if (bytes.length !== 33 && bytes.length !== 65) {
    throw new Error(
      `Invalid public key length (${bytes.length} bytes). Must be 33 bytes (compressed) or 65 bytes (uncompressed).`
    );
  }
  try {
    const point = secp256k1.ProjectivePoint.fromHex(bytes);
    point.assertValidity();
    return point;
  } catch (err) {
    throw new Error(`Invalid secp256k1 public key: ${(err as Error).message}`);
  }
}

/**
 * Derives the Ethereum checksum address from a secp256k1 public key point.
 * Address = last 20 bytes of keccak256(uncompressed_point_without_04_prefix).
 */
export function deriveEthereumAddress(
  point: typeof secp256k1.ProjectivePoint.prototype | string | Uint8Array
): Hex {
  let rawPoint: typeof secp256k1.ProjectivePoint.prototype;
  if (typeof point === 'string') {
    rawPoint = validateAndParsePoint(point);
  } else if (point instanceof Uint8Array) {
    rawPoint = secp256k1.ProjectivePoint.fromHex(point);
  } else {
    rawPoint = point;
  }

  // Uncompressed representation: 0x04 || X (32 bytes) || Y (32 bytes)
  const uncompressed = rawPoint.toRawBytes(false);
  // Slice off the 0x04 prefix byte (first byte)
  const pubKeyCoordinates = uncompressed.slice(1);
  // Hash with keccak256
  const hash = keccak_256(pubKeyCoordinates);
  // Take last 20 bytes
  const addressBytes = hash.slice(-20);
  const addressHex = bytesToHex(addressBytes);
  // Return EIP-55 checksummed address
  return getAddress(addressHex) as Hex;
}
