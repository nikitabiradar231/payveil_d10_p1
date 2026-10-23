import { secp256k1 } from '@noble/curves/secp256k1';
import { CURVE_ORDER } from './constants.js';
import type { Hex, SpendingKeyPair, StealthKeys, ViewingKeyPair } from './types.js';
import {
  bigIntToHex32,
  bytesToBigInt,
  bytesToHex,
  hexToBytes,
  secureRandomBytes,
  validateScalar
} from './utils.js';

/**
 * Generates a fresh, cryptographically secure secp256k1 private key.
 * Uses CSPRNG and validates that 1 <= scalar < n.
 */
export function generatePrivateKey(): Hex {
  while (true) {
    const raw = secureRandomBytes(32);
    const scalar = bytesToBigInt(raw);
    if (scalar > 0n && scalar < CURVE_ORDER) {
      return bigIntToHex32(scalar);
    }
  }
}

/**
 * Computes the secp256k1 public key from a private key.
 * @param privateKey 32-byte hex private key scalar.
 * @param compressed Whether to return 33-byte compressed format (default: true).
 */
export function getPublicKey(privateKey: Hex | string, compressed = true): Hex {
  let clean = privateKey.startsWith('0x') || privateKey.startsWith('0X') ? privateKey.slice(2) : privateKey;
  if (clean.length > 0 && clean.length <= 64) {
    clean = clean.padStart(64, '0');
  }
  const bytes = hexToBytes(`0x${clean}`);
  if (bytes.length !== 32) {
    throw new Error(`Invalid private key length: expected 32 bytes, got ${bytes.length}`);
  }
  const scalar = bytesToBigInt(bytes);
  validateScalar(scalar);

  const point = secp256k1.ProjectivePoint.BASE.multiply(scalar);
  return bytesToHex(point.toRawBytes(compressed));
}

/**
 * Validates a private key scalar and returns its BigInt value.
 */
export function parseAndValidatePrivateKey(privateKey: string): bigint {
  let clean = privateKey.startsWith('0x') || privateKey.startsWith('0X') ? privateKey.slice(2) : privateKey;
  if (clean.length > 0 && clean.length <= 64) {
    clean = clean.padStart(64, '0');
  }
  const bytes = hexToBytes(`0x${clean}`);
  if (bytes.length !== 32) {
    throw new Error(`Invalid private key length: expected 32 bytes, got ${bytes.length}`);
  }
  const scalar = bytesToBigInt(bytes);
  validateScalar(scalar);
  return scalar;
}

/**
 * Generates an independent spending key pair.
 */
export function generateSpendingKeyPair(): SpendingKeyPair {
  const privateKey = generatePrivateKey();
  const publicKey = getPublicKey(privateKey, true);
  return { privateKey, publicKey };
}

/**
 * Generates an independent viewing key pair.
 */
export function generateViewingKeyPair(): ViewingKeyPair {
  const privateKey = generatePrivateKey();
  const publicKey = getPublicKey(privateKey, true);
  return { privateKey, publicKey };
}

/**
 * Generates both spending and viewing key pairs.
 * Notice: Although generated together for convenience upon user onboarding,
 * the spending and viewing keys are strictly distinct and must be managed separately.
 */
export function generateStealthKeys(): StealthKeys {
  const spending = generateSpendingKeyPair();
  const viewing = generateViewingKeyPair();
  return { spending, viewing };
}

/**
 * Security safeguard: asserts that an object given to the scanner does not contain
 * a spending private key or any spending scalar authority.
 */
export function assertScannerSafety(params: Record<string, unknown>): void {
  if ('spendingPrivateKey' in params && params.spendingPrivateKey !== undefined) {
    throw new Error('SECURITY VIOLATION: Scanner received a spending private key!');
  }
  if ('spending' in params && typeof params.spending === 'object' && params.spending !== null) {
    if ('privateKey' in (params.spending as Record<string, unknown>)) {
      throw new Error('SECURITY VIOLATION: Scanner received spending key object with privateKey!');
    }
  }
}
