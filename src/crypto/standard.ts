import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { CURVE_ORDER, SCHEME_ID } from './constants.js';
import { parseAndValidatePrivateKey } from './keys.js';
import { recoverStealthPrivateKey } from './recovery.js';
import type { Hex } from './types.js';
import {
  bytesToBigInt,
  deriveEthereumAddress,
  hexToBytes,
  validateAndParsePoint
} from './utils.js';

export interface CheckStealthAddressParams {
  stealthAddress?: Hex | string;
  userStealthAddress?: Hex | string;
  ephemeralPublicKey?: Hex | string;
  ephemeralPubKey?: Hex | string;
  viewingPrivateKey?: Hex | string;
  viewingKey?: Hex | string;
  spendingPublicKey?: Hex | string;
  spendingPubKey?: Hex | string;
  viewTag?: Hex | string;
  schemeId?: bigint | number;
}

export interface ComputeStealthKeyParams {
  stealthAddress?: Hex | string;
  userStealthAddress?: Hex | string;
  expectedStealthAddress?: Hex | string;
  ephemeralPublicKey?: Hex | string;
  ephemeralPubKey?: Hex | string;
  viewingPrivateKey?: Hex | string;
  viewingKey?: Hex | string;
  spendingPrivateKey?: Hex | string;
  spendingKey?: Hex | string;
  schemeId?: bigint | number;
}

/**
 * ERC-5564 Standard checkStealthAddress implementation.
 *
 * Checks if a given stealth announcement belongs to the recipient:
 * 1. Computes shared secret s = p_view * P_ephemeral
 * 2. Hashes shared secret s_h = keccak256(s_compressed)
 * 3. Compares viewTag if provided (fast filter)
 * 4. Derives stealth public key P_stealth = P_spend + (s_h mod n) * G
 * 5. Returns true if pubkeyToAddress(P_stealth) matches stealthAddress.
 *
 * Supports both object params and positional args matching ERC-5564.
 */
export function checkStealthAddress(
  arg1: CheckStealthAddressParams | string,
  arg2?: string,
  arg3?: string,
  arg4?: string,
  arg5?: string
): boolean {
  let stealthAddress: string;
  let ephemeralPublicKey: string;
  let viewingPrivateKey: string;
  let spendingPublicKey: string;
  let viewTag: string | undefined;

  if (typeof arg1 === 'object') {
    stealthAddress = (arg1.stealthAddress || arg1.userStealthAddress) as string;
    ephemeralPublicKey = (arg1.ephemeralPublicKey || arg1.ephemeralPubKey) as string;
    viewingPrivateKey = (arg1.viewingPrivateKey || arg1.viewingKey) as string;
    spendingPublicKey = (arg1.spendingPublicKey || arg1.spendingPubKey) as string;
    viewTag = arg1.viewTag as string | undefined;
  } else {
    stealthAddress = arg1;
    ephemeralPublicKey = arg2!;
    viewingPrivateKey = arg3!;
    spendingPublicKey = arg4!;
    viewTag = arg5;
  }

  if (!stealthAddress || !ephemeralPublicKey || !viewingPrivateKey || !spendingPublicKey) {
    throw new Error('checkStealthAddress requires stealthAddress, ephemeralPublicKey, viewingPrivateKey, and spendingPublicKey');
  }

  // 1. Validate points and scalar
  const pViewScalar = parseAndValidatePrivateKey(viewingPrivateKey as Hex);
  const pSpend = validateAndParsePoint(spendingPublicKey);
  const rPoint = validateAndParsePoint(ephemeralPublicKey);

  // 2. ECDH shared secret: S = p_view * R
  const sPoint = rPoint.multiply(pViewScalar);
  const sCompressed = sPoint.toRawBytes(true);

  // 3. Hash shared secret: s_h = keccak256(S)
  const sHash = keccak_256(sCompressed);

  // 4. View tag check if provided
  if (viewTag) {
    const expectedViewTagByte = sHash[0];
    const cleanTag = viewTag.startsWith('0x') ? viewTag.slice(2) : viewTag;
    const providedViewTagByte = parseInt(cleanTag.slice(0, 2), 16);
    if (expectedViewTagByte !== providedViewTagByte) {
      return false;
    }
  }

  // 5. Derive stealth public key: P_stealth = P_spend + (s_h mod n) * G
  const hScalar = bytesToBigInt(sHash) % CURVE_ORDER;
  if (hScalar === 0n) {
    return false;
  }
  const hG = secp256k1.ProjectivePoint.BASE.multiply(hScalar);
  const pStealth = pSpend.add(hG);

  // 6. Compare derived address with target address
  const derivedAddress = deriveEthereumAddress(pStealth);
  return derivedAddress.toLowerCase() === stealthAddress.toLowerCase();
}

/**
 * ERC-5564 Standard computeStealthKey implementation.
 *
 * Computes the recipient's stealth private key:
 * 1. Computes shared secret s = p_view * P_ephemeral
 * 2. Hashes shared secret s_h = keccak256(s_compressed)
 * 3. Computes p_stealth = (p_spend + (s_h mod n)) mod n
 * 4. Validates that p_stealth * G matches stealthAddress if provided.
 *
 * Supports both object params and positional args matching ERC-5564.
 */
export function computeStealthKey(
  arg1: ComputeStealthKeyParams | string,
  arg2?: string,
  arg3?: string,
  arg4?: string
): Hex {
  let stealthAddress: string | undefined;
  let ephemeralPublicKey: string;
  let viewingPrivateKey: string;
  let spendingPrivateKey: string;

  if (typeof arg1 === 'object') {
    stealthAddress = (arg1.stealthAddress || arg1.userStealthAddress || arg1.expectedStealthAddress) as string | undefined;
    ephemeralPublicKey = (arg1.ephemeralPublicKey || arg1.ephemeralPubKey) as string;
    viewingPrivateKey = (arg1.viewingPrivateKey || arg1.viewingKey) as string;
    spendingPrivateKey = (arg1.spendingPrivateKey || arg1.spendingKey) as string;
  } else {
    stealthAddress = arg1;
    ephemeralPublicKey = arg2!;
    viewingPrivateKey = arg3!;
    spendingPrivateKey = arg4!;
  }

  if (!ephemeralPublicKey || !viewingPrivateKey || !spendingPrivateKey) {
    throw new Error('computeStealthKey requires ephemeralPublicKey, viewingPrivateKey, and spendingPrivateKey');
  }

  const result = recoverStealthPrivateKey({
    spendingPrivateKey: spendingPrivateKey as Hex,
    viewingPrivateKey: viewingPrivateKey as Hex,
    ephemeralPublicKey: ephemeralPublicKey as Hex,
    expectedStealthAddress: stealthAddress as Hex | undefined
  });

  return result.stealthPrivateKey;
}
