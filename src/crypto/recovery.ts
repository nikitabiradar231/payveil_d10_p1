import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { CURVE_ORDER } from './constants.js';
import { parseAndValidatePrivateKey } from './keys.js';
import type { Hex, RecoverStealthKeyParams } from './types.js';
import {
  bigIntToHex32,
  bytesToBigInt,
  deriveEthereumAddress,
  validateAndParsePoint,
  validateScalar
} from './utils.js';

export interface RecoveredStealthKeyResult {
  readonly stealthPrivateKey: Hex;
  readonly stealthAddress: Hex;
}

/**
 * Recovers the stealth private key using the spending private key,
 * viewing private key, and the announcement's ephemeral public key.
 *
 * Formula:
 * 1. S = p_view * R
 * 2. s_h = keccak256(S_compressed)
 * 3. h = s_h mod n
 * 4. p_stealth = (p_spend + h) mod n
 *
 * Verification:
 * Validates that p_stealth * G matches the derived stealth address.
 */
export function recoverStealthPrivateKey({
  spendingPrivateKey,
  viewingPrivateKey,
  ephemeralPublicKey,
  expectedStealthAddress
}: RecoverStealthKeyParams): RecoveredStealthKeyResult {
  // 1. Validate inputs
  const pSpendScalar = parseAndValidatePrivateKey(spendingPrivateKey);
  const pViewScalar = parseAndValidatePrivateKey(viewingPrivateKey);
  const rPoint = validateAndParsePoint(ephemeralPublicKey);

  // 2. Compute ECDH shared secret: S = p_view * R
  const sPoint = rPoint.multiply(pViewScalar);
  const sCompressed = sPoint.toRawBytes(true);

  // 3. Hash shared secret: s_h = keccak256(S)
  const sHash = keccak_256(sCompressed);

  // 4. Scalar h = s_h mod n
  const hScalar = bytesToBigInt(sHash) % CURVE_ORDER;

  // 5. Recover stealth private key: p_stealth = (p_spend + h) mod n
  const pStealthScalar = (pSpendScalar + hScalar) % CURVE_ORDER;
  validateScalar(pStealthScalar);

  // 6. Verify recovered key
  const recoveredPoint = secp256k1.ProjectivePoint.BASE.multiply(pStealthScalar);
  const stealthAddress = deriveEthereumAddress(recoveredPoint);

  if (
    expectedStealthAddress &&
    stealthAddress.toLowerCase() !== expectedStealthAddress.toLowerCase()
  ) {
    throw new Error(
      `Recovered stealth key produces address ${stealthAddress}, which does not match expected address ${expectedStealthAddress}`
    );
  }

  const stealthPrivateKey = bigIntToHex32(pStealthScalar);

  return {
    stealthPrivateKey,
    stealthAddress
  };
}
