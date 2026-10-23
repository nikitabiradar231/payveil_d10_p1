import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { CURVE_ORDER } from './constants.js';
import { generatePrivateKey, parseAndValidatePrivateKey } from './keys.js';
import { parseStealthMetaAddress } from './metaAddress.js';
import type { GenerateStealthAddressParams, GenerateStealthAddressResult, Hex } from './types.js';
import {
  bytesToBigInt,
  bytesToHex,
  deriveEthereumAddress,
  validateAndParsePoint
} from './utils.js';

/**
 * Payer-side stealth address derivation according to ERC-5564 Scheme 1 (secp256k1).
 *
 * Steps:
 * 1. Parse recipient's stealth meta-address to extract P_spend and P_view.
 * 2. Generate a fresh, cryptographically secure ephemeral private scalar r.
 * 3. Compute ephemeral public key R = r * G.
 * 4. Compute ECDH shared secret point S = r * P_view.
 * 5. Hash the shared secret s_h = keccak256(S_compressed).
 * 6. Derive scalar h = s_h mod n.
 * 7. Extract view tag = first byte of s_h.
 * 8. Derive stealth public key P_stealth = P_spend + h * G.
 * 9. Derive Ethereum stealth address from P_stealth.
 */
export function generateStealthAddress({
  stealthMetaAddress,
  ephemeralPrivateKey
}: GenerateStealthAddressParams): GenerateStealthAddressResult {
  // 1. Parse recipient meta-address
  const { spendingPublicKey, viewingPublicKey } = parseStealthMetaAddress(stealthMetaAddress);
  const pSpend = validateAndParsePoint(spendingPublicKey);
  const pView = validateAndParsePoint(viewingPublicKey);

  // 2. Generate or validate ephemeral private key
  let rScalar: bigint;
  let ephemeralKeyHex: Hex;

  if (ephemeralPrivateKey) {
    rScalar = parseAndValidatePrivateKey(ephemeralPrivateKey);
    ephemeralKeyHex = ephemeralPrivateKey;
  } else {
    ephemeralKeyHex = generatePrivateKey();
    rScalar = parseAndValidatePrivateKey(ephemeralKeyHex);
  }

  // 3. Ephemeral public key R = r * G (compressed 33 bytes)
  const rPoint = secp256k1.ProjectivePoint.BASE.multiply(rScalar);
  const ephemeralPublicKey = bytesToHex(rPoint.toRawBytes(true));

  // 4. ECDH shared secret S = r * P_view
  const sPoint = pView.multiply(rScalar);
  const sCompressed = sPoint.toRawBytes(true);

  // 5. Hash shared secret s_h = keccak256(S)
  const sHash = keccak_256(sCompressed);

  // 6. Scalar h = s_h mod n
  const hScalar = bytesToBigInt(sHash) % CURVE_ORDER;
  if (hScalar === 0n) {
    // Statistically impossible (2^-256), but required for cryptographic completeness
    throw new Error('Derived scalar h is zero; ephemeral key must be regenerated');
  }

  // 7. View tag = first byte of keccak256(S)
  const viewTagByte = sHash[0];
  const viewTag: Hex = `0x${viewTagByte.toString(16).padStart(2, '0')}`;

  // 8. Stealth public key P_stealth = P_spend + h * G
  const hG = secp256k1.ProjectivePoint.BASE.multiply(hScalar);
  const pStealth = pSpend.add(hG);

  // 9. Derive Ethereum address
  const stealthAddress = deriveEthereumAddress(pStealth);

  // Metadata: first byte must be view tag (per ERC-5564)
  const metadata: Hex = viewTag;

  return {
    stealthAddress,
    ephemeralPublicKey,
    viewTag,
    metadata
  };
}
