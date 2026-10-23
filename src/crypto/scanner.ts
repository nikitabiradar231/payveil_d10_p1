import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { CURVE_ORDER, SCHEME_ID } from './constants.js';
import { assertScannerSafety, parseAndValidatePrivateKey } from './keys.js';
import type { AnnouncementData, Hex, ScanMatch, ScanParams } from './types.js';
import {
  bytesToBigInt,
  deriveEthereumAddress,
  hexToBytes,
  validateAndParsePoint
} from './utils.js';

export interface ScanDiagnostics {
  totalAnnouncements: number;
  schemeMismatches: number;
  invalidEphemeralKeys: number;
  viewTagChecks: number;
  viewTagSkips: number;
  viewTagMatches: number;
  addressDerivations: number;
  addressMatches: number;
}

export interface ScanResult {
  matches: ScanMatch[];
  diagnostics: ScanDiagnostics;
}

/**
 * Recipient-side scanner for detecting incoming ERC-5564 stealth payments.
 *
 * CRITICAL SECURITY INVARIANT:
 * This function accepts ONLY:
 * 1. viewingPrivateKey (scalar p_view)
 * 2. spendingPublicKey (curve point P_spend)
 * 3. announcements (public on-chain events)
 *
 * It NEVER accepts, requests, loads, derives, or possesses the spending private key.
 */
export function scanAnnouncements(
  params: ScanParams,
  options?: {
    onAddressDerivation?: (announcement: AnnouncementData) => void;
  }
): ScanResult {
  // Runtime guard against accidental spending key leakage into scanner
  assertScannerSafety(params as unknown as Record<string, unknown>);

  const { viewingPrivateKey, spendingPublicKey, announcements } = params;

  // Validate viewing private key
  const pViewScalar = parseAndValidatePrivateKey(viewingPrivateKey);

  // Validate spending public key
  const pSpend = validateAndParsePoint(spendingPublicKey);

  const matches: ScanMatch[] = [];
  const diagnostics: ScanDiagnostics = {
    totalAnnouncements: announcements.length,
    schemeMismatches: 0,
    invalidEphemeralKeys: 0,
    viewTagChecks: 0,
    viewTagSkips: 0,
    viewTagMatches: 0,
    addressDerivations: 0,
    addressMatches: 0
  };

  for (const ann of announcements) {
    // 1. Filter by scheme identifier
    if (ann.schemeId !== SCHEME_ID) {
      diagnostics.schemeMismatches++;
      continue;
    }

    // 2. Validate ephemeral public key
    let rPoint: typeof secp256k1.ProjectivePoint.prototype;
    try {
      rPoint = validateAndParsePoint(ann.ephemeralPubKey);
    } catch {
      diagnostics.invalidEphemeralKeys++;
      continue;
    }

    // 3. Extract announced view tag from metadata (first byte)
    const metadataBytes = hexToBytes(ann.metadata);
    if (metadataBytes.length === 0) {
      diagnostics.viewTagSkips++;
      continue;
    }
    const announcedViewTag = metadataBytes[0];

    // 4. Compute ECDH shared secret: S = p_view * R
    const sPoint = rPoint.multiply(pViewScalar);
    const sCompressed = sPoint.toRawBytes(true);

    // 5. Hash shared secret: s_h = keccak256(S)
    const sHash = keccak_256(sCompressed);

    // 6. View tag check (first byte of s_h)
    diagnostics.viewTagChecks++;
    const calculatedViewTag = sHash[0];

    // 7. VIEW-TAG-FIRST FILTERING:
    // If the view tag does not match, SKIP IMMEDIATELY!
    // No address derivation or point addition is performed.
    if (calculatedViewTag !== announcedViewTag) {
      diagnostics.viewTagSkips++;
      continue;
    }

    diagnostics.viewTagMatches++;

    // 8. View tag matched! Proceed with address derivation.
    diagnostics.addressDerivations++;
    options?.onAddressDerivation?.(ann);

    const hScalar = bytesToBigInt(sHash) % CURVE_ORDER;
    const hG = secp256k1.ProjectivePoint.BASE.multiply(hScalar);
    const pStealth = pSpend.add(hG);
    const derivedAddress = deriveEthereumAddress(pStealth);

    // 9. Compare derived stealth address with announced stealth address
    if (derivedAddress.toLowerCase() === ann.stealthAddress.toLowerCase()) {
      diagnostics.addressMatches++;
      const viewTagHex: Hex = `0x${calculatedViewTag.toString(16).padStart(2, '0')}`;

      matches.push({
        stealthAddress: derivedAddress,
        ephemeralPublicKey: ann.ephemeralPubKey,
        viewTag: viewTagHex,
        metadata: ann.metadata,
        transactionHash: ann.transactionHash,
        blockNumber: ann.blockNumber,
        timestamp: ann.timestamp,
        amount: ann.amount
      });
    }
  }

  return { matches, diagnostics };
}
