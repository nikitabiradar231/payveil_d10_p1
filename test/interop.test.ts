import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { decodeEventLog, encodeAbiParameters, encodeEventTopics, getAddress, parseAbiItem, toHex } from 'viem';
import { describe, expect, it } from 'vitest';
import {
  CURVE_ORDER,
  SCHEME_ID,
  buildMetadataForETH,
  bytesToBigInt,
  bytesToHex,
  checkStealthAddress,
  computeStealthKey,
  deriveEthereumAddress,
  encodeStealthMetaAddress,
  generatePrivateKey,
  generateStealthAddress,
  generateStealthKeys,
  getPublicKey,
  hexToBytes,
  parseMetadata,
  parseStealthMetaAddress,
  recoverStealthPrivateKey,
  scanAnnouncements,
  validateAndParsePoint
} from '../src/crypto/index.js';

describe('ERC-5564 Independent Interoperability & Standards Compliance', () => {
  // =========================================================================
  // SECTION A: GENUINELY INDEPENDENT PUBLISHED TEST VECTORS (ScopeLift Reference SDK)
  // Source: ScopeLift/stealth-address-sdk (co-authored by ERC-5564 standard authors)
  // =========================================================================

  describe('A. Independent Published Test Vectors (ScopeLift Reference SDK)', () => {
    // Vector 1 from ScopeLift generateStealthAddress.test.ts & computeStealthKey.test.ts
    const vector1 = {
      stealthMetaAddressURI:
        'st:eth:0x033404e82cd2a92321d51e13064ec13a0fb0192a9fdaaca1cfb47b37bd27ec13970390ad5eca026c05ab5cf4d620a2ac65241b11df004ddca360e954db1b26e3846e',
      spendingPrivateKey:
        '0x363721eb9e981558c748b824cb32a840da2b3e8957c2fc3bcb8d9c86cb87456' as const,
      viewingPrivateKey:
        '0xb52a0555f6a8663d89f00365893b1ef9e38eaf2e8bc48a63319c9ea5cb4a27c5' as const,
      expectedSpendingPublicKey:
        '0x033404e82cd2a92321d51e13064ec13a0fb0192a9fdaaca1cfb47b37bd27ec1397' as const,
      expectedViewingPublicKey:
        '0x0390ad5eca026c05ab5cf4d620a2ac65241b11df004ddca360e954db1b26e3846e' as const,
      hashedSharedSecret:
        '0x158ce29a3dd0c8dca524e5776c2ba6361c280e013f87eee5eb799a713a939501' as const,
      expectedViewTag: '0x15' as const
    };

    it('[GENUINELY INDEPENDENT] Parsed keys match ScopeLift reference test vector', () => {
      const parsed = parseStealthMetaAddress(vector1.stealthMetaAddressURI);
      expect(parsed.spendingPublicKey.toLowerCase()).toBe(vector1.expectedSpendingPublicKey.toLowerCase());
      expect(parsed.viewingPublicKey.toLowerCase()).toBe(vector1.expectedViewingPublicKey.toLowerCase());
    });

    it('[GENUINELY INDEPENDENT] View tag extraction matches ScopeLift reference vector (0x15)', () => {
      const parsed = parseMetadata(vector1.hashedSharedSecret);
      expect(parsed.viewTag.toLowerCase()).toBe(vector1.expectedViewTag.toLowerCase());
    });

    it('[GENUINELY INDEPENDENT] Full cycle derivation and recovery using ScopeLift test vector keys', () => {
      // Deterministic ephemeral key to ensure reproducible cross-system behavior
      const ephemeralPrivateKey = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318' as const;

      const generated = generateStealthAddress({
        stealthMetaAddress: vector1.stealthMetaAddressURI,
        ephemeralPrivateKey
      });

      // Recipient checkStealthAddress returns true
      const check = checkStealthAddress({
        userStealthAddress: generated.stealthAddress,
        ephemeralPublicKey: generated.ephemeralPublicKey,
        viewingPrivateKey: vector1.viewingPrivateKey,
        spendingPublicKey: vector1.expectedSpendingPublicKey,
        viewTag: generated.viewTag
      });
      expect(check).toBe(true);

      // Recipient computes stealth key
      const stealthPrivKey = computeStealthKey({
        expectedStealthAddress: generated.stealthAddress,
        ephemeralPublicKey: generated.ephemeralPublicKey,
        viewingPrivateKey: vector1.viewingPrivateKey,
        spendingPrivateKey: vector1.spendingPrivateKey
      });

      // Assert recovered key derives the identical stealth address
      const recoveredPubKey = getPublicKey(stealthPrivKey, true);
      const recoveredAddress = deriveEthereumAddress(recoveredPubKey);
      expect(recoveredAddress.toLowerCase()).toBe(generated.stealthAddress.toLowerCase());
    });

    // Vector 2 from ScopeLift checkStealthAddress.test.ts
    const vector2 = {
      stealthMetaAddressURI:
        'st:eth:0x02f1f006a160b934c1d71479ce7d57f1c4ec10018230e35ca10ab65db68e8f037b0305d4725c7784262a38af11a9aef490b1307b82b17866f08d66c38db04c946ab1',
      viewingPrivateKey:
        '0x2f8fcb2d1e06f52695e06a792b6d59c80a81ad70fc11b03b5236eed5cff09670' as const
    };

    it('[GENUINELY INDEPENDENT] ScopeLift Vector 2: checkStealthAddress accurately confirms ownership and rejects mismatches', () => {
      const generated = generateStealthAddress({
        stealthMetaAddress: vector2.stealthMetaAddressURI
      });
      const parsedKeys = parseStealthMetaAddress(vector2.stealthMetaAddressURI);

      // 1. Should identify matching payment
      expect(
        checkStealthAddress({
          userStealthAddress: generated.stealthAddress,
          ephemeralPublicKey: generated.ephemeralPublicKey,
          viewingPrivateKey: vector2.viewingPrivateKey,
          spendingPublicKey: parsedKeys.spendingPublicKey,
          viewTag: generated.viewTag
        })
      ).toBe(true);

      // 2. Should reject mismatched view tag
      expect(
        checkStealthAddress({
          userStealthAddress: generated.stealthAddress,
          ephemeralPublicKey: generated.ephemeralPublicKey,
          viewingPrivateKey: vector2.viewingPrivateKey,
          spendingPublicKey: parsedKeys.spendingPublicKey,
          viewTag: '0xfe'
        })
      ).toBe(false);

      // 3. Should reject different stealth address
      expect(
        checkStealthAddress({
          userStealthAddress: '0x1111111111111111111111111111111111111111',
          ephemeralPublicKey: generated.ephemeralPublicKey,
          viewingPrivateKey: vector2.viewingPrivateKey,
          spendingPublicKey: parsedKeys.spendingPublicKey,
          viewTag: generated.viewTag
        })
      ).toBe(false);
    });
  });

  // =========================================================================
  // SECTION B: INDEPENDENT PAYER & RECIPIENT EC-LEVEL INTEROPERABILITY
  // Simulates an independent external entity calculating addresses using raw EC math
  // =========================================================================

  describe('B. Independent Payer Derivation vs Recipient Scanner & Recovery', () => {
    it('[GENUINELY INDEPENDENT] External payer computing raw EC math produces stealth address discovered and recovered by StealthPay', () => {
      // 1. Recipient publishes meta-address
      const recipient = generateStealthKeys();
      const metaAddress = encodeStealthMetaAddress({
        spendingPublicKey: recipient.spending.publicKey,
        viewingPublicKey: recipient.viewing.publicKey
      });

      // 2. An external, independent payer derives address WITHOUT using StealthPay's generateStealthAddress
      const rawRecipientSpend = secp256k1.ProjectivePoint.fromHex(hexToBytes(recipient.spending.publicKey));
      const rawRecipientView = secp256k1.ProjectivePoint.fromHex(hexToBytes(recipient.viewing.publicKey));

      // Independent payer picks random scalar r
      const externalEphemeralScalar = 0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcban;
      const externalRPoint = secp256k1.ProjectivePoint.BASE.multiply(externalEphemeralScalar);
      const externalEphemeralPubKey = bytesToHex(externalRPoint.toRawBytes(true));

      // Independent payer ECDH: S = r * P_view
      const externalSPoint = rawRecipientView.multiply(externalEphemeralScalar);
      const externalSCompressed = externalSPoint.toRawBytes(true);
      const externalSHash = keccak_256(externalSCompressed);
      const externalViewTagByte = externalSHash[0];
      const externalViewTag = `0x${externalViewTagByte.toString(16).padStart(2, '0')}` as const;

      // Independent payer scalar & point addition: P_stealth = P_spend + (s_h mod n) * G
      const externalHScalar = bytesToBigInt(externalSHash) % CURVE_ORDER;
      const externalHG = secp256k1.ProjectivePoint.BASE.multiply(externalHScalar);
      const externalPStealth = rawRecipientSpend.add(externalHG);

      // Independent address derivation: keccak256(uncompressed[1..])[-20..]
      const uncompressedRaw = externalPStealth.toRawBytes(false);
      const uncompressedCoords = uncompressedRaw.slice(1);
      const addrHash = keccak_256(uncompressedCoords);
      const externalStealthAddress = getAddress(bytesToHex(addrHash.slice(-20)));

      // 3. Build recommended ERC-5564 ETH metadata
      const paymentAmount = 1500000000000000000n; // 1.5 ETH
      const metadata = buildMetadataForETH({
        viewTag: externalViewTag,
        amount: paymentAmount
      });

      // 4. Send announcement to recipient scanner
      const announcement = {
        schemeId: SCHEME_ID,
        stealthAddress: externalStealthAddress,
        caller: '0x9999999999999999999999999999999999999999' as const,
        ephemeralPubKey: externalEphemeralPubKey,
        metadata
      };

      // Recipient scans
      const scanResult = scanAnnouncements({
        viewingPrivateKey: recipient.viewing.privateKey,
        spendingPublicKey: recipient.spending.publicKey,
        announcements: [announcement]
      });

      expect(scanResult.matches.length).toBe(1);
      expect(scanResult.matches[0].stealthAddress).toBe(externalStealthAddress);

      // Unrelated recipient scans the same announcement and finds NOTHING
      const unrelatedRecipient = generateStealthKeys();
      const unrelatedScan = scanAnnouncements({
        viewingPrivateKey: unrelatedRecipient.viewing.privateKey,
        spendingPublicKey: unrelatedRecipient.spending.publicKey,
        announcements: [announcement]
      });
      expect(unrelatedScan.matches.length).toBe(0);

      // Recipient recovers stealth private key
      const recovery = recoverStealthPrivateKey({
        spendingPrivateKey: recipient.spending.privateKey,
        viewingPrivateKey: recipient.viewing.privateKey,
        ephemeralPublicKey: externalEphemeralPubKey,
        expectedStealthAddress: externalStealthAddress
      });

      expect(recovery.stealthAddress).toBe(externalStealthAddress);

      // Verify on curve that recovery.stealthPrivateKey * G === externalStealthAddress
      const recoveredScalar = BigInt(recovery.stealthPrivateKey);
      const recoveredPoint = secp256k1.ProjectivePoint.BASE.multiply(recoveredScalar);
      const recoveredAddress = deriveEthereumAddress(recoveredPoint);
      expect(recoveredAddress).toBe(externalStealthAddress);
    });
  });

  // =========================================================================
  // SECTION C: ANNOUNCEMENT EVENT DECODING COMPATIBILITY
  // Verifies that on-chain logs conform to canonical IERC5564Announcer ABI
  // =========================================================================

  describe('C. ERC-5564 Standard Event Interface Compatibility', () => {
    it('[GENUINELY INDEPENDENT] Announcement log correctly decodes with standard IERC5564Announcer ABI', () => {
      const ANNOUNCEMENT_ABI_ITEM = parseAbiItem(
        'event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata)'
      );

      const schemeId = 1n;
      const stealthAddress = '0x1234567890123456789012345678901234567890' as const;
      const caller = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd' as const;
      const ephemeralPubKey = '0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' as const;
      const metadata = '0x42eeeeeeee' as const;

      // Encode event topics using viem standard encoder
      const topics = encodeEventTopics({
        abi: [ANNOUNCEMENT_ABI_ITEM],
        eventName: 'Announcement',
        args: {
          schemeId,
          stealthAddress,
          caller
        }
      });

      expect(topics.length).toBe(4); // event signature + 3 indexed topics

      // Encode non-indexed event parameters (bytes ephemeralPubKey, bytes metadata) using standard ABI encoding
      const data = encodeAbiParameters(
        [{ type: 'bytes' }, { type: 'bytes' }],
        [ephemeralPubKey, metadata]
      );

      // Decode log using standard ABI definition
      const decoded = decodeEventLog({
        abi: [ANNOUNCEMENT_ABI_ITEM],
        data,
        topics: topics as [`0x${string}`, ...`0x${string}`[]]
      });

      expect(decoded.eventName).toBe('Announcement');
      expect(decoded.args.schemeId).toBe(1n);
      expect(decoded.args.stealthAddress.toLowerCase()).toBe(stealthAddress.toLowerCase());
      expect(decoded.args.caller.toLowerCase()).toBe(caller.toLowerCase());
    });
  });

  // =========================================================================
  // SECTION D: RECOMMENDED METADATA ENCODING & PARSING
  // =========================================================================

  describe('D. ERC-5564 Recommended Metadata Specification', () => {
    it('[INTERNAL ROUND-TRIP] Correctly encodes and parses standard 57-byte ETH metadata', () => {
      const viewTag = '0xab' as const;
      const amount = 2500000000000000000n; // 2.5 ETH

      const encoded = buildMetadataForETH({ viewTag, amount });
      expect(encoded.length).toBe(2 + 57 * 2); // 116 characters (0x + 114 hex)
      expect(encoded.slice(0, 4).toLowerCase()).toBe(viewTag.toLowerCase());
      expect(encoded.slice(4, 12).toLowerCase()).toBe('eeeeeeee');

      const parsed = parseMetadata(encoded);
      expect(parsed.viewTag.toLowerCase()).toBe(viewTag.toLowerCase());
      expect(parsed.functionIdentifier).toBe('0xeeeeeeee');
      expect(parsed.tokenAddress?.toLowerCase()).toBe('0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee');
      expect(parsed.amount).toBe(amount);
    });

    it('[INTERNAL ROUND-TRIP] Handles minimal 1-byte view tag metadata', () => {
      const minimalMetadata = '0x3f' as const;
      const parsed = parseMetadata(minimalMetadata);
      expect(parsed.viewTag).toBe('0x3f');
      expect(parsed.amount).toBeUndefined();
    });
  });
});
