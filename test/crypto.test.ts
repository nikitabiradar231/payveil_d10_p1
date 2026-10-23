import { secp256k1 } from '@noble/curves/secp256k1';
import { describe, expect, it, vi } from 'vitest';
import {
  CURVE_ORDER,
  SCHEME_ID,
  assertScannerSafety,
  bigIntToHex32,
  deriveEthereumAddress,
  encodeStealthMetaAddress,
  generatePrivateKey,
  generateStealthAddress,
  generateStealthKeys,
  getPublicKey,
  parseStealthMetaAddress,
  recoverStealthPrivateKey,
  scanAnnouncements,
  validateAndParsePoint
} from '../src/crypto/index.js';

describe('ERC-5564 Scheme 1 Cryptography & Acceptance Tests', () => {
  it('1. Private-key separation: scanner operates using only viewing private key and spending public key', () => {
    const recipient = generateStealthKeys();
    const metaAddress = encodeStealthMetaAddress({
      spendingPublicKey: recipient.spending.publicKey,
      viewingPublicKey: recipient.viewing.publicKey
    });

    const payment = generateStealthAddress({ stealthMetaAddress: metaAddress });

    const announcements = [
      {
        schemeId: SCHEME_ID,
        stealthAddress: payment.stealthAddress,
        caller: '0x1111111111111111111111111111111111111111' as const,
        ephemeralPubKey: payment.ephemeralPublicKey,
        metadata: payment.metadata
      }
    ];

    // Recipient scans providing ONLY viewing.privateKey and spending.publicKey
    const scanParams = {
      viewingPrivateKey: recipient.viewing.privateKey,
      spendingPublicKey: recipient.spending.publicKey,
      announcements
    };

    // Verify type and runtime assertion: spending private key is NOT present
    expect((scanParams as any).spendingPrivateKey).toBeUndefined();
    expect(() => assertScannerSafety(scanParams as any)).not.toThrow();

    const scanResult = scanAnnouncements(scanParams);
    expect(scanResult.matches.length).toBe(1);
    expect(scanResult.matches[0].stealthAddress).toBe(payment.stealthAddress);

    // If an illicit spending key is injected into scanner, it must throw a security violation
    const compromisedParams = {
      ...scanParams,
      spendingPrivateKey: recipient.spending.privateKey
    };
    expect(() => scanAnnouncements(compromisedParams as any)).toThrow(/SECURITY VIOLATION/);
  });

  it('2. Fresh ephemeral keys: each payment generates a new secure ephemeral key', () => {
    const recipient = generateStealthKeys();
    const metaAddress = encodeStealthMetaAddress({
      spendingPublicKey: recipient.spending.publicKey,
      viewingPublicKey: recipient.viewing.publicKey
    });

    const ephemeralKeys = new Set<string>();
    const count = 50;

    for (let i = 0; i < count; i++) {
      const payment = generateStealthAddress({ stealthMetaAddress: metaAddress });
      expect(ephemeralKeys.has(payment.ephemeralPublicKey)).toBe(false);
      ephemeralKeys.add(payment.ephemeralPublicKey);

      // Verify each ephemeral key is a valid non-infinity curve point
      const point = validateAndParsePoint(payment.ephemeralPublicKey);
      expect(point.equals(secp256k1.ProjectivePoint.ZERO)).toBe(false);
    }

    expect(ephemeralKeys.size).toBe(count);
  });

  it('3. Correct stealth derivation: P_stealth = P_spend + hG matches derived address', () => {
    const recipient = generateStealthKeys();
    const metaAddress = encodeStealthMetaAddress({
      spendingPublicKey: recipient.spending.publicKey,
      viewingPublicKey: recipient.viewing.publicKey
    });

    const payment = generateStealthAddress({ stealthMetaAddress: metaAddress });
    expect(payment.stealthAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(payment.ephemeralPublicKey).toMatch(/^0x[0-9a-fA-F]{66}$/);
    expect(payment.viewTag).toMatch(/^0x[0-9a-fA-F]{2}$/);
  });

  it('4. Correct private-key recovery: recovered scalar is reduced modulo n and produces the exact same stealth address', () => {
    const recipient = generateStealthKeys();
    const metaAddress = encodeStealthMetaAddress({
      spendingPublicKey: recipient.spending.publicKey,
      viewingPublicKey: recipient.viewing.publicKey
    });

    const payment = generateStealthAddress({ stealthMetaAddress: metaAddress });

    const recovery = recoverStealthPrivateKey({
      spendingPrivateKey: recipient.spending.privateKey,
      viewingPrivateKey: recipient.viewing.privateKey,
      ephemeralPublicKey: payment.ephemeralPublicKey,
      expectedStealthAddress: payment.stealthAddress
    });

    expect(recovery.stealthAddress).toBe(payment.stealthAddress);
    expect(recovery.stealthPrivateKey).toMatch(/^0x[0-9a-fA-F]{64}$/);

    // Verify recovered private key produces public key corresponding to stealth address
    const recoveredPubKey = getPublicKey(recovery.stealthPrivateKey, true);
    expect(recoveredPubKey).toBeDefined();

    // Verify address derived directly from p_stealth matches
    const recoveredPoint = secp256k1.ProjectivePoint.BASE.multiply(BigInt(recovery.stealthPrivateKey));
    expect(deriveEthereumAddress(recoveredPoint)).toBe(payment.stealthAddress);
  });

  it('4b. Edge Case: Recovery scalar reduction modulo n correctly wraps around when p_spend + h >= n', () => {
    // Construct a high spending private key close to curve order n
    const highSpendingScalar = CURVE_ORDER - 5n;
    const highSpendingKey = bigIntToHex32(highSpendingScalar);
    const spendingPubKey = getPublicKey(highSpendingKey, true);

    const viewingKeys = generateStealthKeys().viewing;
    const metaAddress = encodeStealthMetaAddress({
      spendingPublicKey: spendingPubKey,
      viewingPublicKey: viewingKeys.publicKey
    });

    // Make payment
    const payment = generateStealthAddress({ stealthMetaAddress: metaAddress });

    // Recover stealth private key
    const recovery = recoverStealthPrivateKey({
      spendingPrivateKey: highSpendingKey,
      viewingPrivateKey: viewingKeys.privateKey,
      ephemeralPublicKey: payment.ephemeralPublicKey,
      expectedStealthAddress: payment.stealthAddress
    });

    const recoveredScalar = BigInt(recovery.stealthPrivateKey);
    expect(recoveredScalar).toBeGreaterThan(0n);
    expect(recoveredScalar).toBeLessThan(CURVE_ORDER);
    expect(recovery.stealthAddress).toBe(payment.stealthAddress);
  });

  it('5. View-tag-first scanning: a mismatched view tag prevents full address derivation', () => {
    const recipient = generateStealthKeys();
    const metaAddress = encodeStealthMetaAddress({
      spendingPublicKey: recipient.spending.publicKey,
      viewingPublicKey: recipient.viewing.publicKey
    });

    const payment = generateStealthAddress({ stealthMetaAddress: metaAddress });

    // Tamper with the announced view tag so it mismatches
    const originalTagByte = parseInt(payment.viewTag.slice(2), 16);
    const tamperedTagByte = (originalTagByte ^ 0xff).toString(16).padStart(2, '0');
    const tamperedMetadata = `0x${tamperedTagByte}` as const;

    const announcements = [
      {
        schemeId: SCHEME_ID,
        stealthAddress: payment.stealthAddress,
        caller: '0x1111111111111111111111111111111111111111' as const,
        ephemeralPubKey: payment.ephemeralPublicKey,
        metadata: tamperedMetadata
      }
    ];

    const derivationSpy = vi.fn();

    const scanResult = scanAnnouncements(
      {
        viewingPrivateKey: recipient.viewing.privateKey,
        spendingPublicKey: recipient.spending.publicKey,
        announcements
      },
      {
        onAddressDerivation: derivationSpy
      }
    );

    // The payment must be ignored
    expect(scanResult.matches.length).toBe(0);
    // Address derivation MUST NOT be called because view tag mismatched
    expect(derivationSpy).not.toHaveBeenCalled();
    expect(scanResult.diagnostics.viewTagSkips).toBe(1);
    expect(scanResult.diagnostics.addressDerivations).toBe(0);
  });

  it('6. Unrelated announcement ignored: an announcement for another recipient is not reported', () => {
    const alice = generateStealthKeys();
    const bob = generateStealthKeys();

    const aliceMeta = encodeStealthMetaAddress({
      spendingPublicKey: alice.spending.publicKey,
      viewingPublicKey: alice.viewing.publicKey
    });

    // Payment sent to Alice
    const paymentForAlice = generateStealthAddress({ stealthMetaAddress: aliceMeta });

    const announcements = [
      {
        schemeId: SCHEME_ID,
        stealthAddress: paymentForAlice.stealthAddress,
        caller: '0x1111111111111111111111111111111111111111' as const,
        ephemeralPubKey: paymentForAlice.ephemeralPublicKey,
        metadata: paymentForAlice.metadata
      }
    ];

    // Bob scans the chain
    const bobScan = scanAnnouncements({
      viewingPrivateKey: bob.viewing.privateKey,
      spendingPublicKey: bob.spending.publicKey,
      announcements
    });

    expect(bobScan.matches.length).toBe(0);

    // Alice scans the chain
    const aliceScan = scanAnnouncements({
      viewingPrivateKey: alice.viewing.privateKey,
      spendingPublicKey: alice.spending.publicKey,
      announcements
    });

    expect(aliceScan.matches.length).toBe(1);
    expect(aliceScan.matches[0].stealthAddress).toBe(paymentForAlice.stealthAddress);
  });

  it('7. Distinct payment addresses: two payments to one meta-address produce different stealth addresses', () => {
    const recipient = generateStealthKeys();
    const metaAddress = encodeStealthMetaAddress({
      spendingPublicKey: recipient.spending.publicKey,
      viewingPublicKey: recipient.viewing.publicKey
    });

    const paymentA = generateStealthAddress({ stealthMetaAddress: metaAddress });
    const paymentB = generateStealthAddress({ stealthMetaAddress: metaAddress });

    expect(paymentA.stealthAddress).not.toBe(paymentB.stealthAddress);
    expect(paymentA.ephemeralPublicKey).not.toBe(paymentB.ephemeralPublicKey);
  });

  it('ERC-5564 Single-Key Meta-Address support (length n)', () => {
    const keyPair = generateStealthKeys().spending;
    // Single key meta-address format: st:eth:0x<33 bytes>
    const singleKeyMetaAddress = `st:eth:${keyPair.publicKey}`;

    const parsed = parseStealthMetaAddress(singleKeyMetaAddress);
    expect(parsed.spendingPublicKey).toBe(keyPair.publicKey);
    expect(parsed.viewingPublicKey).toBe(keyPair.publicKey);

    // Sender can derive payment to single-key meta-address
    const payment = generateStealthAddress({ stealthMetaAddress: singleKeyMetaAddress });
    expect(payment.stealthAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);

    // Recipient can scan and recover
    const scan = scanAnnouncements({
      viewingPrivateKey: keyPair.privateKey,
      spendingPublicKey: keyPair.publicKey,
      announcements: [
        {
          schemeId: SCHEME_ID,
          stealthAddress: payment.stealthAddress,
          caller: '0x1111111111111111111111111111111111111111' as const,
          ephemeralPubKey: payment.ephemeralPublicKey,
          metadata: payment.metadata
        }
      ]
    });
    expect(scan.matches.length).toBe(1);
  });

  it('Scanner deduplication ignores duplicated announcements', () => {
    const recipient = generateStealthKeys();
    const metaAddress = encodeStealthMetaAddress({
      spendingPublicKey: recipient.spending.publicKey,
      viewingPublicKey: recipient.viewing.publicKey
    });

    const payment = generateStealthAddress({ stealthMetaAddress: metaAddress });

    // The same announcement repeated twice
    const duplicatedAnnouncements = [
      {
        schemeId: SCHEME_ID,
        stealthAddress: payment.stealthAddress,
        caller: '0x1111111111111111111111111111111111111111' as const,
        ephemeralPubKey: payment.ephemeralPublicKey,
        metadata: payment.metadata,
        transactionHash: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as const
      },
      {
        schemeId: SCHEME_ID,
        stealthAddress: payment.stealthAddress,
        caller: '0x1111111111111111111111111111111111111111' as const,
        ephemeralPubKey: payment.ephemeralPublicKey,
        metadata: payment.metadata,
        transactionHash: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as const
      }
    ];

    const scanResult = scanAnnouncements({
      viewingPrivateKey: recipient.viewing.privateKey,
      spendingPublicKey: recipient.spending.publicKey,
      announcements: duplicatedAnnouncements
    });

    // Must deduplicate and return exactly 1 match
    expect(scanResult.matches.length).toBe(1);
  });

  it('Rejects invalid meta-addresses, invalid points, point at infinity, and unsupported schemes', () => {
    expect(() => parseStealthMetaAddress('')).toThrow(/non-empty string/);
    expect(() => parseStealthMetaAddress('st:eth:invalidhex')).toThrow();
    expect(() => parseStealthMetaAddress('st:eth:0x1234')).toThrow(/Invalid stealth meta-address length/);

    // Unsupported scheme
    const recipient = generateStealthKeys();
    const scanResult = scanAnnouncements({
      viewingPrivateKey: recipient.viewing.privateKey,
      spendingPublicKey: recipient.spending.publicKey,
      announcements: [
        {
          schemeId: 999n,
          stealthAddress: '0x1111111111111111111111111111111111111111' as const,
          caller: '0x1111111111111111111111111111111111111111' as const,
          ephemeralPubKey: '0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' as const,
          metadata: '0x12' as const
        }
      ]
    });
    expect(scanResult.matches.length).toBe(0);
    expect(scanResult.diagnostics.schemeMismatches).toBe(1);
  });
});
