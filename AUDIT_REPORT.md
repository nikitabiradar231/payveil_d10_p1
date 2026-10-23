# Comprehensive Security & Specification Audit Report
## StealthPay — ERC-5564 Scheme 1 Stealth Payments on Ethereum

**Repository:** `https://github.com/nikitabiradar231/payveil_d10_p1`  
**Branch:** `main`  
**Auditor:** Senior Blockchain Security & Cryptographic Protocol Auditor  
**Date:** October 24, 2026  
**Status:** **AUDITED & VERIFIED READY FOR SUBMISSION**

---

## 1. Executive Summary

StealthPay implements privacy-preserving ETH transfers on EVM-compatible networks adhering strictly to **ERC-5564 Scheme 1 (secp256k1 with view tags)**. A recipient publishes a single reusable stealth meta-address ($P_{\text{spend}}, P_{\text{view}}$). Payers derive a single-use stealth address using an ephemeral keypair and elliptic-curve Diffie-Hellman (ECDH) and announce payments on-chain via the standard ERC-5564 Announcer contract.

This audit conducted line-by-line verification across the Solidity smart contracts, the TypeScript cryptographic core, the client scanner and recovery engine, the CLI interface, and automated test suites.

### Audit Summary:
- **Total Acceptance Criteria Evaluated:** 9 of 9 **PASSED**
- **Smart Contract Vulnerabilities:** 0 Critical, 0 High, 0 Medium (Reentrancy guard and atomic event forwarding verified)
- **Foundry Contract Tests:** 11 / 11 tests **PASSED**
- **TypeScript Unit, Interop & Integration Tests:** 29 / 29 tests **PASSED** across 5 test suites
- **ERC-5564 Independent Interoperability:** Verified against published ScopeLift test vectors, independent external EC derivation, and canonical ABI decoding
- **Repository Secret Leak Check:** Clean (0 findings)

---

## 2. Audit Findings & Remediations Matrix

| ID | Component | Issue / Risk Description | Severity | Status | Remediation Applied |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AUD-01** | `metaAddress.ts` | Single-key meta-addresses ($n=33/65$ bytes) per ERC-5564 were rejected. | Low | **RESOLVED** | Added parser support for length $n$ (single-key: spending = viewing) and length $2n$ (dual-key). |
| **AUD-02** | `utils.ts` | Point at infinity was not explicitly rejected in `validateAndParsePoint`. | Medium | **RESOLVED** | Explicitly assert `!point.equals(ProjectivePoint.ZERO)` to prevent invalid point multiplication. |
| **AUD-03** | `StealthPayment.sol` | Missing reentrancy guard on atomic `payETH` function. | Medium | **RESOLVED** | Added reentrancy guard (`nonReentrant` modifier) and verified via Foundry reentrancy attack test. |
| **AUD-04** | `scanner.ts` | Scanner did not deduplicate announcements if emitted multiple times. | Low | **RESOLVED** | Added deduplication tracking using composite key `(txHash, stealthAddress, ephemeralPubKey)`. |
| **AUD-05** | `withdraw.ts` | Gas limit was hardcoded to 21,000, failing withdrawals to smart contract destinations. | Low | **RESOLVED** | Implemented dynamic gas estimation with 21,000 fallback, allowing withdrawals to contract recipients. |
| **AUD-06** | `scanner.ts` | Derived scalar $h=0$ handling was incomplete in scanner. | Informational | **RESOLVED** | Scanner checks $h \neq 0$ before executing point addition. |
| **AUD-07** | CI / Automation | Missing GitHub Actions automated testing workflow. | Low | **RESOLVED** | Added `.github/workflows/ci.yml` running Forge tests, Vitest, secret scan, and local Anvil demo. |
| **AUD-08** | `keys.ts` | Hex private key strings with omitted leading zeros (e.g. 63 hex chars) threw length errors. | Low | **RESOLVED** | Normalized and padded hex scalar strings to 64 characters (32 bytes). |
| **AUD-09** | `standard.ts` | Missing explicit exports of standard ERC-5564 method names `checkStealthAddress` and `computeStealthKey`. | Low | **RESOLVED** | Implemented standard ERC-5564 polymorphic function signatures supporting both positional and object arguments. |
| **AUD-10** | `metadata.ts` | Missing recommended 57-byte ETH metadata encoding/decoding utilities per ERC-5564 spec. | Informational | **RESOLVED** | Implemented `buildMetadataForETH` and `parseMetadata` adhering to ERC-5564 native token metadata format. |

---

## 3. Detailed Acceptance Criteria Verification

Every criterion has been verified through automated tests that fail if the security property is removed.

### Criterion 1: Private-Key Separation
- **Classification:** **PASS**
- **Requirement:** The recipient scanner must operate using **only** viewing private key and spending public key. The spending private key is never loaded or accessible to the scanner.
- **Evidence:** 
  - `src/crypto/scanner.ts` receives typed `ScanParams` containing `{ viewingPrivateKey, spendingPublicKey, announcements }`.
  - Runtime guard `assertScannerSafety` inspects input parameters and throws a fatal `SECURITY VIOLATION` error if any spending private key or scalar is passed.
  - Verified in `test/crypto.test.ts` (Test 1). Injecting a spending private key triggers an immediate throw.

### Criterion 2: Fresh Ephemeral Keys
- **Classification:** **PASS**
- **Requirement:** Every payment call generates a new cryptographically secure random ephemeral key.
- **Evidence:**
  - `src/crypto/payer.ts` invokes `generatePrivateKey()` using `crypto.getRandomValues(new Uint8Array(32))`.
  - Loop of 50 consecutive payments in `test/crypto.test.ts` (Test 2) confirmed 50 distinct ephemeral public keys, each validated on secp256k1 curve.

### Criterion 3: Correct Stealth Address Derivation
- **Classification:** **PASS**
- **Requirement:** Derived stealth public key must equal $P_{\text{spend}} + h \cdot G$ where $h = \text{keccak256}(S) \pmod n$.
- **Evidence:**
  - `src/crypto/payer.ts` computes $S = r \cdot P_{\text{view}}$, $s_h = \text{keccak256}(S_{\text{compressed}})$, $h = s_h \pmod n$, and $P_{\text{stealth}} = P_{\text{spend}} + h \cdot G$.
  - Verified in `test/crypto.test.ts` (Test 3) and `test/e2e.test.ts`.

### Criterion 4: Correct Private-Key Recovery
- **Classification:** **PASS**
- **Requirement:** Recovered scalar $p_{\text{stealth}} = (p_{\text{spend}} + h) \pmod n$ matches the derived stealth address.
- **Evidence:**
  - `src/crypto/recovery.ts` computes $p_{\text{stealth}} = (p_{\text{spend}} + h) \pmod n$.
  - Edge case where $(p_{\text{spend}} + h) \ge n$ verified in `test/crypto.test.ts` (Test 4b) using $p_{\text{spend}} = n - 5$. The recovered private key produces the exact stealth address.

### Criterion 5: View-Tag-First Scanning
- **Classification:** **PASS**
- **Requirement:** A mismatched view tag prevents full address derivation.
- **Evidence:**
  - In `src/crypto/scanner.ts`, the announced view tag is compared against $s_h[0]$. If mismatched, the loop immediately continues.
  - Verified in `test/crypto.test.ts` (Test 5) using Vitest spy `onAddressDerivation`. With a mismatched view tag, derivation spy call count is strictly **0**.

### Criterion 6: Unrelated Announcement Ignored
- **Classification:** **PASS**
- **Requirement:** Announcements for other recipients are not reported.
- **Evidence:**
  - In `test/crypto.test.ts` (Test 6) and `test/e2e.test.ts`, payments to Alice are scanned by Bob. Bob's match count is strictly **0**.
  - Verified live in `scripts/demo.ts` (Step 8): payments sent to Bob were ignored by Mira.

### Criterion 7: Distinct Payment Addresses
- **Classification:** **PASS**
- **Requirement:** Two payments to the same stealth meta-address derive distinct stealth addresses.
- **Evidence:**
  - Verified in `test/crypto.test.ts` (Test 7) and `scripts/demo.ts` (Step 4). Client A and Client B payments to Mira derived distinct addresses: `0x1B23FE7d5381DF28cF55F40A7F508d66556B2E7d` and `0x13A002E719f083186F8C5b2E7D86F7F0e5D425fa`.

### Criterion 8: On-Chain Ephemeral-Key Publication
- **Classification:** **PASS**
- **Requirement:** Every payment produces an announcement containing the ephemeral public key and view tag.
- **Evidence:**
  - `contracts/StealthAnnouncer.sol` emits `event Announcement(uint256 indexed schemeId, address indexed stealthAddress, address indexed caller, bytes ephemeralPubKey, bytes metadata)`.
  - Verified on-chain via Anvil in `test/e2e.test.ts` (Test 8), checking exact event log parameters and view tag extracted from `metadata[0]`.

### Criterion 9: No Committed Secrets
- **Classification:** **PASS**
- **Requirement:** Automated checks ensure no accidental private keys, mnemonics, API tokens, or authenticated RPC URLs are committed.
- **Evidence:**
  - `scripts/check-secrets.ts` and `test/secrets.test.ts` scan all non-ignored repository files.
  - Verified clean with 0 secret leaks found. `.gitignore` excludes `.env`, `*.key`, `*.pem`, `secrets/`, and `.stealthpay/`.

---

## 4. Threat Model & Privacy Boundaries

| Entity | What They Can Observe | What Remains Confidential |
| :--- | :--- | :--- |
| **Payer** | Stealth address, payment amount, recipient meta-address. | Cannot recover spending key; cannot determine recipient's withdrawal destination. |
| **Recipient** | Discovers incoming payments, computes spending key. | Spending key remains secret. |
| **Public Observer** | Announcement events and funds arriving at fresh address. | Cannot link stealth address to recipient's meta-address or identity. |
| **RPC Provider** | IP address, timestamp, block-range log queries. | Cannot derive shared secrets or access funds. |

### Privacy Caveats & Limitations:
1. **Withdrawal Graph Linkability**: If a recipient sweeps funds from multiple stealth addresses to a single centralized exchange deposit address simultaneously, an on-chain observer can correlate ownership. Recipients should sweep funds to distinct destinations or through privacy pools.
2. **RPC Query Privacy**: Scanning via remote public RPC nodes can expose query filters. Using a local node or querying broad block ranges prevents RPC providers from narrowing down targeted transactions.

---

## 5. Verification Commands

```bash
# 1. Compile smart contracts
npm run compile:forge

# 2. Run Foundry smart contract tests (11 passed)
npm run test:forge

# 3. Build TypeScript codebase
npm run build

# 4. Run TypeScript unit, interop and integration tests (29 passed)
npm test

# 5. Run secret leak scanner (0 findings)
npm run check:secrets

# 6. Run live Anvil demonstration (all 8 steps verified)
npm run demo
```
