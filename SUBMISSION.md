# StealthPay — Buildathon Submission

## Project Overview

- **Project Name:** StealthPay
- **One-Line Pitch:** A provably compliant, standards-native ERC-5564 Scheme 1 stealth payment engine on Ethereum enabling non-interactive, single-use address derivation and view-tag-accelerated payment scanning.
- **Track / Challenge:** “Pay Me Somewhere New Every Time”
- **Repository:** [https://github.com/nikitabiradar231/payveil_d10_p1](https://github.com/nikitabiradar231/payveil_d10_p1)
- **Branch:** `main`
- **Specification:** [ERC-5564: Stealth Addresses (Scheme 1: secp256k1 with view tags)](https://eips.ethereum.org/EIPS/eip-5564)

---

## 1. The Real-World Problem

On public blockchains such as Ethereum, transaction transparency creates a fundamental conflict with user privacy:
- **Permanent Address Linkability:** When a recipient (e.g. an e-commerce merchant, a political dissident, a non-profit organization, or a payroll recipient) publishes a static public address, every incoming payment is permanently recorded on the public transaction ledger.
- **Observer Surveillance:** Anyone—blockchain analysis firms, competitors, malicious actors, or curious observers—can inspect the recipient's entire transaction history, monitor real-time revenue streams, calculate exact balances, and identify payer identities.
- **Operational Friction of Manual Rotation:** Asking a recipient to generate and send a new address for every payment requires out-of-band communication, breaks asynchronous invoicing, creates severe UX hurdles, and fails if the recipient is offline.

---

## 2. How Stealth Payments Solve the Problem

ERC-5564 stealth payments introduce **non-interactive, reusable meta-addresses** with **view-tag-filtered discovery**:
1. **One Static Meta-Address:** The recipient publishes a single reusable stealth meta-address consisting of two public keys:
   $$P_{\text{spend}} = p_{\text{spend}} \cdot G, \quad P_{\text{view}} = p_{\text{view}} \cdot G$$
   Formatted as standard URI: `st:eth:0x<P_spend_33B><P_view_33B>`.
2. **Asynchronous One-Time Address Derivation:** Anyone can pay the recipient without contacting them. The payer chooses a fresh CSPRNG ephemeral scalar $r$, computes an ECDH shared secret $S = r \cdot P_{\text{view}}$, and derives a fresh one-time stealth address:
   $$P_{\text{stealth}} = P_{\text{spend}} + (\text{keccak256}(S_{\text{compressed}}) \pmod n) \cdot G$$
   $$\text{Address} = \text{last20}(\text{keccak256}(\text{uncompressed } P_{\text{stealth}} \setminus \{0\text{x}04\}))$$
3. **Unlinkable On-Chain Activity:** Public observers and block explorers see funds sent to a brand-new address that has never existed before and shares no mathematical connection to the recipient's identity or meta-address.
4. **Fast View-Tag Discovery (~99.6% Speedup):** Payers publish a 1-byte view tag ($v = s_h[0]$) in the announcement metadata. The recipient's scanner compares this byte before performing heavy elliptic curve point additions, skipping ~255 out of 256 non-matching announcements with negligible CPU cost.
5. **Sole Recipient Control:** Only the recipient who holds $p_{\text{spend}}$ and $p_{\text{view}}$ can compute the stealth private key:
   $$p_{\text{stealth}} = (p_{\text{spend}} + (\text{keccak256}(S_{\text{compressed}}) \pmod n)) \pmod n$$
   and authorize withdrawals from the stealth address.

---

## 3. Architecture & Technology Stack

```mermaid
graph TD
    subgraph Client-Side Cryptography [TypeScript Cryptographic Core]
        KM[Key Manager: Strict Spending/Viewing Separation]
        PD[Payer Derivation: CSPRNG r, ECDH, Keccak-256]
        VT[View Tag Generator: 1-byte s_h[0]]
        SC[Scanner Engine: View-Tag-First Filter]
        RC[Recovery Engine: Modulo n Scalar Addition]
    end

    subgraph Smart Contracts [Foundry / Solidity 0.8.20]
        SA[StealthAnnouncer.sol: ERC-5564 Canonical Singleton]
        SP[StealthPayment.sol: Atomic Payment Router + Reentrancy Guard]
    end

    subgraph Client Application [User Tools]
        CLI[StealthPay CLI: keys, meta-address, pay, scan, withdraw]
        DEMO[Interactive End-to-End Anvil Demo]
    end

    PD -->|Announce| SA
    PD -->|Pay ETH & Announce| SP
    SP -->|Forward ETH| StealthAddr[One-Time Stealth Address]
    SP -->|Emit Announcement| SA
    SA -->|Read Logs| SC
    SC -->|Identify Matches| RC
    RC -->|Recover Key & Sweep| StealthAddr
```

### Core Technologies
- **Smart Contracts:** Solidity `^0.8.20`, compiled and rigorously tested with Foundry `forge` (11 tests).
- **Elliptic-Curve Arithmetic:** `@noble/curves/secp256k1` (audited, zero-dependency constant-time curve primitives).
- **Hashing & Encoding:** `@noble/hashes/sha3` (Keccak-256), `viem` (EIP-55 checksums, ABI encoding, RPC client).
- **Testing & Tooling:** Foundry (`forge`, `anvil`), Vitest (29 unit & integration tests), TypeScript `5.x`, Commander.js CLI.

---

## 4. Key Differentiators & Utility

1. **Strict Cryptographic Specification Adherence:**
   - Adheres byte-for-byte to ERC-5564 Scheme 1, matching the canonical reference implementation from ScopeLift.
   - Verified against published test vectors and independent external EC math derivation.
2. **Defense-in-Depth Key Separation:**
   - The scanner module is cryptographically and architecturally prevented from ever receiving or accepting the spending private key. Passing a spending private key triggers a fatal `SECURITY VIOLATION` error.
3. **Atomic Payment Router (`StealthPayment.sol`):**
   - Combines native ETH forwarding and ERC-5564 announcement emission into a single transaction with a non-reentrant mutex. Prevents partial states where funds are transferred but announcements fail to emit.
4. **Dynamic Sweep Gas Calculation:**
   - Withdrawal engine automatically estimates recipient contract gas requirements or falls back to standard 21,000 gas for EOAs, preventing failed sweeps or stranded funds.
5. **Production-Grade Developer Experience:**
   - Full CLI (`stealthpay keys create`, `meta-address`, `pay`, `scan`, `withdraw`) and programmatic SDK exports (`generateStealthAddress`, `checkStealthAddress`, `computeStealthKey`, `buildMetadataForETH`, `parseMetadata`).

---

## 5. Concise Demo Walkthrough

The repository includes a self-contained, reproducible 8-step interactive demonstration running on a local Anvil chain (`npm run demo`):

1. **Step 1 — Key Generation:** Recipient Mira generates independent spending and viewing keypairs and outputs her reusable meta-address `st:eth:0x...`.
2. **Step 2 — Client A Payment:** Client A sends 0.50 ETH via `StealthPayment.sol` to Mira's meta-address, emitting an `Announcement` event with ephemeral public key $R_A$ and view tag $v_A$.
3. **Step 3 — Client B Payment:** Client B sends 0.75 ETH to the same meta-address, emitting $R_B$ and $v_B$.
4. **Noise Generation:** An unrelated payment of 0.10 ETH is sent to a separate recipient (Bob) to generate background on-chain noise.
5. **Step 4 — Address Uniqueness:** Asserts that Client A and Client B payments derived completely distinct stealth addresses.
6. **Step 5 & 6 — Safe Fast Scanning:** Mira scans the chain using **only** her viewing private key and spending public key. The scanner fast-filters unrelated announcements, detects exactly her two payments, and verifies the on-chain balances.
7. **Step 7 — Just-in-Time Recovery & Sweep:** Mira inputs her spending private key strictly during the withdrawal phase to recover $p_{\text{stealth}}^{(A)}$ and $p_{\text{stealth}}^{(B)}$ modulo $n$, sweeping net funds (1.24995 ETH after gas) into her cold storage address.
8. **Step 8 — Unrelated Payment Rejection:** Asserts that Bob's payment was completely ignored by Mira's scanner.

---

## 6. The Nine Scored Acceptance Criteria & Evidence

| # | Acceptance Criterion | Status | Implementation File | Verification Test |
| :- | :--- | :---: | :--- | :--- |
| **1** | Scanner never receives or loads spending private key | **PASS** | [`src/crypto/scanner.ts`](src/crypto/scanner.ts), [`src/crypto/keys.ts`](src/crypto/keys.ts) | `test/crypto.test.ts` (Test 1) & `assertScannerSafety` |
| **2** | Fresh cryptographically secure ephemeral key per payment | **PASS** | [`src/crypto/payer.ts`](src/crypto/payer.ts) (`generatePrivateKey`) | `test/crypto.test.ts` (Test 2: 50 distinct curve points) |
| **3** | Stealth public key derivation $P_{\text{stealth}} = P_{\text{spend}} + h \cdot G$ | **PASS** | [`src/crypto/payer.ts`](src/crypto/payer.ts), [`src/crypto/utils.ts`](src/crypto/utils.ts) | `test/crypto.test.ts` (Test 3) |
| **4** | Recovered spending scalar correctly reduced modulo $n$ | **PASS** | [`src/crypto/recovery.ts`](src/crypto/recovery.ts) | `test/crypto.test.ts` (Test 4 & Test 4b: $p_{\text{spend}} = n - 5$) |
| **5** | View-tag checked before full address derivation | **PASS** | [`src/crypto/scanner.ts`](src/crypto/scanner.ts) (lines 105-111) | `test/crypto.test.ts` (Test 5: spy derivation count = 0) |
| **6** | Unrelated announcements ignored | **PASS** | [`src/crypto/scanner.ts`](src/crypto/scanner.ts) | `test/crypto.test.ts` (Test 6) & `scripts/demo.ts` (Step 8) |
| **7** | Two payments to one meta-address derive distinct addresses | **PASS** | [`src/crypto/payer.ts`](src/crypto/payer.ts) | `test/crypto.test.ts` (Test 7) & `test/e2e.test.ts` |
| **8** | Ephemeral public key published on-chain | **PASS** | [`contracts/StealthAnnouncer.sol`](contracts/StealthAnnouncer.sol) | `test/e2e.test.ts` (Test 8: verified event log topics & data) |
| **9** | No real secrets committed in tracked files | **PASS** | [`.gitignore`](.gitignore), [`scripts/check-secrets.ts`](scripts/check-secrets.ts) | `test/secrets.test.ts` (4 tests: 0 leaks across repository) |

---

## 7. ERC-5564 Interoperability Findings

A dedicated test suite [`test/interop.test.ts`](test/interop.test.ts) independently validates standards compliance and interoperability:

### Independent Test Classification:
1. **ScopeLift Reference SDK Test Vectors (Genuinely Independent):**
   - Verified against published vectors from `@scopelift/stealth-address-sdk` (co-authored by ERC-5564 standard authors).
   - Validates spending/viewing public key extraction from `st:eth:0x...` URIs.
   - Validates that hashed shared secret extraction produces the identical view tag byte (`0x15`).
   - Validates that cross-SDK keypairs execute full-cycle derivation and private key recovery.
2. **External Payer Derivation via Raw EC Primitives (Genuinely Independent):**
   - An external entity deriving addresses using pure elliptic curve mathematics without calling StealthPay payer functions produces addresses that StealthPay's scanner detects and recovers.
3. **ERC-5564 Event Log ABI Decoding (Genuinely Independent):**
   - Encodes and decodes announcement events using canonical viem ABI definitions against `IERC5564Announcer`.
4. **Tolerance for Unpadded Private Key Scalars:**
   - Handles 63-hex-character unpadded scalars (common in JavaScript BigInt string conversions) by automatically normalizing them to 64 hex characters (32 bytes).
5. **ERC-5564 Recommended 57-Byte ETH Metadata Format:**
   - Implements `buildMetadataForETH` and `parseMetadata` adhering to ERC-5564 metadata guidelines:
     - Byte 1: View tag (1 byte)
     - Bytes 2-5: Function identifier `0xeeeeeeee` (4 bytes)
     - Bytes 6-25: Token address `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` (20 bytes)
     - Bytes 26-57: Payment amount `uint256` (32 bytes)
6. **Standard Function Interface Exports:**
   - Library exports standard ERC-5564 functions: `generateStealthAddress`, `checkStealthAddress`, and `computeStealthKey`.

---

## 8. Security Model & Privacy Limitations

### What is Protected:
- **Payer Confidentiality:** Public observers cannot correlate the one-time stealth address with the recipient's identity or meta-address.
- **Spending Key Isolation:** The viewing key allows scanning and payment discovery without risking spending authority. If the viewing key or scanning server is compromised, funds cannot be stolen.

### What is Visible (Privacy Boundaries):
- **On-Chain Value & Timestamps:** Public observers see that *some* address received an ETH transfer and that an announcement was made on the announcer contract.
- **Announcement Link:** Public observers can link the announcement event to the stealth address transfer if both occur in the same block/transaction.
- **Withdrawal Linkability Caveat:** If a recipient sweeps multiple stealth addresses into a single account (e.g. an exchange deposit address) in quick succession, an external observer can correlate those stealth addresses through transaction graph heuristics. **Mitigation:** Recipients should sweep funds to distinct destinations, use privacy pools, or stagger withdrawal times.
- **RPC Query Metadata:** Centralized RPC providers can see IP addresses and log filter parameters. **Mitigation:** Query wide block ranges or use a local/private RPC node.

---

## 9. Setup & Reproduction Commands

To reproduce the verification from a clean checkout:

```bash
# 1. Install dependencies
npm install

# 2. Compile Solidity smart contracts via Foundry
npm run compile:forge

# 3. Execute all Foundry smart contract tests (11 tests)
npm run test:forge

# 4. Compile TypeScript codebase
npm run build

# 5. Execute all Vitest unit and integration tests (29 tests)
npm test

# 6. Execute automated secret leak scanner (0 findings)
npm run check:secrets

# 7. Start local Anvil node (if not already running)
anvil --port 8545 &

# 8. Deploy contracts to local Anvil node
npm run deploy:local

# 9. Execute full 8-step interactive end-to-end demonstration
npm run demo
```

---

## 10. Known Limitations & Future Improvements

1. **Gas Cost of Individual Sweeps:**
   - Each stealth address requires an independent withdrawal transaction. For low-value micro-transfers, withdrawal gas costs represent a higher proportion of the payment value. Future versions could support batched ERC-4337 sweeps.
2. **ERC-20 Token Approvals & Gas Funding:**
   - To sweep ERC-20 tokens from a fresh stealth address, the address requires native ETH for gas. Future work can integrate paymasters or ERC-4337 gas sponsorship so recipients can sweep tokens without funding the stealth address with ETH first.
3. **ERC-6538 Registry Integration:**
   - StealthPay supports direct URI and keystore exchange. Future versions can add direct lookup via the ERC-6538 Stealth Meta-Address Registry contract.

---

## Submission Checklist

- [x] Solidity smart contracts compiled and tested via Foundry (11/11 passing).
- [x] TypeScript cryptography implementing ERC-5564 Scheme 1 with `@noble/curves`.
- [x] All 9 acceptance criteria proven through automated tests.
- [x] Published ScopeLift test vectors verified in `test/interop.test.ts`.
- [x] Full 8-step end-to-end interactive demo running on local Anvil.
- [x] Secret leak scanner verified (0 secrets committed).
- [x] GitHub Actions CI workflow configured and passing.
- [x] Complete documentation: `README.md`, `AUDIT_REPORT.md`, and `SUBMISSION.md`.
