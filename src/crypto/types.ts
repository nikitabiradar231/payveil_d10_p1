export type Hex = `0x${string}`;

/**
 * Key pair containing private key and public key.
 */
export interface KeyPair {
  readonly privateKey: Hex;
  readonly publicKey: Hex;
}

/**
 * Spending key pair owned by the recipient.
 * The spending private key controls spending authority and must remain secret.
 */
export interface SpendingKeyPair {
  readonly privateKey: Hex;
  readonly publicKey: Hex;
}

/**
 * Viewing key pair owned by the recipient.
 * The viewing private key is used to scan announcements and detect incoming payments.
 */
export interface ViewingKeyPair {
  readonly privateKey: Hex;
  readonly publicKey: Hex;
}

/**
 * Recipient's separated keys.
 */
export interface StealthKeys {
  readonly spending: SpendingKeyPair;
  readonly viewing: ViewingKeyPair;
}

/**
 * Parsed components of a stealth meta-address.
 */
export interface StealthMetaAddressComponents {
  readonly spendingPublicKey: Hex;
  readonly viewingPublicKey: Hex;
  readonly chain: string;
}

/**
 * Parameters for generating a stealth address.
 */
export interface GenerateStealthAddressParams {
  readonly stealthMetaAddress: string;
  /**
   * Optional ephemeral private key (strictly for testing).
   * In production, a cryptographically secure random key is always generated.
   */
  readonly ephemeralPrivateKey?: Hex;
}

/**
 * Output of payer-side stealth address generation.
 */
export interface GenerateStealthAddressResult {
  readonly stealthAddress: Hex;
  readonly ephemeralPublicKey: Hex;
  readonly viewTag: Hex;
  readonly metadata: Hex;
}

/**
 * Public on-chain announcement data from ERC-5564 Announcer.
 */
export interface AnnouncementData {
  readonly schemeId: bigint;
  readonly stealthAddress: Hex;
  readonly caller: Hex;
  readonly ephemeralPubKey: Hex;
  readonly metadata: Hex;
  readonly blockNumber?: bigint;
  readonly transactionHash?: Hex;
  readonly timestamp?: bigint;
  readonly amount?: bigint;
}

/**
 * Scan parameters provided to the recipient scanner.
 * Notice: MUST only contain viewing private key and spending public key.
 * Spending private key is strictly excluded by design.
 */
export interface ScanParams {
  readonly viewingPrivateKey: Hex;
  readonly spendingPublicKey: Hex;
  readonly announcements: readonly AnnouncementData[];
}

/**
 * A matched payment detected during scanning.
 */
export interface ScanMatch {
  readonly stealthAddress: Hex;
  readonly ephemeralPublicKey: Hex;
  readonly viewTag: Hex;
  readonly metadata: Hex;
  readonly transactionHash?: Hex;
  readonly blockNumber?: bigint;
  readonly timestamp?: bigint;
  readonly amount?: bigint;
}

/**
 * Parameters for recovering a stealth private key to spend funds.
 */
export interface RecoverStealthKeyParams {
  readonly spendingPrivateKey: Hex;
  readonly viewingPrivateKey: Hex;
  readonly ephemeralPublicKey: Hex;
  readonly expectedStealthAddress?: Hex;
}
