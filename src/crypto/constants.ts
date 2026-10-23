import { secp256k1 } from '@noble/curves/secp256k1';

/**
 * ERC-5564 Scheme 1 identifier for secp256k1 with view tags.
 */
export const SCHEME_ID = 1n;

/**
 * SECP256k1 curve order n.
 */
export const CURVE_ORDER = secp256k1.CURVE.n;

/**
 * Standard prefix for ERC-5564 stealth meta-addresses.
 */
export const META_ADDRESS_PREFIX = 'st:';

/**
 * Default chain identifier string for Ethereum.
 */
export const DEFAULT_CHAIN = 'eth';

/**
 * Length in bytes of a compressed secp256k1 public key.
 */
export const COMPRESSED_PUBKEY_BYTE_LENGTH = 33;

/**
 * Length in bytes of an uncompressed secp256k1 public key.
 */
export const UNCOMPRESSED_PUBKEY_BYTE_LENGTH = 65;
