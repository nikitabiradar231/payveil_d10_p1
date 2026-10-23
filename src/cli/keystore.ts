import fs from 'node:fs';
import path from 'node:path';
import { generateStealthKeys } from '../crypto/keys.js';
import { encodeStealthMetaAddress } from '../crypto/metaAddress.js';
import type { StealthKeys } from '../crypto/types.js';

export const DEFAULT_KEYSTORE_PATH = path.resolve(process.cwd(), '.stealthpay', 'keys.json');

export function loadKeystore(filePath = DEFAULT_KEYSTORE_PATH): StealthKeys {
  if (!fs.existsSync(filePath)) {
    throw new Error(
      `Keystore not found at ${filePath}. Please run "stealthpay keys create" first.`
    );
  }
  const content = fs.readFileSync(filePath, 'utf8');
  return JSON.parse(content);
}

export function saveKeystore(keys: StealthKeys, filePath = DEFAULT_KEYSTORE_PATH): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  fs.writeFileSync(filePath, JSON.stringify(keys, null, 2), {
    encoding: 'utf8',
    mode: 0o600
  });
}

export function createNewKeystore(filePath = DEFAULT_KEYSTORE_PATH): {
  keys: StealthKeys;
  metaAddress: string;
  path: string;
} {
  const keys = generateStealthKeys();
  saveKeystore(keys, filePath);
  const metaAddress = encodeStealthMetaAddress({
    spendingPublicKey: keys.spending.publicKey,
    viewingPublicKey: keys.viewing.publicKey
  });

  return {
    keys,
    metaAddress,
    path: filePath
  };
}
