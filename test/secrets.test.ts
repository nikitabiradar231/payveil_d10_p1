import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanFileForSecrets, scanRepository } from '../scripts/check-secrets.js';

describe('9. No committed secrets scanner & security checks', () => {
  it('Repository is clean of accidental secrets and keys', () => {
    const findings = scanRepository();
    expect(findings).toEqual([]);
  });

  it('Secret scanner detects simulated leaked private keys, API keys, and authenticated RPC URLs', () => {
    const leakedContent = `
      # Some config
      INFURA_URL = "https://infura.io/v3/0123456789abcdef0123456789abcdef"
      AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
      RPC_SECRET = "https://admin:superSecretP@ssword@rpc.example.com"
      SPENDING_KEY = "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
    `;

    const findings = scanFileForSecrets('test-leak.txt', leakedContent);
    expect(findings.length).toBeGreaterThanOrEqual(4);
    expect(findings.some((f) => f.type.includes('Infura'))).toBe(true);
    expect(findings.some((f) => f.type.includes('AWS'))).toBe(true);
    expect(findings.some((f) => f.type.includes('Authenticated RPC'))).toBe(true);
    expect(findings.some((f) => f.type.includes('Private Key'))).toBe(true);
  });

  it('Allows documented local-chain defaults and test vectors', () => {
    const allowedContent = `
      // Documented Anvil default test key
      const key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
      // Test mnemonic
      const mnemonic = "test test test test test test test test test test test junk";
    `;

    const findings = scanFileForSecrets('allowed.ts', allowedContent);
    expect(findings).toEqual([]);
  });

  it('.gitignore correctly excludes .env, keys, and private data', () => {
    const gitignorePath = path.resolve(process.cwd(), '.gitignore');
    expect(fs.existsSync(gitignorePath)).toBe(true);
    const content = fs.readFileSync(gitignorePath, 'utf8');

    expect(content).toContain('.env');
    expect(content).toContain('*.key');
    expect(content).toContain('*.pem');
    expect(content).toContain('secrets/');
    expect(content).toContain('node_modules/');
  });
});
