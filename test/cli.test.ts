import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { createProgram } from '../src/cli/index.js';

describe('CLI Integration Tests', () => {
  const testKeystorePath = path.resolve(process.cwd(), '.stealthpay', 'test_keys.json');

  it('stealthpay keys create generates a valid keystore file', async () => {
    if (fs.existsSync(testKeystorePath)) {
      fs.unlinkSync(testKeystorePath);
    }

    const program = createProgram();
    // Prevent process.exit during test
    program.exitOverride();

    await program.parseAsync(['node', 'stealthpay', 'keys', 'create', '--out', testKeystorePath]);

    expect(fs.existsSync(testKeystorePath)).toBe(true);
    const content = JSON.parse(fs.readFileSync(testKeystorePath, 'utf8'));

    expect(content.spending.privateKey).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(content.spending.publicKey).toMatch(/^0x[0-9a-fA-F]{66}$/);
    expect(content.viewing.privateKey).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(content.viewing.publicKey).toMatch(/^0x[0-9a-fA-F]{66}$/);

    // Clean up test file
    fs.unlinkSync(testKeystorePath);
  });

  it('stealthpay balance executes and reports balance', async () => {
    const program = createProgram();
    program.exitOverride();

    let output = '';
    const originalLog = console.log;
    console.log = (msg: string) => {
      output += `${msg}\n`;
    };

    try {
      await program.parseAsync([
        'node',
        'stealthpay',
        'balance',
        '--address',
        '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
      ]);
    } finally {
      console.log = originalLog;
    }

    expect(output).toContain('Balance of 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266');
    expect(output).toContain('ETH');
  });
});
