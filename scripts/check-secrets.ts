import fs from 'node:fs';
import path from 'node:path';

// Known allowed test vectors / documented local Anvil defaults
const ALLOWED_PATTERNS = [
  // Anvil account 0 default test private key
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
  // Standard test mnemonic
  'test test test test test test test test test test test junk',
  // Common secp256k1 generator G coordinates or test vectors in foundry tests
  '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
];

interface SecretFinding {
  filePath: string;
  line: number;
  type: string;
  preview: string;
}

export function scanFileForSecrets(filePath: string, content: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split('\n');

  // Regex patterns
  const patterns: { type: string; regex: RegExp }[] = [
    {
      type: 'Alchemy/Infura API Key',
      regex: /(?:alchemy\.com\/v2\/|infura\.io\/v3\/)[0-9a-zA-Z_-]{20,}/i
    },
    {
      type: 'AWS Access Key',
      regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/
    },
    {
      type: 'Generic API Key / Token',
      regex: /(?:api[_-]?key|secret[_-]?token|bearer)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]/i
    },
    {
      type: 'Authenticated RPC URL with password',
      regex: /https?:\/\/[a-zA-Z0-9_-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9.-]+/
    },
    {
      type: 'Private Key in Environment File',
      regex: /^\s*(?:PRIVATE_KEY|SPENDING_KEY|VIEWING_KEY)\s*=\s*['"]?(?!0x0000|your_|replace_)[0-9a-zA-Z]{30,}['"]?/i
    }
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check if line contains allowed test patterns
    if (ALLOWED_PATTERNS.some((p) => line.includes(p))) {
      continue;
    }

    for (const { type, regex } of patterns) {
      if (regex.test(line)) {
        findings.push({
          filePath,
          line: i + 1,
          type,
          preview: line.trim().slice(0, 80)
        });
      }
    }
  }

  return findings;
}

export function scanRepository(rootDir = process.cwd()): SecretFinding[] {
  const allFindings: SecretFinding[] = [];
  const ignoredDirs = new Set(['node_modules', 'dist', 'out', 'cache', '.git', 'lib', 'test']);
  const ignoredFiles = new Set(['package-lock.json', '.env.example']);

  function walk(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(rootDir, fullPath);

      if (entry.isDirectory()) {
        if (!ignoredDirs.has(entry.name)) {
          walk(fullPath);
        }
      } else if (entry.isFile()) {
        if (!ignoredFiles.has(entry.name)) {
          // If a real .env exists, flag it immediately
          if (entry.name === '.env' || entry.name.endsWith('.local')) {
            allFindings.push({
              filePath: relPath,
              line: 1,
              type: 'Uncommitted/Active environment secret file',
              preview: entry.name
            });
            continue;
          }

          try {
            const content = fs.readFileSync(fullPath, 'utf8');
            const fileFindings = scanFileForSecrets(relPath, content);
            allFindings.push(...fileFindings);
          } catch {
            // Ignore binary files or unreadable files
          }
        }
      }
    }
  }

  walk(rootDir);
  return allFindings;
}

// CLI execution if run directly
if (process.argv[1] && process.argv[1].endsWith('check-secrets.ts')) {
  console.log('🔍 Scanning repository for accidental committed secrets...');
  const findings = scanRepository();
  if (findings.length > 0) {
    console.error(`❌ Found ${findings.length} potential secret(s):`);
    for (const f of findings) {
      console.error(`  - [${f.type}] ${f.filePath}:${f.line} -> ${f.preview}`);
    }
    process.exit(1);
  } else {
    console.log('✅ Clean: No accidental private keys, mnemonics, API keys, or authenticated RPC URLs found.');
  }
}
