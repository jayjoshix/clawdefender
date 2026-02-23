import { spawn } from 'child_process';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';

// 1. Get Keypair from environment
const privKey = process.env.SUI_KEYPAIR;
if (!privKey) {
  console.error('SUI_KEYPAIR environment variable is required');
  process.exit(1);
}
const { secretKey } = decodeSuiPrivateKey(privKey);
const keypair = Ed25519Keypair.fromSecretKey(secretKey);
const address = keypair.toSuiAddress();

// 2. Run E2E script and interact
const child = spawn('npx', ['tsx', 'packages/openclaw-adapter/src/test-telegram-e2e.ts'], {
  stdio: ['pipe', 'pipe', 'pipe'],
  cwd: process.cwd(),
  env: { ...process.env, FORCE_COLOR: '0' } // disable color to make parsing easier
});

let buffer = '';

child.stdout.on('data', (data) => {
  const str = data.toString();
  buffer += str;
  process.stdout.write(str);

  if (str.includes('Approve? (y/n):')) {
    child.stdin.write('y\n');
  }

  if (str.includes('Sui address')) {
    // By the time it asks for Sui address, the payload should be in our buffer
    const lines = buffer.split('\n');
    const jsonLine = lines.find(l => l.startsWith('{') && l.includes('CLAWGUARD_APPROVAL_V1'));

    if (jsonLine) {
      const encoder = new TextEncoder();
      const bytes = encoder.encode(jsonLine);
      keypair.signPersonalMessage(bytes).then(sig => {
        child.stdin.write(`${address}\n`);
        setTimeout(() => {
          child.stdin.write(`${sig.signature}\n`);
        }, 500); // Wait a bit longer before sending signature
      });
    } else {
      console.error("\n[!] COULD NOT FIND JSON PAYLOAD IN BUFFER", lines);
    }
  }
});

child.stderr.on('data', (data) => {
  process.stderr.write(data);
});

child.on('close', (code) => {
  process.exit(code);
});

// kill child on exit
process.on('SIGINT', () => child.kill('SIGINT'));
process.on('SIGTERM', () => child.kill('SIGTERM'));
