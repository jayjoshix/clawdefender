import { exec } from 'child_process';
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
const child = exec('npx tsx packages/openclaw-adapter/src/test-telegram-e2e.ts');

child.stdout.on('data', (data) => {
  process.stdout.write(data);

  if (data.includes('Approve? (y/n):')) {
    child.stdin.write('y\n');
  }

  if (data.includes('Sign these bytes with your Sui wallet:')) {
    // Extract the payload from the lines following this
    const lines = data.split('\n');
    const jsonLine = lines.find(l => l.startsWith('{') && l.includes('CLAWGUARD_APPROVAL_V1'));
    if (jsonLine) {
      const encoder = new TextEncoder();
      const bytes = encoder.encode(jsonLine);
      keypair.signPersonalMessage(bytes).then(sig => {
        child.stdin.write(`${address}\n`);
        setTimeout(() => {
          child.stdin.write(`${sig.signature}\n`);
        }, 100);
      });
    }
  }

  if (data.includes('Sui address')) {
    // Sometimes it prompts directly, handled above but just in case
  }
});

child.stderr.on('data', (data) => {
  process.stderr.write(data);
});

child.on('exit', (code) => {
  process.exit(code);
});
