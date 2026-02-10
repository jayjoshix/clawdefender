import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { readFileSync, existsSync, writeFileSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';
import { stableJson } from '../src/util/canonical-json.js';

const KEY_PATH = resolve(import.meta.dirname, '../.approver-key.json');
const payload = process.argv[2];

if (!payload) {
    console.error('Usage: pnpm exec tsx scripts/sign-approval.ts <json-payload>');
    process.exit(1);
}

let keypair: Ed25519Keypair;
if (existsSync(KEY_PATH)) {
    const raw = readFileSync(KEY_PATH, 'utf-8');
    const exported = JSON.parse(raw);
    keypair = Ed25519Keypair.fromSecretKey(exported.privateKey);
    console.error('🔑 Using key:', keypair.toSuiAddress());
} else {
    keypair = new Ed25519Keypair();
    writeFileSync(KEY_PATH, JSON.stringify({ privateKey: keypair.getSecretKey() }));
    chmodSync(KEY_PATH, 0o600);
    console.error('🔑 Generated new key:', keypair.toSuiAddress());
    console.error('   ⚠️  Add this address to your approvers.yaml file!');
}

const parsed = JSON.parse(payload);
let objectToSign = parsed;

// If the input is wrapped in a "payload" property (like from the API response), unwrap it
if (parsed.payload && typeof parsed.payload === 'object') {
    console.error('📦 Unwraping payload from response wrapper...');
    objectToSign = parsed.payload;
}

// Canonicalize the object to sign (match server's stableJson)
// Simple approach: parse and re-stringify with sorted keys if possible, 
// but for the demo, we rely on the API returning already canonical fields.
// The server expects us to sign the EXACT JSON string of the canonical payload.

// Re-serialize with stableJson to match server's formatting
const encodedPayload = stableJson(objectToSign);
const encoder = new TextEncoder();
const payloadBytes = encoder.encode(encodedPayload);

// Use signPersonalMessage for Sui wallet compatibility
// This produces a signature that verifyPersonalMessageSignature can verify
const { signature } = await keypair.signPersonalMessage(payloadBytes);

// Output in format expected by Telegram handler
console.log(`sig:${objectToSign.proposalId} ${keypair.toSuiAddress()} ${signature}`);

