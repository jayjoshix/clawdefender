#!/usr/bin/env npx tsx
/**
 * ClawGuard Signature Helper
 * 
 * Signs approval payloads using a Sui Ed25519 keypair.
 * 
 * Usage:
 *   npx tsx sign-approval.ts <json-payload>
 *   npx tsx sign-approval.ts "$(cat payload.json)"
 * 
 * The script will output in the format required by the Telegram handler:
 *   sig:<proposalId> <address> <signature>
 */

import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { readFileSync, existsSync, writeFileSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';

// Key storage path (same as used in demo)
const KEY_PATH = process.env.KEY_PATH || resolve(process.cwd(), '.approver-key.json');

function getOrCreateKeypair(): Ed25519Keypair {
    if (existsSync(KEY_PATH)) {
        try {
            const raw = readFileSync(KEY_PATH, 'utf-8');
            const exported = JSON.parse(raw);
            const keypair = Ed25519Keypair.fromSecretKey(exported.privateKey);
            console.error(`🔑 Using existing key: ${keypair.toSuiAddress()}`);
            return keypair;
        } catch (e) {
            console.error('Failed to load key, generating new one');
        }
    }

    // Generate new keypair
    const keypair = new Ed25519Keypair();
    writeFileSync(KEY_PATH, JSON.stringify({ privateKey: keypair.getSecretKey() }));
    chmodSync(KEY_PATH, 0o600);
    console.error(`🔑 Generated new key: ${keypair.toSuiAddress()}`);
    console.error(`   Saved to: ${KEY_PATH}`);
    return keypair;
}

async function main() {
    const payload = process.argv[2];

    if (!payload) {
        console.error('Usage: npx tsx sign-approval.ts <json-payload>');
        console.error('');
        console.error('Example:');
        console.error('  npx tsx sign-approval.ts \'{"action":"exec",...}\'');
        process.exit(1);
    }

    // Parse and extract proposalId
    let parsed: { proposalId?: string };
    try {
        parsed = JSON.parse(payload);
    } catch (e) {
        console.error('Invalid JSON payload');
        process.exit(1);
    }

    if (!parsed.proposalId) {
        console.error('Payload must contain proposalId');
        process.exit(1);
    }

    const keypair = getOrCreateKeypair();
    const address = keypair.toSuiAddress();

    // Convert JSON to bytes (UTF-8 encoded)
    const encoder = new TextEncoder();
    const payloadBytes = encoder.encode(payload);

    // Sign using signPersonalMessage (adds Intent scope and serializes with flag/pubkey)
    const { signature } = await keypair.signPersonalMessage(payloadBytes);

    // signature is already base64 encoded serialized signature
    const signatureBase64 = signature;

    // Output in the format expected by Telegram handler
    console.log(`sig:${parsed.proposalId} ${address} ${signatureBase64}`);

    // Also show the hash for verification
    const hash = createHash('sha256').update(payloadBytes).digest('hex');
    console.error(`\n📋 Proposal ID: ${parsed.proposalId}`);
    console.error(`🔏 SHA-256: ${hash}`);
    console.error(`📝 Address: ${address}`);
}

main().catch(console.error);
