#!/usr/bin/env node
/**
 * Verify the integrity of a ClawGuard session log.
 * Usage: tsx scripts/verify_log.ts <path-to-log.jsonl>
 */

import { verifyLogChain } from '../src/logging/hash-chain.js';

const args = process.argv.slice(2);
const logPath = args.find(arg => arg !== '--');

if (!logPath) {
    console.error('Usage: verify_log.ts <path-to-log.jsonl>');
    process.exit(1);
}

console.log(`Verifying log: ${logPath}`);

const result = verifyLogChain(logPath);

if (result.valid) {
    console.log('✅ Log chain is valid and tamper-free');
    process.exit(0);
} else {
    console.error(`❌ Log verification failed: ${result.error}`);
    if (result.brokenAt !== undefined) {
        console.error(`   Broken at entry: ${result.brokenAt + 1}`);
    }
    process.exit(1);
}
