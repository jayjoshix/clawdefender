#!/usr/bin/env npx tsx
/**
 * ClawGuard Telegram Approval Handler E2E Test
 * 
 * This script tests the full integration of the Telegram approval handler
 * with the ClawGuard server.
 * 
 * Prerequisites:
 * 1. ClawGuard server running on localhost:3000
 * 2. Environment variables set:
 *    - TELEGRAM_BOT_TOKEN: Your Telegram bot token
 *    - TELEGRAM_CHAT_ID: Chat ID for approvals
 *    - TELEGRAM_USER_ID: Your Telegram user ID (for authorization)
 *    - CLAWGUARDTOKEN: ClawGuard server token (optional if no auth)
 * 
 * Usage:
 *   # Start ClawGuard server first
 *   pnpm demo
 *   
 *   # In another terminal, run this test
 *   npx tsx packages/openclaw-adapter/src/test-telegram-e2e.ts
 */

import { ClawGuardClient, executeWithClawGuard } from './index.js';
import { createTelegramApprovalHandler, cliApprovalHandler } from './telegram.js';

// Configuration from environment
const CLAWGUARD_URL = process.env.CLAWGUARD_URL || 'http://localhost:3000';
const CLAWGUARD_TOKEN = process.env.CLAWGUARDTOKEN || '';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const TELEGRAM_USER_ID = process.env.TELEGRAM_USER_ID;

async function main() {
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('🔌 ClawGuard Telegram Approval Handler E2E Test');
    console.log('═══════════════════════════════════════════════════════════════\n');

    // Check if Telegram credentials are available
    const useTelegram = TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID && TELEGRAM_USER_ID;

    if (useTelegram) {
        console.log('✅ Telegram credentials found - using Telegram approval handler');
        console.log(`   Bot Token: ${TELEGRAM_BOT_TOKEN?.slice(0, 15)}...`);
        console.log(`   Chat ID: ${TELEGRAM_CHAT_ID}`);
        console.log(`   User ID: ${TELEGRAM_USER_ID}\n`);
    } else {
        console.log('⚠️  Telegram credentials not found - using CLI approval handler');
        console.log('   Set TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_USER_ID to test Telegram\n');
    }

    // Create ClawGuard client
    const client = new ClawGuardClient(CLAWGUARD_URL, CLAWGUARD_TOKEN);

    // Check server status
    console.log('📡 Checking ClawGuard server status...');
    try {
        const status = await client.status();
        console.log(`   ✅ Server running`);
        console.log(`   Session: ${status.sessionId}`);
        console.log(`   Policy: ${status.policyPath}`);
        console.log(`   Policy Hash: ${status.policyHash.slice(0, 16)}...\n`);
    } catch (e) {
        console.error('❌ ClawGuard server not reachable at', CLAWGUARD_URL);
        console.error('   Start the server first: pnpm demo\n');
        process.exit(1);
    }

    // Create approval handler
    const approvalHandler = useTelegram
        ? createTelegramApprovalHandler({
            botToken: TELEGRAM_BOT_TOKEN!,
            chatId: TELEGRAM_CHAT_ID!,
            allowedUserIds: [parseInt(TELEGRAM_USER_ID!)],
            pollIntervalMs: 2000,
            timeoutMs: 300000, // 5 minutes
            dropBacklogOnStart: true,
            requireFullProposalId: true,
        })
        : cliApprovalHandler;

    // ═══════════════════════════════════════════════════════════════
    // Test 1: Allowed action (no approval needed)
    // ═══════════════════════════════════════════════════════════════
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('🟢 Test 1: Allowed action (ls /tmp)');
    console.log('═══════════════════════════════════════════════════════════════\n');

    try {
        const result1 = await executeWithClawGuard(client, 'shell', 'exec', { command: 'ls /tmp' });
        console.log(`   Decision: ${result1.decision}`);
        if (result1.decision === 'allow') {
            console.log('   ✅ Action executed successfully');
            // console.log('   Output:', result1.output);
        } else {
            console.log(`   Reason: ${result1.reason}`);
        }
    } catch (e) {
        console.error('   ❌ Error:', e);
    }
    console.log();

    // ═══════════════════════════════════════════════════════════════
    // Test 2: Denied action (policy blocks)
    // ═══════════════════════════════════════════════════════════════
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('🔴 Test 2: Denied action (cat ~/.ssh/id_rsa)');
    console.log('═══════════════════════════════════════════════════════════════\n');

    try {
        const result2 = await executeWithClawGuard(client, 'shell', 'exec', { command: 'cat ~/.ssh/id_rsa' });
        console.log(`   Decision: ${result2.decision}`);
        if (result2.decision === 'deny') {
            console.log('   ✅ Action correctly denied');
            console.log(`   Reason: ${result2.reason}`);
        }
    } catch (e) {
        console.error('   ❌ Error:', e);
    }
    console.log();

    // ═══════════════════════════════════════════════════════════════
    // Test 3: Approval required (untrusted source)
    // ═══════════════════════════════════════════════════════════════
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('🟡 Test 3: Approval required (untrusted source)');
    console.log('═══════════════════════════════════════════════════════════════\n');

    if (useTelegram) {
        console.log('   📱 Sending approval request to Telegram...');
        console.log('   👉 Check your Telegram chat and click Approve/Deny\n');
    } else {
        console.log('   ⌨️  CLI approval mode - follow the prompts\n');
    }

    try {
        const result3 = await executeWithClawGuard(
            client,
            'shell',
            'exec',
            { command: 'echo "Hello from approved action"' },
            {
                meta: { untrustedSource: 'web' }, // Forces approval
                approvalHandler,
            }
        );

        console.log(`   Decision: ${result3.decision}`);
        if (result3.decision === 'allow') {
            console.log('   ✅ Action approved and executed');
            console.log(`   Output: ${result3.output}`);
        } else if (result3.decision === 'deny') {
            console.log('   ❌ Action denied');
            console.log(`   Reason: ${result3.reason}`);
        } else if (result3.decision === 'needs_approval') {
            console.log('   ⏳ Approval not provided (no handler)');
        }
    } catch (e: any) {
        if (e.message?.includes('denied by user')) {
            console.log('   ❌ User denied the approval');
        } else if (e.message?.includes('timed out')) {
            console.log('   ⏰ Approval request timed out');
        } else {
            console.error('   ❌ Error:', e.message);
        }
    }
    console.log();

    console.log('═══════════════════════════════════════════════════════════════');
    console.log('🎉 E2E Test Complete');
    console.log('═══════════════════════════════════════════════════════════════\n');
}

main().catch(console.error);
