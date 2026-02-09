/**
 * ClawGuard Telegram Approval Handler
 *
 * Routes approval requests to a Telegram bot and waits for cryptographic signatures.
 * Works with the OpenClaw adapter's `approvalHandler` option.
 *
 * CRITICAL: Uses server-returned payload directly for signing bytes.
 * The server's /v1/approval_payload/:proposalId returns the canonical payload
 * that must be signed - we don't reconstruct it to avoid byte mismatches.
 */

// Node.js crypto compatibility (globalThis.crypto may not exist in older Node)
import { webcrypto } from 'node:crypto';
const cryptoSubtle = globalThis.crypto?.subtle ?? webcrypto.subtle;

import type { ApprovalPayload, ApproveInput } from './index.js';

export interface TelegramApprovalConfig {
    /** Telegram Bot API token */
    botToken: string;
    /** Chat ID to send approval requests to (can be group or user) */
    chatId: string | number;
    /** 
     * Allowed Telegram user IDs (restrict who can approve).
     * REQUIRED for security - the server accepts any valid signature from allowlisted addresses,
     * so the bot must restrict who can submit signatures.
     */
    allowedUserIds: number[];
    /** If true, drop prefix support and require full proposal ID (recommended) */
    requireFullProposalId?: boolean;
    /** Polling interval in ms for checking approval status (default: 2000) */
    pollIntervalMs?: number;
    /** Maximum time to wait for approval in ms (default: 300000 = 5 min) */
    timeoutMs?: number;
    /** If true, drop all pending Telegram updates on startup (default: true for security) */
    dropBacklogOnStart?: boolean;
    /** Behavior when sendDocument fails for long payloads (default: 'reject' for safety) */
    onDocumentSendFail?: 'reject' | 'reject_with_cli_hint' | 'chunks';
}

interface PendingApproval {
    proposalId: string;
    payload: ApprovalPayload;
    messageId: number;
    sigRequestMessageId?: number;
    awaitingSignature: boolean;
    resolve: (input: ApproveInput) => void;
    reject: (error: Error) => void;
    expiresAt: number;
}

// Validation patterns (must match server's Zod schemas)
const SUI_ADDRESS_REGEX = /^0x[a-fA-F0-9]{64}$/;
const BASE64_SIGNATURE_REGEX = /^[A-Za-z0-9+/_-]+=*$/;
const UUID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

// Telegram API constants
const ALLOWED_UPDATES = encodeURIComponent(JSON.stringify(['message', 'callback_query']));
const TELEGRAM_MESSAGE_LIMIT = 4096;
const TELEGRAM_CALLBACK_DATA_LIMIT = 64;

/**
 * Generate canonical JSON exactly as the server does.
 * Uses alphabetically sorted keys and compact format (no whitespace).
 */
function stableJson(obj: unknown): string {
    return JSON.stringify(canonicalize(obj));
}

/**
 * Recursively canonicalize: sort object keys, preserve array order.
 * Matches the server's canonicalize() implementation.
 */
function canonicalize(value: unknown): unknown {
    if (value === null) return null;
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return value;
    if (typeof value === 'string') return value;

    if (Array.isArray(value)) {
        return value.map(v => canonicalize(v));
    }

    if (typeof value === 'object') {
        const sorted: Record<string, unknown> = {};
        for (const key of Object.keys(value as object).sort()) {
            const v = (value as Record<string, unknown>)[key];
            if (v !== undefined) {
                sorted[key] = canonicalize(v);
            }
        }
        return sorted;
    }

    throw new Error(`Non-JSON type: ${typeof value}`);
}

/**
 * Compute SHA-256 hash of a string (for human verification).
 */
async function computeSha256(text: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await cryptoSubtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Escape Markdown special characters to prevent injection.
 * (Kept for reference but not used - we use plain text for safety)
 */
function escapeMarkdown(text: string): string {
    return text.replace(/[_*`\[\]()~>#+\-=|{}.!\\]/g, '\\$&');
}

// UTF-8 byte length helper
const textEncoder = new TextEncoder();
function utf8ByteLen(s: string): number {
    return textEncoder.encode(s).length;
}

/**
 * Get first Unicode code point (handles surrogate pairs).
 * Returns the first code point as a string, handling non-BMP chars.
 */
function takeFirstCodePoint(s: string): string {
    if (!s) return '';
    const first = s.codePointAt(0);
    if (first === undefined) return '';
    return String.fromCodePoint(first);
}

/**
 * Truncate string to fit within maxBytes UTF-8 limit without splitting code points.
 */
function truncateToUtf8Bytes(s: string, maxBytes: number): string {
    let result = '';
    let bytes = 0;
    for (const char of s) {
        const charBytes = utf8ByteLen(char);
        if (bytes + charBytes > maxBytes) break;
        result += char;
        bytes += charBytes;
    }
    return result;
}

/**
 * Fail-closed invariant check: ensure payload fields are consistent.
 * Prevents subtle client-side drift from causing signature rejection.
 */
function assertPayloadConsistent(proposalId: string, ap: ApprovalPayload): void {
    const p = ap.payload;

    if (p.proposalId !== proposalId) {
        throw new Error(`Payload mismatch: proposalId ${p.proposalId} !== ${proposalId}`);
    }
    if (typeof ap.expiresAt === 'number' && p.expiresAt !== ap.expiresAt) {
        throw new Error(`Payload mismatch: expiresAt ${p.expiresAt} !== ${ap.expiresAt}`);
    }
    if (typeof ap.nonce === 'string' && p.nonce !== ap.nonce) {
        throw new Error(`Payload mismatch: nonce ${p.nonce} !== ${ap.nonce}`);
    }
}

/**
 * Telegram Approval Handler Factory
 *
 * Creates an approval handler that sends requests to Telegram and collects signatures.
 * Uses Sui wallet signatures over the server-provided canonical payload bytes.
 *
 * Usage:
 * ```ts
 * import { ClawGuardClient, executeWithClawGuard } from '@clawguard/openclaw-adapter';
 * import { createTelegramApprovalHandler } from '@clawguard/openclaw-adapter/telegram';
 *
 * const client = new ClawGuardClient('http://localhost:3000', 'token');
 * const telegramApprover = createTelegramApprovalHandler({
 *     botToken: process.env.TELEGRAM_BOT_TOKEN!,
 *     chatId: process.env.TELEGRAM_CHAT_ID!,
 *     allowedUserIds: [123456789], // REQUIRED: only this user can approve
 * });
 *
 * const result = await executeWithClawGuard(client, 'shell', 'exec', { command: 'rm cache/*' }, {
 *     approvalHandler: telegramApprover,
 * });
 * ```
 */
export function createTelegramApprovalHandler(config: TelegramApprovalConfig) {
    const {
        botToken, chatId, allowedUserIds,
        pollIntervalMs = 2000, timeoutMs = 300000,
        requireFullProposalId = true, dropBacklogOnStart = true,
        onDocumentSendFail = 'reject'
    } = config;
    const baseUrl = `https://api.telegram.org/bot${botToken}`;
    // Normalize chatId to string for consistent comparison
    const normalizedChatId = String(chatId);

    // Fail-closed: require allowedUserIds
    if (!allowedUserIds || allowedUserIds.length === 0) {
        throw new Error(
            'TelegramApprovalConfig.allowedUserIds is required. ' +
            'The server accepts any valid signature from allowlisted addresses, ' +
            'so the bot must restrict who can submit signatures.'
        );
    }

    // In-memory store of pending approvals
    const pendingApprovals = new Map<string, PendingApproval>();

    // Persisted offset survives multiple polling sessions (avoids replaying old updates)
    let offset = 0;

    // Polling for bot updates
    let pollingStarted = false;
    let backlogDropped = !dropBacklogOnStart; // Skip drop if not requested
    let lastPollingEnded = 0; // Track when polling last ended for resync

    // Telegram may randomize update_id after 7+ days with no updates
    const RESYNC_IDLE_MS = 7 * 24 * 3600_000; // 7 days

    async function startPolling() {
        // Invariant: one polling loop per handler (never allow second loop)
        if (pollingStarted) return;
        pollingStarted = true;

        // If process was idle for >7 days AND dropBacklogOnStart is enabled, resync offset
        const idleMs = Date.now() - lastPollingEnded;
        const needsResync = dropBacklogOnStart && lastPollingEnded > 0 && idleMs > RESYNC_IDLE_MS;

        // Drop backlog on first start OR after long idle (Telegram supports negative offset)
        if (!backlogDropped || needsResync) {
            try {
                const resp = await fetch(`${baseUrl}/getUpdates?offset=-1&limit=1&allowed_updates=${ALLOWED_UPDATES}`);
                const data = await resp.json() as { ok: boolean; result?: TelegramUpdate[] };
                // Confirm the last update and start after it
                const last = data.ok ? data.result?.[0]?.update_id : undefined;
                if (typeof last === 'number') offset = last + 1;
                backlogDropped = true;
            } catch { /* ignore */ }
        }

        while (pendingApprovals.size > 0) {
            try {
                // Use allowed_updates to reduce noise and attack surface
                const response = await fetch(
                    `${baseUrl}/getUpdates?offset=${offset}&timeout=30&allowed_updates=${ALLOWED_UPDATES}`
                );
                const data = await response.json() as { ok: boolean; result: TelegramUpdate[] };

                if (data.ok && data.result) {
                    for (const update of data.result) {
                        offset = update.update_id + 1;
                        await handleUpdate(update);
                    }
                }
            } catch (error) {
                console.error('[ClawGuard Telegram] Polling error:', error);
            }

            // Check for expired approvals
            const now = Date.now();
            const nowSeconds = Math.floor(now / 1000);
            for (const [id, approval] of pendingApprovals) {
                if (now > approval.expiresAt || nowSeconds > approval.payload.expiresAt) {
                    approval.reject(new Error('Approval request timed out or expired'));
                    pendingApprovals.delete(id);
                    await editMessage(approval.messageId, formatApprovalMessage(approval.payload, 'expired'));
                }
            }

            await sleep(pollIntervalMs);
        }
        pollingStarted = false;
        lastPollingEnded = Date.now(); // Track for resync on next session
    }

    async function handleUpdate(update: TelegramUpdate) {
        // Security: restrict by chat ID (normalize to string for comparison)
        const updateChatId = update.callback_query?.message?.chat?.id ?? update.message?.chat?.id;
        if (updateChatId !== undefined && String(updateChatId) !== normalizedChatId) {
            // Ignore updates from other chats
            return;
        }

        const userId = update.callback_query?.from?.id ?? update.message?.from?.id;

        // Security: restrict by user ID (fail-closed)
        if (!userId || !allowedUserIds.includes(userId)) {
            if (update.callback_query) {
                await answerCallbackQuery(update.callback_query.id, '⛔ You are not authorized to approve');
            }
            return;
        }

        // Handle callback query (inline button press)
        if (update.callback_query) {
            // Fail-closed: require message/chat.id (skip inline-mode queries)
            if (!update.callback_query.message?.chat?.id) {
                await answerCallbackQuery(update.callback_query.id, '⛔ Invalid callback source');
                return;
            }

            const callbackData = update.callback_query.data;
            if (!callbackData) {
                await answerCallbackQuery(update.callback_query.id, '⛔ No callback data');
                return;
            }

            const [action, proposalId] = callbackData.split(':');
            const pending = pendingApprovals.get(proposalId);

            if (!pending) {
                await answerCallbackQuery(update.callback_query.id, '⏰ Approval request expired');
                return;
            }

            if (action === 'deny') {
                try {
                    await editMessage(pending.messageId, formatApprovalMessage(pending.payload, 'denied'));
                    await answerCallbackQuery(update.callback_query.id, '❌ Denied');
                } catch (e) {
                    console.error('[ClawGuard Telegram] Failed to send deny confirmation:', e);
                }
                pending.reject(new Error('Approval denied by user'));
                pendingApprovals.delete(proposalId);
                return;
            }

            if (action === 'approve') {
                try {
                    pending.awaitingSignature = true;
                    await editMessage(
                        pending.messageId,
                        formatApprovalMessage(pending.payload, 'pending_signature')
                    );

                    // Use server-returned payload directly - safest approach
                    // The server's /v1/approval_payload/:proposalId returns the exact payload to sign
                    assertPayloadConsistent(proposalId, pending.payload);
                    const canonicalBytes = stableJson(pending.payload.payload);

                    // Compute hash for human verification (user can verify locally)
                    const hashHex = await computeSha256(canonicalBytes);

                    // Send signing instructions as PLAIN TEXT to avoid markdown injection
                    // Handle message length limit (Telegram caps at ~4096 chars)
                    const fullMessage =
                        `🔑 Sign with Sui Wallet\n\n` +
                        `📋 Proposal ID: ${proposalId}\n` +
                        `🔏 SHA-256: ${hashHex}\n\n` +
                        `Sign these EXACT bytes:\n\n` +
                        canonicalBytes + '\n\n' +
                        `Reply format: sig:${proposalId} <address> <signature>\n\n` +
                        `⏰ Expires: ${new Date(pending.payload.expiresAt * 1000).toLocaleString()}`;

                    let sigMsgId: number;
                    if (utf8ByteLen(fullMessage) > TELEGRAM_MESSAGE_LIMIT || utf8ByteLen(canonicalBytes) > TELEGRAM_MESSAGE_LIMIT - 100) {
                        // Too long: send as file for exact copy (no chunking copy/paste risk)
                        await sendMessagePlain(
                            `🔑 Sign with Sui wallet\n` +
                            `📋 Proposal: ${proposalId}\n` +
                            `🔏 SHA-256: ${hashHex}\n` +
                            `Reply: sig:${proposalId} <address> <sig>\n` +
                            `⏰ Expires: ${new Date(pending.payload.expiresAt * 1000).toLocaleTimeString()}\n\n` +
                            `↓ Download the file below and sign its EXACT contents`
                        );
                        // Send payload as file - user downloads and signs exact bytes
                        try {
                            sigMsgId = await sendDocumentFromString(canonicalBytes, `payload_${proposalId.slice(0, 8)}.json`);
                        } catch (e) {
                            // Fail-closed by default - configurable via onDocumentSendFail
                            console.error('[ClawGuard Telegram] sendDocument failed:', e);

                            if (onDocumentSendFail === 'chunks') {
                                // Dev/test mode: fall back to chunks (copy/paste risk)
                                console.warn('[ClawGuard Telegram] Falling back to chunks (dev mode)');
                                sigMsgId = await sendPureChunks(canonicalBytes);
                            } else {
                                // Production: fail-closed
                                // Wrap notifications in try/finally to ensure reject/delete even on transient API failures
                                try {
                                    const hint = onDocumentSendFail === 'reject_with_cli_hint'
                                        ? '. Use CLI approval handler instead.'
                                        : '';
                                    await editMessage(pending.messageId, formatApprovalMessage(pending.payload, 'failed_delivery'));
                                    await sendMessagePlain(`❌ File upload failed. Cannot deliver signing payload safely${hint}`);
                                    await answerCallbackQuery(update.callback_query!.id, '❌ Delivery failed');
                                } catch (notifyErr) {
                                    console.error('[ClawGuard Telegram] Failed to notify on delivery failure:', notifyErr);
                                } finally {
                                    pending.reject(new Error('sendDocument failed - cannot deliver payload safely'));
                                    pendingApprovals.delete(proposalId);
                                }
                                return;
                            }
                        }
                    } else {
                        sigMsgId = await sendMessagePlain(fullMessage);
                    }
                    pending.sigRequestMessageId = sigMsgId;
                    await answerCallbackQuery(update.callback_query.id, '✅ Now sign and send your signature');
                } catch (approveErr) {
                    // Internal error during approve flow - revert state and allow retry
                    console.error('[ClawGuard Telegram] Error in approve flow:', approveErr);
                    pending.awaitingSignature = false;
                    try {
                        await editMessage(pending.messageId, formatApprovalMessage(pending.payload, 'pending'));
                        await answerCallbackQuery(update.callback_query.id, '❌ Internal error; try again');
                    } catch { /* best effort */ }
                }
            } else {
                // Unknown action - fail-closed, always answer to stop spinner
                await answerCallbackQuery(update.callback_query.id, '⛔ Unknown action');
            }
        }

        // Handle text message (signature submission)
        if (update.message?.text && update.message.from) {
            // Fail-closed: require chat.id for symmetric policy
            if (!update.message.chat?.id) {
                return;
            }

            const text = update.message.text.trim();

            // Parse: expect "sig:<proposalId or prefix> <address> <signature>"
            const sigMatch = text.match(/^sig:([a-f0-9-]+)\s+(0x[a-fA-F0-9]{64})\s+([A-Za-z0-9+/_-]+=*)$/i);

            if (sigMatch) {
                const [, proposalIdOrPrefix, address, signature] = sigMatch;

                // With requireFullProposalId=true (default), require exact UUID match
                if (requireFullProposalId && !UUID_REGEX.test(proposalIdOrPrefix)) {
                    await sendMessage(`❌ Full proposal ID required (UUID format)`);
                    return;
                }

                // Direct lookup when using full proposal ID (O(1) instead of O(n))
                if (requireFullProposalId) {
                    const matched = pendingApprovals.get(proposalIdOrPrefix);
                    if (!matched || !matched.awaitingSignature) {
                        await sendMessage(`❌ No pending approval for \`${proposalIdOrPrefix}\``);
                        return;
                    }

                    // Validate address format
                    if (!SUI_ADDRESS_REGEX.test(address)) {
                        await sendMessage(`❌ Invalid Sui address.\nExpected: \`0x\` + 64 hex chars`);
                        return;
                    }

                    // Validate signature format
                    if (!BASE64_SIGNATURE_REGEX.test(signature)) {
                        await sendMessage(`❌ Invalid signature.\nExpected: Base64 string`);
                        return;
                    }

                    // Success! Resolve the approval
                    // Success!
                    // 1. Send feedback first (before resolving which might exit process)
                    try {
                        await editMessage(matched.messageId, formatApprovalMessage(matched.payload, 'approved'));
                        await sendMessage(`✅ Approved!\n🆔 \`${proposalIdOrPrefix.slice(0, 8)}...\`\n👤 \`${address.slice(0, 10)}...${address.slice(-6)}\``);
                    } catch (e) {
                        console.error('[ClawGuard Telegram] Failed to send approval confirmation:', e);
                    }

                    // 2. Resolve the approval (unblocks main loop)
                    assertPayloadConsistent(matched.proposalId, matched.payload);
                    matched.resolve({
                        proposalId: matched.proposalId,
                        expiresAt: matched.payload.expiresAt,
                        nonce: matched.payload.nonce,
                        approverAddress: address,
                        signature: signature,
                    });

                    // 3. Cleanup
                    pendingApprovals.delete(proposalIdOrPrefix);
                    return;
                }

                // Prefix mode: O(n) scan (only if requireFullProposalId=false)
                const matches: [string, PendingApproval][] = [];
                const isFullId = proposalIdOrPrefix.includes('-'); // UUIDs contain dashes
                for (const [id, approval] of pendingApprovals) {
                    if (approval.awaitingSignature) {
                        if (id === proposalIdOrPrefix) {
                            matches.push([id, approval]);
                        } else if (!requireFullProposalId && !isFullId && id.startsWith(proposalIdOrPrefix)) {
                            matches.push([id, approval]);
                        }
                    }
                }

                if (matches.length === 0) {
                    await sendMessage(`❌ No pending approval found for \`${proposalIdOrPrefix}\``);
                    return;
                }

                if (matches.length > 1) {
                    // Ambiguous prefix - refuse to avoid mis-binding
                    await sendMessage(
                        `❌ Ambiguous proposal ID prefix \`${proposalIdOrPrefix}\`.\n` +
                        `Matches ${matches.length} proposals. Use full proposal ID:\n` +
                        matches.map(([id]) => `• \`${id}\``).join('\n')
                    );
                    return;
                }

                const [matchedId, matchedApproval] = matches[0];

                // Validate address format
                if (!SUI_ADDRESS_REGEX.test(address)) {
                    await sendMessage(`❌ Invalid Sui address.\nExpected: \`0x\` + 64 hex chars`);
                    return;
                }

                // Validate signature format
                if (!BASE64_SIGNATURE_REGEX.test(signature)) {
                    await sendMessage(`❌ Invalid signature.\nExpected: Base64 string`);
                    return;
                }

                // Success! Resolve the approval
                assertPayloadConsistent(matchedApproval.proposalId, matchedApproval.payload);
                matchedApproval.resolve({
                    proposalId: matchedApproval.proposalId,
                    expiresAt: matchedApproval.payload.expiresAt,
                    nonce: matchedApproval.payload.nonce,
                    approverAddress: address,
                    signature: signature,
                });
                pendingApprovals.delete(matchedId);

                await editMessage(matchedApproval.messageId, formatApprovalMessage(matchedApproval.payload, 'approved'));
                await sendMessage(`✅ Approved!\n🆔 \`${matchedId.slice(0, 8)}...\`\n👤 \`${address.slice(0, 10)}...${address.slice(-6)}\``);
                return;
            }

            // Help message for invalid format
            if (text.toLowerCase().includes('sig:') || text.startsWith('0x')) {
                await sendMessage(
                    `❌ Invalid format.\n\n` +
                    `**Use:** \`sig:<proposal_id> <sui_address> <base64_sig>\``
                );
            }
        }
    }

    async function sendMessage(text: string, replyMarkup?: InlineKeyboardMarkup): Promise<number> {
        const response = await fetch(`${baseUrl}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: chatId,
                text,
                // Plain text: no parse_mode to avoid markdown edge cases
                reply_markup: replyMarkup,
            }),
        });
        const data = await response.json() as { ok: boolean; result?: { message_id: number }; description?: string };
        // Fail-closed: throw if message wasn't sent
        if (!data.ok || !data.result?.message_id) {
            throw new Error(`Telegram sendMessage failed: ${data.description ?? 'unknown error'}`);
        }
        return data.result.message_id;
    }

    // Plain text version for signing instructions (avoids markdown injection)
    async function sendMessagePlain(text: string): Promise<number> {
        const response = await fetch(`${baseUrl}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, text }),
        });
        const data = await response.json() as { ok: boolean; result?: { message_id: number }; description?: string };
        if (!data.ok || !data.result?.message_id) {
            throw new Error(`Telegram sendMessage failed: ${data.description ?? 'unknown error'}`);
        }
        return data.result.message_id;
    }

    // Send content as a downloadable file (for long payloads - eliminates copy/paste risk)
    // Telegram caption limit: 1024 characters
    const TELEGRAM_CAPTION_LIMIT = 1024;
    async function sendDocumentFromString(content: string, filename: string): Promise<number> {
        // Use FormData to send as multipart/form-data
        const formData = new FormData();
        formData.append('chat_id', String(chatId));

        // Create a Blob with the exact content bytes (explicit UTF-8 encoding)
        const contentBytes = new TextEncoder().encode(content);
        const blob = new Blob([contentBytes], { type: 'application/json' });
        formData.append('document', blob, filename);

        // Truncate caption to fit Telegram limit
        const caption = truncateToUtf8Bytes(`📄 Sign the EXACT contents of this file`, TELEGRAM_CAPTION_LIMIT);
        formData.append('caption', caption);

        const response = await fetch(`${baseUrl}/sendDocument`, {
            method: 'POST',
            body: formData,
        });
        const data = await response.json() as { ok: boolean; result?: { message_id: number }; description?: string };
        if (!data.ok || !data.result?.message_id) {
            throw new Error(`Telegram sendDocument failed: ${data.description ?? 'unknown error'}`);
        }
        return data.result.message_id;
    }

    // Send pure payload chunks without any headers mixed in (for signing)
    // Part numbers are sent as SEPARATE messages to avoid copy/paste contamination
    async function sendPureChunks(body: string): Promise<number> {
        const totalParts = Math.ceil(utf8ByteLen(body) / (TELEGRAM_MESSAGE_LIMIT - 50));
        let lastMsgId = 0;
        let remaining = body;
        let partNum = 0;

        while (remaining.length > 0) {
            partNum++;

            // Send part indicator as SEPARATE message (not mixed with payload)
            if (totalParts > 1) {
                await sendMessagePlain(`↓↓↓ Part ${partNum}/${totalParts} ↓↓↓`);
            }

            // Chunk by code points to avoid splitting multi-byte chars
            let chunk = '';
            let chunkBytes = 0;
            for (const char of remaining) {
                const charBytes = utf8ByteLen(char);
                if (chunkBytes + charBytes > TELEGRAM_MESSAGE_LIMIT) break;
                chunk += char;
                chunkBytes += charBytes;
            }

            // Safety: ensure we make progress (surrogate-safe)
            if (chunk.length === 0 && remaining.length > 0) {
                chunk = takeFirstCodePoint(remaining);
            }

            remaining = remaining.slice(chunk.length);

            // Invariant assertion
            if (utf8ByteLen(chunk) > TELEGRAM_MESSAGE_LIMIT) {
                throw new Error(`Pure chunk exceeds Telegram limit`);
            }

            // Send PURE payload chunk - no headers, no labels
            lastMsgId = await sendMessagePlain(chunk);
        }
        return lastMsgId;
    }

    async function editMessage(messageId: number, text: string): Promise<void> {
        await fetch(`${baseUrl}/editMessageText`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                chat_id: chatId,
                message_id: messageId,
                text,
                // Plain text: no parse_mode to avoid markdown edge cases
            }),
        });
    }

    async function answerCallbackQuery(callbackQueryId: string, text: string): Promise<void> {
        await fetch(`${baseUrl}/answerCallbackQuery`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                callback_query_id: callbackQueryId,
                text,
            }),
        });
    }

    function formatApprovalMessage(
        payload: ApprovalPayload,
        status: 'pending' | 'pending_signature' | 'approved' | 'denied' | 'expired' | 'failed_delivery'
    ): string {
        const emoji: Record<string, string> = {
            pending: '⏳', pending_signature: '🔑', approved: '✅', denied: '❌', expired: '⏰', failed_delivery: '🚨',
        };

        const p = payload.payload;
        // Plain text format - no markdown to avoid parsing issues
        const msg = `${emoji[status]} ClawGuard Approval

🔧 ${p.tool} → ${p.action}
🔐 Args: ${p.argsHash.slice(0, 12)}...
${p.untrustedSource ? `⚠️ Source: ${p.untrustedSource.slice(0, 50).replace(/[\n\r]/g, ' ')}\n` : ''}⏰ ${new Date(p.expiresAt * 1000).toLocaleTimeString()}
🆔 ${p.proposalId.slice(0, 8)}...

${status.replace('_', ' ').toUpperCase()}`;
        // Truncate to fit Telegram limit (prevents send/edit failures)
        return truncateToUtf8Bytes(msg, TELEGRAM_MESSAGE_LIMIT - 10);
    }

    return async function telegramApprovalHandler(
        proposalId: string,
        payload: ApprovalPayload,
    ): Promise<ApproveInput> {
        return new Promise<ApproveInput>((resolve, reject) => {
            // Fail-closed: reject non-UUID proposalId when requireFullProposalId is true
            if (requireFullProposalId && !UUID_REGEX.test(proposalId)) {
                reject(new Error(`Invalid proposal ID format: must be full UUID when requireFullProposalId is true`));
                return;
            }

            // Validate callback_data length (Telegram limit: 1-64 bytes)
            const approveData = `approve:${proposalId}`;
            const denyData = `deny:${proposalId}`;
            if (utf8ByteLen(approveData) > TELEGRAM_CALLBACK_DATA_LIMIT ||
                utf8ByteLen(denyData) > TELEGRAM_CALLBACK_DATA_LIMIT) {
                reject(new Error(`Proposal ID too long for Telegram callback_data (max ${TELEGRAM_CALLBACK_DATA_LIMIT} bytes)`));
                return;
            }

            const inlineKeyboard: InlineKeyboardMarkup = {
                inline_keyboard: [[
                    { text: '✅ Approve', callback_data: approveData },
                    { text: '❌ Deny', callback_data: denyData },
                ]],
            };

            sendMessage(formatApprovalMessage(payload, 'pending'), inlineKeyboard)
                .then((messageId) => {
                    pendingApprovals.set(proposalId, {
                        proposalId,
                        payload,
                        messageId,
                        awaitingSignature: false,
                        resolve,
                        reject,
                        expiresAt: Date.now() + timeoutMs,
                    });
                    startPolling();
                })
                .catch(reject);
        });
    };
}

// Types
interface TelegramUpdate {
    update_id: number;
    message?: {
        message_id: number;
        chat?: { id: number };
        from?: { id: number };
        text?: string;
    };
    callback_query?: {
        id: string;
        from?: { id: number };
        data?: string;
        message?: { message_id: number; chat?: { id: number } };
    };
}

interface InlineKeyboardMarkup {
    inline_keyboard: Array<Array<{ text: string; callback_data: string }>>;
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * CLI approval handler for development/testing.
 */
export async function cliApprovalHandler(
    proposalId: string,
    payload: ApprovalPayload,
): Promise<ApproveInput> {
    const readline = await import('node:readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    const p = payload.payload;
    const canonicalBytes = stableJson(p);

    console.log('\n' + '═'.repeat(50));
    console.log('🛡️  ClawGuard Approval Request');
    console.log('═'.repeat(50));
    console.log(`Tool:     ${p.tool} → ${p.action}`);
    console.log(`Proposal: ${p.proposalId}`);
    console.log(`Expires:  ${new Date(p.expiresAt * 1000).toLocaleString()}`);
    if (p.untrustedSource) console.log(`⚠️ Source: ${p.untrustedSource}`);
    console.log('─'.repeat(50));
    console.log('Sign these bytes with your Sui wallet:');
    console.log(canonicalBytes);
    console.log('═'.repeat(50));

    return new Promise((resolve, reject) => {
        rl.question('\nApprove? (y/n): ', (answer) => {
            if (answer.toLowerCase() !== 'y') {
                rl.close();
                return reject(new Error('Denied'));
            }

            rl.question('Sui address (0x...): ', (address) => {
                if (!SUI_ADDRESS_REGEX.test(address)) {
                    rl.close();
                    return reject(new Error('Invalid address'));
                }

                rl.question('Base64 signature: ', (signature) => {
                    rl.close();
                    if (!BASE64_SIGNATURE_REGEX.test(signature)) {
                        return reject(new Error('Invalid signature'));
                    }
                    resolve({
                        proposalId,
                        expiresAt: payload.expiresAt,
                        nonce: payload.nonce,
                        approverAddress: address,
                        signature,
                    });
                });
            });
        });
    });
}
