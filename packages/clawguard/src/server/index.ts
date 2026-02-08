import Fastify from 'fastify';
import cors from '@fastify/cors';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import yaml from 'js-yaml';
import { PolicyEvaluator, ActionRequest, ToolType } from '../policy/evaluator.js';
import { HashChainLogger, sha256, verifyLogChain } from '../logging/hash-chain.js';
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'node:fs';
import {
    buildCanonicalPayload,
    verifyApproval,
    NonceTracker,
    generateNonce,
    computeMsgHash,
    MAX_APPROVAL_TTL,
    type SignedApproval,
    type ApprovalRecord,
    type ApproversConfig,
} from '../approval/index.js';
import { createPermit, verifyPermit } from '../auth/permit.js';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';

// Server Identity (Persistent)
const LOG_DIR = resolve(process.env.LOGDIR ?? '.logs');
if (!existsSync(LOG_DIR)) {
    mkdirSync(LOG_DIR, { recursive: true });
}
const KEY_PATH = resolve(LOG_DIR, 'server-key.json');
let serverKeypair: Ed25519Keypair;
const usedPermits = new Set<string>(); // Replay protection for current session

if (existsSync(KEY_PATH)) {
    try {
        const raw = readFileSync(KEY_PATH, 'utf-8');
        const exported = JSON.parse(raw);
        serverKeypair = Ed25519Keypair.fromSecretKey(exported.privateKey);
        console.log(`🔑 Loaded Server Identity: ${serverKeypair.toSuiAddress()}`);
    } catch (e) {
        console.error('Failed to load server key, generating new one:', e);
        serverKeypair = new Ed25519Keypair();
        writeFileSync(KEY_PATH, JSON.stringify({ privateKey: serverKeypair.getSecretKey() }));
        chmodSync(KEY_PATH, 0o600);
    }
} else {
    serverKeypair = new Ed25519Keypair();
    writeFileSync(KEY_PATH, JSON.stringify({ privateKey: serverKeypair.getSecretKey() }));
    chmodSync(KEY_PATH, 0o600);
    console.log(`🔑 Generated New Server Identity: ${serverKeypair.toSuiAddress()}`);
}
const serverId = serverKeypair.toSuiAddress();

// Event constants for log/rehydration consistency
// Event constants for log/rehydration consistency
const EVENT = {
    PROPOSAL_CREATED: 'proposal_created',
    APPROVAL_PAYLOAD_ISSUED: 'approval_payload_issued',
    APPROVAL_PAYLOAD_REUSED: 'approval_payload_reused',
    SIGNED_APPROVAL: 'signed_approval',
    SIGNED_APPROVAL_FAILED: 'signed_approval_failed',
    EXECUTE_BLOCKED: 'execute_blocked_missing_approval',
    EXECUTE: 'execute',
    EXECUTE_FAILED: 'execute_failed',
    AGENT_COMPLETED: 'agentcompleted',
} as const;

// Request/Response schemas
const ProposeActionSchema = z.object({
    tool: z.enum(['shell', 'filesystem', 'network', 'browser']),
    action: z.string(),
    args: z.record(z.unknown()),
    context: z.record(z.unknown()).optional(),
    meta: z.object({
        untrustedSource: z.enum(['web', 'email', 'issue', 'clipboard']).optional(),
    }).optional(),
});

const SignedApproveSchema = z.object({
    proposalId: z.string().uuid(),
    expiresAt: z.number().int().positive(),
    nonce: z.string().length(64), // 32 bytes hex
    approverAddress: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
    signature: z.string().regex(/^[A-Za-z0-9+/_-]+=*$/), // Base64 or Base64URL
});

const ExecuteActionSchema = z.object({
    proposalId: z.string().uuid(),
});

// Types
interface Proposal {
    id: string;
    tool: ToolType;
    action: string;
    args: Record<string, unknown>;
    context?: Record<string, unknown>;
    decision: 'allow' | 'deny' | 'needs_approval';
    reason: string;
    approved: boolean;
    executed: boolean;
    createdAt: Date;
    // New fields for signed approvals
    entryHash: string;           // Hash of the proposal log entry
    argsHash: string;            // SHA256 of args
    policyHash: string;          // Policy hash at proposal time
    untrustedSource?: 'web' | 'email' | 'issue' | 'clipboard';
    // Issued approval challenge (authoritative)
    pendingApproval?: {
        nonce: string;
        expiresAt: number;
        msgHash: string;
    };
}

interface ArtifactRef {
    type: string;
    path?: string;
    hash?: string;
}

// Server state
const proposals = new Map<string, Proposal>();
const approvalRecords = new Map<string, ApprovalRecord>(); // proposalId -> ApprovalRecord
const nonceTracker = new NonceTracker();

// Load approvers config
function loadApproversConfig(path?: string): ApproversConfig {
    const configPath = path ?? resolve(import.meta.dirname, '../../approvers.yaml');
    if (!existsSync(configPath)) {
        console.warn(`Approvers config not found at ${configPath}, using empty allowlist`);
        return { approvers: [] };
    }
    const content = readFileSync(configPath, 'utf-8');
    return yaml.load(content) as ApproversConfig;
}

/**
 * Rehydrate server state from log entries on startup.
 * Uses event field and raw detail fields for deterministic reconstruction.
 * 
 * SECURITY NOTE: The *verified* log chain is the single source of truth.
 * - Rehydration restores the `NonceTracker` to prevent replay attacks across restarts.
 * - If log verification fails, we must NOT rehydrate (fail-closed), relying on a fresh state 
 *   to avoid accepting previously utilized nonces.
 */
function rehydrateFromLog(
    logger: HashChainLogger,
    proposals: Map<string, Proposal>,
    approvalRecords: Map<string, ApprovalRecord>,
    nonceTracker: NonceTracker,
    sessionId: string
): { rehydratedProposals: number; rehydratedApprovals: number } {
    const entries = logger.readAll();
    let rehydratedProposals = 0;
    let rehydratedApprovals = 0;

    for (const entry of entries) {
        // Rebuild proposals from proposal_created events
        if (entry.event === EVENT.PROPOSAL_CREATED && entry.proposalId && entry.proposalDetails) {
            // Verify args hash integrity
            const recomputedArgsHash = sha256(entry.proposalDetails.args);
            if (recomputedArgsHash !== entry.proposalDetails.argsHash) {
                console.warn(`⚠️ Proposal ${entry.proposalId} dropped: args hash mismatch (integrity check failed)`);
                continue;
            }
            if (entry.proposalDetails.argsHash !== entry.args_hash) {
                console.warn(`⚠️ Proposal ${entry.proposalId} dropped: log args_hash mismatch (integrity check failed)`);
                continue;
            }

            if (!proposals.has(entry.proposalId)) {
                proposals.set(entry.proposalId, {
                    id: entry.proposalId,
                    tool: entry.tool as ToolType,
                    action: entry.proposalDetails.requestedAction,
                    args: entry.proposalDetails.args,
                    decision: entry.decision as 'allow' | 'deny' | 'needs_approval',
                    reason: entry.reason,
                    approved: false,
                    executed: false,
                    createdAt: new Date(entry.ts),
                    entryHash: entry.entry_hash,
                    argsHash: entry.proposalDetails.argsHash,
                    policyHash: entry.proposalDetails.policyHash,
                    untrustedSource: entry.proposalDetails.untrustedSource as Proposal['untrustedSource'],
                });
                rehydratedProposals++;
            }
        }

        // Rebuild pendingApproval from approval_payload_issued/reused events
        if ((entry.event === EVENT.APPROVAL_PAYLOAD_ISSUED || entry.event === EVENT.APPROVAL_PAYLOAD_REUSED)
            && entry.proposalId && entry.pendingApprovalDetails) {
            const proposal = proposals.get(entry.proposalId);
            if (proposal) {
                const { nonce, expiresAt, msgHash } = entry.pendingApprovalDetails;

                // Verify msgHash integrity (reconstruct payload)
                const payload = buildCanonicalPayload({
                    sessionId,
                    proposalId: proposal.id,
                    proposalEntryHash: proposal.entryHash,
                    tool: proposal.tool,
                    action: proposal.action,
                    argsHash: proposal.argsHash,
                    policyHash: proposal.policyHash,
                    expiresAt,
                    nonce,
                    untrustedSource: proposal.untrustedSource,
                });

                const recomputedMsgHash = computeMsgHash(payload);
                if (recomputedMsgHash !== msgHash) {
                    console.warn(`⚠️ Pending approval for ${entry.proposalId} dropped: msgHash mismatch (integrity check failed)`);
                    continue;
                }

                const now = Math.floor(Date.now() / 1000);
                // Only restore if not expired
                if (expiresAt > now) {
                    proposal.pendingApproval = { nonce, expiresAt, msgHash };
                }
            }
        }

        // Rebuild approvalRecords from signed_approval events
        if (entry.event === EVENT.SIGNED_APPROVAL && entry.proposalId && entry.approvalDetails) {
            const proposal = proposals.get(entry.proposalId);
            if (proposal) {
                proposal.approved = true;
                proposal.pendingApproval = undefined; // Clear pending after approval

                // Rebuild ApprovalRecord from approvalDetails
                const record: ApprovalRecord = {
                    approval: {
                        proposalId: entry.proposalId,
                        expiresAt: entry.approvalDetails.expiresAt,
                        nonce: entry.approvalDetails.nonce,
                        approverAddress: entry.approvalDetails.approverAddress,
                        signature: entry.approvalDetails.signature,
                    },
                    msgHash: entry.approvalDetails.msgHash,
                    verifiedAt: new Date(entry.ts),
                    proposalEntryHash: entry.approvalDetails.proposalEntryHash,
                };
                approvalRecords.set(entry.proposalId, record);

                // Mark nonce as used (replay prevention)
                nonceTracker.checkAndMark(sessionId, entry.approvalDetails.approverAddress, entry.approvalDetails.nonce);

                rehydratedApprovals++;
            }
        }

        // Mark executed proposals from execute events (server-side)
        if (entry.event === EVENT.EXECUTE && entry.proposalId && entry.decision === 'allow') {
            const proposal = proposals.get(entry.proposalId);
            if (proposal) {
                proposal.executed = true;
            }
        }

        // Mark executed proposals from agent_completed events (Plan B)
        if (entry.event === EVENT.AGENT_COMPLETED && entry.proposalId) {
            const proposal = proposals.get(entry.proposalId);
            if (proposal) {
                proposal.executed = true;
            }
        }
    }

    return { rehydratedProposals, rehydratedApprovals };
}

/**
 * Get or create a persistent session ID.
 * This ensures that restarts don't invalidate prior approvals (which sign sessionId).
 */
function getOrCreateSessionId(logDir: string, providedId?: string): string {
    if (providedId) return providedId;

    // Use native mkdirSync to avoid shell injection
    mkdirSync(logDir, { recursive: true });

    const sessionFile = resolve(logDir, 'session-id.txt');
    if (existsSync(sessionFile)) {
        const existing = readFileSync(sessionFile, 'utf-8').trim();
        if (existing) return existing;
    }

    const newId = randomUUID();
    writeFileSync(sessionFile, newId, 'utf-8');
    return newId;
}

export async function createServer(options?: {
    policyPath?: string;
    logDir?: string;
    sessionId?: string;
    approversPath?: string;
}) {
    const logDir = options?.logDir ?? process.env.LOGDIR ?? '.logs';
    const sessionId = getOrCreateSessionId(logDir, options?.sessionId);

    const evaluator = new PolicyEvaluator(options?.policyPath);
    const hashLogger = new HashChainLogger({ logDir, sessionId });
    const approversConfig = loadApproversConfig(options?.approversPath);

    // Verify log chain integrity before trusting it
    const logPath = hashLogger.getLogPath();
    if (existsSync(logPath)) {
        const chainResult = verifyLogChain(logPath);
        if (!chainResult.valid) {
            console.error(`❌ Log chain integrity check FAILED at entry ${chainResult.brokenAt}: ${chainResult.error}`);
            console.error('⚠️  Refusing to rehydrate from untrusted log. Rotating log file.');

            // Rotate corrupt log
            hashLogger.rotateLog();
            console.log('🔄 Log rotated to start fresh chain.');
        } else {
            // Rehydrate state from verified log
            const { rehydratedProposals, rehydratedApprovals } = rehydrateFromLog(
                hashLogger,
                proposals,
                approvalRecords,
                nonceTracker,
                sessionId
            );
            if (rehydratedProposals > 0 || rehydratedApprovals > 0) {
                console.log(`🔄 Rehydrated ${rehydratedProposals} proposals and ${rehydratedApprovals} approvals from log`);
            }
        }
    }

    // Auth token (optional, but strongly recommended for production)
    const authToken = process.env.CLAWGUARDTOKEN;
    if (!authToken) {
        console.warn('⚠️  CLAWGUARDTOKEN not set → running unauthenticated (dev mode)');
    }

    // Fastify has built-in pino logger
    const app = Fastify({ logger: true });
    await app.register(cors);

    // Protected paths for auth
    const protectedPaths = ['/v1/propose_action', '/v1/approval_payload', '/v1/approve_action', '/v1/execute_action', '/v1/complete_action'];

    // Simple in-memory rate limiter for approval_payload
    const approvalPayloadRateLimit = new Map<string, { count: number; resetAt: number }>();
    const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
    const RATE_LIMIT_MAX = 10; // 10 requests per minute per IP

    app.addHook('preHandler', async (request, reply) => {
        // Skip auth for non-protected paths
        if (!protectedPaths.some(p => request.url.startsWith(p))) {
            return;
        }

        // Rate limit approval_payload specifically
        if (request.url.startsWith('/v1/approval_payload')) {
            // CAUTION: request.ip may be spoofed if behind a reverse proxy without proper trust configuration.
            // If deploying behind Nginx/LB, configure Fastify 'trustProxy' or validating headers.
            const ip = request.ip || 'unknown';
            const now = Date.now();
            const entry = approvalPayloadRateLimit.get(ip);

            if (entry && entry.resetAt > now) {
                if (entry.count >= RATE_LIMIT_MAX) {
                    return reply.status(429).send({
                        error: 'Rate limit exceeded',
                        hint: `Max ${RATE_LIMIT_MAX} requests per minute for approval_payload`,
                        retryAfter: Math.ceil((entry.resetAt - now) / 1000),
                    });
                }
                entry.count++;
            } else {
                approvalPayloadRateLimit.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
            }
        }

        // Skip if no token configured (development mode)
        if (!authToken) {
            return;
        }

        // Robust Bearer parsing (handle extra whitespace)
        const authHeader = request.headers.authorization?.trim();
        const provided = authHeader?.startsWith('Bearer ')
            ? authHeader.slice(7).trim()
            : undefined;

        if (provided !== authToken) {
            // Log auth failure
            hashLogger.log({
                tool: 'server',
                action: 'auth_failed',
                args_hash: sha256({ path: request.url, method: request.method }),
                decision: 'deny',
                reason: 'Invalid or missing CLAWGUARD_TOKEN',
                result_hash: sha256({ blocked: true }),
            });

            return reply.status(401).send({
                error: 'Unauthorized',
                hint: 'Set Authorization: Bearer <CLAWGUARD_TOKEN> header',
            });
        }
    });

    // GET /v1/status
    app.get('/v1/status', async () => {
        return {
            status: 'ok',
            sessionId,
            authEnabled: !!authToken,
            proposalCount: proposals.size,
            approverCount: approversConfig.approvers.length,
            logPath: hashLogger.getLogPath(),
            lastHash: hashLogger.getLastHash(),
            policyPath: evaluator.getPolicyPath(),
            policyHash: evaluator.getPolicyHash(),
        };
    });

    // POST /v1/propose_action
    app.post('/v1/propose_action', async (request, reply) => {
        const parseResult = ProposeActionSchema.safeParse(request.body);
        if (!parseResult.success) {
            return reply.status(400).send({
                error: 'Invalid request',
                details: parseResult.error.format(),
            });
        }

        const { tool, action, args, context, meta } = parseResult.data;
        const actionRequest: ActionRequest = { tool, action, args, context };

        let evalResult = evaluator.evaluate(actionRequest);
        const policyHash = evaluator.getPolicyHash();
        const argsHash = sha256(args);

        // Untrusted-input gate: force needs_approval for risky tools
        const riskyTools: ToolType[] = ['shell', 'network'];
        if (meta?.untrustedSource && riskyTools.includes(tool) && evalResult.decision === 'allow') {
            evalResult = {
                decision: 'needs_approval',
                reason: `${evalResult.reason} (forced approval: untrusted source '${meta.untrustedSource}')`,
            };
        }

        const proposalId = randomUUID();

        // Log the proposal with raw details for rehydration
        const logEntry = hashLogger.log({
            tool,
            action,
            args_hash: argsHash,
            decision: evalResult.decision,
            reason: evalResult.reason,
            result_hash: sha256({}), // No result yet
            proposalId,
            event: 'proposal_created',
            proposalDetails: {
                requestedAction: action,
                args,
                argsHash,
                policyHash,
                untrustedSource: meta?.untrustedSource,
            },
        });

        const proposal: Proposal = {
            id: proposalId,
            tool,
            action,
            args,
            context,
            decision: evalResult.decision,
            reason: evalResult.reason,
            approved: evalResult.decision === 'allow',
            executed: false,
            createdAt: new Date(),
            entryHash: logEntry.entry_hash,
            argsHash,
            policyHash,
            untrustedSource: meta?.untrustedSource,
        };

        proposals.set(proposalId, proposal);

        // If Allowed, Issue Permit (Plan B)
        let permit: string | undefined;
        if (evalResult.decision === 'allow') {
            permit = await createPermit({
                v: 1,
                iss: serverId,
                sub: sessionId,
                aud: 'openclaw-runtime',
                sessionId,
                proposalId,
                proposalEntryHash: logEntry.entry_hash,
                policyHash,
                tool,
                action,
                argsHash,
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + 60, // 60s TTL
                jti: proposalId, // Simple nonce binding
            }, serverKeypair);
        }

        return {
            decision: evalResult.decision,
            reason: evalResult.reason,
            proposalId,
            proposalEntryHash: logEntry.entry_hash,
            permit,
            // Pointer to authoritative approval issuance
            approvalRequired: evalResult.decision === 'needs_approval' ? {

                endpoint: `/v1/approval_payload/${proposalId}`,
                ttlSeconds: MAX_APPROVAL_TTL,
            } : undefined,
        };
    });

    // GET /v1/approval_payload/:proposalId - Get payload to sign (idempotent)
    app.get<{ Params: { proposalId: string } }>('/v1/approval_payload/:proposalId', async (request, reply) => {
        const { proposalId } = request.params;
        const proposal = proposals.get(proposalId);

        if (!proposal) {
            return reply.status(404).send({ error: 'Proposal not found' });
        }

        if (proposal.decision !== 'needs_approval') {
            return reply.status(400).send({ error: 'Proposal does not require approval' });
        }

        const now = Math.floor(Date.now() / 1000);

        // Lazy clear: remove stale pendingApproval if expired
        if (proposal.pendingApproval && proposal.pendingApproval.expiresAt <= now) {
            proposal.pendingApproval = undefined;
        }

        // Idempotent: if pendingApproval exists and not expired, return same
        if (proposal.pendingApproval && proposal.pendingApproval.expiresAt > now) {
            const { nonce, expiresAt, msgHash } = proposal.pendingApproval;

            // Rebuild payload for response (same nonce/expiresAt)
            const payload = buildCanonicalPayload({
                sessionId,
                proposalId,
                proposalEntryHash: proposal.entryHash,
                tool: proposal.tool,
                action: proposal.action,
                argsHash: proposal.argsHash,
                policyHash: proposal.policyHash,
                expiresAt,
                nonce,
                untrustedSource: proposal.untrustedSource,
            });

            // Log reuse for audit trail with raw details for rehydration
            hashLogger.log({
                tool: proposal.tool,
                action: proposal.action,
                args_hash: proposal.argsHash,
                decision: 'allow',
                reason: 'Returning existing pendingApproval (idempotent)',
                result_hash: sha256({ msgHash }),
                proposalId,
                event: 'approval_payload_reused',
                pendingApprovalDetails: { nonce, expiresAt, msgHash },
            });

            return {
                payload,
                msgHash,
                expiresAt,
                nonce,
                reissued: false,
                instructions: [
                    '1. Review the payload carefully (this is what you are approving)',
                    '2. Sign the payload JSON bytes as a personal message with your Sui wallet',
                    '3. POST to /v1/approve_action with { proposalId, expiresAt, nonce, approverAddress, signature }',
                ],
            };
        }

        // Issue new nonce and expiresAt (first time or after expiry)
        const nonce = generateNonce();
        const expiresAt = now + MAX_APPROVAL_TTL;

        const payload = buildCanonicalPayload({
            sessionId,
            proposalId,
            proposalEntryHash: proposal.entryHash,
            tool: proposal.tool,
            action: proposal.action,
            argsHash: proposal.argsHash,
            policyHash: proposal.policyHash,
            expiresAt,
            nonce,
            untrustedSource: proposal.untrustedSource,
        });

        const msgHash = computeMsgHash(payload);

        // Store issued approval (authoritative)
        proposal.pendingApproval = { nonce, expiresAt, msgHash };

        // Log approval_payload_issued event with raw details for rehydration
        hashLogger.log({
            tool: proposal.tool,
            action: proposal.action,
            args_hash: proposal.argsHash,
            decision: 'allow',
            reason: 'Approval payload issued for signing',
            result_hash: sha256({ msgHash }),
            proposalId,
            event: 'approval_payload_issued',
            pendingApprovalDetails: { nonce, expiresAt, msgHash },
        });

        return {
            payload,
            msgHash,
            expiresAt,
            nonce,
            reissued: true,
            instructions: [
                '1. Review the payload carefully (this is what you are approving)',
                '2. Sign the payload JSON bytes as a personal message with your Sui wallet',
                '3. POST to /v1/approve_action with { proposalId, expiresAt, nonce, approverAddress, signature }',
            ],
        };
    });

    // POST /v1/approve_action - Signed approval
    app.post('/v1/approve_action', async (request, reply) => {
        const parseResult = SignedApproveSchema.safeParse(request.body);
        if (!parseResult.success) {
            return reply.status(400).send({
                error: 'Invalid request',
                details: parseResult.error.format(),
            });
        }

        const approval: SignedApproval = parseResult.data;
        const proposal = proposals.get(approval.proposalId);

        if (!proposal) {
            return reply.status(404).send({ error: 'Proposal not found' });
        }

        if (proposal.decision === 'allow') {
            return reply.status(400).send({ error: 'Proposal already allowed, no approval needed' });
        }

        if (proposal.decision === 'deny') {
            return reply.status(403).send({ error: 'Proposal denied by policy, cannot approve' });
        }

        // Require issued approval (from /v1/approval_payload/:proposalId)
        if (!proposal.pendingApproval) {
            return reply.status(400).send({
                error: 'No approval issued. GET /v1/approval_payload/:proposalId first.',
            });
        }

        // Validate nonce and expiresAt match issued values (authoritative)
        if (approval.nonce !== proposal.pendingApproval.nonce) {
            return reply.status(400).send({ error: 'Nonce does not match issued approval' });
        }
        if (approval.expiresAt !== proposal.pendingApproval.expiresAt) {
            return reply.status(400).send({ error: 'expiresAt does not match issued approval' });
        }

        // Enforce TTL cap (server-side, reject anything beyond MAX_APPROVAL_TTL)
        const now = Math.floor(Date.now() / 1000);
        if (approval.expiresAt > now + MAX_APPROVAL_TTL) {
            return reply.status(400).send({
                error: `expiresAt too far in future (max ${MAX_APPROVAL_TTL}s)`,
            });
        }

        // Check nonce reuse (read-only first to prevent DoS via invalid signatures)
        if (!nonceTracker.check(sessionId, approval.approverAddress, approval.nonce)) {
            return reply.status(400).send({ error: 'Nonce already used (replay attempt)' });
        }

        // Build expected payload (must match issued msgHash)
        const expectedPayload = buildCanonicalPayload({
            sessionId,
            proposalId: approval.proposalId,
            proposalEntryHash: proposal.entryHash,
            tool: proposal.tool,
            action: proposal.action,
            argsHash: proposal.argsHash,
            policyHash: proposal.policyHash,
            expiresAt: approval.expiresAt,
            nonce: approval.nonce,
            untrustedSource: proposal.untrustedSource,
        });

        // Cryptographic binding: verify rebuilt payload matches issued msgHash
        const rebuiltMsgHash = computeMsgHash(expectedPayload);
        if (rebuiltMsgHash !== proposal.pendingApproval.msgHash) {
            return reply.status(500).send({
                error: 'Internal error: payload mismatch (possible server bug)',
                hint: 'This should never happen; if it does, contact support.',
            });
        }

        try {
            const record = await verifyApproval(
                approval,
                expectedPayload,
                approversConfig.approvers
            );

            // Valid signature! Now atomically consume the nonce to prevent replay
            if (!nonceTracker.checkAndMark(sessionId, approval.approverAddress, approval.nonce)) {
                throw new Error('Nonce already used (race condition replay attempt)');
            }

            // Store approval record
            approvalRecords.set(approval.proposalId, record);
            proposal.approved = true;
            proposal.pendingApproval = undefined; // Clear pending

            // Log the approval with RAW fields for forensic verification
            hashLogger.log({
                tool: proposal.tool,
                action: proposal.action,
                args_hash: proposal.argsHash,
                decision: 'allow',
                reason: `Signed by ${approval.approverAddress}`,
                result_hash: sha256({ approved: true }),
                proposalId: approval.proposalId,
                event: 'signed_approval',
                // Raw approval details stored verbatim for independent verification
                approvalDetails: {
                    approverAddress: approval.approverAddress,
                    signature: approval.signature,
                    msgHash: record.msgHash,
                    nonce: approval.nonce,
                    expiresAt: approval.expiresAt,
                    proposalEntryHash: record.proposalEntryHash,
                },
            });

            // Issue Permit (Plan B: Approval Success)
            const permit = await createPermit({
                v: 1,
                iss: serverId,
                sub: sessionId,
                aud: 'openclaw-runtime',
                sessionId,
                proposalId: approval.proposalId,
                proposalEntryHash: record.proposalEntryHash,
                policyHash: proposal.policyHash,
                tool: proposal.tool,
                action: proposal.action,
                argsHash: proposal.argsHash,
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + 60, // 60s TTL
                jti: approval.nonce,
            }, serverKeypair);

            return {
                approved: true,
                proposalId: approval.proposalId,
                msgHash: record.msgHash,
                approverAddress: approval.approverAddress,
                verifiedAt: record.verifiedAt.toISOString(),
                permit,
            };

        } catch (e) {
            const errorMsg = e instanceof Error ? e.message : String(e);

            // Log failed approval attempt with raw fields
            hashLogger.log({
                tool: proposal.tool,
                action: proposal.action,
                args_hash: proposal.argsHash,
                decision: 'deny',
                reason: `Approval failed: ${errorMsg}`,
                result_hash: sha256({ error: errorMsg }),
                proposalId: approval.proposalId,
                event: 'signed_approval_failed',
            });

            return reply.status(403).send({
                error: 'Approval verification failed',
                details: errorMsg,
            });
        }
    });

    // POST /v1/execute_action
    app.post('/v1/execute_action', async (request, reply) => {
        const parseResult = ExecuteActionSchema.safeParse(request.body);
        if (!parseResult.success) {
            return reply.status(400).send({
                error: 'Invalid request',
                details: parseResult.error.format(),
            });
        }

        const { proposalId } = parseResult.data;
        const proposal = proposals.get(proposalId);

        if (!proposal) {
            return reply.status(404).send({
                error: 'Proposal not found',
                proposalId,
            });
        }

        if (proposal.decision === 'deny') {
            return reply.status(403).send({
                ok: false,
                error: 'Action denied by policy',
                reason: proposal.reason,
            });
        }

        // Check signed approval for needs_approval proposals
        if (proposal.decision === 'needs_approval') {
            const approvalRecord = approvalRecords.get(proposalId);

            if (!approvalRecord) {
                // Log blocked execution attempt
                hashLogger.log({
                    tool: proposal.tool,
                    action: proposal.action,
                    args_hash: proposal.argsHash,
                    event: 'execute_blocked_missing_approval',
                    decision: 'deny',
                    reason: 'Execution blocked: signed approval required but not provided',
                    result_hash: sha256({ blocked: true }),
                    proposalId,
                });

                return reply.status(403).send({
                    ok: false,
                    error: 'Action requires signed approval',
                    hint: 'GET /v1/approval_payload/:proposalId for signing instructions',
                });
            }

            // Check expiry
            const now = Math.floor(Date.now() / 1000);
            if (approvalRecord.approval.expiresAt < now) {
                return reply.status(403).send({
                    ok: false,
                    error: 'Approval has expired',
                    expiredAt: approvalRecord.approval.expiresAt,
                    currentTime: now,
                });
            }
        }

        if (proposal.executed) {
            return reply.status(409).send({
                ok: false,
                error: 'Action already executed',
            });
        }

        // Execute the action
        let output: unknown;
        const artifactRefs: ArtifactRef[] = [];

        try {
            switch (proposal.tool) {
                case 'shell':
                    const command = (proposal.args.command as string) ?? proposal.action;
                    const result = execSync(command, {
                        encoding: 'utf-8',
                        timeout: 30000,
                        maxBuffer: 1024 * 1024,
                    });
                    output = result;
                    artifactRefs.push({ type: 'stdout', hash: sha256(result) });
                    break;

                case 'filesystem':
                    if (proposal.action === 'read') {
                        const path = proposal.args.path as string;
                        const content = readFileSync(path, 'utf-8');
                        output = content;
                        artifactRefs.push({ type: 'file', path, hash: sha256(content) });
                    } else if (proposal.action === 'write') {
                        const path = proposal.args.path as string;
                        const content = proposal.args.content as string;
                        writeFileSync(path, content);
                        output = { written: true, path };
                        artifactRefs.push({ type: 'file', path, hash: sha256(content) });
                    }
                    break;

                default:
                    output = { message: `Tool ${proposal.tool} execution not implemented` };
            }

            proposal.executed = true;

            // Log execution
            hashLogger.log({
                tool: proposal.tool,
                action: proposal.action,
                args_hash: proposal.argsHash,
                decision: 'allow',
                reason: 'Execution completed',
                result_hash: sha256(output),
                proposalId,
                event: 'execute',
            });

            return {
                ok: true,
                output,
                artifactRefs,
            };

        } catch (error) {
            const errorMsg = error instanceof Error ? error.message : String(error);

            hashLogger.log({
                tool: proposal.tool,
                action: proposal.action,
                args_hash: proposal.argsHash,
                decision: 'deny',
                reason: `Execution failed: ${errorMsg}`,
                result_hash: sha256({ error: errorMsg }),
                proposalId,
                event: 'execute_failed',
            });

            return reply.status(500).send({
                ok: false,
                error: errorMsg,
                artifactRefs,
            });
        }
    });

    // POST /v1/complete_action (Plan B: Hardened Agent reports completion)
    app.post('/v1/complete_action', async (request, reply) => {
        const { proposalId, result, permit } = request.body as { proposalId: string; result: unknown; permit?: string };

        if (!proposalId) return reply.status(400).send({ error: 'Missing proposalId' });

        // 1. Verify Permit (Security Critical)
        if (!permit) {
            return reply.status(401).send({ error: 'Missing permit token' });
        }

        let payload;
        try {
            // Verify signature using server's public key
            const publicKey = serverKeypair.getPublicKey();
            payload = await verifyPermit(permit, publicKey);
        } catch (e) {
            console.error('Permit verification failed:', e);
            return reply.status(403).send({ error: 'Invalid permit signature' });
        }

        // 2. Bind Permit to Proposal
        if (payload.proposalId !== proposalId) { return reply.status(403).send({ error: 'Permit proposalId mismatch' }); }
        if (payload.sessionId !== sessionId) { return reply.status(403).send({ error: 'Permit sessionId mismatch' }); }

        const proposal = proposals.get(proposalId);
        if (!proposal) { return reply.status(404).send({ error: 'Proposal not found' }); }

        // 3. Verify Proposal Binding (Prevent args swapping)
        if (payload.argsHash !== proposal.argsHash) { return reply.status(403).send({ error: 'Permit args mismatch' }); }
        if (payload.tool !== proposal.tool) { return reply.status(403).send({ error: 'Permit tool mismatch' }); }
        if (payload.action !== proposal.action) { return reply.status(403).send({ error: 'Permit action mismatch' }); }
        if (payload.policyHash !== proposal.policyHash) { return reply.status(403).send({ error: 'Permit policy mismatch' }); }
        // Ensure proposal has entryHash (it should after being logged)
        if (proposal.entryHash && payload.proposalEntryHash !== proposal.entryHash) {
            return reply.status(403).send({ error: 'Permit entryHash mismatch' });
        }

        // 4. Check Expiry
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp < now) { return reply.status(403).send({ error: 'Permit expired' }); }

        // 5. Replay Protection (JTI + Used Permits)
        if (usedPermits.has(payload.jti)) {
            return reply.status(403).send({ error: 'Permit already used (replay)' });
        }

        if (proposal.executed) {
            return reply.status(409).send({ error: 'Action already executed' });
        }

        // Mark Used (Before logging to prevent race)
        usedPermits.add(payload.jti);
        proposal.executed = true;

        hashLogger.log({
            tool: proposal.tool,
            action: proposal.action,
            args_hash: proposal.argsHash,
            decision: 'allow',
            reason: 'Agent reported completion (Plan B)',
            result_hash: sha256(result),
            proposalId,
            event: 'agent_completed',
            completionDetails: { result },
        });

        return { ok: true, status: 'recorded' };
    });

    return { app, evaluator, hashLogger, sessionId };
}

// Start server if run directly
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
    const { app } = await createServer();
    const port = parseInt(process.env.PORT ?? '3000', 10);
    await app.listen({ port, host: '127.0.0.1' });
    console.log(`ClawGuard server listening on http://127.0.0.1:${port}`);
}
