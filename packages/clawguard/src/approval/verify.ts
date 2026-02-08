/**
 * Signed-Approval Verification
 * 
 * Uses Mysten SDK's verifyPersonalMessageSignature for Sui wallet compatibility.
 * Signs stableJson(payload) bytes directly - human-auditable in wallet UI.
 * Logs msgHash = sha256(payloadJson) for compact integrity anchoring.
 */

import { randomBytes } from 'node:crypto';
import { verifyPersonalMessageSignature } from '@mysten/sui/verify';
import type {
    ApprovalPayloadV1,
    SignedApproval,
    ApprovalRecord,
    Approver
} from './types.js';
import type { ToolType } from '../policy/evaluator.js';
import { canonicalize, stableJson, sha256 } from '../util/canonical-json.js';

// Re-export for convenience
export { canonicalize, stableJson };

/** Maximum approval TTL in seconds (5 minutes) */
export const MAX_APPROVAL_TTL = 300;

/**
 * Compute SHA256 hash of stableJson representation
 */
export function computeMsgHash(payload: ApprovalPayloadV1): string {
    return sha256(payload);
}

/**
 * Get msg bytes for signing (payload JSON bytes - human-auditable in wallet UI)
 */
export function getMsgBytes(payload: ApprovalPayloadV1): Uint8Array {
    const json = stableJson(payload);
    return new TextEncoder().encode(json);
}

/**
 * Generate a random 32-byte nonce (hex)
 */
export function generateNonce(): string {
    return randomBytes(32).toString('hex');
}

/**
 * Build canonical approval payload from proposal data
 */
export function buildCanonicalPayload(params: {
    sessionId: string;
    proposalId: string;
    proposalEntryHash: string;
    tool: ToolType;
    action: string;
    argsHash: string;
    policyHash: string;
    expiresAt: number;
    nonce: string;
    untrustedSource?: 'web' | 'email' | 'issue' | 'clipboard';
}): ApprovalPayloadV1 {
    const payload: ApprovalPayloadV1 = {
        domain: 'CLAWGUARD_APPROVAL_V1',
        intent: 'EXECUTE_ACTION',
        sessionId: params.sessionId,
        proposalId: params.proposalId,
        proposalEntryHash: params.proposalEntryHash,
        tool: params.tool,
        action: params.action,
        argsHash: params.argsHash,
        policyHash: params.policyHash,
        expiresAt: params.expiresAt,
        nonce: params.nonce,
    };

    // Only include untrustedSource if present (for stable serialization)
    if (params.untrustedSource) {
        payload.untrustedSource = params.untrustedSource;
    }

    return payload;
}

/**
 * Verify a signed approval against expected payload and allowlist.
 * Uses Mysten SDK verifyPersonalMessageSignature with address binding.
 * 
 * @returns ApprovalRecord if valid
 * @throws Error if verification fails
 */
export async function verifyApproval(
    approval: SignedApproval,
    expectedPayload: ApprovalPayloadV1,
    allowlist: Approver[]
): Promise<ApprovalRecord> {
    // 1. Check approver is in allowlist
    const approver = allowlist.find(a =>
        a.address.toLowerCase() === approval.approverAddress.toLowerCase()
    );
    if (!approver) {
        throw new Error(`Approver ${approval.approverAddress} not in allowlist`);
    }

    // 2. Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (approval.expiresAt < now) {
        throw new Error(`Approval expired at ${approval.expiresAt}, current time ${now}`);
    }

    // 3. Verify nonce matches
    if (approval.nonce !== expectedPayload.nonce) {
        throw new Error('Nonce mismatch');
    }

    // 4. Compute message hash and get bytes
    const msgHash = computeMsgHash(expectedPayload);
    const msgBytes = getMsgBytes(expectedPayload);

    // 5. Verify signature with address binding
    try {
        const publicKey = await verifyPersonalMessageSignature(
            msgBytes,
            approval.signature,
            { address: approval.approverAddress }
        );

        // Signature verified and matches expected address
        console.log(`   ✅ Signature verified for ${approver.name} (${publicKey.toSuiAddress()})`);
    } catch (e) {
        throw new Error(`Signature verification failed: ${e instanceof Error ? e.message : e}`);
    }

    // 6. Return approval record
    return {
        approval,
        msgHash,
        verifiedAt: new Date(),
        proposalEntryHash: expectedPayload.proposalEntryHash,
    };
}

/**
 * Check if a nonce has been seen (for replay prevention)
 */
export class NonceTracker {
    private seen = new Map<string, Set<string>>(); // sessionId+approver -> nonces

    /**
     * Check and mark nonce as seen
     * @returns true if nonce is fresh (not seen before)
     */
    check(sessionId: string, approverAddress: string, nonce: string): boolean {
        const key = `${sessionId}:${approverAddress.toLowerCase()}`;
        if (!this.seen.has(key)) return true;
        return !this.seen.get(key)!.has(nonce);
    }

    /**
     * Check and mark nonce as seen
     */
    checkAndMark(sessionId: string, approverAddress: string, nonce: string): boolean {
        const key = `${sessionId}:${approverAddress.toLowerCase()}`;

        if (!this.seen.has(key)) {
            this.seen.set(key, new Set());
        }

        const nonces = this.seen.get(key)!;
        if (nonces.has(nonce)) {
            return false; // Already seen
        }

        nonces.add(nonce);
        return true; // Fresh nonce
    }

    /**
     * Clear nonces for a session (on session end)
     */
    clearSession(sessionId: string): void {
        for (const key of this.seen.keys()) {
            if (key.startsWith(`${sessionId}:`)) {
                this.seen.delete(key);
            }
        }
    }
}
