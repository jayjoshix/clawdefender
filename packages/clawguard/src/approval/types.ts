/**
 * Signed-Approval Types
 * 
 * Canonical types for cryptographic approval workflow.
 * Signatures bind approvals to exact proposal state.
 */

import type { ToolType } from '../policy/evaluator.js';

/**
 * Canonical approval payload that gets signed.
 * Server computes: msgHash = sha256(stableJson(payload))
 * Approver signs: msgHash bytes as personal message
 */
export interface ApprovalPayloadV1 {
    /** Domain separator for signature isolation */
    domain: 'CLAWGUARD_APPROVAL_V1';
    /** Intent of this signature (prevents reuse for other purposes) */
    intent: 'EXECUTE_ACTION';
    /** Current session ID */
    sessionId: string;
    /** Proposal being approved */
    proposalId: string;
    /** Hash of the proposal log entry (immutable, race-free binding) */
    proposalEntryHash: string;
    /** Tool type */
    tool: ToolType;
    /** Action name */
    action: string;
    /** SHA256 of stableJson(args) */
    argsHash: string;
    /** Policy file hash at proposal time */
    policyHash: string;
    /** Expiration timestamp (Unix seconds) */
    expiresAt: number;
    /** Random 32-byte hex nonce (prevents replay) */
    nonce: string;
    /** Untrusted source flag if present (for risk context) */
    untrustedSource?: 'web' | 'email' | 'issue' | 'clipboard';
}

/**
 * Signed approval submitted by approver
 */
export interface SignedApproval {
    /** Proposal ID being approved */
    proposalId: string;
    /** Expiration timestamp (Unix seconds) */
    expiresAt: number;
    /** Random 32-byte hex nonce */
    nonce: string;
    /** Sui address of approver (hex, 0x-prefixed) */
    approverAddress: string;
    /** Base64-encoded signature over msgHash */
    signature: string;
}

/**
 * Server-side approval record (stored after verification)
 */
export interface ApprovalRecord {
    /** Original signed approval */
    approval: SignedApproval;
    /** Hash that was signed: sha256(stableJson(payload)) */
    msgHash: string;
    /** Timestamp when approval was verified */
    verifiedAt: Date;
    /** Proposal entry hash that was bound */
    proposalEntryHash: string;
}

/**
 * Approver from allowlist config
 */
export interface Approver {
    /** Sui address (hex, 0x-prefixed) */
    address: string;
    /** Human-readable name */
    name: string;
}

/**
 * Approvers config file schema
 */
export interface ApproversConfig {
    approvers: Approver[];
}
