/**
 * Approval Module
 * 
 * Exports signed-approval types and verification utilities.
 */

export type {
    ApprovalPayloadV1,
    SignedApproval,
    ApprovalRecord,
    Approver,
    ApproversConfig,
} from './types.js';

export {
    canonicalize,
    stableJson,
    computeMsgHash,
    getMsgBytes,
    generateNonce,
    buildCanonicalPayload,
    verifyApproval,
    NonceTracker,
    MAX_APPROVAL_TTL,
} from './verify.js';
