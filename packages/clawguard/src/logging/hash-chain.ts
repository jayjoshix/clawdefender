import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { PolicyDecision } from '../policy/schema.js';
import { sha256, sha256Bytes, stableJson } from '../util/canonical-json.js';

// Re-export for backwards compatibility
export { sha256, sha256Bytes };

export interface LogEntry {
    ts: string;
    tool: string;
    action: string; // User-requested action (e.g., "cat ~/.ssh/id_rsa")
    args_hash: string;
    decision: PolicyDecision;
    reason: string;
    result_hash: string;
    prev_hash: string;
    entry_hash: string;
    proposalId?: string;
    approvalId?: string;

    /** Semantic event type for rehydration (e.g., 'proposal_created', 'execute', 'signed_approval') */
    event?: string;

    /** Raw proposal details for rehydration (stored on proposal_created) */
    proposalDetails?: {
        requestedAction: string;
        args: Record<string, unknown>;
        argsHash: string;
        policyHash: string;
        untrustedSource?: string;
    };

    /** Raw pending approval details for rehydration (stored on approval_payload_issued) */
    pendingApprovalDetails?: {
        nonce: string;
        expiresAt: number;
        msgHash: string;
    };

    /** Raw approval details for forensic verification (stored on signed_approval) */
    approvalDetails?: {
        approverAddress: string;
        signature: string;
        msgHash: string;
        nonce: string;
        expiresAt: number;
        proposalEntryHash: string;
    };

    /** Raw completion details from agent (Plan B) */
    completionDetails?: {
        result: unknown;
    };
}

export interface LogOptions {
    logDir: string;
    sessionId: string;
}


export class HashChainLogger {
    private logPath: string;
    private prevHash: string = '0'.repeat(64); // Genesis hash

    constructor(options: LogOptions) {
        const { logDir, sessionId } = options;

        // Ensure log directory exists
        if (!existsSync(logDir)) {
            mkdirSync(logDir, { recursive: true });
        }

        this.logPath = join(logDir, `session-${sessionId}.jsonl`);

        // If log file exists, get the last hash
        if (existsSync(this.logPath)) {
            const content = readFileSync(this.logPath, 'utf-8').trim();
            if (content) {
                const lines = content.split('\n');
                const lastLine = lines[lines.length - 1];
                try {
                    const lastEntry = JSON.parse(lastLine) as LogEntry;
                    this.prevHash = lastEntry.entry_hash;
                } catch {
                    // Log corrupted, start fresh
                }
            }
        } else {
            // Create empty log file to mark session start
            appendFileSync(this.logPath, '');
        }
    }

    /**
     * Append a tamper-evident log entry
     */
    log(entry: Omit<LogEntry, 'ts' | 'entry_hash' | 'prev_hash'>): LogEntry {
        const ts = new Date().toISOString();

        // Build the entry without entry_hash first
        const partial: Omit<LogEntry, 'entry_hash'> = {
            ts,
            tool: entry.tool,
            action: entry.action,
            args_hash: entry.args_hash,
            decision: entry.decision,
            reason: entry.reason,
            result_hash: entry.result_hash,
            prev_hash: this.prevHash,
            proposalId: entry.proposalId,
            approvalId: entry.approvalId,

            // New fields for rehydration/audit (must be part of hash chain)
            event: entry.event,
            proposalDetails: entry.proposalDetails,
            pendingApprovalDetails: entry.pendingApprovalDetails,
            approvalDetails: entry.approvalDetails,
            completionDetails: entry.completionDetails,
        };

        // Compute entry hash over all fields except entry_hash itself
        const entry_hash = sha256(partial);

        const fullEntry: LogEntry = {
            ...partial,
            entry_hash,
        };

        // Append to log file (stableJson for deterministic key order)
        appendFileSync(this.logPath, stableJson(fullEntry) + '\n');

        // Update prev_hash for next entry
        this.prevHash = entry_hash;

        return fullEntry;
    }

    /**
     * Get the current log path
     */
    getLogPath(): string {
        return this.logPath;
    }

    /**
     * Rotate the current log file (e.g., if corrupt) and start fresh.
     * Renames current file to .corrupt-<timestamp> and resets prevHash.
     */
    rotateLog(): void {
        if (existsSync(this.logPath)) {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const corruptedPath = `${this.logPath}.corrupt-${timestamp}`;
            try {
                // Rename corrupt file
                const { renameSync } = require('node:fs');
                renameSync(this.logPath, corruptedPath);
            } catch (e) {
                console.error(`Failed to rotate log: ${e}`);
            }
        }

        // Reset chain state
        this.prevHash = '0'.repeat(64);

        // Create new empty log (truncate if rename failed to ensure fresh start)
        writeFileSync(this.logPath, '');

        // Log a reset marker
        this.log({
            tool: 'system',
            action: 'log_rotation',
            args_hash: '0'.repeat(64),
            decision: 'allow',
            reason: 'Log chain reset due to corruption/verification failure',
            result_hash: '0'.repeat(64),
            event: 'log_reset',
        });
    }

    /**
     * Get the last hash in the chain
     */
    getLastHash(): string {
        return this.prevHash;
    }

    /**
     * Read all entries from the log
     */
    readAll(): LogEntry[] {
        if (!existsSync(this.logPath)) {
            return [];
        }

        const content = readFileSync(this.logPath, 'utf-8').trim();
        if (!content) {
            return [];
        }

        return content.split('\n').map(line => JSON.parse(line) as LogEntry);
    }
}

/**
 * Verify the integrity of a log file
 * Returns { valid: boolean, error?: string, brokenAt?: number }
 */
export function verifyLogChain(logPath: string): { valid: boolean; error?: string; brokenAt?: number } {
    if (!existsSync(logPath)) {
        return { valid: false, error: 'Log file does not exist' };
    }

    const content = readFileSync(logPath, 'utf-8').trim();
    if (!content) {
        return { valid: true }; // Empty log is valid
    }

    const lines = content.split('\n');
    let prevHash = '0'.repeat(64); // Genesis hash

    for (let i = 0; i < lines.length; i++) {
        let entry: LogEntry;
        try {
            entry = JSON.parse(lines[i]) as LogEntry;
        } catch (e) {
            return { valid: false, error: `Invalid JSON at line ${i + 1}`, brokenAt: i };
        }

        // Verify prev_hash chain
        if (entry.prev_hash !== prevHash) {
            return {
                valid: false,
                error: `Chain broken at line ${i + 1}: expected prev_hash ${prevHash}, got ${entry.prev_hash}`,
                brokenAt: i,
            };
        }

        // Verify entry_hash
        const { entry_hash, ...partial } = entry;
        const computed = sha256(partial);
        if (computed !== entry_hash) {
            return {
                valid: false,
                error: `Hash mismatch at line ${i + 1}: expected ${computed}, got ${entry_hash}`,
                brokenAt: i,
            };
        }

        prevHash = entry_hash;
    }

    return { valid: true };
}
