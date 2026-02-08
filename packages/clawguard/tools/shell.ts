/**
 * Shell Tool Wrapper for OpenClaw Integration
 * 
 * Wraps shell commands through ClawGuard policy firewall.
 * Instead of direct execution, commands go through propose -> approve -> execute flow.
 */

const CLAWGUARD_URL = process.env.CLAWGUARD_URL ?? 'http://localhost:3000';

export interface ShellResult {
    success: boolean;
    output?: string;
    error?: string;
    blocked?: boolean;
    reason?: string;
    proposalId?: string;
    approvalId?: string;
}

/**
 * Execute a shell command through ClawGuard policy firewall.
 * 
 * @param command - The shell command to execute
 * @param autoApprove - If true, automatically approve if needs_approval
 * @returns Result with output or blocked status
 */
export async function shellExec(command: string, autoApprove = false): Promise<ShellResult> {
    // Step 1: Propose the action
    const proposeResponse = await fetch(`${CLAWGUARD_URL}/v1/propose_action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            tool: 'shell',
            action: 'exec',
            args: { command },
        }),
    });

    if (!proposeResponse.ok) {
        const error = await proposeResponse.text();
        return { success: false, error: `Propose failed: ${error}` };
    }

    const proposal = await proposeResponse.json() as {
        decision: string;
        reason: string;
        proposalId: string;
        approvalId?: string;
    };

    // Step 2: Handle denied actions
    if (proposal.decision === 'deny') {
        return {
            success: false,
            blocked: true,
            reason: proposal.reason,
            proposalId: proposal.proposalId,
        };
    }

    // Step 3: Handle actions needing approval
    if (proposal.decision === 'needs_approval') {
        if (!autoApprove) {
            return {
                success: false,
                blocked: true,
                reason: `Approval required: ${proposal.reason}`,
                proposalId: proposal.proposalId,
                approvalId: proposal.approvalId,
            };
        }

        // Auto-approve
        const approveResponse = await fetch(`${CLAWGUARD_URL}/v1/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approvalId: proposal.approvalId }),
        });

        if (!approveResponse.ok) {
            const error = await approveResponse.text();
            return { success: false, error: `Approve failed: ${error}` };
        }
    }

    // Step 4: Execute the action
    const executeResponse = await fetch(`${CLAWGUARD_URL}/v1/execute_action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proposalId: proposal.proposalId }),
    });

    const executeResult = await executeResponse.json() as {
        ok: boolean;
        output?: string;
        error?: string;
    };

    if (!executeResult.ok) {
        return {
            success: false,
            error: executeResult.error,
            proposalId: proposal.proposalId,
        };
    }

    return {
        success: true,
        output: executeResult.output,
        proposalId: proposal.proposalId,
    };
}

/**
 * Approve a pending action by its approvalId
 */
export async function approveAction(approvalId: string): Promise<boolean> {
    const response = await fetch(`${CLAWGUARD_URL}/v1/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approvalId }),
    });

    return response.ok;
}

export default { shellExec, approveAction };
