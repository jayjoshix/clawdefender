/**
 * Browser Tool Wrapper for OpenClaw Integration
 * 
 * Wraps browser automation through ClawGuard policy firewall.
 * Checks domain allowlist before permitting navigation.
 */

const CLAWGUARD_URL = process.env.CLAWGUARD_URL ?? 'http://localhost:3000';

export interface BrowserResult {
    success: boolean;
    allowed?: boolean;
    error?: string;
    blocked?: boolean;
    reason?: string;
    proposalId?: string;
    approvalId?: string;
}

/**
 * Check if a URL is allowed for browser navigation.
 * 
 * @param url - The URL to navigate to
 * @param autoApprove - If true, automatically approve if needs_approval
 * @returns Result indicating if navigation is allowed
 */
export async function checkNavigation(url: string, autoApprove = false): Promise<BrowserResult> {
    // Extract domain from URL
    let domain: string;
    try {
        const parsed = new URL(url);
        domain = parsed.hostname;
    } catch {
        return { success: false, error: 'Invalid URL' };
    }

    // Propose the navigation
    const proposeResponse = await fetch(`${CLAWGUARD_URL}/v1/propose_action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            tool: 'browser',
            action: 'navigate',
            args: { url, domain },
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

    if (proposal.decision === 'deny') {
        return {
            success: false,
            blocked: true,
            reason: proposal.reason,
            proposalId: proposal.proposalId,
        };
    }

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
        await fetch(`${CLAWGUARD_URL}/v1/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approvalId: proposal.approvalId }),
        });
    }

    return {
        success: true,
        allowed: true,
        proposalId: proposal.proposalId,
    };
}

/**
 * Approve a pending browser action
 */
export async function approveNavigation(approvalId: string): Promise<boolean> {
    const response = await fetch(`${CLAWGUARD_URL}/v1/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approvalId }),
    });

    return response.ok;
}

export default { checkNavigation, approveNavigation };
