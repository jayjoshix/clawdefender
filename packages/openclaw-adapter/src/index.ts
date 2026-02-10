/**
 * ClawGuard OpenClaw Adapter
 *
 * Wraps OpenClaw tool invocations through ClawGuard's policy firewall.
 * Supports both Plan A (server-executed) and Plan B (agent-executed) flows.
 */

export type Tool = 'shell' | 'filesystem' | 'network' | 'browser';
export type Decision = 'allow' | 'deny' | 'needs_approval';

/** Tools that the server can execute (Plan A) */
const SERVER_EXECUTABLE_TOOLS: Tool[] = ['shell', 'filesystem'];

export interface ProposeResponse {
    decision: Decision;
    reason: string;
    proposalId: string;
    proposalEntryHash: string;
    permit?: string; // Present on 'allow' for Plan B
    approvalRequired?: {
        endpoint: string;
        ttlSeconds: number;
    };
}

export interface ApprovalPayload {
    payload: {
        sessionId: string;
        proposalId: string;
        proposalEntryHash: string;
        tool: Tool;
        action: string;
        argsHash: string;
        policyHash: string;
        expiresAt: number;
        nonce: string;
        untrustedSource?: 'web' | 'email' | 'issue' | 'clipboard';
    };
    msgHash: string;
    expiresAt: number;
    nonce: string;
}

export interface ApproveInput {
    proposalId: string;
    expiresAt: number;
    nonce: string;
    approverAddress: string;
    signature: string;
}

export interface StatusResponse {
    sessionId: string;
    authEnabled: boolean;
    proposalCount: number;
    approverCount: number;
    logPath: string;
    lastHash: string;
    policyPath: string;
    policyHash: string;
}

export interface ExecuteResult {
    ok: boolean;
    output?: unknown;
    error?: string;
    hint?: string;
    artifactRefs?: Array<{ type: string; path?: string; hash: string }>;
}

export interface CompleteResult {
    ok: boolean;
    status?: string;
}

/**
 * ClawGuard Client for OpenClaw Integration
 *
 * Usage:
 * ```ts
 * const claw = new ClawGuardClient('http://localhost:3000', 'your-token');
 *
 * // Propose an action
 * const proposal = await claw.propose('shell', 'exec', { command: 'ls -la' });
 *
 * if (proposal.decision === 'deny') {
 *   throw new Error(`Blocked: ${proposal.reason}`);
 * }
 *
 * if (proposal.decision === 'needs_approval') {
 *   // Route to human approver, then call claw.approveAction(...)
 * }
 *
 * // Plan A: Server executes (shell, filesystem)
 * const result = await claw.executeAction(proposal.proposalId);
 *
 * // Plan B: Agent executes (network, browser), then reports
 * const output = await runToolLocally(tool, action, args);
 * await claw.completeAction(proposal.proposalId, output, proposal.permit!);
 * ```
 */
export class ClawGuardClient {
    constructor(
        readonly baseUrl: string,
        readonly token?: string,
    ) { }

    private async req<T>(path: string, body?: unknown): Promise<T> {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
        };
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        const response = await fetch(`${this.baseUrl}${path}`, {
            method: body ? 'POST' : 'GET',
            headers,
            body: body ? JSON.stringify(body) : undefined,
        });

        const json = await response.json();

        if (!response.ok) {
            throw new ClawGuardError(path, response.status, json);
        }

        return json as T;
    }

    /**
     * Propose an action for policy evaluation.
     *
     * @param tool - Tool type: 'shell' | 'filesystem' | 'network' | 'browser'
     * @param action - Action name (e.g., 'exec', 'read', 'write', 'egress')
     * @param args - Tool-specific arguments
     * @param meta - Optional metadata for security context
     */
    async propose(
        tool: Tool,
        action: string,
        args: Record<string, unknown>,
        meta?: { untrustedSource?: 'web' | 'email' | 'issue' | 'clipboard' },
    ): Promise<ProposeResponse> {
        return this.req<ProposeResponse>('/v1/propose_action', {
            tool,
            action,
            args,
            meta,
        });
    }

    /**
     * Get approval payload for human signing.
     * Route this to Telegram/Slack/Web for human approval.
     */
    async getApprovalPayload(proposalId: string): Promise<ApprovalPayload> {
        return this.req<ApprovalPayload>(`/v1/approval_payload/${proposalId}`);
    }

    /**
     * Submit a signed approval from a human approver.
     */
    async approveAction(input: ApproveInput): Promise<{ approved: true; permit: string }> {
        return this.req<{ approved: true; permit: string }>('/v1/approve_action', input);
    }

    /**
     * Plan A: Have the ClawGuard server execute the action.
     * Only works for: shell, filesystem.
     * For network/browser, use Plan B (completeAction).
     */
    async executeAction(proposalId: string): Promise<ExecuteResult> {
        return this.req<ExecuteResult>('/v1/execute_action', { proposalId });
    }

    /**
     * Plan B: Agent executed locally, reports completion to ClawGuard.
     * Required for: network, browser (server doesn't implement these).
     *
     * @param proposalId - The proposal ID from propose()
     * @param result - The result of the local execution
     * @param permit - The permit token from propose() or approveAction()
     */
    async completeAction(
        proposalId: string,
        result: unknown,
        permit: string,
    ): Promise<CompleteResult> {
        return this.req<CompleteResult>('/v1/complete_action', {
            proposalId,
            result,
            permit,
        });
    }

    /**
     * Check server status and policy hash.
     */
    async status(): Promise<StatusResponse> {
        return this.req('/v1/status');
    }
}

/**
 * Error class for ClawGuard API failures.
 */
export class ClawGuardError extends Error {
    constructor(
        public readonly path: string,
        public readonly statusCode: number,
        public readonly response: unknown,
    ) {
        super(`ClawGuard ${path} failed (${statusCode}): ${JSON.stringify(response)}`);
        this.name = 'ClawGuardError';
    }
}

/**
 * Determines if a tool should use Plan A (server-executed) or Plan B (agent-executed).
 * - Plan A: shell, filesystem (server has implementations)
 * - Plan B: network, browser (agent must execute locally)
 */
export function shouldUseServerExecution(tool: Tool): boolean {
    return SERVER_EXECUTABLE_TOOLS.includes(tool);
}

/**
 * High-level wrapper for OpenClaw tool execution.
 * Automatically handles the propose → (approve) → execute/complete flow.
 * 
 * Uses safe defaults:
 * - shell/filesystem → Plan A (server executes)
 * - network/browser → Plan B (agent executes, requires localExecutor)
 */
export async function executeWithClawGuard(
    client: ClawGuardClient,
    tool: Tool,
    action: string,
    args: Record<string, unknown>,
    options?: {
        /** Override: force Plan B even for shell/filesystem */
        forceAgentExecution?: boolean;
        /** Local execution function (required for network/browser, optional for others) */
        localExecutor?: (tool: Tool, action: string, args: Record<string, unknown>) => Promise<unknown>;
        /** Approval handler for needs_approval decisions */
        approvalHandler?: (proposalId: string, payload: ApprovalPayload) => Promise<ApproveInput>;
        /** Metadata for security context */
        meta?: { untrustedSource?: 'web' | 'email' | 'issue' | 'clipboard' };
    },
): Promise<{ decision: Decision; output?: unknown; reason?: string; proposalId?: string }> {
    // Determine execution strategy
    const useServerExecution = shouldUseServerExecution(tool) && !options?.forceAgentExecution;

    // Validate: Plan B tools MUST have localExecutor
    if (!useServerExecution && !options?.localExecutor) {
        throw new Error(
            `Tool '${tool}' requires Plan B execution, but no localExecutor was provided. ` +
            `Provide a localExecutor function to execute this tool locally.`
        );
    }

    // Step 1: Propose
    const proposal = await client.propose(tool, action, args, options?.meta);

    // Step 2: Handle decision
    if (proposal.decision === 'deny') {
        return { decision: 'deny', reason: proposal.reason, proposalId: proposal.proposalId };
    }

    let permit = proposal.permit;

    // Step 3: Handle approval if needed
    if (proposal.decision === 'needs_approval') {
        if (!options?.approvalHandler) {
            return {
                decision: 'needs_approval',
                reason: `Approval required. ProposalId: ${proposal.proposalId}`,
                proposalId: proposal.proposalId,
            };
        }

        const payload = await client.getApprovalPayload(proposal.proposalId);
        const approveInput = await options.approvalHandler(proposal.proposalId, payload);
        const approveResult = await client.approveAction(approveInput);
        permit = approveResult.permit;
    }

    // Step 4: Execute
    if (useServerExecution) {
        // Plan A: Server executes (shell, filesystem)
        const result = await client.executeAction(proposal.proposalId);
        if (!result.ok) {
            return { decision: 'deny', reason: result.error, proposalId: proposal.proposalId };
        }
        return { decision: 'allow', output: result.output, proposalId: proposal.proposalId };
    } else {
        // Plan B: Agent executes locally (network, browser)
        const result = await options!.localExecutor!(tool, action, args);
        await client.completeAction(proposal.proposalId, result, permit!);
        return { decision: 'allow', output: result, proposalId: proposal.proposalId };
    }
}

/**
 * Factory for creating a safety-wrapped toolset compatible with OpenClawAgent.
 */
export function createClawGuardToolset(client: ClawGuardClient) {
    return {
        shellExec: async (command: string, opts?: { untrustedSource?: 'web' | 'email' | 'issue' | 'clipboard' }) => {
            const res = await executeWithClawGuard(client, 'shell', 'exec', { command }, { meta: opts });
            return res.output;
        },
        readFile: async (path: string, opts?: { untrustedSource?: 'web' | 'email' | 'issue' | 'clipboard' }) => {
            const res = await executeWithClawGuard(client, 'filesystem', 'read', { path }, { meta: opts });
            return res.output;
        },
        writeFile: async (path: string, content: string, opts?: { untrustedSource?: 'web' | 'email' | 'issue' | 'clipboard' }) => {
            const res = await executeWithClawGuard(client, 'filesystem', 'write', { path, content }, { meta: opts });
            return res.output;
        }
    };
}

