import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import yaml from 'js-yaml';
import { Policy, PolicySchema, PolicyDecision, EvaluationResult, PolicyRule } from './schema.js';

export type ToolType = 'shell' | 'filesystem' | 'network' | 'browser';

export interface ActionRequest {
    tool: ToolType;
    action: string;
    args: Record<string, unknown>;
    context?: Record<string, unknown>;
    untrustedSource?: string;
}

import { createHash } from 'node:crypto';

export class PolicyEvaluator {
    private policy: Policy;
    private policyPath: string;
    private policyHash: string;

    constructor(policyPath?: string) {
        this.policyPath = policyPath ?? resolve(import.meta.dirname, '../../policy.yaml');
        const content = readFileSync(this.policyPath, 'utf-8');
        this.policyHash = createHash('sha256').update(content).digest('hex');
        const parsed = yaml.load(content);
        this.policy = PolicySchema.parse(parsed);
    }

    getPolicyPath(): string {
        return this.policyPath;
    }

    getPolicyHash(): string {
        return this.policyHash;
    }

    /**
     * Deterministic policy evaluation.
     * Order establishes "Most-Restrictive-Wins" precedence:
     * 1. Deny (Highest priority - always blocks)
     * 2. Needs Approval (Blocks execution until approved)
     * 3. Allow (Permits execution)
     * 4. Default (Deny)
     */
    evaluate(request: ActionRequest): EvaluationResult {
        const { tool } = request;

        switch (tool) {
            case 'shell':
                return this.evaluateShell(request);
            case 'filesystem':
                return this.evaluateFilesystem(request);
            case 'network':
                return this.evaluateNetwork(request);
            case 'browser':
                return this.evaluateBrowser(request);
            default:
                return {
                    decision: this.policy.defaults.decision,
                    reason: this.policy.defaults.reason,
                };
        }
    }

    private evaluateShell(request: ActionRequest): EvaluationResult {
        const { action, args } = request;
        const command = (args.command as string) ?? action;
        const rules = this.policy.rules.shell;

        if (!rules) {
            return this.defaultResult();
        }

        // Check deny rules first (highest priority)
        if (rules.deny) {
            for (const rule of rules.deny) {
                if (this.matchesRule(rule, command, request)) {
                    return { decision: 'deny', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check needs_approval rules
        if (rules.needs_approval) {
            for (const rule of rules.needs_approval) {
                if (this.matchesRule(rule, command, request)) {
                    return { decision: 'needs_approval', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check allow rules
        if (rules.allow) {
            for (const rule of rules.allow) {
                if (this.matchesRule(rule, command, request)) {
                    // Check paths_except for file-reading commands
                    if (rule.paths_except) {
                        // Extract file path from command (e.g., "cat ~/.ssh/id_rsa" -> "~/.ssh/id_rsa")
                        const extractedPaths = this.extractPathsFromCommand(command);

                        for (const filePath of extractedPaths) {
                            for (const exceptPattern of rule.paths_except) {
                                if (this.matchesPattern(filePath, exceptPattern)) {
                                    return {
                                        decision: 'deny',
                                        reason: `Access to ${filePath} is restricted`,
                                        matchedRule: rule
                                    };
                                }
                            }
                        }
                    }
                    return { decision: 'allow', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        return this.defaultResult();
    }

    /**
     * Extract file paths from shell commands
     * Handles: cat file, head file, tail file, less file, more file
     */
    private extractPathsFromCommand(command: string): string[] {
        const paths: string[] = [];

        // Commands that read files
        const fileReadingCommands = ['cat', 'head', 'tail', 'less', 'more', 'bat', 'view'];

        // Split command by pipes and process each part
        const parts = command.split('|').map(p => p.trim());

        for (const part of parts) {
            const tokens = part.split(/\s+/);
            const cmd = tokens[0];

            if (fileReadingCommands.includes(cmd)) {
                // Get all arguments that look like file paths (not flags)
                for (let i = 1; i < tokens.length; i++) {
                    const token = tokens[i];
                    // Skip flags (start with -)
                    if (!token.startsWith('-')) {
                        paths.push(token);
                    }
                }
            }
        }

        return paths;
    }

    private evaluateFilesystem(request: ActionRequest): EvaluationResult {
        const { action, args } = request;
        const path = (args.path as string) ?? '';
        const operation = action === 'read' ? 'read' : 'write';
        const rules = this.policy.rules.filesystem?.[operation];

        if (!rules) {
            return this.defaultResult();
        }

        // Check deny rules first
        if (rules.deny) {
            for (const rule of rules.deny) {
                if (this.matchesRule(rule, path, request)) {
                    return { decision: 'deny', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check needs_approval rules
        if (rules.needs_approval) {
            for (const rule of rules.needs_approval) {
                if (this.matchesRule(rule, path, request)) {
                    return { decision: 'needs_approval', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check allow rules
        if (rules.allow) {
            for (const rule of rules.allow) {
                if (this.matchesRule(rule, path, request)) {
                    return { decision: 'allow', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        return this.defaultResult();
    }

    private evaluateNetwork(request: ActionRequest): EvaluationResult {
        const { args } = request;
        const domain = (args.domain as string) ?? (args.url as string) ?? (args.host as string) ?? '';
        const rules = this.policy.rules.network?.egress;

        if (!rules) {
            return this.defaultResult();
        }

        // Check deny rules first
        if (rules.deny) {
            for (const rule of rules.deny) {
                if (this.matchesRule(rule, domain, request)) {
                    return { decision: 'deny', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check allow rules before needs_approval for network
        if (rules.allow) {
            for (const rule of rules.allow) {
                if (this.matchesRule(rule, domain, request)) {
                    return { decision: 'allow', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check needs_approval rules
        if (rules.needs_approval) {
            for (const rule of rules.needs_approval) {
                if (this.matchesRule(rule, domain, request)) {
                    return { decision: 'needs_approval', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        return this.defaultResult();
    }

    private evaluateBrowser(request: ActionRequest): EvaluationResult {
        const { args } = request;
        const domain = (args.domain as string) ?? (args.url as string) ?? '';
        const rules = this.policy.rules.browser;

        if (!rules) {
            return this.defaultResult();
        }

        // Check deny rules first
        if (rules.deny) {
            for (const rule of rules.deny) {
                if (this.matchesRule(rule, domain, request)) {
                    return { decision: 'deny', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check allow rules before needs_approval for browser
        if (rules.allow) {
            for (const rule of rules.allow) {
                if (this.matchesRule(rule, domain, request)) {
                    return { decision: 'allow', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check needs_approval rules
        if (rules.needs_approval) {
            for (const rule of rules.needs_approval) {
                if (this.matchesRule(rule, domain, request)) {
                    return { decision: 'needs_approval', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        return this.defaultResult();
    }

    private matchesPattern(input: string, pattern: string): boolean {
        const home = process.env.HOME ?? '';

        // Helper to expand ~ and $HOME
        const expand = (s: string) => s.replace(/^~/, home).split('$HOME').join(home);

        const expandedPattern = expand(pattern);
        const expandedInput = expand(input);

        // Convert glob pattern to regex
        const regexPattern = expandedPattern
            .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // Escape special regex chars
            .replace(/\*/g, '.*')                    // * -> .*
            .replace(/\?/g, '.');                    // ? -> .

        const regex = new RegExp(`^${regexPattern}$`, 'i');
        return regex.test(expandedInput);
    }

    private matchesRule(rule: PolicyRule, input: string, request: ActionRequest): boolean {
        // 1. Check pattern/path/domain match
        const pattern = rule.pattern ?? rule.path ?? rule.domain;
        if (pattern) {
            // For network/browser, use matchesDomain, else matchesPattern
            const isDomain = request.tool === 'network' || request.tool === 'browser';
            const matches = isDomain
                ? this.matchesDomain(input, pattern)
                : this.matchesPattern(input, pattern);

            if (!matches) return false;
        }

        // 2. Check PBAC conditions
        return this.checkConditions(rule, request);
    }

    private checkConditions(rule: PolicyRule, request: ActionRequest): boolean {
        if (!rule.conditions) return true;

        // Check untrusted_source
        if (rule.conditions.untrusted_source) {
            // Mapping: YAML keys are snake_case, Request props are camelCase
            if (!request.untrustedSource) return false;
            if (!rule.conditions.untrusted_source.includes(request.untrustedSource)) return false;
        }

        return true;
    }

    private matchesDomain(input: string, pattern: string): boolean {
        // Special case: match full URL for file:// and similar non-http schemes
        if (pattern.startsWith('file://') || input.startsWith('file://')) {
            return this.matchesPattern(input, pattern);
        }

        // Extract domain from URL if needed
        let domain = input;
        try {
            const url = new URL(input.startsWith('http') ? input : `https://${input}`);
            domain = url.hostname + (url.port ? `:${url.port}` : '');
        } catch {
            // Use input as-is if not a valid URL
        }

        return this.matchesPattern(domain, pattern);
    }

    private defaultResult(): EvaluationResult {
        return {
            decision: this.policy.defaults.decision,
            reason: this.policy.defaults.reason,
        };
    }

    getPolicy(): Policy {
        return this.policy;
    }
}
