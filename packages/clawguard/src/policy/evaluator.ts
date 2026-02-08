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
     * Order: deny -> needs_approval -> allow -> default
     */
    evaluate(request: ActionRequest): EvaluationResult {
        const { tool, action, args } = request;

        switch (tool) {
            case 'shell':
                return this.evaluateShell(action, args);
            case 'filesystem':
                return this.evaluateFilesystem(action, args);
            case 'network':
                return this.evaluateNetwork(action, args);
            case 'browser':
                return this.evaluateBrowser(action, args);
            default:
                return {
                    decision: this.policy.defaults.decision,
                    reason: this.policy.defaults.reason,
                };
        }
    }

    private evaluateShell(action: string, args: Record<string, unknown>): EvaluationResult {
        const command = (args.command as string) ?? action;
        const rules = this.policy.rules.shell;

        if (!rules) {
            return this.defaultResult();
        }

        // Check deny rules first (highest priority)
        if (rules.deny) {
            for (const rule of rules.deny) {
                if (this.matchesPattern(command, rule.pattern)) {
                    return { decision: 'deny', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check needs_approval rules
        if (rules.needs_approval) {
            for (const rule of rules.needs_approval) {
                if (this.matchesPattern(command, rule.pattern)) {
                    return { decision: 'needs_approval', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check allow rules
        if (rules.allow) {
            for (const rule of rules.allow) {
                if (this.matchesPattern(command, rule.pattern)) {
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

    private evaluateFilesystem(action: string, args: Record<string, unknown>): EvaluationResult {
        const path = (args.path as string) ?? '';
        const operation = action === 'read' ? 'read' : 'write';
        const rules = this.policy.rules.filesystem?.[operation];

        if (!rules) {
            return this.defaultResult();
        }

        // Check deny rules first
        if (rules.deny) {
            for (const rule of rules.deny) {
                if (this.matchesPattern(path, rule.path)) {
                    return { decision: 'deny', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check needs_approval rules
        if (rules.needs_approval) {
            for (const rule of rules.needs_approval) {
                if (this.matchesPattern(path, rule.path)) {
                    return { decision: 'needs_approval', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check allow rules
        if (rules.allow) {
            for (const rule of rules.allow) {
                if (this.matchesPattern(path, rule.path)) {
                    return { decision: 'allow', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        return this.defaultResult();
    }

    private evaluateNetwork(action: string, args: Record<string, unknown>): EvaluationResult {
        const domain = (args.domain as string) ?? (args.url as string) ?? (args.host as string) ?? '';
        const rules = this.policy.rules.network?.egress;

        if (!rules) {
            return this.defaultResult();
        }

        // Check deny rules first
        if (rules.deny) {
            for (const rule of rules.deny) {
                if (this.matchesDomain(domain, rule.domain)) {
                    return { decision: 'deny', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check allow rules before needs_approval for network
        if (rules.allow) {
            for (const rule of rules.allow) {
                if (this.matchesDomain(domain, rule.domain)) {
                    return { decision: 'allow', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check needs_approval rules
        if (rules.needs_approval) {
            for (const rule of rules.needs_approval) {
                if (this.matchesDomain(domain, rule.domain)) {
                    return { decision: 'needs_approval', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        return this.defaultResult();
    }

    private evaluateBrowser(action: string, args: Record<string, unknown>): EvaluationResult {
        const domain = (args.domain as string) ?? (args.url as string) ?? '';
        const rules = this.policy.rules.browser;

        if (!rules) {
            return this.defaultResult();
        }

        // Check deny rules first
        if (rules.deny) {
            for (const rule of rules.deny) {
                if (this.matchesDomain(domain, rule.domain)) {
                    return { decision: 'deny', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check allow rules before needs_approval for browser
        if (rules.allow) {
            for (const rule of rules.allow) {
                if (this.matchesDomain(domain, rule.domain)) {
                    return { decision: 'allow', reason: rule.reason, matchedRule: rule };
                }
            }
        }

        // Check needs_approval rules
        if (rules.needs_approval) {
            for (const rule of rules.needs_approval) {
                if (this.matchesDomain(domain, rule.domain)) {
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
