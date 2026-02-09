import { z } from 'zod';

// PBAC Conditions
const ConditionsSchema = z.object({
    untrusted_source: z.array(z.string()).optional(),
}).optional();

// Pattern rule schema
const PatternRuleSchema = z.object({
    pattern: z.string(),
    reason: z.string(),
    paths_except: z.array(z.string()).optional(),
    conditions: ConditionsSchema,
});

// Path rule schema
const PathRuleSchema = z.object({
    path: z.string(),
    reason: z.string(),
    conditions: ConditionsSchema,
});

// Domain rule schema
const DomainRuleSchema = z.object({
    domain: z.string(),
    reason: z.string(),
    conditions: ConditionsSchema,
});

// Shell rules
const ShellRulesSchema = z.object({
    deny: z.array(PatternRuleSchema).optional(),
    needs_approval: z.array(PatternRuleSchema).optional(),
    allow: z.array(PatternRuleSchema).optional(),
});

// Filesystem rules
const FilesystemRulesSchema = z.object({
    read: z.object({
        deny: z.array(PathRuleSchema).optional(),
        needs_approval: z.array(PathRuleSchema).optional(),
        allow: z.array(PathRuleSchema).optional(),
    }).optional(),
    write: z.object({
        deny: z.array(PathRuleSchema).optional(),
        needs_approval: z.array(PathRuleSchema).optional(),
        allow: z.array(PathRuleSchema).optional(),
    }).optional(),
});

// Network rules
const NetworkRulesSchema = z.object({
    egress: z.object({
        deny: z.array(DomainRuleSchema).optional(),
        needs_approval: z.array(DomainRuleSchema).optional(),
        allow: z.array(DomainRuleSchema).optional(),
    }).optional(),
});

// Browser rules
const BrowserRulesSchema = z.object({
    deny: z.array(DomainRuleSchema).optional(),
    needs_approval: z.array(DomainRuleSchema).optional(),
    allow: z.array(DomainRuleSchema).optional(),
});

// Full policy schema
export const PolicySchema = z.object({
    version: z.string(),
    defaults: z.object({
        decision: z.enum(['allow', 'deny', 'needs_approval']),
        reason: z.string(),
    }),
    rules: z.object({
        shell: ShellRulesSchema.optional(),
        filesystem: FilesystemRulesSchema.optional(),
        network: NetworkRulesSchema.optional(),
        browser: BrowserRulesSchema.optional(),
    }),
});

export type Policy = z.infer<typeof PolicySchema>;
export type PolicyDecision = 'allow' | 'deny' | 'needs_approval';

export interface PolicyRule {
    pattern?: string;
    path?: string;
    domain?: string;
    reason: string;
    paths_except?: string[];
    conditions?: {
        untrusted_source?: string[];
    };
}

export interface EvaluationResult {
    decision: PolicyDecision;
    reason: string;
    matchedRule?: PolicyRule;
}
