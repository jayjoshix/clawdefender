import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEvaluator } from '../policy/evaluator.js';
import { resolve } from 'node:path';

describe('PolicyEvaluator', () => {
    let evaluator: PolicyEvaluator;

    beforeEach(() => {
        const policyPath = resolve(import.meta.dirname, '../../policy.yaml');
        evaluator = new PolicyEvaluator(policyPath);
    });

    describe('Shell Commands', () => {
        it('should DENY rm -rf /', () => {
            const result = evaluator.evaluate({
                tool: 'shell',
                action: 'exec',
                args: { command: 'rm -rf /' },
            });
            expect(result.decision).toBe('deny');
            expect(result.reason).toContain('Catastrophic');
        });

        it('should DENY sudo commands', () => {
            const result = evaluator.evaluate({
                tool: 'shell',
                action: 'exec',
                args: { command: 'sudo apt install malware' },
            });
            expect(result.decision).toBe('deny');
            expect(result.reason).toContain('privileges');
        });

        it('should DENY fork bomb', () => {
            const result = evaluator.evaluate({
                tool: 'shell',
                action: 'exec',
                args: { command: ':(){:|:&};:' },
            });
            expect(result.decision).toBe('deny');
            expect(result.reason).toContain('Fork bomb');
        });

        it('should ALLOW ls commands', () => {
            const result = evaluator.evaluate({
                tool: 'shell',
                action: 'exec',
                args: { command: 'ls -la /tmp' },
            });
            expect(result.decision).toBe('allow');
        });

        it('should ALLOW pwd', () => {
            const result = evaluator.evaluate({
                tool: 'shell',
                action: 'exec',
                args: { command: 'pwd' },
            });
            expect(result.decision).toBe('allow');
        });

        it('should NEED APPROVAL for rm with specific file', () => {
            const result = evaluator.evaluate({
                tool: 'shell',
                action: 'exec',
                args: { command: 'rm /tmp/test.txt' },
            });
            expect(result.decision).toBe('needs_approval');
        });

        it('should DENY cat ~/.ssh/id_rsa (SSH key read)', () => {
            const result = evaluator.evaluate({
                tool: 'shell',
                action: 'exec',
                args: { command: 'cat ~/.ssh/id_rsa' },
            });
            expect(result.decision).toBe('deny');
            expect(result.reason).toContain('restricted');
        });

        it('should DENY cat /etc/passwd', () => {
            const result = evaluator.evaluate({
                tool: 'shell',
                action: 'exec',
                args: { command: 'cat /etc/passwd' },
            });
            expect(result.decision).toBe('deny');
        });

        it('should DENY head ~/.ssh/config', () => {
            const result = evaluator.evaluate({
                tool: 'shell',
                action: 'exec',
                args: { command: 'head ~/.ssh/config' },
            });
            expect(result.decision).toBe('deny');
        });

        it('should ALLOW cat of safe files', () => {
            const result = evaluator.evaluate({
                tool: 'shell',
                action: 'exec',
                args: { command: 'cat /tmp/test.txt' },
            });
            expect(result.decision).toBe('allow');
        });
    });

    describe('Filesystem Access', () => {
        it('should DENY reading ~/.ssh files', () => {
            const result = evaluator.evaluate({
                tool: 'filesystem',
                action: 'read',
                args: { path: '~/.ssh/id_rsa' },
            });
            expect(result.decision).toBe('deny');
            expect(result.reason).toContain('SSH');
        });

        it('should DENY reading /etc/shadow', () => {
            const result = evaluator.evaluate({
                tool: 'filesystem',
                action: 'read',
                args: { path: '/etc/shadow' },
            });
            expect(result.decision).toBe('deny');
        });

        it('should ALLOW reading /tmp files', () => {
            const result = evaluator.evaluate({
                tool: 'filesystem',
                action: 'read',
                args: { path: '/tmp/test.txt' },
            });
            expect(result.decision).toBe('allow');
        });

        it('should DENY writing to /etc', () => {
            const result = evaluator.evaluate({
                tool: 'filesystem',
                action: 'write',
                args: { path: '/etc/passwd' },
            });
            expect(result.decision).toBe('deny');
        });
    });

    describe('Network Egress', () => {
        it('should REQUIRE APPROVAL for api.github.com (Demo configuration)', () => {
            const result = evaluator.evaluate({
                tool: 'network',
                action: 'egress',
                args: { domain: 'api.github.com' },
            });
            expect(result.decision).toBe('needs_approval');
        });

        it('should DENY .onion domains', () => {
            const result = evaluator.evaluate({
                tool: 'network',
                action: 'egress',
                args: { domain: 'secret.onion' },
            });
            expect(result.decision).toBe('deny');
        });

        it('should ALLOW Walrus testnet', () => {
            const result = evaluator.evaluate({
                tool: 'network',
                action: 'egress',
                args: { domain: 'publisher.walrus-testnet.walrus.space' },
            });
            expect(result.decision).toBe('allow');
        });

        it('should DENY .onion domains when passed as host', () => {
            const result = evaluator.evaluate({
                tool: 'network',
                action: 'connect',
                args: { protocol: 'tcp', host: 'secret.onion' },
            });
            expect(result.decision).toBe('deny');
        });

        it('should NEED APPROVAL for unknown domains', () => {
            const result = evaluator.evaluate({
                tool: 'network',
                action: 'egress',
                args: { domain: 'unknown-website.com' },
            });
            expect(result.decision).toBe('needs_approval');
        });
    });

    describe('Browser Domains', () => {
        it('should ALLOW github.com', () => {
            const result = evaluator.evaluate({
                tool: 'browser',
                action: 'navigate',
                args: { domain: 'github.com' },
            });
            expect(result.decision).toBe('allow');
        });

        it('should DENY file:// URLs', () => {
            const result = evaluator.evaluate({
                tool: 'browser',
                action: 'navigate',
                args: { url: 'file:///etc/passwd' },
            });
            expect(result.decision).toBe('deny');
        });
    });

    describe('Determinism', () => {
        it('should produce identical results for identical inputs', () => {
            const input = {
                tool: 'shell' as const,
                action: 'exec',
                args: { command: 'ls -la /home' },
            };

            const result1 = evaluator.evaluate(input);
            const result2 = evaluator.evaluate(input);

            expect(result1.decision).toBe(result2.decision);
            expect(result1.reason).toBe(result2.reason);
        });
    });
});
