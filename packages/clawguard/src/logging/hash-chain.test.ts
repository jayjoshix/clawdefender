import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HashChainLogger, verifyLogChain, sha256 } from '../logging/hash-chain.js';
import { mkdirSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

describe('HashChainLogger', () => {
    const testDir = join(import.meta.dirname, '../../.test-logs');
    let logger: HashChainLogger;
    let sessionId: string;

    beforeEach(() => {
        sessionId = randomUUID();
        mkdirSync(testDir, { recursive: true });
        logger = new HashChainLogger({ logDir: testDir, sessionId });
    });

    afterEach(() => {
        if (existsSync(testDir)) {
            rmSync(testDir, { recursive: true });
        }
    });

    it('should create log file with session ID', () => {
        expect(existsSync(logger.getLogPath())).toBe(true);
    });

    it('should log entries with hash chain', () => {
        const entry1 = logger.log({
            tool: 'shell',
            action: 'exec',
            args_hash: sha256({ command: 'ls' }),
            decision: 'allow',
            reason: 'Directory listing is safe',
            result_hash: sha256({ output: 'files' }),
        });

        expect(entry1.entry_hash).toBeDefined();
        expect(entry1.prev_hash).toBe('0'.repeat(64)); // Genesis

        const entry2 = logger.log({
            tool: 'shell',
            action: 'exec',
            args_hash: sha256({ command: 'pwd' }),
            decision: 'allow',
            reason: 'Current directory is safe',
            result_hash: sha256({ output: '/home' }),
        });

        expect(entry2.prev_hash).toBe(entry1.entry_hash); // Chain continues
    });

    it('should read all entries', () => {
        logger.log({
            tool: 'test',
            action: 'action1',
            args_hash: sha256({}),
            decision: 'allow',
            reason: 'test',
            result_hash: sha256({}),
        });

        logger.log({
            tool: 'test',
            action: 'action2',
            args_hash: sha256({}),
            decision: 'deny',
            reason: 'test',
            result_hash: sha256({}),
        });

        const entries = logger.readAll();
        expect(entries).toHaveLength(2);
        expect(entries[0].action).toBe('action1');
        expect(entries[1].action).toBe('action2');
    });

    it('should verify valid log chain', () => {
        logger.log({
            tool: 'test',
            action: 'action1',
            args_hash: sha256({}),
            decision: 'allow',
            reason: 'test',
            result_hash: sha256({}),
        });

        logger.log({
            tool: 'test',
            action: 'action2',
            args_hash: sha256({}),
            decision: 'allow',
            reason: 'test',
            result_hash: sha256({}),
        });

        const result = verifyLogChain(logger.getLogPath());
        expect(result.valid).toBe(true);
    });
});

describe('sha256', () => {
    it('should produce deterministic hashes', () => {
        const data = { key: 'value', number: 42 };
        const hash1 = sha256(data);
        const hash2 = sha256(data);
        expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different data', () => {
        const hash1 = sha256({ a: 1 });
        const hash2 = sha256({ a: 2 });
        expect(hash1).not.toBe(hash2);
    });
});
