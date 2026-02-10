
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createClawGuardToolset, ClawGuardClient } from './index';

describe('createClawGuardToolset', () => {
    let client: ClawGuardClient;
    let mockReq: any;

    beforeEach(() => {
        // Mock ClawGuardClient
        client = new ClawGuardClient('http://localhost:3000');
        mockReq = vi.fn().mockResolvedValue({
            decision: 'allow',
            proposalId: 'prop-123',
            output: 'success-output'
        });
        // @ts-ignore
        client['req'] = mockReq;

        // Mock executeAction to return success
        // @ts-ignore
        client.executeAction = vi.fn().mockResolvedValue({ ok: true, output: 'success-output' });
        // @ts-ignore
        client.propose = vi.fn().mockResolvedValue({ decision: 'allow', proposalId: 'prop-123' });
    });

    it('should create a toolset with shellExec', async () => {
        const tools = createClawGuardToolset(client);
        expect(tools.shellExec).toBeDefined();

        const result = await tools.shellExec('ls -la');
        expect(client.propose).toHaveBeenCalledWith('shell', 'exec', { command: 'ls -la' }, undefined);
        expect(client.executeAction).toHaveBeenCalledWith('prop-123');
        expect(result).toBe('success-output');
    });

    it('should create a toolset with readFile', async () => {
        const tools = createClawGuardToolset(client);
        expect(tools.readFile).toBeDefined();

        const result = await tools.readFile('/tmp/test.txt');
        expect(client.propose).toHaveBeenCalledWith('filesystem', 'read', { path: '/tmp/test.txt' }, undefined);
        expect(result).toBe('success-output');
    });

    it('should pass untrustedSource metadata', async () => {
        const tools = createClawGuardToolset(client);
        await tools.shellExec('curl malicious.com', { untrustedSource: 'web' });

        expect(client.propose).toHaveBeenCalledWith('shell', 'exec', { command: 'curl malicious.com' }, { untrustedSource: 'web' });
    });
});
