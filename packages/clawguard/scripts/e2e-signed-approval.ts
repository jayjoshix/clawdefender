
import { spawn, ChildProcess } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { getMsgBytes } from '../src/approval/verify.js';

const TEST_DIR = resolve('/tmp', `clawguard-e2e-${randomUUID()}`);
let BASE_URL = '';
const TOKEN = 'test-token';

async function wait(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchJson(method: string, path: string, body?: any) {
    const headers: Record<string, string> = {
        'Authorization': `Bearer ${TOKEN}`,
        'Content-Type': 'application/json'
    };
    const res = await fetch(`${BASE_URL}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined
    });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, json };
}

async function waitForServer() {
    for (let i = 0; i < 20; i++) {
        try {
            const res = await fetch(`${BASE_URL}/v1/status`);
            if (res.ok) return;
        } catch (e) { }
        await wait(500);
    }
    throw new Error('Server timed out');
}

async function stopServer(server: ChildProcess, timeoutMs = 5000) {
    if (server.exitCode !== null || server.signalCode !== null) return;

    // Kill process group (requires detached: true matching startServer)
    const pid = server.pid;
    if (!pid) return;

    try {
        process.kill(-pid, 'SIGTERM');
    } catch (e) {
        // Process might be gone already
    }

    await new Promise<void>((resolve, reject) => {
        let timer: NodeJS.Timeout;
        const cleanup = () => {
            server.off('exit', onExit);
            server.off('close', onClose);
            server.off('error', onError);
            clearTimeout(timer);
        };

        const onExit = () => { cleanup(); resolve(); };
        const onClose = () => { cleanup(); resolve(); };
        const onError = (e: any) => { cleanup(); reject(e); };

        server.once('exit', onExit);
        server.once('close', onClose);
        server.once('error', onError);

        timer = setTimeout(() => {
            // Hard kill group if still running
            try { process.kill(-pid, 'SIGKILL'); } catch (e) { }

            // Final fallback: just resolve after a short grace period if it won't die
            // preventing the test from hanging forever.
            setTimeout(() => { cleanup(); resolve(); }, 1000);
        }, timeoutMs);
    });
}

// Setup test environment
function setup() {
    if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(TEST_DIR, { recursive: true });
    mkdirSync(resolve(TEST_DIR, 'logs'), { recursive: true });

    // Create policy requiring approval for 'ls'
    writeFileSync(resolve(TEST_DIR, 'policy.yaml'), `
version: "1.0"
defaults:
  decision: deny
  reason: "Default deny"
rules:
  shell:
    needs_approval:
      - pattern: "ls*"
        reason: "Sensitive command requires approval"
`);

    // Generate Keypair
    const keypair = new Ed25519Keypair();
    const address = keypair.toSuiAddress();
    console.log(`🔑 Generated test approver: ${address}`);

    // Create approvers config
    writeFileSync(resolve(TEST_DIR, 'approvers.yaml'), `
approvers:
  - address: "${address}"
    name: "E2E Test Approver"
`);

    return { keypair, address };
}



async function startServer(): Promise<ChildProcess> {
    const env = {
        ...process.env,
        CLAWGUARDTOKEN: TOKEN,
        PORT: '0', // Let OS assign
        POLICY_PATH: resolve(TEST_DIR, 'policy.yaml'),
        LOGDIR: resolve(TEST_DIR, 'logs'),
        APPROVERS_PATH: resolve(TEST_DIR, 'approvers.yaml')
    };

    // Spawn detached to allow killing process tree
    const serverProcess = spawn('npx', [
        'tsx',
        'scripts/e2e-server-wrapper.ts'
    ], {
        env,
        stdio: ['ignore', 'pipe', 'pipe'], // Pipe stdout to parse port
        cwd: process.cwd(),
        detached: true
    });

    serverProcess.unref(); // Don't hold parent alive
    serverProcess.stderr?.pipe(process.stderr); // Pass through stderr

    // Parse port from stdout with timeout
    await new Promise<void>((resolve, reject) => {
        let buffer = '';
        let timeout: NodeJS.Timeout;

        const cleanup = () => {
            serverProcess.stdout?.off('data', onData);
            serverProcess.off('error', onErr);
            serverProcess.off('exit', onExit);
            clearTimeout(timeout);
        };

        const onData = (chunk: Buffer) => {
            buffer += chunk.toString();
            // process.stdout.write(chunk); // Mirroring optional, but useful
            const match = buffer.match(/E2E_BASE_URL=(http:\/\/[^\s]+)/);
            if (match) {
                BASE_URL = match[1];
                cleanup();
                resolve();
            }
        };

        const onErr = (e: any) => { cleanup(); reject(e); };
        const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
            cleanup();
            reject(new Error(`Server exited early: code=${code}, signal=${signal}`));
        };

        serverProcess.stdout?.on('data', onData);
        serverProcess.once('error', onErr);
        serverProcess.once('exit', onExit);

        timeout = setTimeout(() => {
            cleanup();
            reject(new Error(`Server start timed out after 10s. Stdout: ${buffer.slice(-200)}`));
        }, 10000);
    });

    await waitForServer();
    console.log(`✅ Server verified up at ${BASE_URL}`);
    return serverProcess;
}

async function runTest() {
    console.log(`🚀 Starting end-to-end signed approval test in ${TEST_DIR}...`);
    const { keypair, address } = setup();

    let server = await startServer();
    let proposalId: string = '';

    try {
        // 1. Propose action (ls -la)
        console.log('\n📝 1. Proposing action (ls -la)...');
        const proposeRes = await fetchJson('POST', '/v1/propose_action', {
            tool: 'shell',
            action: 'ls -la',
            args: { command: 'ls -la' }
        });

        console.log(`Response: ${proposeRes.status}`, proposeRes.json);
        if (proposeRes.status !== 200) throw new Error('Expected 200 OK (needs_approval)');
        if (proposeRes.json.decision !== 'needs_approval') throw new Error('Expected needs_approval');

        proposalId = proposeRes.json.proposalId;
        const approvalEndpoint = proposeRes.json.approvalRequired?.endpoint;
        if (!approvalEndpoint?.includes(proposalId)) {
            throw new Error(`Approval endpoint mismatch: ${approvalEndpoint}`);
        }
        console.log(`✅ Proposal created: ${proposalId}`);

        // 2. Get payload for signing
        console.log('\n📥 2. Fetching approval payload...');
        const payloadRes = await fetchJson('GET', `/v1/approval_payload/${proposalId}`);
        if (payloadRes.status !== 200) throw new Error('Failed to get payload');

        // Extract nonce/expiresAt from top-level response for robustness
        const { payload, nonce, expiresAt } = payloadRes.json;
        console.log('Payload received, nonce:', nonce);

        // --- Negative Test 1: Try executing before approval ---
        console.log('\n🚫 Negative Test 1: Executing before approval...');
        const prematureExec = await fetchJson('POST', '/v1/execute_action', { proposalId });
        if (prematureExec.status !== 403) throw new Error(`Expected 403 Forbidden, got ${prematureExec.status}`);
        console.log('✅ Correctly blocked (requires signed approval)');

        // 3. Sign payload
        console.log('\n✍️  3. Signing payload...');
        const bytesToSign = getMsgBytes(payload);
        const signatureEntry = await keypair.signPersonalMessage(bytesToSign);
        const signature = signatureEntry.signature;

        // 4. Submit approval
        console.log('\n📤 4. Submitting approval...');

        // --- Negative Test 2: Submit invalid signature ---
        console.log('🚫 Negative Test 2: Submitting INVALID signature...');
        const invalidApprove = await fetchJson('POST', '/v1/approve_action', {
            approverAddress: address,
            signature: Buffer.from('invalid').toString('base64'),
            nonce,
            expiresAt,
            proposalId
        });
        if (invalidApprove.status !== 403) throw new Error(`Expected 403 Forbidden, got ${invalidApprove.status}`);
        console.log('✅ Correctly blocked (invalid signature)');

        // --- Concurrency / TOCTOU Test (Valid Signature) ---
        console.log('\n🏎️  Concurrency Test: Submitting 2 identical valid approvals...');
        const requestBody = {
            approverAddress: address,
            signature,
            nonce,
            expiresAt,
            proposalId
        };

        // Fire 2 requests concurrently
        const results = await Promise.allSettled([
            fetchJson('POST', '/v1/approve_action', requestBody),
            fetchJson('POST', '/v1/approve_action', requestBody)
        ]);

        const successCount = results.filter(r => r.status === 'fulfilled' && r.value.status === 200).length;
        const failedRequests = results.filter(r => r.status === 'rejected' || (r.status === 'fulfilled' && r.value.status !== 200));
        const failCount = failedRequests.length;

        console.log(`Concurrency Results: ${successCount} success, ${failCount} fail`);
        if (successCount !== 1 || failCount !== 1) throw new Error(`Expected queries: 1 success, 1 fail. Got: ${successCount} success, ${failCount} fail`);
        console.log('✅ Concurrency race handled correctly (TOCTOU protection)');

        // --- Replay Test ---
        console.log('\n🚫 Negative Test 3: Replay attack (Sequential)...');
        const replayRes = await fetchJson('POST', '/v1/approve_action', requestBody);
        // Expect 400 Bad Request (Nonce already used OR No approval issued if cleared)
        // Expect 400 Bad Request (Nonce already used OR No approval issued if cleared)
        const err = replayRes.json.error;
        // Logic: If status is 400 or 403, and it failed, we accept it as "Replay Blocked".
        // The exact message depends on race timing (nonce used vs pending cleared).
        if ((replayRes.status === 400 || replayRes.status === 403)) {
            console.log(`✅ Replay correctly blocked (Status ${replayRes.status}: ${err})`);
        } else {
            throw new Error(`Expected 400/403 for replay, got ${replayRes.status} ${JSON.stringify(replayRes.json)}`);
        }

        // 5. Execute action
        console.log('\n⚡ 5. Executing action...');
        const executeRes = await fetchJson('POST', '/v1/execute_action', { proposalId });
        if (executeRes.status !== 200 || !executeRes.json.ok) throw new Error('Execution failed');
        console.log('✅ Action executed successfully');

        // 6. Verify Logs (Rehydration Check)
        console.log('\n🔄 6. Restarting server to verify rehydration...');
        await stopServer(server);
        server = await startServer();

        // Assert status
        const statusRes = await fetchJson('GET', '/v1/status');
        if ((statusRes.json.proposalCount ?? 0) === 0) throw new Error('Rehydration failed: 0 proposals in status');
        console.log('✅ Server status confirms rehydration');

        // Check proposal execution status (idempotency/restored state)
        const verifyRes = await fetchJson('POST', '/v1/execute_action', { proposalId });
        if (verifyRes.status === 409 && verifyRes.json.error === 'Action already executed') {
            console.log('✅ Rehydration verified: Proposal correctly marked as executed.');
        } else {
            throw new Error(`❌ Rehydration FAILED: Expected 409 Conflict, got ${verifyRes.status}`);
        }

        // --- Post-Restart Replay Test ---
        console.log('\n🚫 Negative Test 4: Replay attack after restart...');
        const postRestartReplay = await fetchJson('POST', '/v1/approve_action', requestBody);
        if (postRestartReplay.status === 400 || postRestartReplay.status === 403) {
            console.log('✅ Post-restart replay correctly blocked');
        } else {
            throw new Error(`Expected 400/403 for post-restart replay, got ${postRestartReplay.status}`);
        }

        console.log('\n🎉 ALL TESTS PASSED!');

    } catch (e) {
        console.error('\n❌ TEST FAILED:', e);
        process.exit(1);
    } finally {
        if (server) await stopServer(server);
        console.log(`\nlogs available in ${resolve(TEST_DIR, 'logs')}`);
    }
}

runTest();
