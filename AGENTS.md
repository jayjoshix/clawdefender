# ClawGuard Project Context

**Role**: Security Middleware for AI Agents
**Stack**: TypeScript (Node.js 20+), Fastify, Sui SDK, Seal SDK v2, Walrus

> **Critical Rule**: If this document conflicts with the code (types/schemas), **the code is the source of truth**.

## 1. Purpose & Scope
ClawGuard is a sidecar proxy that intercepts tool calls from an AI Agent, enforces security policies, and logs execution to a tamper-evident ledger.

-   **Goal**: Prevent agents from executing dangerous commands (e.g., `rm -rf /`, exfiltrating keys) and prove auditability.
-   **Non-Goal**: Host-level security. We assume the host OS is not compromised; ClawGuard protects the *agent's* tool usage, not the underlying server.

## 2. API Surface
The agent interacts with ClawGuard via HTTP (default port 3000).

### Endpoints
-   `GET /v1/status`: Health check.
-   `POST /v1/propose_action`: Main entry point. Returns `permit` if allowed.
-   `GET /v1/approval_payload/:id`: Fetch canonical payload for signing.
-   `POST /v1/approve_action`: Submit Ed25519 signature. Returns `permit` on success.
-   `POST /v1/execute_action`: Execute an approved/allowed action (server-side).
-   `POST /v1/complete_action`: Report agent-side execution with permit (Plan B).

### Execution Modes
1.  **Server-Side (Default)**: Agent calls `propose_action` → `execute_action`. Server runs the tool.
2.  **Agent-Side (Plan B)**: Agent calls `propose_action` → receives `permit` → executes locally → `complete_action`. Useful for browser automation or when server cannot execute.

### Tool Request Shapes (`propose_action`)
Ensure `args` match the policy engine's expectations:
> **Strict JSON Requirement**: Arguments must be **plain JSON objects**. Complex types like `Date`, `Buffer`, or custom class instances will be rejected during canonicalization.

1.  **Shell**:
    ```json
    { "tool": "shell", "action": "ls -la", "args": { "command": "ls -la" } }
    ```
2.  **Filesystem**:
    ```json
    { "tool": "filesystem", "action": "write", "args": { "path": "./file.txt", "content": "..." } }
    ```
3.  **Network** (Critical: use `host` or `domain`):
    ```json
    { "tool": "network", "action": "connect", "args": { "protocol": "tcp", "host": "example.com" } }
    ```
    *Specific Test Case*:
    ```json
    { "tool": "network", "action": "egress", "args": { "host": "secret.onion" } }
    ```

## 3. Security Invariants & Verification

| Invariant | Implementation Log | Verify By |
|-----------|-------------------|-----------|
| **Policy Enforcement** | `src/policy/evaluator.ts` | `pnpm test src/policy/evaluator.test.ts` |
| **Tamper-Evident Logs** | `src/logging/hash-chain.ts` | `pnpm verify-log -- logs/*.jsonl` |
| **Approval Replay Protection** | `NonceTracker` (rehydrated) | `pnpm test:e2e` (Replay scenario) |
| **Permit Replay Protection** | `usedPermits` (in-memory) + `proposal.executed` (rehydrated) | Restart server, retry permit |
| **Network Normalization** | `evaluator.ts` (best practice: use `host`/`domain` in args) | `pnpm test` (.onion regression) |
| **Audit Anchoring** | `src/bundler` + `seal-client` | `pnpm demo -- --verify` |
| **Permit Binding (Plan B)** | `complete_action` verifies all fields | Forge permit with wrong `argsHash` |
| **Server Identity** | `logs/server-key.json` (chmod 600) | `ls -la logs/server-key.json` |

## 4. Repository Map

-   `packages/clawguard`: **Core Server**.
    -   `src/server`: Fastify API.
    -   `src/policy`: Engine.
    -   `src/approval`: Signature verification.
    -   `src/auth`: Permit token generation/verification (Plan B).
-   `packages/seal-client`: **Sui Encryption**. (SDK v2 wrapper).
-   `packages/walrus-client`: **Storage**. (HTTP Blob storage).
-   `move/seal_policy`: **On-Chain**. Sui Move package for access control.
-   `demo/`: **E2E Script**. Orchestrates the full flow in `index.ts`.

## 5. Operational Guide

### Golden Path (Reliable Setup)
```bash
pnpm install && pnpm build && pnpm test && pnpm test:e2e
```

### Essential Commands
-   **Start Server**: `cd packages/clawguard && pnpm start`
-   **Run Demo**: `pnpm demo` (Interactive integration test)
    -   *Note*: `pnpm demo` runs entirely locally if `SUI_KEYPAIR` is missing.
-   **Verify Logs**: `pnpm verify-log -- <path/to/log.jsonl>`
    -   *Note*: Paths can be absolute (e.g., `/tmp/logs/session-1.jsonl`).

### Environment Variables
| Variable | Purpose | Required For |
|----------|---------|--------------|
| `CLAWGUARDTOKEN` | Bearer token for API | Server / Client |
| `POLICY_PATH` | Path to `policy.yaml` | Server |
| `LOGDIR` | Directory for JSONL logs | Server (Core for audit) |
| `SUI_KEYPAIR` | Private key for **demo/client** transactions | `pnpm demo` (Client-side transactions) |
| `SEAL_PACKAGE_ID` | Move package ID | `pnpm demo` (Encryption) |

## 6. Constraints ("Do Not Do")
1.  **Do Not** change policy semantics (allow/deny logic) without updating `evaluator.test.ts`.
2.  **Do Not** modify Move package IDs in `seal-client` unless redeploying the contract.
3.  **Do Not** assume `pnpm start` hot-reloads; always restart server after code changes.

## 7. Known Gotchas
-   **Network Policies**: The policy engine normalizes `host`, `domain`, and `url`. Ensure specific deny rules (like `*.onion`) are tested if tool arguments vary.
-   **Faucet**: Ensure your wallet has gas. Use the appropriate faucet for your network (Discord for Testnet/Devnet; `sui client faucet` for localnet).
-   **Plan B Permits**: Permits expire quickly (60s). Agents must call `complete_action` promptly. The `usedPermits` set is in-memory only (resets on restart), but `proposal.executed` persists via log rehydration (both `execute` and `agentcompleted` events).
