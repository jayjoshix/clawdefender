# @clawguard/openclaw-adapter

OpenClaw integration for ClawGuard policy firewall.

## Installation

```bash
pnpm add @clawguard/openclaw-adapter
```

## Quick Start

```ts
import { ClawGuardClient, executeWithClawGuard } from '@clawguard/openclaw-adapter';

const client = new ClawGuardClient('http://localhost:3000', process.env.CLAWGUARDTOKEN);

// Plan A: shell/filesystem (server executes automatically)
const result = await executeWithClawGuard(client, 'shell', 'exec', { command: 'ls -la' });

if (result.decision === 'allow') {
    console.log('Output:', result.output);
} else if (result.decision === 'deny') {
    console.log('Blocked:', result.reason);
}
```

## Plan A vs Plan B (Safe Defaults)

| Tool | Executor | Notes |
|------|----------|-------|
| `shell` | **Server (Plan A)** | ClawGuard server runs the command |
| `filesystem` | **Server (Plan A)** | ClawGuard server reads/writes files |
| `network` | **Agent (Plan B)** | Requires `localExecutor` |
| `browser` | **Agent (Plan B)** | Requires `localExecutor` |

The adapter **enforces** this routing. Calling `executeWithClawGuard` for `network`/`browser` without a `localExecutor` throws an error.

### Plan B Example (Network/Browser)

```ts
const result = await executeWithClawGuard(client, 'network', 'egress', { url: 'https://api.example.com' }, {
    localExecutor: async (tool, action, args) => {
        // Your OpenClaw agent runs the network call
        const response = await fetch(args.url as string);
        return { status: response.status, body: await response.text() };
    },
});
```

## Approval Flow

For `needs_approval` decisions, provide an approval handler:

```ts
const result = await executeWithClawGuard(client, 'shell', 'exec', { command: 'rm -rf /tmp/cache' }, {
    approvalHandler: async (proposalId, payload) => {
        // Route to Telegram/Slack for human approval
        const signature = await getHumanApprovalViaTelegram(payload);
        return {
            proposalId,
            expiresAt: payload.expiresAt,
            nonce: payload.nonce,
            approverAddress: '0x...',
            signature,
        };
    },
});
```

## Untrusted Sources

Mark actions from external sources to force approval:

```ts
const result = await executeWithClawGuard(client, 'shell', 'exec', { command: userInput }, {
    meta: { untrustedSource: 'web' }, // Forces needs_approval for shell/network
});
```

---

## Telegram Approval Handler

Route approvals through Telegram with inline buttons:

```ts
import { ClawGuardClient, executeWithClawGuard } from '@clawguard/openclaw-adapter';
import { createTelegramApprovalHandler } from '@clawguard/openclaw-adapter/telegram';

const client = new ClawGuardClient('http://localhost:3000', process.env.CLAWGUARDTOKEN);
const telegramApprover = createTelegramApprovalHandler({
    botToken: process.env.TELEGRAM_BOT_TOKEN!,
    chatId: process.env.TELEGRAM_CHAT_ID!,
    timeoutMs: 300000, // 5 minutes
});

const result = await executeWithClawGuard(client, 'shell', 'exec', { command: 'rm -rf /tmp/cache' }, {
    approvalHandler: telegramApprover,
});
```

**Flow:**
1. Bot sends approval request with ✅ Approve / ❌ Deny buttons
2. User clicks Approve
3. Bot asks for wallet signature
4. User signs the `msgHash` and pastes signature
5. Action executes

### CLI Approval (Development)

For local testing without Telegram:

```ts
import { cliApprovalHandler } from '@clawguard/openclaw-adapter/telegram';

const result = await executeWithClawGuard(client, 'shell', 'exec', { command: 'rm cache/*' }, {
    approvalHandler: cliApprovalHandler,
});
```

---

## Docker Command

Both env var naming conventions are supported:

```bash
docker run -d -p 3000:3000 \
  -e CLAWGUARDTOKEN="your-secret-token" \
  -e POLICY_PATH=/app/policy.yaml \
  -e LOGDIR=/app/.logs \
  -v "$(pwd)/policy.yaml:/app/policy.yaml:ro" \
  -v "$(pwd)/.logs:/app/.logs" \
  jayjoshix/clawguard-server:latest
```

Alternative (legacy naming without underscores also works):
```bash
-e POLICYPATH=/app/policy.yaml \
-e APPROVERSPATH=/app/approvers.yaml \
-e TRUSTPROXY=true
```
