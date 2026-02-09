# ClawGuard — DeepSurge Submission

> **ClawGuard turns any OpenClaw agent into a cryptographically auditable firewall**: every risky action is proposed, policy-checked, approved, logged, and anchored to Sui/Walrus for post-mortem verification.

> **Designed for Suixclaw**: every decision (`allow` / `deny` / `needs_approval`) is machine-parseable, and every session has a verifiable Seal + Walrus + SessionReceipt trail so agents can audit other agents.

---

## 🔴 Problem

**Agents have root.** One prompt injection or model bug can `rm -rf /` or drain wallets—and logs can be tampered post-incident, making forensics unreliable.

---

## ✅ Solution

ClawGuard intercepts every tool call and enforces a fail-closed security pipeline:

1. **Policy Firewall** → `allow` / `deny` / `needs_approval`
2. **Signed Approval** → nonce-bound Ed25519 signature (Telegram or API)
3. **Execute** → `spawnSync(shell: false)` hardened execution
4. **Log Chain** → `prev_hash` → `entry_hash` binding
5. **Seal Encrypt** → threshold encryption (Sui Seal package)
6. **Walrus Store** → durable ciphertext layer
7. **SessionReceipt** → on-chain root of trust with `policyHash`, `finalLogHash`, `blobId`, `bundleHash`

**Adversarial Proof Mode**: An unauthorized wallet can download ciphertext from Walrus but *fails* to decrypt due to missing AccessCap—proving logs are protected by on-chain access control, not obscurity.

---

## 🧪 What Judges Can Verify in 5 Minutes

> **Prerequisites**: `pnpm`, Node 20+, and access to Sui testnet (for on-chain modes).

```bash
git clone https://github.com/jayjoshix/clawdefender.git
cd clawdefender && pnpm install && pnpm build

# 1. See malicious command DENIED, benign ALLOWED
pnpm demo
# Expected: cat ~/.ssh/id_rsa → DENIED, rm -rf / → DENIED, ls -la /tmp → ALLOWED

# 2. Off-chain verification of Walrus bundle + log hash
pnpm demo -- --verify

# 3. Adversarial proof: decryption fails without AccessCap
pnpm demo -- --verify-denied

# 4. Pure on-chain verification (trusts only Sui + Walrus)
pnpm demo -- --receipt 0x<Sui_Receipt_Object_ID>
```

---

## 🔗 Sui Integration

| Component | Usage |
|-----------|-------|
| **Sui Seal** | Threshold encryption (Sui Seal package); decryption gated by on-chain policy |
| **Walrus** | Durable ciphertext storage with blob epochs |
| **SessionReceipt** | Move object: `policyHash`, `finalLogHash`, `blobId`, `bundleHash` |
| **AccessCap** | On-chain capability controlling log decryption |

> **Simulation Mode**: If `SEAL_PACKAGE_ID` or `SUI_KEYPAIR` are not set, ClawGuard runs in simulation mode: Walrus upload still happens, but SessionReceipt minting is skipped. Judges can still run `--verify` off-chain.

---

## 🏆 Hackathon Scoring

### Technical Merit
- Nonce-tracked approvals prevent replay attacks
- `argsHash` / `policyHash` / `entryHash` binding ensures integrity
- Log rehydration is **fail-closed**: on startup, `verifyLogChain()` runs before trusting any previous entries; if verification fails, it rotates the log
- Agent Plan B execution via permit system

### Creativity
- **"Black box flight recorder"** pattern for AI agents
- Verifiable post-hoc proofs anchored on-chain
- Context-aware PBAC: same command allowed/denied based on source

### Sui Integration
- Seal-based encryption with on-chain access control
- Walrus as immutable ciphertext layer
- SessionReceipt on Sui as root of trust

---

## 🔌 How to Use With Your Agent

In OpenClaw, route tools through ClawGuard by swapping direct shell/network/filesystem calls for `propose → (optional approve) → execute`. The included `@clawguard/openclaw-adapter` wraps these endpoints into an OpenClaw-compatible tool client.

```typescript
import { ClawGuardClient } from '@clawguard/openclaw-adapter';
const client = new ClawGuardClient('http://localhost:3000', process.env.CLAWGUARDTOKEN);

// Inside your OpenClaw agent tool implementation:
const result = await client.proposeAction('shell', 'exec', { command: 'ls -la' });
// → allow | deny | needs_approval

// Prove your agent's behavior from chain alone:
// pnpm demo -- --receipt <id>
```

### Why Track 2 ("Jarvis") Teams Should Care
- Protect your always-on assistant from `rm -rf` and wallet drains without touching your agent logic
- Get a ready-made, on-chain-verifiable audit trail you can show in *your* Track 2 submission: `pnpm demo -- --receipt <id>`

---

## ❓ FAQ for Judges

**Q: What if the log is corrupted?**  
`verifyLogChain()` recomputes all hashes and compares against on-chain `finalLogHash`. Corruption is detected and rejected.

**Q: What if the approver key is compromised?**  
Each approval is nonce-bound. Replay is impossible. Remove compromised addresses from `approvers.yaml`.

**Q: Does this prevent prompt injection?**  
It **contains the blast radius**. Malicious commands are denied, require approval, or logged immutably for forensics.

---

## 📸 Visual Proofs

1. **Policy Denial**: `cat ~/.ssh/id_rsa` → **BLOCKED**
2. **Telegram Approval**: `shell:exec` → User signs offline → **APPROVED**
3. **On-Chain Receipt**: [Suiscan Link] (shows `policyHash`, `finalLogHash`)

---

## 🔗 Links

- **GitHub**: https://github.com/jayjoshix/clawdefender
- **Demo Video**: [Link]
- **Track**: Safety & Security — Fighting Magic with Magic
