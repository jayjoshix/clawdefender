# ClawGuard — DeepSurge Submission

> **ClawGuard turns any OpenClaw agent into a cryptographically auditable firewall**: every risky action is proposed, policy-checked, approved, logged, and anchored to Sui/Walrus for post-mortem verification.

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
5. **Seal Encrypt** → threshold encryption with on-chain AccessCap
6. **Walrus Store** → durable ciphertext layer
7. **SessionReceipt** → on-chain root of trust with `policyHash`, `finalLogHash`, `blobId`, `bundleHash`

---

## 🧪 What Judges Can Verify in 5 Minutes

```bash
git clone https://github.com/jayjoshix/clawdefender.git
cd clawdefender && pnpm install && pnpm build

# 1. See malicious command DENIED, benign ALLOWED
pnpm demo

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
| **Sui Seal** | Threshold encryption; decryption gated by on-chain policy |
| **Walrus** | Durable ciphertext storage with blob epochs |
| **SessionReceipt** | Move object: `policyHash`, `finalLogHash`, `blobId`, `bundleHash` |
| **AccessCap** | On-chain capability controlling log decryption |

---

## 🏆 Hackathon Scoring

### Technical Merit
- Nonce-tracked approvals prevent replay attacks
- `argsHash` / `policyHash` / `entryHash` binding ensures integrity
- Fail-closed log rehydration only after `verifyLogChain()`
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

Drop ClawGuard in front of shell/network/filesystem and route tools via propose → approve → execute:

```typescript
import { ClawGuardClient } from '@clawguard/openclaw-adapter';
const client = new ClawGuardClient('http://localhost:3000', process.env.CLAWGUARDTOKEN);

const result = await client.proposeAction('shell', 'exec', { command: 'ls -la' });
// → allow | deny | needs_approval

// Prove your agent's behavior from chain alone:
// pnpm demo -- --receipt <id>
```

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
