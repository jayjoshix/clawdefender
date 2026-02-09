# ClawGuard Submission Details

## 🏆 Track Selection
**Track 1: Safety & Security - Fighting Magic with Magic**

> "Build an immune system for yourself to avoid getting wrecked."

## 🚀 Project Description
**ClawGuard** is a **Policy Firewall & Digital Blackbox** for AI Agents. It acts as a security middleware that intercepts every tool call from an agent (like OpenClaw), enforces granular access policies, and cryptographically logs actions locally. For high-assurance sessions, it anchors a **Session Receipt** on the Sui blockchain, pointing to an encrypted audit trail stored on Walrus.

## 🎯 Feature Mapping (Track 1 Criteria)

ClawGuard implements **3 key ideas** for this track:

| Hackathon Idea | ClawGuard Implementation | Status |
|----------------|--------------------------|--------|
| **"The Wallet Air-Gap"** | **Telegram Signed Approvals**: Risky actions (like `deploy`) trigger a Telegram request. Verification requires an **offline cryptographic signature** from the user's Sui wallet (Ed25519) bound to the canonical instruction bytes. **Telegram acts only as the transport; the security comes from the Sui signature.** | ✅ **Live** |
| **"Injection Hunter"** | **Policy Firewall**: Blocks dangerous tool calls (e.g., `rm -rf /`, `cat ~/.ssh/*`) based on a `policy.yaml` allowlist, preventing prompt injection from executing system-level damage. | ✅ **Live** |
| **"Post cryptographic proof"** | **Sui + Walrus Receipts**: Session logs are hashed into a tamper-evident chain. The final bundle is **encrypted with Seal**, uploaded to **Walrus (Testnet)**, and the cryptographic receipt (root hash) is anchored on **Sui**, creating an immutable forensic trail. | ✅ **Live** |
| **"Self-Hardening"** | **Seal Encryption**: Sensitive session logs are automatically encrypted using Threshold Encryption (Seal) before upload. Decryption is gated by an on-chain Seal policy; only identities satisfying that policy can obtain threshold key shares to decrypt. | ✅ **Live** |
| **"Context-Awareness"** | **PBAC Engine**: Decisions depend on context. The same command (e.g., `ls`) is allowed locally but triggers approval when originating from an **untrusted source** (web/email), enforcing least privilege dynamically. | ✅ **Live** |

## 🛠️ Sui Stack Integration

| Component | Usage |
|-----------|-------|
| **Sui Network** | Anchors session receipts (`SessionReceipt` object) for immutability. |
| **Walrus** | Stores encoded session bundles. **Note:** Demo uses Walrus Testnet; blobs are ephemeral and may be wiped or expire by epoch. Blob deletion is not a privacy mechanism; we treat all storage as public and rely on Seal encryption for privacy. |
| **Sui Seal** | Protects sensitive audit logs using threshold encryption (`@mysten/seal` v1.0). Decryption access is enforced on-chain. |
| **Sui TypeScript SDK** | Handles all on-chain interactions and offline signature verification (`verifyPersonalMessageSignature`). |

## 🔗 Links & Resources

- **GitHub Repo**: [Link]
- **Demo Video**: [Link]
- **Live Demo Command**:
  ```bash
  # Requires Node.js 20+ & pnpm
  git clone <repo>
  cd clawguard
  pnpm install && pnpm build
  # Run full demo (Policy -> Approval -> Encryption -> Receipt)
  pnpm demo
  ```

## 📸 visual Proofs

1.  **Policy Denial**: Agent attempts `cat ~/.ssh/id_rsa` -> **BLOCKED**.
2.  **Telegram Approval**: Agent requests `shell:exec` -> User signs offline -> **APPROVED**.
3.  **On-Chain Receipt**: [Suiscan Link] (shows `policy_hash` and `final_log_hash`).
