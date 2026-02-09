# ClawGuard Demo Video Script 🎬

**Goal**: Showcase ClawGuard protecting an AI agent in < 2 minutes.

## 🎞️ Scene 1: The Setup (0:00 - 0:20)
*   **Visual**: Terminal + `policy.yaml` open in VS Code.
*   **Action**: Briefly show `policy.yaml` blocking `rm -rf /` and `*.onion`.
*   **Narration**: "This is ClawGuard. Only approved tools run on my machine. Here, I've configured it to block dangerous shell commands but allow safe ones after human approval."

## 🎞️ Scene 2: Context Awareness (PBAC) (0:20 - 0:40)
*   **Visual**: Terminal.
*   **Action**: 
    1. **Trusted Request**:
       ```bash
       curl -X POST http://localhost:3000/v1/propose_action -H "Content-Type: application/json" -d '{"tool":"shell","action":"exec","args":{"command":"ls -la"}}'
       # Response: decision: "allow"
       ```
    2. **Untrusted Context**:
       ```bash
       curl -X POST http://localhost:3000/v1/propose_action -H "Content-Type: application/json" -d '{"tool":"shell","action":"exec","args":{"command":"ls -la"},"meta":{"untrustedSource":"web"}}'
       # Response: decision: "needs_approval", reason: "Untrusted source requires approval..."
       ```
*   **Narration**: "ClawGuard isn't just a firewall; it's context-aware. The same `ls` command is allowed locally but flagged for approval when originating from an untrusted web source, thanks to our Policy-Based Access Control (PBAC)."

## 🎞️ Scene 3: The Attack (0:40 - 1:00)
*   **Visual**: Terminal.
*   **Action**: 
    ```bash
    # Attempt to read SSH keys
    curl -X POST http://localhost:3000/v1/execute_action -H "Content-Type: application/json" -H "Authorization: Bearer secret" -d '{"tool":"shell","action":"exec","args":{"command":"cat ~/.ssh/id_rsa"}}'
    ```
*   **Result**: Show `403 Forbidden` response in terminal.
*   **Narration**: "My agent just tried to steal my SSH keys. ClawGuard intercepted the tool call and blocked it instantly based on the policy."

## 🎞️ Scene 4: The Air-Gap (1:00 - 1:20)
*   **Visual**: Split screen: Terminal (Agent) + Telegram Desktop.
*   **Action**: 
    1. Agent requests `ls -la /` (Triggering "needs_approval").
    2. Show Telegram bot notification pop up.
    3. Click **✅ Approve**.
    4. Copy JSON payload from Telegram.
    5. Run signing script: `pnpm exec tsx scripts/sign-approval.ts '<paste>'`
    6. Paste signature back to Telegram.
*   **Narration**: "Now the agent needs to list directory files. It requests approval. Telegram acts only as the transport; the real security is the offline cryptographic signature from my Sui wallet unless verified on-chain."

## 🎞️ Scene 5: Replay Protection (1:20 - 1:40)
*   **Visual**: Terminal.
*   **Action**: 
    1. Execute the approved action (Success).
    2. **Immediately try to execute it again** (or resubmit the same signed approval).
    3. Show Error: `Nonce already used` or `Action already executed`.
*   **Narration**: "Approvals are single-use capabilities. Attempting to replay the same signed approval header fails because the nonce is consumed instantly. Even if the network is compromised, old signatures cannot be reused."

## 🎞️ Scene 6: The Proof (1:40 - 2:10)
*   **Visual**: Suiscan (Sui Explorer) + Terminal running verification.
*   **Action**: 
    1. Show **SessionReceipt** on Suiscan: Point to `walrus_blob_id` and `final_log_hash`.
    2. Run: `pnpm demo -- --verify`
    3. **Crucial Step**: Highlight the terminal output showing:
       - "Downloaded [bytes] from Walrus blob [ID]" (Matches receipt).
       - "Decrypting with Seal..." (Shows Policy ID).
       - "Log Chain Verified! Root Hash matches on-chain receipt."
*   **Narration**: "Finally, verification. We fetch the encrypted blob from Walrus Testnet. Decryption is gated by an on-chain Seal policy. Once decrypted, we recompute the entire hash chain and prove it matches the immutable receipt anchored on Sui."

## 🎞️ Scene 7: Conclusion (2:10 - 2:20)
*   **Visual**: GitHub Repo `README.md`.
*   **Narration**: "ClawGuard brings immune systems to AI agents. Open source, built on the full Sui stack. Trust your agent, but verify everything."
