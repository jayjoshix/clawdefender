**ClawGuard (Track 1)** — Policy firewall + cryptographic approvals + tamper-evident log chain + Seal/Walrus + on-chain SessionReceipt.

**Verify:**
1) `pnpm demo` (expects `cat ~/.ssh/id_rsa` denied, `rm -rf /` denied, `ls -la /tmp` allowed)
2) `pnpm demo -- --verify-denied` (unauthorized wallet fails to decrypt; proves AccessCap gating)
3) `pnpm demo -- --receipt 0xaa9a4db701295141cbb05705c1280a6162816fdc` (pure on-chain verification)

**Outputs:**
`receiptObjectId`, `policyHash`, `finalLogHash`, `blobId`, `bundleHash`

**Repo:** https://github.com/jayjoshix/clawdefender
**Video:** <LINK_TO_VIDEO>
