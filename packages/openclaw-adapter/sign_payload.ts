import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';

function stableJson(obj: unknown): string {
    return JSON.stringify(obj, (_, v) => {
        if (v !== null && typeof v === 'object' && !Array.isArray(v))
            return Object.keys(v as object).sort().reduce((s: Record<string, unknown>, k) => { s[k] = (v as Record<string, unknown>)[k]; return s; }, {});
        return v;
    });
}

async function main() {
    const proposalId = process.argv[2];
    if (!proposalId) {
        console.error("Usage: npx tsx sign_payload.ts <proposal-id>");
        process.exit(1);
    }

    try {
        const response = await fetch(`http://localhost:3000/v1/approval_payload/${proposalId}`);
        if (!response.ok) {
            throw new Error(`Failed to fetch payload: ${response.statusText}`);
        }

        const data = await response.json();
        const payload = data.payload;

        const { secretKey } = decodeSuiPrivateKey(process.env.SUI_KEYPAIR || '');
        const kp = Ed25519Keypair.fromSecretKey(secretKey);
        const address = kp.toSuiAddress();

        const bytes = new TextEncoder().encode(stableJson(payload));
        const { signature } = await kp.signPersonalMessage(bytes);

        console.log(`\n✅ Generated Telegram Reply:\n`);
        console.log(`sig:${proposalId} ${address} ${signature}\n`);
    } catch (e) {
        console.error("Error signing payload:", e instanceof Error ? e.message : e);
    }
}

main();
