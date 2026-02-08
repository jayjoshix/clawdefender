
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';

const PRIV_KEY_BECH32 = process.env.SUI_KEYPAIR;
if (!PRIV_KEY_BECH32) {
    throw new Error('SUI_KEYPAIR environment variable is required');
}
const SERVER_URL = 'http://localhost:3000';
const TOKEN = 'secret-token';

// --- Canonical JSON (Simple Implementation) ---
function canonicalize(value: any): any {
    if (value === null || typeof value !== 'object') {
        return value;
    }
    if (Array.isArray(value)) {
        return value.map(canonicalize);
    }
    const sorted: Record<string, any> = {};
    Object.keys(value).sort().forEach(key => {
        const v = value[key];
        if (v !== undefined) {
            sorted[key] = canonicalize(v);
        }
    });
    return sorted;
}

function stableJson(obj: any): string {
    return JSON.stringify(canonicalize(obj));
}
// ----------------------------------------------

async function main() {
    console.log('🚀 Starting Manual Approval Flow (Corrected)...');

    // 1. Propose Action
    const proposeRes = await fetch(`${SERVER_URL}/v1/propose_action`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${TOKEN}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            tool: 'shell',
            action: 'rm test.txt',
            args: { command: 'rm test.txt' }
        })
    });
    const proposeJson = await proposeRes.json();
    console.log('1. Proposed:', proposeJson);

    if (proposeJson.decision !== 'needs_approval') {
        console.error('Expected needs_approval, got:', proposeJson.decision);
        return;
    }

    const proposalId = proposeJson.proposalId;

    // 2. Get Payload
    const payloadRes = await fetch(`${SERVER_URL}/v1/approval_payload/${proposalId}`, {
        headers: { 'Authorization': `Bearer ${TOKEN}` }
    });
    const payloadJson = await payloadRes.json();
    // Use the inner payload object
    const rawPayload = payloadJson.payload;
    console.log('2. Got Payload, Expires At:', rawPayload.expiresAt);

    // 3. Sign Payload (Canonicalized)
    const { schema, secretKey } = decodeSuiPrivateKey(PRIV_KEY_BECH32);
    const keypair = Ed25519Keypair.fromSecretKey(secretKey);
    const signerAddress = keypair.toSuiAddress();
    console.log('3. Signing with address:', signerAddress);

    // CRITICAL: Must use canonical JSON string for signing
    const jsonString = stableJson(rawPayload);
    const message = new TextEncoder().encode(jsonString);
    const { signature } = await keypair.signPersonalMessage(message);

    // 4. Submit Approval
    const approveRes = await fetch(`${SERVER_URL}/v1/approve_action`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${TOKEN}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            proposalId,
            expiresAt: rawPayload.expiresAt,
            nonce: rawPayload.nonce,
            approverAddress: signerAddress,
            signature
        })
    });

    if (!approveRes.ok) {
        const err = await approveRes.text();
        console.error('4. Approval Failed:', err);
        return;
    }
    console.log('4. Approval Submitted');

    // 5. Execute
    const execRes = await fetch(`${SERVER_URL}/v1/execute_action`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${TOKEN}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ proposalId })
    });

    const execJson = await execRes.json();
    console.log('5. Execution Result:', execJson);
}

main().catch(console.error);
