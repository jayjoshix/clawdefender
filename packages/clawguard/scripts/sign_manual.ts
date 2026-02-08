
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';

const PRIV_KEY_BECH32 = process.env.SUI_KEYPAIR;
if (!PRIV_KEY_BECH32) {
    throw new Error('SUI_KEYPAIR environment variable is required');
}

const payload = {
    "domain": "CLAWGUARD_APPROVAL_V1",
    "intent": "EXECUTE_ACTION",
    "sessionId": "975ea244-69f1-455c-866b-541a70ee5e0b",
    "proposalId": "6321b495-f5c8-4689-a5a6-bae0f6f37148",
    "proposalEntryHash": "0dfeec5b1de34ff8428b9f27c382f7ab6cdc749b2023a16084e727ec887ae3c8",
    "tool": "shell",
    "action": "rm test.txt",
    "argsHash": "e4cc2949253d3789985d218c3c0bd6e591985c18c7bf5ad13d54e51d332e5509",
    "policyHash": "30547685d36effc3c0ee3a1310f26e1e931997a8c24d8a12b55486c9c91c56de",
    "expiresAt": 1770531229,
    "nonce": "06b9380c28efb919d3c20d73f3a0c61a2d825dd74aa36829c63654d17f3af89f"
};

async function main() {
    const { schema, secretKey } = decodeSuiPrivateKey(PRIV_KEY_BECH32);
    const keypair = Ed25519Keypair.fromSecretKey(secretKey);
    console.log(`Signer: ${keypair.toSuiAddress()}`);

    const message = new TextEncoder().encode(JSON.stringify(payload));
    const { signature } = await keypair.signPersonalMessage(message);

    console.log(`Signature: ${signature}`);
}

main().catch(console.error);
