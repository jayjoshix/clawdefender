
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { stableJson } from '../util/canonical-json.js';

export interface PermitPayload {
    v: 1;
    iss: string;      // clawguard public key id / instance id
    sub: string;      // subject (e.g. agent-id)
    aud: 'openclaw-runtime';
    sessionId: string;

    proposalId: string;
    proposalEntryHash: string;
    policyHash: string;

    tool: string;
    action: string;
    argsHash: string; // sha256(canonical(args))

    iat: number;
    exp: number;      // short (e.g., 30-120s)
    jti: string;      // nonce / token id
}

export async function createPermit(payload: PermitPayload, keypair: Ed25519Keypair): Promise<string> {
    const canonicalPayload = stableJson(payload);
    const payloadBytes = new TextEncoder().encode(canonicalPayload);
    const payloadB64 = Buffer.from(payloadBytes).toString('base64url');

    const signature = await keypair.sign(payloadBytes);
    const signatureB64 = Buffer.from(signature).toString('base64url');

    return `${payloadB64}.${signatureB64}`;
}

export async function verifyPermit(token: string, publicKey: Ed25519PublicKey): Promise<PermitPayload> {
    const [payloadB64, signatureB64] = token.split('.');
    if (!payloadB64 || !signatureB64) {
        throw new Error('Invalid permit token format');
    }

    const payloadBytes = Buffer.from(payloadB64, 'base64url');
    const signatureBytes = Buffer.from(signatureB64, 'base64url');

    const isValid = await publicKey.verify(payloadBytes, signatureBytes);
    if (!isValid) {
        throw new Error('Invalid permit signature');
    }

    const json = new TextDecoder().decode(payloadBytes);
    return JSON.parse(json) as PermitPayload;
}
