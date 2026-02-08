/**
 * Seal Client - Decentralized secrets management on Sui
 * 
 * Uses @mysten/seal SDK v1.0.0 for threshold encryption with on-chain access control.
 * Compatible with @mysten/sui v2.x
 */

import { SealClient, SessionKey, EncryptedObject, type SealClientOptions, type KeyServerConfig } from '@mysten/seal';
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from '@mysten/sui/jsonRpc';
import { Transaction } from '@mysten/sui/transactions';
import { Signer } from '@mysten/sui/cryptography';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { toHex } from '@mysten/sui/utils';

export interface SealClientConfig {
    network: 'testnet' | 'mainnet';
    /** Optional custom key server configs */
    keyServerConfigs?: KeyServerConfig[];
    /** Whether to verify key servers (default: true) */
    verifyKeyServers?: boolean;
}

// Official Testnet key servers for Seal v1.0.0
// See: https://docs.seal.mystenlabs.xyz/testnet
export const TESTNET_KEY_SERVER_CONFIGS: KeyServerConfig[] = [
    { objectId: '0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75', weight: 1 },
    { objectId: '0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8', weight: 1 },
];

// Official Mainnet key servers for Seal v1.0.0
export const MAINNET_KEY_SERVER_CONFIGS: KeyServerConfig[] = [
    // Add mainnet servers when available
];

/**
 * Create a SuiClient compatible with Seal SDK
 */
function createSuiClient(network: 'testnet' | 'mainnet') {
    const url = getJsonRpcFullnodeUrl(network);
    return new SuiJsonRpcClient({
        url,
        network
    });
}

/**
 * Create a SealClient with key server configuration
 */
export async function getSealClient(config: SealClientConfig): Promise<SealClient> {
    const suiClient = createSuiClient(config.network);

    const serverConfigs = config.keyServerConfigs ??
        (config.network === 'testnet' ? TESTNET_KEY_SERVER_CONFIGS : MAINNET_KEY_SERVER_CONFIGS);

    if (serverConfigs.length === 0) {
        throw new Error('No key servers available for the specified network');
    }

    return new SealClient({
        suiClient,
        serverConfigs,
        verifyKeyServers: config.verifyKeyServers ?? true,
    });
}

/**
 * Create a session key for decryption
 */
export async function createSessionKey(
    address: string,
    packageId: string,
    ttlMin: number,
    signer: Signer,
    network: 'testnet' | 'mainnet' = 'testnet'
): Promise<SessionKey> {
    const suiClient = createSuiClient(network);

    // Use the new SessionKey.create() factory method
    const sessionKey = await SessionKey.create({
        address,
        packageId,
        ttlMin,
        signer,
        suiClient,
    });

    return sessionKey;
}

/**
 * Convert bytes to hex string for Seal id parameter
 */
export function bytesToId(bytes: Uint8Array): string {
    return toHex(bytes);
}

/**
 * Encrypt a session bundle
 * @param bundleBytes - The bundle data to encrypt
 * @param sealClient - Initialized SealClient
 * @param packageId - The Move package ID for access control
 * @param id - Identity namespace for encryption (e.g., session ID as hex string)
 * @returns Encrypted bytes
 */
export async function encryptSessionBundle(
    bundleBytes: Uint8Array,
    sealClient: SealClient,
    packageId: string,
    id: string
): Promise<Uint8Array> {
    // Encrypt using the Seal SDK
    // The id is used as the identity namespace - only those who can
    // call seal_approve_* with this id can decrypt
    const { encryptedObject } = await sealClient.encrypt({
        data: bundleBytes,
        packageId,
        id,
        threshold: 2, // 2-of-n threshold for decryption
    });

    return encryptedObject;
}

/**
 * Decrypt a session bundle
 * @param encryptedBytes - The encrypted bundle data
 * @param sessionKey - Initialized and signed SessionKey
 * @param txBytes - Transaction bytes from buildApprovalTx (only calls seal_approve_*)
 * @param sealClient - Initialized SealClient
 * @returns Decrypted bytes
 */
export async function decryptSessionBundle(
    encryptedBytes: Uint8Array,
    sessionKey: SessionKey,
    txBytes: Uint8Array,
    sealClient: SealClient
): Promise<Uint8Array> {
    // Decrypt using the Seal SDK
    const decrypted = await sealClient.decrypt({
        data: encryptedBytes,
        sessionKey,
        txBytes,
    });

    return decrypted;
}

/**
 * Build a transaction that calls seal_approve_access
 * This transaction is used for decryption - it must only call seal_approve_* functions
 * 
 * @param packageId - The deployed seal_policy package ID
 * @param accessCapId - The AccessCap object ID that the user owns
 * @param id - The identity bytes to verify
 * @param client - SuiClient for transaction resolution (required in SDK v2)
 * @returns Transaction bytes for use with decrypt
 */
export async function buildApprovalTx(
    packageId: string,
    accessCapId: string,
    id: Uint8Array,
    client: SuiJsonRpcClient
): Promise<{ txBytes: Uint8Array; tx: Transaction }> {
    const tx = new Transaction();

    // Call seal_approve_access(id: vector<u8>, cap: &AccessCap)
    tx.moveCall({
        target: `${packageId}::policy::seal_approve_access`,
        arguments: [
            tx.pure.vector('u8', Array.from(id)),
            tx.object(accessCapId),
        ],
    });

    // Build with onlyTransactionKind: true for Seal, passing client for resolution
    const txBytes = await tx.build({ onlyTransactionKind: true, client });

    return { txBytes, tx };
}

// Re-export types from @mysten/seal
export { SealClient, SessionKey, EncryptedObject } from '@mysten/seal';
export type { KeyServerConfig, SealClientOptions } from '@mysten/seal';
export { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
export { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from '@mysten/sui/jsonRpc';
