import { describe, it, expect } from 'vitest';
import { TESTNET_KEY_SERVER_CONFIGS, bytesToId } from './index.js';

describe('SealClient', () => {
    it('should have fallback key server IDs', () => {
        // The seal client requires network access and real Sui transactions,
        // so we only test the static configuration here
        expect(TESTNET_KEY_SERVER_CONFIGS).toBeDefined();
        expect(TESTNET_KEY_SERVER_CONFIGS.length).toBeGreaterThan(0);
        expect(TESTNET_KEY_SERVER_CONFIGS[0].objectId).toMatch(/^0x[a-f0-9]+$/);
    });

    it('should convert bytes to hex id', () => {
        const bytes = new Uint8Array([1, 2, 3, 4]);
        const id = bytesToId(bytes);
        expect(id).toBe('01020304');
    });

    // Integration tests would require:
    // - Deployed Move package on Sui testnet
    // - Funded wallet for transactions
    // - Network access to key servers
    it.skip('should encrypt and decrypt a bundle (integration)', async () => {
        // This test requires real Sui transactions and is skipped by default
    });
});
