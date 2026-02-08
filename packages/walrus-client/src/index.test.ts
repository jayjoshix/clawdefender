import { describe, it, expect, beforeAll } from 'vitest';
import { WalrusClient } from './index.js';

describe('WalrusClient', () => {
    let client: WalrusClient;

    beforeAll(() => {
        client = new WalrusClient();
    });

    it('should use default testnet URLs', () => {
        expect(client.getPublisherUrl()).toBe('https://publisher.walrus-testnet.walrus.space');
        expect(client.getAggregatorUrl()).toBe('https://aggregator.walrus-testnet.walrus.space');
    });

    it('should accept custom URLs', () => {
        const customClient = new WalrusClient(
            'https://custom.publisher.example',
            'https://custom.aggregator.example'
        );
        expect(customClient.getPublisherUrl()).toBe('https://custom.publisher.example');
        expect(customClient.getAggregatorUrl()).toBe('https://custom.aggregator.example');
    });

    // Integration test - requires network, run with: pnpm test -- --run
    it.skip('should upload and download a blob (integration)', async () => {
        const testData = new TextEncoder().encode('ClawGuard test blob ' + Date.now());

        // Upload
        const uploadResult = await client.upload(testData, { epochs: 1 });
        expect(uploadResult.blobId).toBeDefined();
        expect(typeof uploadResult.blobId).toBe('string');
        console.log('Uploaded blob:', uploadResult.blobId);

        // Download
        const downloaded = await client.download(uploadResult.blobId);
        expect(downloaded).toEqual(testData);
    });
});
