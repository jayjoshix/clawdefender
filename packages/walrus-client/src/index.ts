/**
 * Walrus Client - Decentralized blob storage on Sui
 * 
 * Handles both response types from Walrus publisher:
 * - newlyCreated.blobObject.blobId (fresh upload)
 * - alreadyCertified.blobId (content deduplication)
 */

export interface UploadOptions {
    /** Number of epochs to store the blob (default: 5) */
    epochs?: number;
    /** Whether the blob can be deleted (default: false for evidence persistence) */
    deletable?: boolean;
}

export interface UploadResult {
    blobId: string;
    txDigest?: string;
    alreadyCertified: boolean;
    /** Blob is deletable */
    deletable?: boolean;
    /** End epoch for blob availability */
    endEpoch?: number;
    /** The full URL used for upload (includes retention params) */
    uploadUrl: string;
}

// Walrus API response types
interface NewlyCreatedResponse {
    newlyCreated: {
        blobObject: {
            id: string;
            blobId: string;
            storedEpoch: number;
            certifiedEpoch: number;
            deletable: boolean;
        };
        cost: number;
    };
}

interface AlreadyCertifiedResponse {
    alreadyCertified: {
        blobId: string;
        endEpoch: number;
        eventOrObject: {
            Event?: {
                txDigest: string;
                eventSeq: string;
            };
        };
    };
}

type WalrusUploadResponse = NewlyCreatedResponse | AlreadyCertifiedResponse;

export class WalrusClient {
    private publisherUrl: string;
    private aggregatorUrl: string;

    constructor(
        publisherUrl?: string,
        aggregatorUrl?: string
    ) {
        this.publisherUrl = publisherUrl
            ?? process.env.WALRUS_PUBLISHER_URL
            ?? 'https://publisher.walrus-testnet.walrus.space';
        this.aggregatorUrl = aggregatorUrl
            ?? process.env.WALRUS_AGGREGATOR_URL
            ?? 'https://aggregator.walrus-testnet.walrus.space';
    }

    /**
     * Upload bytes to Walrus blob storage.
     * Handles both newlyCreated and alreadyCertified responses.
     */
    async upload(fileBytes: Uint8Array, options: UploadOptions = {}): Promise<UploadResult> {
        const epochs = options.epochs ?? 5;
        const deletable = options.deletable ?? false;

        // Build URL with query params
        const url = new URL(`${this.publisherUrl}/v1/blobs`);
        url.searchParams.set('epochs', epochs.toString());
        if (deletable) {
            url.searchParams.set('deletable', 'true');
        }

        const response = await fetch(url.toString(), {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/octet-stream',
            },
            body: fileBytes,
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Walrus upload failed (${response.status}): ${errorText}`);
        }

        const data = await response.json() as WalrusUploadResponse;

        // Handle newlyCreated response
        if ('newlyCreated' in data) {
            return {
                blobId: data.newlyCreated.blobObject.blobId,
                alreadyCertified: false,
                deletable: data.newlyCreated.blobObject.deletable,
                uploadUrl: url.toString(),
            };
        }

        // Handle alreadyCertified response (content deduplication)
        if ('alreadyCertified' in data) {
            return {
                blobId: data.alreadyCertified.blobId,
                txDigest: data.alreadyCertified.eventOrObject.Event?.txDigest,
                alreadyCertified: true,
                endEpoch: data.alreadyCertified.endEpoch,
                uploadUrl: url.toString(),
            };
        }

        throw new Error('Unexpected Walrus response format');
    }

    /**
     * Download a blob from Walrus by its blobId.
     */
    async download(blobId: string): Promise<Uint8Array> {
        const url = `${this.aggregatorUrl}/v1/blobs/${blobId}`;

        const response = await fetch(url, {
            method: 'GET',
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Walrus download failed (${response.status}): ${errorText}`);
        }

        const arrayBuffer = await response.arrayBuffer();
        return new Uint8Array(arrayBuffer);
    }

    /**
     * Get publisher URL
     */
    getPublisherUrl(): string {
        return this.publisherUrl;
    }

    /**
     * Get aggregator URL
     */
    getAggregatorUrl(): string {
        return this.aggregatorUrl;
    }
}

// Default export
export default WalrusClient;
