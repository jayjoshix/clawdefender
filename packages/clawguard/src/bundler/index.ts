/**
 * Session Bundler - Creates encrypted archives of ClawGuard sessions
 * 
 * Creates a tar.gz bundle containing:
 * - policy.yaml used during the session
 * - Session log JSONL
 * - Artifact files (stdout/stderr samples)
 * 
 * Then encrypts with Seal and uploads to Walrus.
 */

import { createReadStream, createWriteStream, existsSync, readFileSync, readdirSync } from 'node:fs';
import { createGzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { join, basename } from 'node:path';
import archiver from 'archiver';
import { sha256Bytes } from '../logging/hash-chain.js';

export interface BundleOptions {
    /** Path to policy.yaml */
    policyPath: string;
    /** Path to session log JSONL file */
    logPath: string;
    /** Optional paths to artifact files */
    artifactPaths?: string[];
    /** Output path for the bundle */
    outputPath: string;
}

export interface BundleResult {
    /** Path to the created bundle */
    bundlePath: string;
    /** SHA256 hash of the bundle */
    bundleHash: string;
    /** Final hash from the log chain */
    finalLogHash: string;
    /** Size of the bundle in bytes */
    bundleSize: number;
}

/**
 * Create a session bundle (tar.gz archive)
 */
export async function createSessionBundle(options: BundleOptions): Promise<BundleResult> {
    const { policyPath, logPath, artifactPaths = [], outputPath } = options;

    // Validate inputs
    if (!existsSync(policyPath)) {
        throw new Error(`Policy file not found: ${policyPath}`);
    }
    if (!existsSync(logPath)) {
        throw new Error(`Log file not found: ${logPath}`);
    }

    // Get final log hash
    const logContent = readFileSync(logPath, 'utf-8').trim();
    let finalLogHash = '0'.repeat(64);
    if (logContent) {
        const lines = logContent.split('\n');
        const lastLine = lines[lines.length - 1];
        try {
            const lastEntry = JSON.parse(lastLine);
            finalLogHash = lastEntry.entry_hash;
        } catch {
            // Use hash of entire log if can't parse
            finalLogHash = sha256Bytes(logContent);
        }
    }

    // Create tar.gz archive
    return new Promise((resolve, reject) => {
        const output = createWriteStream(outputPath);
        const archive = archiver('tar', { gzip: true });

        let bundleSize = 0;

        output.on('close', () => {
            bundleSize = archive.pointer();

            // Read the bundle to compute hash
            const bundleContent = readFileSync(outputPath);
            const bundleHash = sha256Bytes(bundleContent);

            resolve({
                bundlePath: outputPath,
                bundleHash,
                finalLogHash,
                bundleSize,
            });
        });

        output.on('error', reject);
        archive.on('error', reject);

        archive.pipe(output);

        // Add policy.yaml
        archive.file(policyPath, { name: 'policy.yaml' });

        // Add session log
        archive.file(logPath, { name: basename(logPath) });

        // Add artifacts
        for (const artifactPath of artifactPaths) {
            if (existsSync(artifactPath)) {
                archive.file(artifactPath, { name: `artifacts/${basename(artifactPath)}` });
            }
        }

        archive.finalize();
    });
}

/**
 * Extract bundle contents (for verification)
 */
export function readBundleInfo(bundlePath: string): { hash: string; size: number } {
    const content = readFileSync(bundlePath);
    return {
        hash: sha256Bytes(content),
        size: content.length,
    };
}
