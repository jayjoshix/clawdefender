/**
 * Canonical JSON Utilities
 * 
 * Shared module for deterministic JSON serialization.
 * Used by both approval verification and hash-chain logging.
 * 
 * Security features:
 * - Cycle detection (prevents infinite recursion on attacker-controlled input)
 * - Depth limiting (DoS protection)
 * - Plain object enforcement (rejects Date, Buffer, class instances)
 * - Non-finite number rejection (Infinity, NaN, -Infinity)
 * - Resource limits (array length, key count, string size, total nodes)
 */

import { createHash } from 'node:crypto';

// Security limits
const MAX_DEPTH = 50;
const MAX_KEYS_PER_OBJECT = 1000;
const MAX_ARRAY_LENGTH = 10000;
const MAX_STRING_BYTES = 1_000_000; // 1MB
const MAX_TOTAL_NODES = 50000; // Upper bound on total complexity

/**
 * Recursively canonicalize a value for deterministic JSON serialization.
 * - Objects: sorted keys, no undefined values
 * - Arrays: preserved order, elements canonicalized
 * - Primitives: null, boolean, number, string only
 * - Rejects: undefined, functions, symbols, BigInt, cycles, class instances
 * 
 * @param value - The value to canonicalize
 * @param seen - WeakSet for cycle detection (internal use)
 * @param depth - Current recursion depth (internal use)
 * @param counter - Mutable counter object to track total nodes (internal use)
 * @throws Error if value contains non-JSON types, cycles, or exceeds limits
 */
export function canonicalize(
    value: unknown,
    seen: WeakSet<object> = new WeakSet(),
    depth: number = 0,
    counter: { count: number } = { count: 0 }
): unknown {
    // Total node limit (counts primitives and containers)
    counter.count++;
    if (counter.count > MAX_TOTAL_NODES) {
        throw new Error(`Total node limit exceeded (max ${MAX_TOTAL_NODES})`);
    }

    // Depth check
    if (depth > MAX_DEPTH) {
        throw new Error(`Canonicalize depth limit exceeded (max ${MAX_DEPTH})`);
    }

    // Null
    if (value === null) return null;

    // Primitives
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) {
            throw new Error(`Non-finite number in payload: ${value}`);
        }
        return value;
    }
    if (typeof value === 'string') {
        if (value.length > MAX_STRING_BYTES) {
            throw new Error(`String exceeds max length (${value.length} codes > ${MAX_STRING_BYTES})`);
        }
        const byteLen = Buffer.byteLength(value, 'utf8');
        if (byteLen > MAX_STRING_BYTES) {
            throw new Error(`String exceeds max length (${byteLen} bytes > ${MAX_STRING_BYTES})`);
        }
        return value;
    }

    // Arrays - preserve order, canonicalize elements
    if (Array.isArray(value)) {
        if (value.length > MAX_ARRAY_LENGTH) {
            throw new Error(`Array exceeds max length (${value.length} > ${MAX_ARRAY_LENGTH})`);
        }

        // Cycle detection
        if (seen.has(value)) {
            throw new Error('Circular reference detected in payload');
        }
        seen.add(value);

        try {
            return value.map((v) => canonicalize(v, seen, depth + 1, counter));
        } finally {
            seen.delete(value);
        }
    }

    // Plain objects only - reject class instances, Date, Buffer, etc.
    if (typeof value === 'object') {
        // Strict plain object check: must be exactly Object.prototype
        const proto = Object.getPrototypeOf(value);
        if (proto !== Object.prototype) {
            throw new Error(`Non-plain object in payload: ${value?.constructor?.name ?? 'unknown'}`);
        }

        // Cycle detection
        if (seen.has(value)) {
            throw new Error('Circular reference detected in payload');
        }
        seen.add(value);

        try {
            const keys = Object.keys(value as object);
            if (keys.length > MAX_KEYS_PER_OBJECT) {
                throw new Error(`Object exceeds max keys (${keys.length} > ${MAX_KEYS_PER_OBJECT})`);
            }

            const sorted: Record<string, unknown> = {};
            for (const key of keys.sort()) {
                const v = (value as Record<string, unknown>)[key];
                if (v !== undefined) {
                    sorted[key] = canonicalize(v, seen, depth + 1, counter);
                }
            }
            return sorted;
        } finally {
            seen.delete(value);
        }
    }

    // Reject non-JSON types
    throw new Error(`Non-JSON type in payload: ${typeof value}`);
}

/**
 * Deterministic JSON serialization using canonicalize.
 * Produces identical output for semantically equal objects.
 */
export function stableJson(obj: unknown): string {
    return JSON.stringify(canonicalize(obj));
}

/**
 * Compute SHA256 hash of canonicalized JSON representation.
 * Uses stableJson for full recursive key sorting.
 * Explicit 'utf8' encoding for security-critical consistency.
 */
export function sha256(data: unknown): string {
    return createHash('sha256').update(stableJson(data), 'utf8').digest('hex');
}

/**
 * Compute SHA256 hash of a buffer or string directly.
 * For strings, explicit 'utf8' encoding is used.
 */
export function sha256Bytes(data: Buffer | string): string {
    if (typeof data === 'string') {
        return createHash('sha256').update(data, 'utf8').digest('hex');
    }
    return createHash('sha256').update(data).digest('hex');
}
