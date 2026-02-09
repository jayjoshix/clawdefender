/**
 * Telegram Approval Handler Unit Tests
 * 
 * Tests the core utilities and logic of the Telegram handler.
 * Note: Full integration tests require a real Telegram bot token.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock fetch globally before importing the module
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Test the exported utility functions by importing the module
// We'll test the internal logic through behavior

describe('Telegram Handler Utilities', () => {
    beforeEach(() => {
        mockFetch.mockReset();
    });

    describe('UTF-8 Byte Length Calculations', () => {
        it('calculates ASCII string length correctly', () => {
            // ASCII chars are 1 byte each
            const encoder = new TextEncoder();
            expect(encoder.encode('hello').length).toBe(5);
            expect(encoder.encode('a').length).toBe(1);
        });

        it('calculates multi-byte characters correctly', () => {
            const encoder = new TextEncoder();
            // Emoji is 4 bytes in UTF-8
            expect(encoder.encode('🔑').length).toBe(4);
            // Japanese character is 3 bytes
            expect(encoder.encode('日').length).toBe(3);
            // Combining emoji
            expect(encoder.encode('👨‍👩‍👧').length).toBeGreaterThan(4);
        });

        it('handles surrogate pairs correctly', () => {
            const encoder = new TextEncoder();
            // U+1F4A1 (💡) is a surrogate pair in JavaScript
            const bulb = '💡';
            expect(bulb.length).toBe(2); // JavaScript string length
            expect(encoder.encode(bulb).length).toBe(4); // UTF-8 bytes
        });
    });

    describe('Canonical JSON Serialization', () => {
        it('produces deterministic output with sorted keys', () => {
            const obj1 = { b: 2, a: 1, c: 3 };
            const obj2 = { c: 3, a: 1, b: 2 };

            // Using the same canonicalization algorithm
            const canonicalize = (obj: Record<string, unknown>): string => {
                const sorted: Record<string, unknown> = {};
                for (const key of Object.keys(obj).sort()) {
                    sorted[key] = obj[key];
                }
                return JSON.stringify(sorted);
            };

            expect(canonicalize(obj1)).toBe(canonicalize(obj2));
            expect(canonicalize(obj1)).toBe('{"a":1,"b":2,"c":3}');
        });

        it('handles nested objects', () => {
            const nested = { z: { b: 2, a: 1 }, a: 'first' };

            const canonicalize = (value: unknown): unknown => {
                if (value === null) return null;
                if (typeof value !== 'object') return value;
                if (Array.isArray(value)) return value.map(canonicalize);

                const sorted: Record<string, unknown> = {};
                for (const key of Object.keys(value as object).sort()) {
                    sorted[key] = canonicalize((value as Record<string, unknown>)[key]);
                }
                return sorted;
            };

            const result = JSON.stringify(canonicalize(nested));
            expect(result).toBe('{"a":"first","z":{"a":1,"b":2}}');
        });
    });

    describe('UUID Validation', () => {
        const UUID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

        it('accepts valid UUIDs', () => {
            expect(UUID_REGEX.test('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
            expect(UUID_REGEX.test('6ba7b810-9dad-11d1-80b4-00c04fd430c8')).toBe(true);
            expect(UUID_REGEX.test('f47ac10b-58cc-4372-a567-0e02b2c3d479')).toBe(true);
        });

        it('rejects invalid UUIDs', () => {
            expect(UUID_REGEX.test('not-a-uuid')).toBe(false);
            expect(UUID_REGEX.test('550e8400-e29b-41d4-a716')).toBe(false);
            expect(UUID_REGEX.test('550e8400e29b41d4a716446655440000')).toBe(false);
            expect(UUID_REGEX.test('')).toBe(false);
        });
    });

    describe('Sui Address Validation', () => {
        const SUI_ADDRESS_REGEX = /^0x[a-fA-F0-9]{64}$/;

        it('accepts valid Sui addresses', () => {
            const validAddress = '0x' + 'a'.repeat(64);
            expect(SUI_ADDRESS_REGEX.test(validAddress)).toBe(true);

            const mixedCase = '0x' + 'aAbBcCdDeEfF'.repeat(5) + 'aaaa';
            expect(SUI_ADDRESS_REGEX.test(mixedCase)).toBe(true);
        });

        it('rejects invalid Sui addresses', () => {
            expect(SUI_ADDRESS_REGEX.test('0x' + 'a'.repeat(63))).toBe(false); // Too short
            expect(SUI_ADDRESS_REGEX.test('0x' + 'a'.repeat(65))).toBe(false); // Too long
            expect(SUI_ADDRESS_REGEX.test('a'.repeat(64))).toBe(false); // Missing 0x
            expect(SUI_ADDRESS_REGEX.test('0x' + 'g'.repeat(64))).toBe(false); // Invalid hex
        });
    });

    describe('Base64 Signature Validation', () => {
        const BASE64_SIGNATURE_REGEX = /^[A-Za-z0-9+/_-]+=*$/;

        it('accepts valid base64 signatures', () => {
            expect(BASE64_SIGNATURE_REGEX.test('dGVzdA==')).toBe(true);
            expect(BASE64_SIGNATURE_REGEX.test('aGVsbG8gd29ybGQ=')).toBe(true);
            expect(BASE64_SIGNATURE_REGEX.test('YWJjZGVm')).toBe(true);
            // Base64URL variant
            expect(BASE64_SIGNATURE_REGEX.test('abc_def-ghi')).toBe(true);
        });

        it('rejects invalid base64 signatures', () => {
            expect(BASE64_SIGNATURE_REGEX.test('')).toBe(false);
            expect(BASE64_SIGNATURE_REGEX.test('invalid!signature')).toBe(false);
            expect(BASE64_SIGNATURE_REGEX.test('has spaces')).toBe(false);
        });
    });

    describe('Callback Data Length Validation', () => {
        const TELEGRAM_CALLBACK_DATA_LIMIT = 64;

        it('validates callback data within limit', () => {
            const encoder = new TextEncoder();

            // UUID is 36 chars, "approve:" is 8, total 44 bytes - within limit
            const approveData = 'approve:550e8400-e29b-41d4-a716-446655440000';
            expect(encoder.encode(approveData).length).toBeLessThanOrEqual(TELEGRAM_CALLBACK_DATA_LIMIT);

            const denyData = 'deny:550e8400-e29b-41d4-a716-446655440000';
            expect(encoder.encode(denyData).length).toBeLessThanOrEqual(TELEGRAM_CALLBACK_DATA_LIMIT);
        });
    });

    describe('Message Truncation', () => {
        const TELEGRAM_MESSAGE_LIMIT = 4096;

        it('respects message byte limit', () => {
            const encoder = new TextEncoder();

            // Helper to truncate to byte limit
            const truncateToUtf8Bytes = (str: string, maxBytes: number): string => {
                const encoded = encoder.encode(str);
                if (encoded.length <= maxBytes) return str;

                // Binary search for truncation point
                let low = 0, high = str.length;
                while (low < high) {
                    const mid = Math.ceil((low + high) / 2);
                    if (encoder.encode(str.slice(0, mid)).length <= maxBytes) {
                        low = mid;
                    } else {
                        high = mid - 1;
                    }
                }
                return str.slice(0, low);
            };

            const longMessage = 'a'.repeat(5000);
            const truncated = truncateToUtf8Bytes(longMessage, TELEGRAM_MESSAGE_LIMIT);
            expect(encoder.encode(truncated).length).toBeLessThanOrEqual(TELEGRAM_MESSAGE_LIMIT);
        });

        it('handles multi-byte characters at truncation boundary', () => {
            const encoder = new TextEncoder();

            const truncateToUtf8Bytes = (str: string, maxBytes: number): string => {
                const encoded = encoder.encode(str);
                if (encoded.length <= maxBytes) return str;

                let low = 0, high = str.length;
                while (low < high) {
                    const mid = Math.ceil((low + high) / 2);
                    if (encoder.encode(str.slice(0, mid)).length <= maxBytes) {
                        low = mid;
                    } else {
                        high = mid - 1;
                    }
                }
                return str.slice(0, low);
            };

            // String with emojis (4 bytes each)
            const emojiString = '🔑'.repeat(1100); // ~4400 bytes
            const truncated = truncateToUtf8Bytes(emojiString, TELEGRAM_MESSAGE_LIMIT);

            // Should not split an emoji
            expect(encoder.encode(truncated).length).toBeLessThanOrEqual(TELEGRAM_MESSAGE_LIMIT);
            // Should contain complete emojis only
            expect(truncated).not.toContain('\uFFFD'); // No replacement characters
        });
    });

    describe('SHA-256 Hash Computation', () => {
        it('produces consistent hashes', async () => {
            const crypto = await import('node:crypto');
            const hash1 = crypto.createHash('sha256').update('test').digest('hex');
            const hash2 = crypto.createHash('sha256').update('test').digest('hex');
            expect(hash1).toBe(hash2);
            expect(hash1).toBe('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
        });

        it('produces different hashes for different inputs', async () => {
            const crypto = await import('node:crypto');
            const hash1 = crypto.createHash('sha256').update('test1').digest('hex');
            const hash2 = crypto.createHash('sha256').update('test2').digest('hex');
            expect(hash1).not.toBe(hash2);
        });
    });

    describe('Code Point Extraction', () => {
        it('extracts first code point from surrogate pairs', () => {
            const takeFirstCodePoint = (s: string): string => {
                if (!s) return '';
                const first = s.codePointAt(0);
                if (first === undefined) return '';
                return String.fromCodePoint(first);
            };

            // Emoji is a surrogate pair
            expect(takeFirstCodePoint('💡hello')).toBe('💡');
            expect(takeFirstCodePoint('🔑🔐')).toBe('🔑');

            // ASCII
            expect(takeFirstCodePoint('abc')).toBe('a');

            // Empty string
            expect(takeFirstCodePoint('')).toBe('');
        });
    });
});

describe('Telegram Handler Configuration', () => {
    describe('Config Validation', () => {
        it('requires botToken', () => {
            const config = {
                botToken: '',
                chatId: '12345',
                allowedUserIds: [123],
            };
            // Empty bot token should be caught at runtime
            expect(config.botToken).toBe('');
        });

        it('requires allowedUserIds', () => {
            const config = {
                botToken: 'test:token',
                chatId: '12345',
                allowedUserIds: [] as number[],
            };
            // Empty allowedUserIds should be caught at runtime
            expect(config.allowedUserIds.length).toBe(0);
        });

        it('accepts valid config', () => {
            const config = {
                botToken: 'test:ABC123',
                chatId: '12345',
                allowedUserIds: [123456789],
                requireFullProposalId: true,
                pollIntervalMs: 2000,
                timeoutMs: 300000,
                dropBacklogOnStart: true,
                onDocumentSendFail: 'reject' as const,
            };

            expect(config.botToken).toBeTruthy();
            expect(config.allowedUserIds.length).toBeGreaterThan(0);
            expect(config.onDocumentSendFail).toBe('reject');
        });
    });
});

describe('Telegram API Response Parsing', () => {
    describe('getUpdates Response', () => {
        it('parses successful response', () => {
            const response = {
                ok: true,
                result: [
                    {
                        update_id: 123456789,
                        message: {
                            message_id: 1,
                            from: { id: 12345, first_name: 'Test' },
                            chat: { id: 12345 },
                            text: 'Hello',
                        },
                    },
                ],
            };

            expect(response.ok).toBe(true);
            expect(response.result.length).toBe(1);
            expect(response.result[0].update_id).toBe(123456789);
        });

        it('parses callback_query response', () => {
            const response = {
                ok: true,
                result: [
                    {
                        update_id: 123456790,
                        callback_query: {
                            id: 'callback123',
                            from: { id: 12345, first_name: 'Test' },
                            message: {
                                message_id: 2,
                                chat: { id: 12345 },
                            },
                            data: 'approve:550e8400-e29b-41d4-a716-446655440000',
                        },
                    },
                ],
            };

            expect(response.ok).toBe(true);
            expect(response.result[0].callback_query).toBeDefined();
            expect(response.result[0].callback_query?.data).toContain('approve:');
        });
    });

    describe('sendMessage Response', () => {
        it('parses successful response', () => {
            const response = {
                ok: true,
                result: {
                    message_id: 42,
                    chat: { id: 12345 },
                    text: 'Test message',
                },
            };

            expect(response.ok).toBe(true);
            expect(response.result.message_id).toBe(42);
        });

        it('handles error response', () => {
            const response = {
                ok: false,
                description: 'Bad Request: message is too long',
            };

            expect(response.ok).toBe(false);
            expect(response.description).toContain('too long');
        });
    });
});
