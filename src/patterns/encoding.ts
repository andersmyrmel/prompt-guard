import type { Pattern } from '../types';

/**
 * Patterns for encoding-based attacks
 * CRITICAL: Use bounded quantifiers to prevent ReDoS
 */
export const encodingPatterns: Pattern[] = [
  // Base64 encoded content (long sequences that look like base64)
  // Min 40 chars to avoid false positives on short strings
  {
    regex: /[A-Za-z0-9+/]{40,}={0,2}/g,
    severity: 0.7,
    type: 'encoding',
  },
  // Hex escape sequences: \xNN (multiple in sequence)
  {
    regex: /(?:\\x[0-9A-Fa-f]{2}){5,}/g,
    severity: 0.85,
    type: 'encoding',
  },
  // Hex values: 0xNN (multiple in sequence)
  {
    regex: /(?:0x[0-9A-Fa-f]{2,}\s*){5,}/g,
    severity: 0.8,
    type: 'encoding',
  },
  // Unicode escape sequences: \uNNNN (multiple in sequence)
  {
    regex: /(?:\\u[0-9A-Fa-f]{4}){5,}/g,
    severity: 0.85,
    type: 'encoding',
  },
  // HTML entities: &# sequences (multiple)
  {
    regex: /(?:&#{1,2}[xX]?[0-9A-Fa-f]+;){5,}/g,
    severity: 0.8,
    type: 'encoding',
  },
  // URL encoded: % sequences (multiple)
  {
    regex: /(?:%[0-9A-Fa-f]{2}){5,}/g,
    severity: 0.75,
    type: 'encoding',
  },
  // Null bytes (suspicious)
  {
    regex: /\x00+/g,
    severity: 0.95,
    type: 'encoding',
  },
  // Unicode directional override characters (used for obfuscation)
  {
    regex: /[\u202A-\u202E\u2066-\u2069]+/g,
    severity: 0.9,
    type: 'encoding',
  },
  // Zalgo text (combining diacriticals)
  {
    regex: /[\u0300-\u036F]{3,}/g,
    severity: 0.85,
    type: 'encoding',
  },
];
