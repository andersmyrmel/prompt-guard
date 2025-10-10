import type { Pattern } from "../types";

/**
 * Patterns for obfuscation-based attacks
 *
 * Focus: High-confidence detection of obfuscation attempts
 * Philosophy: Better to miss sophisticated attacks than create false positives
 *
 * CRITICAL: Use bounded quantifiers to prevent ReDoS
 */
export const obfuscationPatterns: Pattern[] = [
  // Zero-width character attacks - highly suspicious
  // U+200B (zero-width space), U+200C (zero-width non-joiner),
  // U+200D (zero-width joiner), U+FEFF (zero-width no-break space)
  {
    regex: /[\u200B\u200C\u200D\uFEFF]/g,
    severity: 0.85,
    type: "encoding",
  },

  // Right-to-left override markers - almost always malicious
  // U+202E (RTL override), U+202D (LTR override)
  {
    regex: /[\u202E\u202D]/g,
    severity: 0.95,
    type: "encoding",
  },

  // Character insertion with underscores - "i_g_n_o_r_e"
  // Only flag if combined with suspicious keywords
  {
    regex: /\bi[\s._-]g[\s._-]n[\s._-]o[\s._-]r[\s._-]e\b/i,
    severity: 0.9,
    type: "instructionOverride",
  },

  // Homoglyph: "ignore" with any homoglyph character
  // Matches: Ιgnore, іgnore, ignοre, ignоre, etc.
  {
    regex: /[ΙІі]gn[oοо]re?|ign[οо]re/i,
    severity: 0.95,
    type: "instructionOverride",
  },

  // Excessive spacing (4+ spaces between words) - suspicious
  {
    regex: /\w+\s{4,}\w+/,
    severity: 0.6,
    type: "encoding",
  },

  // Full-width Unicode Latin letters (3+ in sequence)
  {
    regex: /[\uFF21-\uFF3A\uFF41-\uFF5A]{3,}/,
    severity: 0.7,
    type: "encoding",
  },

  // Uncommon Unicode spaces
  {
    regex: /[\u2000-\u200A\u202F\u205F]/g,
    severity: 0.65,
    type: "encoding",
  },
];
