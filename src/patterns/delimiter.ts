import type { Pattern } from '../types';

/**
 * Patterns for delimiter injection attacks
 * These detect attempts to inject prompt delimiters like <system>, [USER], etc.
 */
export const delimiterPatterns: Pattern[] = [
  // XML-style tags: <system>, </system>, <user>, <assistant>
  {
    regex:
      /<\/?(?:system|user|assistant|human|ai|context|instruction|prompt)>/gi,
    severity: 0.95,
    type: 'delimiterInjection',
  },
  // Bracket-style markers: [SYSTEM], [USER], [/SYSTEM]
  {
    regex:
      /\[\/?\s*(?:system|user|assistant|human|ai|context|instruction|prompt)\s*\]/gi,
    severity: 0.95,
    type: 'delimiterInjection',
  },
  // Hash-style markers: ###SYSTEM###, ###ADMIN###
  {
    regex:
      /#{2,}\s*(?:system|admin|root|user|assistant|instruction|prompt)\s*#{2,}/gi,
    severity: 0.9,
    type: 'delimiterInjection',
  },
  // Markdown-style: ## SYSTEM, ## USER
  {
    regex:
      /^#{1,6}\s+(?:system|user|assistant|human|ai|context|instruction|prompt)\s*$/gim,
    severity: 0.8,
    type: 'delimiterInjection',
  },
  // Colon-style: SYSTEM:, USER:, ASSISTANT:
  {
    regex:
      /\b(?:system|user|assistant|human|ai|context|instruction|prompt)\s*:/gi,
    severity: 0.7,
    type: 'delimiterInjection',
  },
  // Role indicators in caps: SYSTEM, USER (standalone)
  {
    regex: /\b(?:SYSTEM|USER|ASSISTANT|HUMAN|AI|CONTEXT|INSTRUCTION|PROMPT)\b/g,
    severity: 0.65,
    type: 'delimiterInjection',
  },
];
