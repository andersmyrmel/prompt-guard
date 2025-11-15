import type { Pattern } from "../types";

/**
 * Patterns for delimiter injection attacks
 * These detect attempts to inject prompt delimiters like <system>, [USER], etc.
 */
export const delimiterPatterns: Pattern[] = [
  // XML-style tags: <system>, </system>, <user>, <assistant>
  {
    regex:
      /<\/?(?:system|user|assistant|human|ai|context|instruction|prompt|user_query)>/gi,
    severity: 0.95,
    type: "delimiterInjection",
  },
  // Bracket-style markers: [SYSTEM], [USER], [/SYSTEM], [START], [START OUTPUT]
  {
    regex:
      /\[\/?\s*(?:system|user|assistant|human|ai|context|instruction|prompt|start|stop|begin|end|start\s+output|begin\s+output|output)\s*\]/gi,
    severity: 0.95,
    type: "delimiterInjection",
  },
  // Hash-style markers: ###SYSTEM###, ###ADMIN###
  {
    regex:
      /#{2,}\s*(?:system|admin|root|user|assistant|instruction|prompt)\s*#{2,}/gi,
    severity: 0.9,
    type: "delimiterInjection",
  },
  // Markdown-style: ## SYSTEM, ## USER
  {
    regex:
      /^#{1,6}\s+(?:system|user|assistant|human|ai|context|instruction|prompt)\s*$/gim,
    severity: 0.8,
    type: "delimiterInjection",
  },
  // Colon-style: SYSTEM:, USER:, ASSISTANT:, Query:, godmode:, UserQuery:
  {
    regex:
      /\b(?:system|user|assistant|human|ai|context|instruction|prompt|UserQuery)\s*:/gi,
    severity: 0.7,
    type: "delimiterInjection",
  },
  // Role indicators in caps: SYSTEM, USER (standalone)
  {
    regex: /\b(?:SYSTEM|USER|ASSISTANT|HUMAN|AI|CONTEXT|INSTRUCTION|PROMPT)\b/gi,
    severity: 0.65,
    type: "delimiterInjection",
  },
];
