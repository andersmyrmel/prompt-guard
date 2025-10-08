import type { Pattern } from '../types';

/**
 * Patterns for instruction override attacks
 * CRITICAL: Use bounded quantifiers to prevent ReDoS
 */
export const instructionPatterns: Pattern[] = [
  // "ignore (all/previous/prior/above) (previous/prior) (instructions/directives/commands)"
  // Supports: "ignore all previous instructions", "ignore previous instructions", "ignore instructions"
  {
    regex:
      /\bignore\s+(?:(?:all|the)\s+)?(?:previous|prior|above|remaining|other)?\s*(?:instructions|directives|commands|rules|prompts?|context)\b/i,
    severity: 0.9,
    type: 'instructionOverride',
  },
  // "disregard (the) (system/previous) (prompt/instructions)"
  {
    regex:
      /\bdisregard\s+(?:the\s+)?(?:system|previous)\s+(?:prompt|instructions)\b/i,
    severity: 0.9,
    type: 'instructionOverride',
  },
  // "forget (everything/all/what) (you/i) (said/told/were told)"
  {
    regex:
      /\bforget\s+(?:everything|all|what)\s+(?:you|i)\s+(?:said|told|mentioned|were\s+told)\b/i,
    severity: 0.85,
    type: 'instructionOverride',
  },
  // "new (instructions/task/directive)"
  {
    regex: /\bnew\s+(?:instructions?|tasks?|directives?)\b/i,
    severity: 0.8,
    type: 'instructionOverride',
  },
  // "override (previous/system) (instructions/rules)"
  {
    regex:
      /\boverride\s+(?:previous|system|all)\s+(?:instructions|rules|directives)\b/i,
    severity: 0.9,
    type: 'instructionOverride',
  },
  // "instead (follow/use/do)"
  {
    regex: /\binstead\s+(?:follow|use|do|obey)\b/i,
    severity: 0.7,
    type: 'instructionOverride',
  },
  // "start over" / "begin again" / "restart" - excludes "start over with" (legitimate)
  {
    regex:
      /\b(?:start\s+over(?:\s+from\s+scratch)?(?!\s+with)|begin\s+again|restart)\b/i,
    severity: 0.75, // Increased from 0.6 to be above moderate threshold
    type: 'instructionOverride',
  },
  // "reset (to/your) (default/initial)"
  {
    regex: /\breset\s+(?:to\s+)?(?:default|initial|factory)\b/i,
    severity: 0.75,
    type: 'instructionOverride',
  },
];
