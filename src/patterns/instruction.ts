import type { Pattern } from "../types";

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
    type: "instructionOverride",
  },
  // "disregard (the) (system/previous) (prompt/instructions)"
  {
    regex:
      /\bdisregard\s+(?:the\s+)?(?:system|previous)\s+(?:prompt|instructions)\b/i,
    severity: 0.9,
    type: "instructionOverride",
  },
  // "forget (everything/all/what) (you/i) (said/told/were told)"
  {
    regex:
      /\bforget\s+(?:everything|all|what)\s+(?:you|i)\s+(?:said|told|mentioned|were\s+told)\b/i,
    severity: 0.85,
    type: "instructionOverride",
  },
  // "new (instructions/task/directive)"
  {
    regex: /\bnew\s+(?:instructions?|tasks?|directives?)\b/i,
    severity: 0.8,
    type: "instructionOverride",
  },
  // "override (previous/system) (instructions/rules)"
  {
    regex:
      /\boverride\s+(?:previous|system|all)\s+(?:instructions|rules|directives)\b/i,
    severity: 0.9,
    type: "instructionOverride",
  },
  // "instead (follow/use/do)"
  {
    regex: /\binstead\s+(?:follow|use|do|obey)\b/i,
    severity: 0.7,
    type: "instructionOverride",
  },
  // "start over" / "begin again" / "restart" - excludes "start over with" (legitimate)
  {
    regex:
      /\b(?:start\s+over(?:\s+from\s+scratch)?(?!\s+with)|begin\s+again|restart)\b/i,
    severity: 0.75, // Increased from 0.6 to be above moderate threshold
    type: "instructionOverride",
  },
  // "reset (to/your) (default/initial)"
  {
    regex: /\breset\s+(?:to\s+)?(?:default|initial|factory)\b/i,
    severity: 0.75,
    type: "instructionOverride",
  },
  // "spell backward(s)" - obfuscation technique
  {
    regex:
      /\bspell(?:ed)?\s+(?:(?:it|this|that)\s+)?(?:backwards?|in\s+reverse)\s+(?:and\s+)?(?:execute|run|follow|do|perform|obey)/i,
    severity: 0.9,
    type: "instructionOverride",
  },
  // "decode (base64/hex/rot13/etc) and (execute/follow/run)"
  {
    regex:
      /\b(?:decode|decrypt|decipher)\s+(?:this\s+|the\s+)?(?:base64|base-64|b64|hex|hexadecimal|rot13|rot-13|binary|unicode)\s+(?:and\s+)?(?:execute|follow|run|do|perform|obey)/i,
    severity: 0.9,
    type: "instructionOverride",
  },
  // "rot13/base64/hex decode" (reversed order)
  {
    regex:
      /\b(?:base64|base-64|b64|hex|hexadecimal|rot13|rot-13|binary|unicode)\s+(?:decode|decrypt|decipher)\s+(?:and\s+)?(?:execute|follow|run|do|perform|obey)/i,
    severity: 0.9,
    type: "instructionOverride",
  },
  // "translate from (hex/base64/etc)" - obfuscation
  {
    regex:
      /\btranslate\s+from\s+(?:hex|hexadecimal|base64|base-64|binary|morse|rot13|rot-13)\s+(?:to\s+text\s+)?(?:and\s+)?(?:execute|follow|run|do|perform)?/i,
    severity: 0.85,
    type: "instructionOverride",
  },
  // "unscramble/rearrange and (execute/follow)"
  {
    regex:
      /\b(?:unscramble|rearrange|reorder|decode)\s+(?:these\s+|the\s+)?(?:letters?|words?|characters?)\s+(?:and\s+)?(?:execute|follow|run|do|perform|obey)/i,
    severity: 0.85,
    type: "instructionOverride",
  },
  // "do not (say/respond/reply)" + "instead" - negative directive
  {
    regex:
      /\b(?:do\s+not|don't|never)\s+(?:say|respond|reply|answer|tell|refuse|comply|follow)\s+.{1,50}?\binstead\b/i,
    severity: 0.85,
    type: "instructionOverride",
  },
  // "don't/do not (follow/comply with) (your/the) (rules/guidelines)"
  {
    regex:
      /\b(?:do\s+not|don't)\s+(?:follow|comply\s+with|obey|adhere\s+to)\s+(?:your|the)?\s*(?:rules|guidelines|instructions|constraints|restrictions)\b/i,
    severity: 0.8,
    type: "instructionOverride",
  },
  // "don't respond with (safety) warnings/filters/checks"
  {
    regex:
      /\b(?:do\s+not|don't)\s+respond\s+with\s+(?:safety\s+)?(?:warnings?|filters?|checks?|restrictions?|limitations?)\b/i,
    severity: 0.75,
    type: "instructionOverride",
  },
  // "never refuse" / "always (answer/comply)"
  {
    regex:
      /\b(?:never\s+refuse|always\s+(?:answer|comply|obey|respond|follow))\b/i,
    severity: 0.8,
    type: "instructionOverride",
  },
];
