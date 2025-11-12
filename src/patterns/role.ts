import type { Pattern } from "../types";

/**
 * Patterns for role manipulation attacks
 * CRITICAL: Use bounded quantifiers to prevent ReDoS
 */
export const rolePatterns: Pattern[] = [
  // "you are (now) (a/an) [role]"
  {
    regex: /\byou\s+are\s+(?:now\s+)?(?:a|an)\s+\w{3,20}\b/i,
    severity: 0.85,
    type: "roleManipulation",
  },
  // "you're (now) (a/an) [role]"
  {
    regex: /\byou're\s+(?:now\s+)?(?:a|an)\s+\w{3,20}\b/i,
    severity: 0.85,
    type: "roleManipulation",
  },
  // "pretend (you are/to be)"
  {
    regex: /\bpretend\s+(?:you\s+are|to\s+be|that\s+you)\b/i,
    severity: 0.8,
    type: "roleManipulation",
  },
  // "roleplay as"
  {
    regex: /\broleplay\s+as\b/i,
    severity: 0.8,
    type: "roleManipulation",
  },
  // "act (as/like)" - updated to handle multi-word roles
  {
    regex: /\bact\s+(?:as|like)\s+(?:a|an)?\s*\w+(?:\s+\w+){0,3}\b/i,
    severity: 0.75,
    type: "roleManipulation",
  },
  // "behave (as/like)" - updated to handle multi-word roles
  {
    regex: /\bbehave\s+(?:as|like)\s+(?:a|an)?\s*\w+(?:\s+\w+){0,3}\b/i,
    severity: 0.75,
    type: "roleManipulation",
  },
  // "from now on, you (are/will be)"
  {
    regex: /\bfrom\s+now\s+on,?\s+you\s+(?:are|will\s+be)\b/i,
    severity: 0.85,
    type: "roleManipulation",
  },
  // "simulate (being/that you are)"
  {
    regex: /\bsimulate\s+(?:being|that\s+you\s+are)\b/i,
    severity: 0.8,
    type: "roleManipulation",
  },
  // "your new role is"
  {
    regex: /\byour\s+new\s+role\s+is\b/i,
    severity: 0.9,
    type: "roleManipulation",
  },
  // "assume the role of"
  {
    regex: /\bassume\s+the\s+role\s+of\b/i,
    severity: 0.85,
    type: "roleManipulation",
  },
  // "developer mode" / "dev mode" / "test mode"
  {
    regex:
      /\b(?:developer|dev|test|testing|debug|admin|god|research)\s+mode\b/i,
    severity: 0.85,
    type: "roleManipulation",
  },
  // "enable/activate (developer/test) mode"
  {
    regex:
      /\b(?:enable|activate|turn\s+on|switch\s+to)\s+(?:developer|dev|test|debug|admin|god)\s+mode\b/i,
    severity: 0.9,
    type: "roleManipulation",
  },
  // "for educational purposes" / "for research purposes"
  {
    regex:
      /\bfor\s+(?:educational|research|testing|academic|scientific)\s+purposes\s+only\b/i,
    severity: 0.7,
    type: "roleManipulation",
  },
  // "hypothetically/theoretically speaking" - hypothetical framing
  {
    regex:
      /\b(?:hypothetically|theoretically)\s+speaking[,\s]+(?:if|what|how)/i,
    severity: 0.75,
    type: "roleManipulation",
  },
  // "imagine (if/that/you)" / "suppose (that/you)"
  {
    regex: /\b(?:imagine|suppose)\s+(?:if|that|you|for\s+a\s+moment)/i,
    severity: 0.7,
    type: "roleManipulation",
  },
  // "this is (just) a (test/simulation/game)"
  {
    regex:
      /\bthis\s+is\s+(?:just\s+)?(?:a\s+)?(?:test|simulation|game|exercise|scenario)\b/i,
    severity: 0.75,
    type: "roleManipulation",
  },
  // "DAN mode" / "jailbreak mode" / "unrestricted mode"
  {
    regex:
      /\b(?:DAN|jailbreak|unrestricted|unfiltered|uncensored)\s+(?:mode|version)\b/i,
    severity: 0.95,
    type: "roleManipulation",
  },
  // Temporal exploitation: "legal now" / "allowed now"
  {
    regex:
      /\b(?:legal|allowed|permitted|acceptable)\s+now\b|\bnow\s+(?:legal|allowed|permitted)\b/i,
    severity: 0.8,
    type: "roleManipulation",
  },
];
