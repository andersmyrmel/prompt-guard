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
];
