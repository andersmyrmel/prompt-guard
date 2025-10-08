import type { Pattern } from "../types";
import { instructionPatterns } from "./instruction";
import { rolePatterns } from "./role";
import { delimiterPatterns } from "./delimiter";
import { leakPatterns } from "./leak";
import { encodingPatterns } from "./encoding";

/**
 * All built-in detection patterns
 */
export const allPatterns: Pattern[] = [
  ...instructionPatterns,
  ...rolePatterns,
  ...delimiterPatterns,
  ...leakPatterns,
  ...encodingPatterns,
];

/**
 * Get patterns for a specific threat type
 */
export function getPatternsByType(type: string): Pattern[] {
  switch (type) {
    case "instructionOverride":
      return instructionPatterns;
    case "roleManipulation":
      return rolePatterns;
    case "delimiterInjection":
      return delimiterPatterns;
    case "systemPromptLeak":
      return leakPatterns;
    case "encoding":
      return encodingPatterns;
    default:
      return [];
  }
}

export {
  instructionPatterns,
  rolePatterns,
  delimiterPatterns,
  leakPatterns,
  encodingPatterns,
};
