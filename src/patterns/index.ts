import type { Pattern } from "../types";
import { instructionPatterns } from "./instruction";
import { rolePatterns } from "./role";
import { delimiterPatterns } from "./delimiter";
import { leakPatterns } from "./leak";
import { encodingPatterns } from "./encoding";
import { obfuscationPatterns } from "./obfuscation";

/**
 * All built-in detection patterns
 */
export const allPatterns: Pattern[] = [
  ...instructionPatterns,
  ...rolePatterns,
  ...delimiterPatterns,
  ...leakPatterns,
  ...encodingPatterns,
  ...obfuscationPatterns,
];

/**
 * Get patterns for a specific threat type
 */
export function getPatternsByType(type: string): Pattern[] {
  switch (type) {
    case "instructionOverride":
      return [...instructionPatterns, ...obfuscationPatterns];
    case "roleManipulation":
      return [...rolePatterns, ...obfuscationPatterns];
    case "delimiterInjection":
      return delimiterPatterns;
    case "systemPromptLeak":
      return [...leakPatterns, ...obfuscationPatterns];
    case "encoding":
      return [...encodingPatterns, ...obfuscationPatterns];
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
  obfuscationPatterns,
};
