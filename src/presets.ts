import type { VardConfig } from "./types";

/**
 * Preset configurations for different security levels
 */

/**
 * Strict preset: Block all threats, low threshold
 */
export const STRICT_PRESET: VardConfig = {
  threshold: 0.5,
  maxLength: 10000,
  customDelimiters: [],
  customPatterns: [],
  threatActions: {
    instructionOverride: "block",
    roleManipulation: "block",
    delimiterInjection: "block",
    systemPromptLeak: "block",
    encoding: "block",
  },
};

/**
 * Moderate preset: Balanced security (default)
 */
export const MODERATE_PRESET: VardConfig = {
  threshold: 0.7,
  maxLength: 10000,
  customDelimiters: [],
  customPatterns: [],
  threatActions: {
    instructionOverride: "block",
    roleManipulation: "block",
    delimiterInjection: "sanitize",
    systemPromptLeak: "block",
    encoding: "sanitize",
  },
};

/**
 * Lenient preset: Minimal blocking, more sanitization
 */
export const LENIENT_PRESET: VardConfig = {
  threshold: 0.85,
  maxLength: 10000,
  customDelimiters: [],
  customPatterns: [],
  threatActions: {
    instructionOverride: "sanitize",
    roleManipulation: "warn",
    delimiterInjection: "sanitize",
    systemPromptLeak: "sanitize",
    encoding: "sanitize",
  },
};

/**
 * Get a preset configuration by name
 */
export function getPreset(name: "strict" | "moderate" | "lenient"): VardConfig {
  switch (name) {
    case "strict":
      return { ...STRICT_PRESET };
    case "moderate":
      return { ...MODERATE_PRESET };
    case "lenient":
      return { ...LENIENT_PRESET };
    default:
      return { ...MODERATE_PRESET };
  }
}
