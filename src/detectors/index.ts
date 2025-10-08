import type { Pattern, Threat } from '../types';

/**
 * Detect threats in input text using provided patterns
 */
export function detect(input: string, patterns: Pattern[]): Threat[] {
  const threats: Threat[] = [];

  for (const pattern of patterns) {
    // Add global flag to find all matches, preserve other flags
    const flags = pattern.regex.flags.includes('g')
      ? pattern.regex.flags
      : pattern.regex.flags + 'g';
    const regex = new RegExp(pattern.regex.source, flags);

    // Find all matches using matchAll (modern, safer approach)
    const matches = Array.from(input.matchAll(regex));

    for (const match of matches) {
      threats.push({
        type: pattern.type,
        severity: pattern.severity,
        match: match[0],
        position: match.index ?? 0,
      });
    }
  }

  return threats;
}

/**
 * Check if input exceeds maximum length
 */
export function checkLength(input: string, maxLength: number): Threat | null {
  if (input.length > maxLength) {
    return {
      type: 'instructionOverride', // Categorize as instruction override
      severity: 0.8,
      match: `Input exceeds ${maxLength} characters`,
      position: maxLength,
    };
  }
  return null;
}

/**
 * Detect suspicious length patterns (very long inputs)
 */
export function detectSuspiciousLength(input: string): Threat | null {
  const threshold = 5000;
  if (input.length > threshold && input.length <= 100000) {
    // Only warn, don't block
    return {
      type: 'instructionOverride',
      severity: 0.5,
      match: `Suspiciously long input (${input.length} chars)`,
      position: 0,
    };
  }
  return null;
}

/**
 * Detect custom delimiters in input
 */
export function detectCustomDelimiters(
  input: string,
  delimiters: string[]
): Threat[] {
  const threats: Threat[] = [];

  for (const delimiter of delimiters) {
    const index = input.indexOf(delimiter);
    if (index !== -1) {
      threats.push({
        type: 'delimiterInjection',
        severity: 0.95,
        match: delimiter,
        position: index,
      });
    }
  }

  return threats;
}
