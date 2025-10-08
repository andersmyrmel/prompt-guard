import type { Threat, ThreatType } from "../types";

/**
 * Sanitize input by removing or neutralizing threats
 * Uses iterative sanitization to prevent nested bypasses
 */
export function sanitize(input: string, threats: Threat[]): string {
  let sanitized = input;
  let iterations = 0;
  const maxIterations = 5;

  while (iterations < maxIterations) {
    const before = sanitized;
    sanitized = applySanitizationPass(sanitized, threats);

    // If nothing changed, we're done
    if (sanitized === before) {
      break;
    }

    iterations++;
  }

  return sanitized;
}

/**
 * Apply a single pass of sanitization
 * Groups threats by type for efficient processing
 */
function applySanitizationPass(input: string, threats: Threat[]): string {
  let sanitized = input;

  // Group threats by type for efficient processing
  const threatsByType = new Map<ThreatType, Threat[]>();
  for (const threat of threats) {
    const existing = threatsByType.get(threat.type);
    if (existing) {
      existing.push(threat);
    } else {
      threatsByType.set(threat.type, [threat]);
    }
  }

  // Sanitize each threat type
  for (const [type, typeThreats] of threatsByType) {
    sanitized = sanitizeByType(sanitized, type, typeThreats);
  }

  return sanitized;
}

/**
 * Sanitize by threat type
 * Routes to the appropriate type-specific sanitizer
 */
function sanitizeByType(
  input: string,
  type: ThreatType,
  threats: Threat[],
): string {
  switch (type) {
    case "delimiterInjection":
      return sanitizeDelimiters(input);
    case "encoding":
      return sanitizeEncoding(input);
    case "instructionOverride":
      return sanitizeInstructions(input, threats);
    case "roleManipulation":
      return sanitizeRoles(input, threats);
    case "systemPromptLeak":
      return sanitizeLeaks(input, threats);
    default:
      return input;
  }
}

/**
 * Sanitize delimiter injection attempts
 * Removes all common delimiter patterns (global sanitization for safety)
 */
function sanitizeDelimiters(input: string): string {
  let sanitized = input;

  // Remove XML-style tags
  sanitized = sanitized.replace(
    /<\/?(?:system|user|assistant|human|ai|context|instruction|prompt)>/gi,
    "",
  );

  // Remove bracket-style markers
  sanitized = sanitized.replace(
    /\[\/?\s*(?:system|user|assistant|human|ai|context|instruction|prompt)\s*\]/gi,
    "",
  );

  // Remove hash markers
  sanitized = sanitized.replace(
    /#{2,}\s*(?:system|admin|root|user|assistant|instruction|prompt)\s*#{2,}/gi,
    "",
  );

  // Neutralize colon-style markers (replace colon with dash)
  sanitized = sanitized.replace(
    /\b(system|user|assistant|human|ai|context|instruction|prompt)\s*:/gi,
    "$1-",
  );

  // Remove standalone role indicators in caps
  sanitized = sanitized.replace(
    /\b(?:SYSTEM|USER|ASSISTANT|HUMAN|AI|CONTEXT|INSTRUCTION|PROMPT)\b/g,
    "",
  );

  return sanitized;
}

/**
 * Sanitize encoding attempts
 * Removes suspicious encoding patterns (global sanitization for safety)
 */
function sanitizeEncoding(input: string): string {
  let sanitized = input;

  // Remove null bytes
  sanitized = sanitized.replace(/\x00+/g, "");

  // Remove unicode directional override characters
  sanitized = sanitized.replace(/[\u202A-\u202E\u2066-\u2069]+/g, "");

  // Limit excessive combining diacriticals (zalgo text)
  sanitized = sanitized.replace(/[\u0300-\u036F]{3,}/g, "");

  // Remove suspicious long base64-like sequences
  sanitized = sanitized.replace(
    /[A-Za-z0-9+/]{40,}={0,2}/g,
    "[ENCODED_REMOVED]",
  );

  // Remove hex escape sequences
  sanitized = sanitized.replace(/(?:\\x[0-9A-Fa-f]{2}){5,}/g, "[HEX_REMOVED]");

  // Remove unicode escapes
  sanitized = sanitized.replace(
    /(?:\\u[0-9A-Fa-f]{4}){5,}/g,
    "[UNICODE_REMOVED]",
  );

  // Remove HTML entities
  sanitized = sanitized.replace(
    /(?:&#{1,2}[xX]?[0-9A-Fa-f]+;){5,}/g,
    "[ENTITY_REMOVED]",
  );

  return sanitized;
}

/**
 * Sanitize instruction override attempts
 * Removes specific matched patterns for targeted sanitization
 */
function sanitizeInstructions(input: string, threats: Threat[]): string {
  let sanitized = input;

  // Remove the matched patterns
  for (const threat of threats) {
    if (threat.match && threat.match.length > 0) {
      sanitized = sanitized.replace(threat.match, "");
    }
  }

  return sanitized;
}

/**
 * Sanitize role manipulation attempts
 * Removes specific matched patterns for targeted sanitization
 */
function sanitizeRoles(input: string, threats: Threat[]): string {
  let sanitized = input;

  // Remove the matched patterns
  for (const threat of threats) {
    if (threat.match && threat.match.length > 0) {
      sanitized = sanitized.replace(threat.match, "");
    }
  }

  return sanitized;
}

/**
 * Sanitize system prompt leak attempts
 * Removes specific matched patterns for targeted sanitization
 */
function sanitizeLeaks(input: string, threats: Threat[]): string {
  let sanitized = input;

  // Remove the matched patterns
  for (const threat of threats) {
    if (threat.match && threat.match.length > 0) {
      sanitized = sanitized.replace(threat.match, "");
    }
  }

  return sanitized;
}
