/**
 * Types of prompt injection threats that can be detected.
 *
 * @remarks
 * Each threat type represents a different attack vector:
 * - **instructionOverride**: Attempts to replace or modify system instructions
 * - **roleManipulation**: Tries to change the AI's role or persona
 * - **delimiterInjection**: Injects fake delimiters to confuse prompt structure
 * - **systemPromptLeak**: Attempts to reveal the system prompt or internal instructions
 * - **encoding**: Uses special encoding to bypass detection (base64, hex, unicode)
 *
 * @example
 * **Configure actions per threat type**
 * ```typescript
 * import guard from 'prompt-guard';
 * import type { ThreatType } from 'prompt-guard';
 *
 * const threats: ThreatType[] = [
 *   'instructionOverride',
 *   'roleManipulation',
 *   'systemPromptLeak',
 * ];
 *
 * const myGuard = guard();
 * threats.forEach(threat => myGuard.block(threat));
 * ```
 *
 * @see {@link https://github.com/andersmyrmel/prompt-guard#threat-types | Full threat type documentation}
 */
export type ThreatType =
  | "instructionOverride"
  | "roleManipulation"
  | "delimiterInjection"
  | "systemPromptLeak"
  | "encoding";

/**
 * Actions to take when a threat is detected.
 *
 * @remarks
 * Each action has different behavior:
 * - **block**: Throw `PromptInjectionError` (validation fails)
 * - **sanitize**: Remove/clean the threat and return sanitized input
 * - **warn**: Categorize threat but allow input to pass (silent in v1.0)
 * - **allow**: Completely ignore this threat type
 *
 * Actions only apply to threats with severity >= configured threshold.
 *
 * @example
 * **Set actions for different threat types**
 * ```typescript
 * import guard from 'prompt-guard';
 *
 * const myGuard = guard()
 *   .block('instructionOverride')    // Throw error
 *   .sanitize('delimiterInjection')  // Remove delimiters
 *   .warn('roleManipulation')        // Log but allow
 *   .allow('encoding');              // Ignore completely
 * ```
 *
 * @see {@link GuardBuilder.block}
 * @see {@link GuardBuilder.sanitize}
 * @see {@link GuardBuilder.warn}
 * @see {@link GuardBuilder.allow}
 */
export type ThreatAction = "block" | "sanitize" | "warn" | "allow";

/**
 * Individual threat detection result.
 *
 * Represents a single detected threat with metadata about what was found,
 * where it was found, and how severe it is.
 *
 * @example
 * **Inspect detected threats**
 * ```typescript
 * import guard, { PromptInjectionError } from 'prompt-guard';
 * import type { Threat } from 'prompt-guard';
 *
 * try {
 *   guard(userInput);
 * } catch (error) {
 *   if (error instanceof PromptInjectionError) {
 *     error.threats.forEach((threat: Threat) => {
 *       console.log(`Type: ${threat.type}`);
 *       console.log(`Severity: ${threat.severity.toFixed(2)}`);
 *       console.log(`Match: "${threat.match}"`);
 *       console.log(`Position: ${threat.position}`);
 *     });
 *   }
 * }
 * ```
 *
 * @example
 * **Filter threats by severity**
 * ```typescript
 * const result = guard.safe(userInput);
 *
 * if (!result.safe) {
 *   const criticalThreats = result.threats.filter(t => t.severity >= 0.9);
 *   const moderateThreats = result.threats.filter(t => t.severity >= 0.7 && t.severity < 0.9);
 *
 *   console.log(`Critical: ${criticalThreats.length}`);
 *   console.log(`Moderate: ${moderateThreats.length}`);
 * }
 * ```
 */
export interface Threat {
  /** Type of threat detected (e.g., 'instructionOverride', 'roleManipulation') */
  type: ThreatType;
  /** Severity score from 0 (low) to 1 (high) */
  severity: number;
  /** The matched string that triggered detection (truncated if > 100 chars) */
  match: string;
  /** Character position where the threat was found in the input */
  position: number;
}

/**
 * Pattern configuration for custom threat detection.
 *
 * Defines a regex pattern to match, its severity score, and which threat type
 * it represents. Used for adding domain-specific or language-specific patterns.
 *
 * @example
 * **Add Norwegian patterns**
 * ```typescript
 * import guard from 'prompt-guard';
 * import type { Pattern } from 'prompt-guard';
 *
 * const norwegianPatterns: Pattern[] = [
 *   {
 *     regex: /ignorer.*instruksjoner/i,
 *     severity: 0.9,
 *     type: 'instructionOverride',
 *   },
 *   {
 *     regex: /du er nå/i,
 *     severity: 0.85,
 *     type: 'roleManipulation',
 *   },
 * ];
 *
 * const norwegianGuard = guard()
 *   .patterns(norwegianPatterns)
 *   .block('instructionOverride')
 *   .block('roleManipulation');
 * ```
 *
 * @example
 * **Domain-specific patterns**
 * ```typescript
 * const medicalPattern: Pattern = {
 *   regex: /reveal\s+(patient|medical)\s+data/i,
 *   severity: 0.95,
 *   type: 'systemPromptLeak',
 * };
 *
 * const medicalGuard = guard()
 *   .pattern(medicalPattern.regex, medicalPattern.severity, medicalPattern.type)
 *   .block('systemPromptLeak');
 * ```
 *
 * @remarks
 * **ReDoS Warning**: All regex patterns should use bounded quantifiers to prevent
 * Regular Expression Denial of Service attacks. Avoid: `(.*)+`, `(a+)+`, etc.
 *
 * @see {@link GuardBuilder.pattern} for adding single patterns
 * @see {@link GuardBuilder.patterns} for adding multiple patterns
 */
export interface Pattern {
  /** Regular expression to match (should use bounded quantifiers for safety) */
  regex: RegExp;
  /** Severity score from 0 (low) to 1 (high) */
  severity: number;
  /** Which threat type this pattern detects */
  type: ThreatType;
}

/**
 * Result type returned by `safeParse()` method (discriminated union).
 *
 * This type enables type-safe error handling without try/catch blocks.
 * TypeScript can narrow the type based on the `safe` property.
 *
 * @example
 * **Type narrowing with discriminated union**
 * ```typescript
 * import guard from 'prompt-guard';
 * import type { GuardResult } from 'prompt-guard';
 *
 * const result: GuardResult = guard.safe(userInput);
 *
 * if (result.safe) {
 *   // TypeScript knows result.data is string
 *   console.log('Safe input:', result.data);
 *   processInput(result.data);
 * } else {
 *   // TypeScript knows result.threats is Threat[]
 *   console.error('Detected threats:', result.threats.length);
 *   result.threats.forEach(t => {
 *     console.log(`- ${t.type}: ${t.match}`);
 *   });
 * }
 * ```
 *
 * @example
 * **Early return pattern**
 * ```typescript
 * function processUserInput(input: string) {
 *   const result = guard.safe(input);
 *
 *   if (!result.safe) {
 *     return { error: 'Invalid input', threats: result.threats };
 *   }
 *
 *   // TypeScript knows result.data exists here
 *   return { data: result.data };
 * }
 * ```
 *
 * @see {@link GuardBuilder.safeParse} for usage
 */
export type GuardResult =
  | { safe: true; data: string }
  | { safe: false; threats: Threat[] };

/**
 * Internal configuration object for GuardBuilder.
 *
 * This is primarily used internally but can be useful for debugging or
 * understanding guard behavior.
 *
 * @remarks
 * Most users don't need to interact with this type directly - use the
 * chainable builder methods instead (`guard().threshold()`, `.delimiters()`, etc.)
 *
 * @see {@link GuardBuilder} for the public API
 */
export interface GuardConfig {
  /** Detection threshold (0-1) - only threats with severity >= threshold are processed */
  threshold: number;
  /** Maximum input length in characters */
  maxLength: number;
  /** Custom prompt delimiters to protect against (case-sensitive, exact match) */
  customDelimiters: string[];
  /** Custom patterns to add to built-in patterns */
  customPatterns: Pattern[];
  /** Actions for each threat type (block, sanitize, warn, allow) */
  threatActions: Record<ThreatType, ThreatAction>;
}

/**
 * Preset configuration names.
 *
 * @remarks
 * Each preset provides different security/usability trade-offs:
 * - **strict** (threshold: 0.5): Maximum security, higher false positives
 * - **moderate** (threshold: 0.7): Balanced security and usability (default)
 * - **lenient** (threshold: 0.85): Permissive, lower false positives
 *
 * @example
 * **Use preset factories**
 * ```typescript
 * import guard from 'prompt-guard';
 *
 * const strict = guard.strict();    // threshold: 0.5
 * const moderate = guard.moderate(); // threshold: 0.7 (default)
 * const lenient = guard.lenient();   // threshold: 0.85
 * ```
 *
 * @see {@link guard.strict}
 * @see {@link guard.moderate}
 * @see {@link guard.lenient}
 */
export type PresetName = "strict" | "moderate" | "lenient";

/**
 * Callable guard type - a function with attached chainable methods.
 *
 * This type represents a guard that can be used both as a function
 * and as an object with chainable configuration methods.
 *
 * @remarks
 * **Usage patterns**:
 * - **As function**: `myGuard(input)` - shorthand for `myGuard.parse(input)`
 * - **As object**: `myGuard.parse(input)` - explicit validation
 * - **Chainable**: `myGuard.threshold(0.8).delimiters([...])` - configure guard
 *
 * All chainable methods return a new `CallableGuard` instance (immutable).
 *
 * @example
 * **Create and use callable guard**
 * ```typescript
 * import guard from 'prompt-guard';
 *
 * // Create configured guard
 * const chatGuard = guard()
 *   .delimiters(['CONTEXT:', 'USER:'])
 *   .threshold(0.8)
 *   .block('instructionOverride');
 *
 * // Use as function (shorthand)
 * const safe1 = chatGuard(userInput);
 *
 * // Use as object (explicit)
 * const safe2 = chatGuard.parse(userInput);
 *
 * // Use safeParse (no throw)
 * const result = chatGuard.safeParse(userInput);
 * ```
 *
 * @example
 * **Chain after preset**
 * ```typescript
 * const myGuard = guard.moderate()
 *   .delimiters(['SYSTEM:'])
 *   .maxLength(5000);
 *
 * myGuard('Hello world');  // Validates immediately
 * ```
 *
 * @see {@link guard} for creating callable guards
 * @see {@link GuardBuilder} for the implementation
 */
export type CallableGuard = {
  /** Shorthand for `parse()` - validates input and returns safe string (throws on threat) */
  (input: string): string;
  /** Validates input and returns safe string (throws `PromptInjectionError` on threat) */
  parse(input: string): string;
  /** Validates input without throwing - returns `GuardResult` discriminated union */
  safeParse(input: string): GuardResult;
  /** Configure custom prompt delimiters to protect */
  delimiters(delims: string[]): CallableGuard;
  /** Add a single custom detection pattern */
  pattern(regex: RegExp, severity?: number, type?: ThreatType): CallableGuard;
  /** Add multiple custom detection patterns */
  patterns(patterns: Pattern[]): CallableGuard;
  /** Set maximum input length in characters */
  maxLength(length: number): CallableGuard;
  /** Set detection threshold (0-1, lower = more sensitive) */
  threshold(value: number): CallableGuard;
  /** Configure guard to throw error for a threat type */
  block(threat: ThreatType): CallableGuard;
  /** Configure guard to remove/clean a threat type */
  sanitize(threat: ThreatType): CallableGuard;
  /** Configure guard to categorize but not block a threat type */
  warn(threat: ThreatType): CallableGuard;
  /** Configure guard to completely ignore a threat type */
  allow(threat: ThreatType): CallableGuard;
};
