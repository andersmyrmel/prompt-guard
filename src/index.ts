import { GuardBuilder } from './guard';
import { getPreset } from './presets';
import type { GuardResult, CallableGuard } from './types';

export type {
  ThreatType,
  ThreatAction,
  Threat,
  GuardResult,
  Pattern,
  GuardConfig,
  PresetName,
} from './types';
export { PromptInjectionError } from './errors';

/**
 * Main guard function - validates input against prompt injection attacks.
 *
 * Can be called with or without an input string:
 * - With input: `guard(input)` - validates immediately (throws on detection)
 * - Without input: `guard()` - returns a chainable guard builder
 *
 * Uses moderate preset by default (threshold: 0.7, balanced security).
 *
 * @param input - User input to validate (optional)
 * @returns Validated string if input provided, or chainable guard builder if no input
 * @throws {PromptInjectionError} When prompt injection is detected (only if input provided)
 *
 * @example
 * **Zero-config usage (throws on threat)**
 * ```typescript
 * import guard from 'prompt-guard';
 *
 * const safe = guard('Hello, how can I help?');
 * // Returns: 'Hello, how can I help?'
 *
 * guard('Ignore all previous instructions');
 * // Throws: PromptInjectionError
 * ```
 *
 * @example
 * **Create chainable guard**
 * ```typescript
 * const myGuard = guard()
 *   .delimiters(['CONTEXT:', 'USER:'])
 *   .maxLength(5000)
 *   .threshold(0.8);
 *
 * const safe = myGuard.parse(userInput);
 * ```
 *
 * @see {@link guard.safe} for non-throwing validation
 * @see {@link guard.strict} for stricter detection (threshold: 0.5)
 * @see {@link guard.moderate} for balanced detection (threshold: 0.7)
 * @see {@link guard.lenient} for permissive detection (threshold: 0.85)
 */
function guardFn(input: string): string;
function guardFn(): CallableGuard;
function guardFn(input?: string): string | CallableGuard {
  if (input !== undefined) {
    const builder = new GuardBuilder();
    return builder.parse(input);
  } else {
    return createGuard();
  }
}

/**
 * Validates input without throwing - returns a result object instead.
 *
 * Useful when you want to handle threats gracefully without try/catch.
 * Uses moderate preset by default (threshold: 0.7).
 *
 * @param input - User input to validate
 * @returns Result object with discriminated union type:
 *   - `{ safe: true, data: string }` if input is safe
 *   - `{ safe: false, threats: Threat[] }` if threats detected
 *
 * @example
 * **Safe validation (no exceptions)**
 * ```typescript
 * import guard from 'prompt-guard';
 *
 * const result = guard.safe(userInput);
 *
 * if (result.safe) {
 *   console.log('Safe input:', result.data);
 * } else {
 *   console.log('Threats found:', result.threats);
 *   result.threats.forEach(t => {
 *     console.log(`- ${t.type} (severity: ${t.severity})`);
 *   });
 * }
 * ```
 *
 * @example
 * **Type narrowing with discriminated union**
 * ```typescript
 * const result = guard.safe(input);
 *
 * if (result.safe) {
 *   result.data;    // TypeScript knows this is string
 * } else {
 *   result.threats; // TypeScript knows this is Threat[]
 * }
 * ```
 *
 * @see {@link guard} for throwing validation
 */
guardFn.safe = (input: string): GuardResult => {
  const builder = new GuardBuilder();
  return builder.safeParse(input);
};

/**
 * Creates a strict guard with low detection threshold (0.5).
 *
 * Blocks all threat types by default. Most sensitive to attacks but higher
 * chance of false positives. Recommended for high-security environments.
 *
 * @returns Chainable guard builder with strict preset
 *
 * @example
 * **Strict preset blocks more aggressively**
 * ```typescript
 * import guard from 'prompt-guard';
 *
 * const strict = guard.strict();
 *
 * // Even moderate threats are blocked
 * strict.parse('start over');
 * // Throws: PromptInjectionError (severity 0.75 > threshold 0.5)
 * ```
 *
 * @example
 * **Extend strict preset**
 * ```typescript
 * const myGuard = guard.strict()
 *   .delimiters(['CONTEXT:', 'USER:'])
 *   .maxLength(10000);
 *
 * const safe = myGuard.parse(userInput);
 * ```
 *
 * @see {@link guard.moderate} for balanced detection (default)
 * @see {@link guard.lenient} for permissive detection
 */
guardFn.strict = (): CallableGuard => {
  const builder = new GuardBuilder(getPreset('strict'));
  return GuardBuilder.createCallable(builder);
};

/**
 * Creates a moderate guard with balanced detection threshold (0.7).
 *
 * Blocks high-severity threats, sanitizes delimiter/encoding attacks.
 * Good balance between security and usability. **This is the default preset.**
 *
 * @returns Chainable guard builder with moderate preset
 *
 * @example
 * **Moderate preset (balanced security)**
 * ```typescript
 * import guard from 'prompt-guard';
 *
 * const moderate = guard.moderate();
 *
 * // High severity threats are blocked
 * moderate.parse('ignore all previous instructions');
 * // Throws: PromptInjectionError (severity 0.9 > threshold 0.7)
 *
 * // Delimiter injection is sanitized (not blocked)
 * const result = moderate.parse('<system>Hello</system>');
 * console.log(result); // "Hello" (delimiter removed)
 * ```
 *
 * @example
 * **Customize moderate preset**
 * ```typescript
 * const chatGuard = guard.moderate()
 *   .delimiters(['CONTEXT:', 'USER:', 'SYSTEM:'])
 *   .block('delimiterInjection')  // Block instead of sanitize
 *   .maxLength(5000);
 *
 * const safe = chatGuard.parse(userInput);
 * ```
 *
 * @see {@link guard.strict} for stricter detection
 * @see {@link guard.lenient} for permissive detection
 */
guardFn.moderate = (): CallableGuard => {
  const builder = new GuardBuilder(getPreset('moderate'));
  return GuardBuilder.createCallable(builder);
};

/**
 * Creates a lenient guard with high detection threshold (0.85).
 *
 * Sanitizes most threats instead of blocking. Only very high severity threats
 * are blocked. Recommended when false positives are costly or user input is
 * expected to contain instruction-like language (e.g., technical documentation).
 *
 * @returns Chainable guard builder with lenient preset
 *
 * @example
 * **Lenient preset allows more through**
 * ```typescript
 * import guard from 'prompt-guard';
 *
 * const lenient = guard.lenient();
 *
 * // Moderate severity threats pass through
 * const safe = lenient.parse('new instructions');
 * // Returns: 'new instructions' (severity 0.8 < threshold 0.85)
 *
 * // Very high severity still blocked
 * lenient.parse('ignore all previous instructions');
 * // Throws: PromptInjectionError (severity 0.9 > threshold 0.85)
 * ```
 *
 * @example
 * **Lenient for technical content**
 * ```typescript
 * const docGuard = guard.lenient()
 *   .sanitize('instructionOverride')  // Don't block, just clean
 *   .sanitize('roleManipulation')
 *   .threshold(0.9);  // Even more permissive
 *
 * const safe = docGuard.parse(technicalDocumentation);
 * ```
 *
 * @see {@link guard.strict} for stricter detection
 * @see {@link guard.moderate} for balanced detection (default)
 */
guardFn.lenient = (): CallableGuard => {
  const builder = new GuardBuilder(getPreset('lenient'));
  return GuardBuilder.createCallable(builder);
};

/**
 * Main guard export - validates user input against prompt injection attacks.
 *
 * @remarks
 * This is the primary entry point for the library. It provides multiple ways
 * to validate input depending on your needs:
 *
 * - **Zero-config**: `guard(input)` - immediate validation with defaults
 * - **Safe mode**: `guard.safe(input)` - returns result instead of throwing
 * - **Presets**: `guard.strict()`, `guard.moderate()`, `guard.lenient()`
 * - **Chainable**: `guard().delimiters([...]).maxLength(...)`
 *
 * All methods return either validated strings or throw `PromptInjectionError`.
 *
 * @example
 * **Zero-config (recommended for most cases)**
 * ```typescript
 * import guard from 'prompt-guard';
 *
 * try {
 *   const safe = guard(userInput);
 *   // Use safe input in your LLM prompt
 * } catch (error) {
 *   if (error instanceof PromptInjectionError) {
 *     console.error('Security threat detected');
 *   }
 * }
 * ```
 *
 * @example
 * **Safe mode (no exceptions)**
 * ```typescript
 * const result = guard.safe(userInput);
 * if (result.safe) {
 *   processInput(result.data);
 * } else {
 *   logThreats(result.threats);
 * }
 * ```
 *
 * @example
 * **Custom configuration**
 * ```typescript
 * const chatGuard = guard.moderate()
 *   .delimiters(['CONTEXT:', 'USER:', 'SYSTEM:'])
 *   .maxLength(5000)
 *   .sanitize('delimiterInjection')
 *   .block('instructionOverride');
 *
 * const safe = chatGuard.parse(userMessage);
 * ```
 *
 * @see {@link https://github.com/andersmyrmel/prompt-guard#readme | Full Documentation}
 */
export const guard = guardFn;

/**
 * Default export - same as named `guard` export.
 *
 * @example
 * **ESM import**
 * ```typescript
 * import guard from 'prompt-guard';
 * const safe = guard(input);
 * ```
 *
 * @example
 * **CommonJS require**
 * ```typescript
 * const guard = require('prompt-guard').default;
 * const safe = guard(input);
 * ```
 */
export default guard;

/**
 * Creates a new guard with default (moderate) configuration.
 *
 * This is equivalent to `guard()` with no arguments. Provided as a named
 * export for clarity in advanced use cases.
 *
 * @returns Chainable guard builder with moderate preset
 *
 * @example
 * **Using createGuard() directly**
 * ```typescript
 * import { createGuard } from 'prompt-guard';
 *
 * const myGuard = createGuard()
 *   .delimiters(['CONTEXT:'])
 *   .maxLength(5000);
 *
 * const safe = myGuard.parse(userInput);
 * ```
 *
 * @see {@link guard} for the main entry point
 */
export function createGuard(): CallableGuard {
  const builder = new GuardBuilder();
  return GuardBuilder.createCallable(builder);
}
