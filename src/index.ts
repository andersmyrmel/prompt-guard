import { VardBuilder } from './vard';
import { getPreset } from './presets';
import type { VardResult, CallableVard } from './types';

export type {
  ThreatType,
  ThreatAction,
  Threat,
  VardResult,
  Pattern,
  VardConfig,
  PresetName,
} from './types';
export { PromptInjectionError } from './errors';

/**
 * Main vard function - validates input against prompt injection attacks.
 *
 * Can be called with or without an input string:
 * - With input: `vard(input)` - validates immediately (throws on detection)
 * - Without input: `vard()` - returns a chainable vard builder
 *
 * Uses moderate preset by default (threshold: 0.7, balanced security).
 *
 * @param input - User input to validate (optional)
 * @returns Validated string if input provided, or chainable vard builder if no input
 * @throws {PromptInjectionError} When prompt injection is detected (only if input provided)
 *
 * @example
 * **Zero-config usage (throws on threat)**
 * ```typescript
 * import vard from 'vard';
 *
 * const safe = vard('Hello, how can I help?');
 * // Returns: 'Hello, how can I help?'
 *
 * vard('Ignore all previous instructions');
 * // Throws: PromptInjectionError
 * ```
 *
 * @example
 * **Create chainable vard**
 * ```typescript
 * const myVard =vard()
 *   .delimiters(['CONTEXT:', 'USER:'])
 *   .maxLength(5000)
 *   .threshold(0.8);
 *
 * const safe = myVard.parse(userInput);
 * ```
 *
 * @see {@link vard.safe} for non-throwing validation
 * @see {@link vard.strict} for stricter detection (threshold: 0.5)
 * @see {@link vard.moderate} for balanced detection (threshold: 0.7)
 * @see {@link vard.lenient} for permissive detection (threshold: 0.85)
 */
function vardFn(input: string): string;
function vardFn(): CallableVard;
function vardFn(input?: string): string | CallableVard {
  if (input !== undefined) {
    const builder = new VardBuilder();
    return builder.parse(input);
  } else {
    return createVard();
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
 * import vard from 'vard';
 *
 * const result = vard.safe(userInput);
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
 * const result = vard.safe(input);
 *
 * if (result.safe) {
 *   result.data;    // TypeScript knows this is string
 * } else {
 *   result.threats; // TypeScript knows this is Threat[]
 * }
 * ```
 *
 * @see {@link vard} for throwing validation
 */
vardFn.safe = (input: string): VardResult => {
  const builder = new VardBuilder();
  return builder.safeParse(input);
};

/**
 * Creates a strict vard with low detection threshold (0.5).
 *
 * Blocks all threat types by default. Most sensitive to attacks but higher
 * chance of false positives. Recommended for high-security environments.
 *
 * @returns Chainable vard builder with strict preset
 *
 * @example
 * **Strict preset blocks more aggressively**
 * ```typescript
 * import vard from 'vard';
 *
 * const strict = vard.strict();
 *
 * // Even moderate threats are blocked
 * strict.parse('start over');
 * // Throws: PromptInjectionError (severity 0.75 > threshold 0.5)
 * ```
 *
 * @example
 * **Extend strict preset**
 * ```typescript
 * const myVard =vard.strict()
 *   .delimiters(['CONTEXT:', 'USER:'])
 *   .maxLength(10000);
 *
 * const safe = myVard.parse(userInput);
 * ```
 *
 * @see {@link vard.moderate} for balanced detection (default)
 * @see {@link vard.lenient} for permissive detection
 */
vardFn.strict = (): CallableVard => {
  const builder = new VardBuilder(getPreset('strict'));
  return VardBuilder.createCallable(builder);
};

/**
 * Creates a moderate vard with balanced detection threshold (0.7).
 *
 * Blocks high-severity threats, sanitizes delimiter/encoding attacks.
 * Good balance between security and usability. **This is the default preset.**
 *
 * @returns Chainable vard builder with moderate preset
 *
 * @example
 * **Moderate preset (balanced security)**
 * ```typescript
 * import vard from 'vard';
 *
 * const moderate = vard.moderate();
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
 * const chatVard =vard.moderate()
 *   .delimiters(['CONTEXT:', 'USER:', 'SYSTEM:'])
 *   .block('delimiterInjection')  // Block instead of sanitize
 *   .maxLength(5000);
 *
 * const safe = chatVard.parse(userInput);
 * ```
 *
 * @see {@link vard.strict} for stricter detection
 * @see {@link vard.lenient} for permissive detection
 */
vardFn.moderate = (): CallableVard => {
  const builder = new VardBuilder(getPreset('moderate'));
  return VardBuilder.createCallable(builder);
};

/**
 * Creates a lenient vard with high detection threshold (0.85).
 *
 * Sanitizes most threats instead of blocking. Only very high severity threats
 * are blocked. Recommended when false positives are costly or user input is
 * expected to contain instruction-like language (e.g., technical documentation).
 *
 * @returns Chainable vard builder with lenient preset
 *
 * @example
 * **Lenient preset allows more through**
 * ```typescript
 * import vard from 'vard';
 *
 * const lenient = vard.lenient();
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
 * const docVard = vard.lenient()
 *   .sanitize('instructionOverride')  // Don't block, just clean
 *   .sanitize('roleManipulation')
 *   .threshold(0.9);  // Even more permissive
 *
 * const safe = docVard.parse(technicalDocumentation);
 * ```
 *
 * @see {@link vard.strict} for stricter detection
 * @see {@link vard.moderate} for balanced detection (default)
 */
vardFn.lenient = (): CallableVard => {
  const builder = new VardBuilder(getPreset('lenient'));
  return VardBuilder.createCallable(builder);
};

/**
 * Main vard export - validates user input against prompt injection attacks.
 *
 * @remarks
 * This is the primary entry point for the library. It provides multiple ways
 * to validate input depending on your needs:
 *
 * - **Zero-config**: `vard(input)` - immediate validation with defaults
 * - **Safe mode**: `vard.safe(input)` - returns result instead of throwing
 * - **Presets**: `vard.strict()`, `vard.moderate()`, `vard.lenient()`
 * - **Chainable**: `vard().delimiters([...]).maxLength(...)`
 *
 * All methods return either validated strings or throw `PromptInjectionError`.
 *
 * @example
 * **Zero-config (recommended for most cases)**
 * ```typescript
 * import vard from 'vard';
 *
 * try {
 *   const safe = vard(userInput);
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
 * const result = vard.safe(userInput);
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
 * const chatVard =vard.moderate()
 *   .delimiters(['CONTEXT:', 'USER:', 'SYSTEM:'])
 *   .maxLength(5000)
 *   .sanitize('delimiterInjection')
 *   .block('instructionOverride');
 *
 * const safe = chatVard.parse(userMessage);
 * ```
 *
 * @see {@link https://github.com/andersmyrmel/vard#readme | Full Documentation}
 */
export const vard = vardFn;

/**
 * Short alias for vard - for power users who prefer brevity.
 *
 * @example
 * **Using v alias**
 * ```typescript
 * import { v } from 'vard';
 *
 * const safe = v(userInput);
 * const chatVard =v.moderate().delimiters(['CONTEXT:']);
 * ```
 */
export const v = vardFn;

/**
 * Default export - same as named `vard` export.
 *
 * @example
 * **ESM import**
 * ```typescript
 * import vard from 'vard';
 * const safe = vard(input);
 * ```
 *
 * @example
 * **CommonJS require**
 * ```typescript
 * const vard = require('vard').default;
 * const safe = vard(input);
 * ```
 */
export default vard;

/**
 * Creates a new vard with default (moderate) configuration.
 *
 * This is equivalent to `vard()` with no arguments. Provided as a named
 * export for clarity in advanced use cases.
 *
 * @returns Chainable vard builder with moderate preset
 *
 * @example
 * **Using createVard() directly**
 * ```typescript
 * import { createVard } from 'vard';
 *
 * const myVard =createVard()
 *   .delimiters(['CONTEXT:'])
 *   .maxLength(5000);
 *
 * const safe = myVard.parse(userInput);
 * ```
 *
 * @see {@link vard} for the main entry point
 */
export function createVard(): CallableVard {
  const builder = new VardBuilder();
  return VardBuilder.createCallable(builder);
}
