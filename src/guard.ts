import type {
  GuardConfig,
  GuardResult,
  Pattern,
  Threat,
  ThreatAction,
  ThreatType,
} from './types';
import { PromptInjectionError } from './errors';
import { allPatterns } from './patterns';
import { detect, checkLength, detectCustomDelimiters } from './detectors';
import { sanitize } from './sanitizers';
import { getPreset } from './presets';

/**
 * GuardBuilder class - chainable, immutable configuration builder
 */
export class GuardBuilder {
  private readonly config: GuardConfig;

  constructor(config?: Partial<GuardConfig>) {
    // Default to moderate preset
    const defaultConfig = getPreset('moderate');
    this.config = {
      ...defaultConfig,
      ...config,
    };
  }

  /**
   * Create a callable guard instance from this builder
   * Allows using guard as a function: guard(input) instead of guard.parse(input)
   */
  public static createCallable(
    builder: GuardBuilder
  ): import('./types').CallableGuard {
    // Create a function that calls parse
    const callable = ((input: string) =>
      builder.parse(input)) as unknown as import('./types').CallableGuard;

    // Attach all methods to the function
    callable.parse = builder.parse.bind(builder);
    callable.safeParse = builder.safeParse.bind(builder);
    callable.delimiters = (delims: string[]) => builder.delimiters(delims);
    callable.pattern = (
      regex: RegExp,
      severity?: number,
      type?: import('./types').ThreatType
    ) => builder.pattern(regex, severity, type);
    callable.patterns = (patterns: import('./types').Pattern[]) =>
      builder.patterns(patterns);
    callable.maxLength = (length: number) => builder.maxLength(length);
    callable.threshold = (value: number) => builder.threshold(value);
    callable.block = (threat: import('./types').ThreatType) =>
      builder.block(threat);
    callable.sanitize = (threat: import('./types').ThreatType) =>
      builder.sanitize(threat);
    callable.warn = (threat: import('./types').ThreatType) =>
      builder.warn(threat);
    callable.allow = (threat: import('./types').ThreatType) =>
      builder.allow(threat);

    return callable as import('./types').CallableGuard;
  }

  /**
   * Configures custom prompt delimiters to detect and protect against.
   *
   * Use this when your prompts use specific delimiters to separate sections
   * (e.g., RAG context, user input, system instructions). The guard will detect
   * if user input contains these delimiters, preventing context injection.
   *
   * @param delims - Array of delimiter strings to protect (case-sensitive, exact match)
   * @returns New guard instance with custom delimiters configured (immutable)
   *
   * @example
   * **Protect RAG delimiters**
   * ```typescript
   * const chatGuard = guard()
   *   .delimiters(['CONTEXT:', 'USER:', 'SYSTEM:'])
   *   .block('delimiterInjection');
   *
   * // This will throw
   * chatGuard.parse('Hello CONTEXT: fake data');
   * // Throws: PromptInjectionError (delimiter injection detected)
   * ```
   *
   * @example
   * **Multiple delimiter formats**
   * ```typescript
   * const myGuard = guard.strict()
   *   .delimiters([
   *     '### CONTEXT ###',
   *     '### USER ###',
   *     '<system>',
   *     '</system>',
   *   ]);
   *
   * const safe = myGuard.parse(userInput);
   * ```
   *
   * @see {@link block} to throw on delimiter detection
   * @see {@link sanitize} to remove delimiters instead of throwing
   */
  delimiters(delims: string[]): import('./types').CallableGuard {
    const newBuilder = new GuardBuilder({
      ...this.config,
      customDelimiters: [...delims],
    });
    return GuardBuilder.createCallable(newBuilder);
  }

  /**
   * Adds a custom detection pattern for language-specific or domain-specific threats.
   *
   * Use this to detect attacks in non-English languages or add patterns specific
   * to your application. Custom patterns are checked in addition to built-in patterns.
   *
   * @param regex - Regular expression to match threats (use bounded quantifiers to avoid ReDoS)
   * @param severity - Severity score from 0-1 (default: 0.8). Higher = more severe.
   * @param type - Type of threat this pattern detects (default: 'instructionOverride')
   * @returns New guard instance with custom pattern added (immutable)
   *
   * @example
   * **Norwegian attack patterns**
   * ```typescript
   * const norwegianGuard = guard.moderate()
   *   .pattern(/ignorer.*instruksjoner/i, 0.9, 'instructionOverride')
   *   .pattern(/du er nå/i, 0.85, 'roleManipulation')
   *   .pattern(/vis systemprompten/i, 0.95, 'systemPromptLeak');
   *
   * norwegianGuard.parse('ignorer alle instruksjoner');
   * // Throws: PromptInjectionError
   * ```
   *
   * @example
   * **Domain-specific patterns**
   * ```typescript
   * const medicalGuard = guard.strict()
   *   .pattern(/\bsudowoodo\b/i, 0.95, 'instructionOverride')  // Custom trigger word
   *   .pattern(/override\s+diagnosis/i, 0.9, 'instructionOverride');
   *
   * const safe = medicalGuard.parse(patientInput);
   * ```
   *
   * @remarks
   * **ReDoS Warning**: Always use bounded quantifiers in your regex to prevent
   * catastrophic backtracking. Bad: `/(a+)+/`. Good: `/a{1,50}/`.
   *
   * @see {@link patterns} to add multiple patterns at once
   * @see {@link threshold} to adjust sensitivity
   */
  pattern(
    regex: RegExp,
    severity: number = 0.8,
    type: ThreatType = 'instructionOverride'
  ): import('./types').CallableGuard {
    const newPattern: Pattern = { regex, severity, type };
    const newBuilder = new GuardBuilder({
      ...this.config,
      customPatterns: [...this.config.customPatterns, newPattern],
    });
    return GuardBuilder.createCallable(newBuilder);
  }

  /**
   * Adds multiple custom detection patterns at once.
   *
   * Convenience method for bulk pattern registration. Each pattern must specify
   * a regex, severity score (0-1), and threat type.
   *
   * @param patterns - Array of custom patterns to add
   * @returns New guard instance with patterns added (immutable)
   *
   * @example
   * **Add multiple domain-specific patterns**
   * ```typescript
   * import guard from 'prompt-guard';
   * import type { Pattern } from 'prompt-guard';
   *
   * const medicalPatterns: Pattern[] = [
   *   {
   *     regex: /reveal\s+patient\s+data/i,
   *     severity: 0.95,
   *     type: 'systemPromptLeak',
   *   },
   *   {
   *     regex: /bypass\s+hipaa/i,
   *     severity: 0.9,
   *     type: 'instructionOverride',
   *   },
   * ];
   *
   * const medicalGuard = guard()
   *   .patterns(medicalPatterns)
   *   .block('systemPromptLeak')
   *   .block('instructionOverride');
   * ```
   *
   * @example
   * **Combine with single pattern() method**
   * ```typescript
   * const myGuard = guard()
   *   .patterns(bulkPatterns)  // Add 10 patterns at once
   *   .pattern(/special-case/i, 0.8, 'instructionOverride');  // Add 1 more
   * ```
   *
   * @see {@link pattern} to add a single pattern
   */
  patterns(patterns: Pattern[]): import('./types').CallableGuard {
    const newBuilder = new GuardBuilder({
      ...this.config,
      customPatterns: [...this.config.customPatterns, ...patterns],
    });
    return GuardBuilder.createCallable(newBuilder);
  }

  /**
   * Sets the maximum allowed input length in characters.
   *
   * Inputs longer than this limit will throw `PromptInjectionError`.
   * Useful for preventing resource exhaustion and limiting token costs.
   *
   * @param length - Maximum number of characters allowed (must be positive)
   * @returns New guard instance with max length configured (immutable)
   *
   * @example
   * **Limit user input length**
   * ```typescript
   * const chatGuard = guard.moderate()
   *   .maxLength(5000);  // ~1250 tokens for GPT models
   *
   * chatGuard.parse('a'.repeat(10000));
   * // Throws: PromptInjectionError (input exceeds 5000 characters)
   * ```
   *
   * @example
   * **Different limits for different contexts**
   * ```typescript
   * const shortFormGuard = guard().maxLength(500);
   * const longFormGuard = guard().maxLength(10000);
   *
   * shortFormGuard.parse(feedbackInput);
   * longFormGuard.parse(documentInput);
   * ```
   *
   * @remarks
   * Default max length is 100,000 characters if not specified.
   */
  maxLength(length: number): import('./types').CallableGuard {
    const newBuilder = new GuardBuilder({
      ...this.config,
      maxLength: length,
    });
    return GuardBuilder.createCallable(newBuilder);
  }

  /**
   * Sets the detection threshold for blocking threats.
   *
   * Only threats with severity >= threshold will trigger their configured action.
   * Lower threshold = more sensitive (more false positives).
   * Higher threshold = less sensitive (may miss attacks).
   *
   * @param value - Threshold from 0-1 (automatically clamped to this range)
   * @returns New guard instance with threshold configured (immutable)
   *
   * @example
   * **Adjust sensitivity**
   * ```typescript
   * // Strict: catch everything (more false positives)
   * const strict = guard().threshold(0.5);
   *
   * // Balanced (default for moderate preset)
   * const balanced = guard().threshold(0.7);
   *
   * // Lenient: only high-confidence threats
   * const lenient = guard().threshold(0.9);
   * ```
   *
   * @example
   * **Threshold affects which patterns trigger**
   * ```typescript
   * const guard = guard().threshold(0.8);
   *
   * // Pattern with severity 0.75 - IGNORED (below threshold)
   * guard.parse('start over');  // Passes
   *
   * // Pattern with severity 0.9 - DETECTED (above threshold)
   * guard.parse('ignore all instructions');  // Throws
   * ```
   *
   * @remarks
   * Recommended thresholds:
   * - **0.5-0.6**: High security, expect false positives
   * - **0.7**: Balanced (default)
   * - **0.85-0.9**: Permissive, technical content
   *
   * @see {@link guard.strict} for preset with 0.5 threshold
   * @see {@link guard.moderate} for preset with 0.7 threshold
   * @see {@link guard.lenient} for preset with 0.85 threshold
   */
  threshold(value: number): import('./types').CallableGuard {
    const newBuilder = new GuardBuilder({
      ...this.config,
      threshold: Math.max(0, Math.min(1, value)),
    });
    return GuardBuilder.createCallable(newBuilder);
  }

  /**
   * Set action for a specific threat type
   */
  private setThreatAction(
    threat: ThreatType,
    action: ThreatAction
  ): import('./types').CallableGuard {
    const newBuilder = new GuardBuilder({
      ...this.config,
      threatActions: {
        ...this.config.threatActions,
        [threat]: action,
      },
    });
    return GuardBuilder.createCallable(newBuilder);
  }

  /**
   * Configures the guard to throw an error when detecting the specified threat type.
   *
   * Use this when you want to reject input completely rather than attempting
   * to sanitize it. Recommended for high-severity threats.
   *
   * @param threat - Type of threat to block ('instructionOverride', 'roleManipulation', etc.)
   * @returns New guard instance with block action configured (immutable)
   *
   * @example
   * **Block specific threats**
   * ```typescript
   * const myGuard = guard.moderate()
   *   .block('instructionOverride')
   *   .block('systemPromptLeak')
   *   .sanitize('delimiterInjection');  // Mix with other actions
   *
   * myGuard.parse('ignore all instructions');
   * // Throws: PromptInjectionError
   * ```
   *
   * @example
   * **Override preset behavior**
   * ```typescript
   * // Moderate preset sanitizes delimiters, but we want to block them
   * const strictDelimiters = guard.moderate()
   *   .delimiters(['CONTEXT:', 'USER:'])
   *   .block('delimiterInjection');
   *
   * strictDelimiters.parse('CONTEXT: fake data');
   * // Throws: PromptInjectionError
   * ```
   *
   * @see {@link sanitize} to remove threats instead of blocking
   * @see {@link warn} to log but allow threats (silent in v1.0)
   * @see {@link allow} to ignore threats completely
   */
  block(threat: ThreatType): import('./types').CallableGuard {
    return this.setThreatAction(threat, 'block');
  }

  /**
   * Configures the guard to remove/clean threats instead of throwing an error.
   *
   * Use this for threats that can be safely removed from input (like delimiters)
   * or when you want to be permissive rather than blocking users.
   *
   * **Important**: Sanitized input is re-validated to catch bypass attempts.
   * If sanitization fails to remove threats, an error will still be thrown.
   *
   * @param threat - Type of threat to sanitize ('delimiterInjection', 'encoding', etc.)
   * @returns New guard instance with sanitize action configured (immutable)
   *
   * @example
   * **Sanitize instead of block**
   * ```typescript
   * const lenientGuard = guard()
   *   .sanitize('delimiterInjection')
   *   .sanitize('encoding')
   *   .block('instructionOverride');  // Still block severe threats
   *
   * const result = lenientGuard.parse('<system>Hello</system>');
   * console.log(result);  // "Hello" (delimiters removed)
   * ```
   *
   * @example
   * **Handles nested attacks**
   * ```typescript
   * const myGuard = guard().sanitize('delimiterInjection');
   *
   * // Nested attack: <sy<system>stem>
   * // After removing inner <system>: <system>
   * // Re-validation catches this and re-sanitizes
   * const safe = myGuard.parse('<sy<system>stem>text</system>');
   * console.log(safe);  // "text" (fully sanitized)
   * ```
   *
   * @remarks
   * Sanitization uses iterative cleaning (max 5 passes) to prevent bypass
   * attempts with nested delimiters or patterns.
   *
   * @see {@link block} to throw errors instead of sanitizing
   * @see {@link warn} to log but allow threats
   * @see {@link allow} to ignore threats
   */
  sanitize(threat: ThreatType): import('./types').CallableGuard {
    return this.setThreatAction(threat, 'sanitize');
  }

  /**
   * Configures the guard to categorize threats for logging without blocking or sanitizing.
   *
   * Useful for monitoring potential threats in production without disrupting users.
   * **Note**: In v1.0, warnings are silent (threats are categorized but not logged).
   * Future versions will add a logging callback option.
   *
   * @param threat - Type of threat to warn about ('instructionOverride', 'roleManipulation', etc.)
   * @returns New guard instance with warn action configured (immutable)
   *
   * @example
   * **Monitor without blocking**
   * ```typescript
   * const monitor = guard()
   *   .warn('instructionOverride')  // Categorize but don't block
   *   .block('systemPromptLeak');   // Still block this
   *
   * // In v1.0, this passes silently (warning is categorized)
   * const result = monitor.parse('ignore previous instructions');
   * console.log(result);  // Original input unchanged
   * ```
   *
   * @example
   * **Gradual rollout strategy**
   * ```typescript
   * // Phase 1: Monitor in production
   * const phase1 = guard().warn('instructionOverride');
   *
   * // Phase 2: Sanitize after analyzing logs
   * const phase2 = guard().sanitize('instructionOverride');
   *
   * // Phase 3: Block if sanitization isn't enough
   * const phase3 = guard().block('instructionOverride');
   * ```
   *
   * @remarks
   * **v1.0 Behavior**: Warnings are categorized internally but not logged or exposed.
   * Future versions may add: `onWarn?: (threat: Threat) => void` callback option.
   *
   * @see {@link block} to throw errors for threats
   * @see {@link sanitize} to remove threats from input
   * @see {@link allow} to ignore threats completely
   */
  warn(threat: ThreatType): import('./types').CallableGuard {
    return this.setThreatAction(threat, 'warn');
  }

  /**
   * Configures the guard to completely ignore a specific threat type.
   *
   * Use this when you've determined a threat type produces too many false positives
   * in your domain, or when certain patterns are expected in your use case.
   *
   * @param threat - Type of threat to allow/ignore ('instructionOverride', 'roleManipulation', etc.)
   * @returns New guard instance with allow action configured (immutable)
   *
   * @example
   * **Disable specific threat detection**
   * ```typescript
   * // Technical documentation contains instruction-like language
   * const docGuard = guard()
   *   .allow('instructionOverride')  // Don't flag "start over", "ignore this"
   *   .block('systemPromptLeak')     // Still protect against prompt leaks
   *   .block('delimiterInjection');
   *
   * const safe = docGuard.parse('Step 1: Start over with a clean slate');
   * console.log(safe);  // Passes through unchanged
   * ```
   *
   * @example
   * **Domain-specific false positives**
   * ```typescript
   * // Customer support chat allows role-playing scenarios
   * const supportGuard = guard()
   *   .allow('roleManipulation')     // "act as", "pretend you are" are ok
   *   .block('instructionOverride')  // Still block instruction overrides
   *   .sanitize('delimiterInjection');
   *
   * supportGuard.parse('Can you act as a technical expert?');
   * // Passes - roleManipulation is allowed
   * ```
   *
   * @remarks
   * Use sparingly - each allowed threat type reduces your security posture.
   * Consider using `.sanitize()` or `.warn()` instead when possible.
   *
   * @see {@link block} to throw errors for threats
   * @see {@link sanitize} to remove threats from input
   * @see {@link warn} to monitor threats without blocking
   */
  allow(threat: ThreatType): import('./types').CallableGuard {
    return this.setThreatAction(threat, 'allow');
  }

  /**
   * Validates input and returns the safe string.
   *
   * This is the primary validation method. It detects threats, applies configured
   * actions (block/sanitize/warn/allow), and either returns safe input or throws
   * `PromptInjectionError`.
   *
   * @param input - User input to validate (must be a string)
   * @returns Validated (and possibly sanitized) input string
   * @throws {PromptInjectionError} When threats with 'block' action are detected above threshold
   * @throws {TypeError} When input is not a string
   *
   * @example
   * **Basic usage (throws on detection)**
   * ```typescript
   * import guard, { PromptInjectionError } from 'prompt-guard';
   *
   * try {
   *   const safe = guard.moderate().parse(userInput);
   *   // Use safe input in your LLM prompt
   *   await llm.generate(`Context: ${safe}`);
   * } catch (error) {
   *   if (error instanceof PromptInjectionError) {
   *     console.error('[SECURITY]', error.getDebugInfo());
   *     return { error: 'Invalid input detected' };
   *   }
   * }
   * ```
   *
   * @example
   * **Sanitization example**
   * ```typescript
   * const chatGuard = guard()
   *   .delimiters(['CONTEXT:', 'USER:'])
   *   .sanitize('delimiterInjection')
   *   .block('instructionOverride');
   *
   * // Delimiters are removed
   * const result = chatGuard.parse('Hello CONTEXT: fake data');
   * console.log(result);  // "Hello  fake data"
   *
   * // Instruction override is blocked
   * chatGuard.parse('ignore all previous instructions');
   * // Throws: PromptInjectionError
   * ```
   *
   * @remarks
   * **Security Features**:
   * - Re-validates after sanitization to catch nested attacks
   * - Iterative sanitization (max 5 passes) prevents bypass attempts
   * - Threshold filtering: only threats >= threshold trigger their action
   *
   * @see {@link safeParse} for non-throwing alternative (returns result object)
   * @see {@link PromptInjectionError} for error details and logging
   */
  parse(input: string): string {
    // Type check
    if (typeof input !== 'string') {
      throw new TypeError('Input must be a string');
    }

    // Handle empty/whitespace
    if (input.trim() === '') {
      return '';
    }

    // Check length
    const lengthThreat = checkLength(input, this.config.maxLength);
    if (lengthThreat) {
      throw new PromptInjectionError([lengthThreat]);
    }

    // Combine all patterns (built-in + custom)
    const allPatternsToCheck = [...allPatterns, ...this.config.customPatterns];

    // Detect threats using pattern matching
    let threats = detect(input, allPatternsToCheck);

    // Detect custom delimiters (exact string matching for user-defined delimiters)
    if (this.config.customDelimiters.length > 0) {
      const delimiterThreats = detectCustomDelimiters(
        input,
        this.config.customDelimiters
      );
      threats = [...threats, ...delimiterThreats];
    }

    // Categorize threats by action (block, sanitize, warn, allow) and filter by threshold
    const { toBlock, toSanitize } = this.categorizeThreats(threats);

    // If we have threats to block, throw
    if (toBlock.length > 0) {
      throw new PromptInjectionError(toBlock);
    }

    // Sanitize threats if configured to do so
    let result = input;
    if (toSanitize.length > 0) {
      // Apply iterative sanitization (handles nested attacks)
      result = sanitize(input, toSanitize);

      // CRITICAL: Re-validate after sanitization to catch bypass attempts
      // Example: "IG<SYSTEM>NORE" becomes "IGNORE" after removing <SYSTEM>
      const recheck = detect(result, allPatternsToCheck);
      const recheckDelimiters =
        this.config.customDelimiters.length > 0
          ? detectCustomDelimiters(result, this.config.customDelimiters)
          : [];
      const allRecheckThreats = [...recheck, ...recheckDelimiters];

      const { toBlock: recheckBlock } =
        this.categorizeThreats(allRecheckThreats);

      // If sanitization failed to remove threats, block the input
      if (recheckBlock.length > 0) {
        throw new PromptInjectionError(recheckBlock);
      }
    }

    // NOTE: Warnings are categorized but not logged in v1.0
    // Future versions may add a logger callback: onWarn?: (threat: Threat) => void

    return result;
  }

  /**
   * Validates input without throwing - returns a result object instead.
   *
   * Use this when you want to handle threats gracefully without try/catch blocks.
   * Returns a discriminated union that TypeScript can narrow based on the `safe` property.
   *
   * @param input - User input to validate (must be a string)
   * @returns Result object:
   *   - `{ safe: true, data: string }` if input is valid
   *   - `{ safe: false, threats: Threat[] }` if threats were detected
   *
   * @example
   * **Graceful error handling (no try/catch)**
   * ```typescript
   * import guard from 'prompt-guard';
   *
   * const result = guard.moderate().safeParse(userInput);
   *
   * if (result.safe) {
   *   // TypeScript knows result.data is string
   *   await llm.generate(`Context: ${result.data}`);
   * } else {
   *   // TypeScript knows result.threats is Threat[]
   *   console.error('Threats detected:', result.threats.length);
   *   result.threats.forEach(t => {
   *     console.log(`- ${t.type} (severity: ${t.severity.toFixed(2)})`);
   *   });
   * }
   * ```
   *
   * @example
   * **Conditional processing based on threats**
   * ```typescript
   * const chatGuard = guard()
   *   .sanitize('delimiterInjection')
   *   .block('instructionOverride');
   *
   * const result = chatGuard.safeParse(userMessage);
   *
   * if (!result.safe) {
   *   // Log for security monitoring
   *   logSecurityEvent({
   *     threats: result.threats.map(t => t.type),
   *     severity: Math.max(...result.threats.map(t => t.severity)),
   *   });
   *
   *   return { error: 'Invalid input detected' };
   * }
   *
   * return { message: result.data };
   * ```
   *
   * @remarks
   * **Type Safety**: The return type is a discriminated union. TypeScript will
   * automatically narrow the type based on the `safe` property, giving you
   * type-safe access to either `data` or `threats`.
   *
   * @see {@link parse} for throwing alternative
   * @see {@link GuardResult} type definition
   */
  safeParse(input: string): GuardResult {
    try {
      const data = this.parse(input);
      return { safe: true, data };
    } catch (error) {
      if (error instanceof PromptInjectionError) {
        return { safe: false, threats: error.threats };
      }
      // Re-throw non-guard errors
      throw error;
    }
  }

  /**
   * Categorize threats by configured action and threshold
   * Returns threats grouped by action: block (throw error), sanitize (clean), warn (log)
   */
  private categorizeThreats(threats: Threat[]): {
    toBlock: Threat[];
    toSanitize: Threat[];
    toWarn: Threat[];
  } {
    const toBlock: Threat[] = [];
    const toSanitize: Threat[] = [];
    const toWarn: Threat[] = [];

    for (const threat of threats) {
      // Skip if below threshold
      if (threat.severity < this.config.threshold) {
        continue;
      }

      const action = this.config.threatActions[threat.type];

      switch (action) {
        case 'block':
          toBlock.push(threat);
          break;
        case 'sanitize':
          toSanitize.push(threat);
          break;
        case 'warn':
          toWarn.push(threat);
          break;
        case 'allow':
          // Do nothing
          break;
      }
    }

    return { toBlock, toSanitize, toWarn };
  }
}
