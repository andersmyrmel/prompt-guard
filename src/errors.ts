import type { Threat } from './types';

/**
 * Error thrown when prompt injection attacks are detected in user input.
 *
 * @remarks
 * This error contains details about detected threats in the `threats` property.
 * Use `getUserMessage()` for user-facing errors (safe, no threat details leaked)
 * and `getDebugInfo()` for server-side logging (detailed threat information).
 *
 * **Security Note**: Never expose `getDebugInfo()` or the `threats` array to
 * end users, as this reveals information about your security measures.
 *
 * @example
 * **Basic error handling**
 * ```typescript
 * import vard, { PromptInjectionError } from 'vard';
 *
 * try {
 *   const safe = vard(userInput);
 *   processInput(safe);
 * } catch (error) {
 *   if (error instanceof PromptInjectionError) {
 *     // Show generic message to user
 *     console.log(error.getUserMessage('en'));
 *
 *     // Log details server-side
 *     console.error('[SECURITY]', error.getDebugInfo());
 *   }
 * }
 * ```
 *
 * @example
 * **Inspecting detected threats**
 * ```typescript
 * try {
 *   vard(userInput);
 * } catch (error) {
 *   if (error instanceof PromptInjectionError) {
 *     error.threats.forEach(threat => {
 *       console.log(`Type: ${threat.type}`);
 *       console.log(`Severity: ${threat.severity}`);
 *       console.log(`Match: ${threat.match}`);
 *       console.log(`Position: ${threat.position}`);
 *     });
 *   }
 * }
 * ```
 *
 * @example
 * **Norwegian error messages**
 * ```typescript
 * try {
 *   vard(userInput);
 * } catch (error) {
 *   if (error instanceof PromptInjectionError) {
 *     return {
 *       error: error.getUserMessage('no')
 *       // Returns: "Ugyldig innhold oppdaget. Vennligst prøv igjen."
 *     };
 *   }
 * }
 * ```
 */
export class PromptInjectionError extends Error {
  /**
   * Array of detected threats. Each threat contains:
   * - `type`: Type of attack detected
   * - `severity`: Severity score (0-1)
   * - `match`: The matched string that triggered detection
   * - `position`: Character position where threat was found
   *
   * @remarks
   * **Security**: Never expose this to end users. Use `getUserMessage()` instead.
   */
  public readonly threats: Threat[];

  /**
   * Creates a new PromptInjectionError.
   *
   * @param threats - Array of detected threats (must not be empty)
   */
  constructor(threats: Threat[]) {
    super('Invalid input detected');
    this.name = 'PromptInjectionError';
    this.threats = threats;

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, PromptInjectionError);
    }
  }

  /**
   * Returns a generic, user-safe error message.
   *
   * This message intentionally does NOT reveal what was detected or why.
   * Use this for user-facing error messages.
   *
   * @param locale - Language for the message ('en' or 'no')
   * @returns Generic error message in the specified language
   *
   * @example
   * **English message (default)**
   * ```typescript
   * error.getUserMessage('en');
   * // Returns: "Invalid input detected. Please try again."
   * ```
   *
   * @example
   * **Norwegian message**
   * ```typescript
   * error.getUserMessage('no');
   * // Returns: "Ugyldig innhold oppdaget. Vennligst prøv igjen."
   * ```
   *
   * @see {@link getDebugInfo} for detailed threat information (server-side only)
   */
  getUserMessage(locale: 'en' | 'no' = 'en'): string {
    return locale === 'no'
      ? 'Ugyldig innhold oppdaget. Vennligst prøv igjen.'
      : 'Invalid input detected. Please try again.';
  }

  /**
   * Returns detailed threat information for logging and debugging.
   *
   * @remarks
   * **Security Warning**: This method returns detailed information about detected
   * threats including attack types, severity scores, and matched patterns.
   * **NEVER expose this to end users** as it reveals your security measures.
   *
   * Use this only for:
   * - Server-side logging
   * - Security monitoring
   * - Debugging during development
   *
   * @returns Formatted string with detailed threat information
   *
   * @example
   * **Server-side logging**
   * ```typescript
   * try {
   *   vard(userInput);
   * } catch (error) {
   *   if (error instanceof PromptInjectionError) {
   *     // Log detailed info server-side (safe)
   *     console.error('[SECURITY]', error.getDebugInfo());
   *
   *     // Return generic message to user (safe)
   *     return { error: error.getUserMessage() };
   *   }
   * }
   * ```
   *
   * @example
   * **Example output**
   * ```
   * Threats detected:
   * - instructionOverride (severity: 0.90, match: "ignore all previous instr...", position: 0)
   * - delimiterInjection (severity: 0.95, match: "<system>", position: 45)
   * ```
   *
   * @see {@link getUserMessage} for safe, user-facing error messages
   */
  getDebugInfo(): string {
    const threatList = this.threats
      .map(
        (t) =>
          `- ${t.type} (severity: ${t.severity.toFixed(2)}, match: "${t.match.substring(0, 30)}${t.match.length > 30 ? '...' : ''}", position: ${t.position})`
      )
      .join('\n');

    return `Threats detected:\n${threatList}`;
  }
}
