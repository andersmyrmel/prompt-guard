# prompt-guard

> Lightweight prompt injection detection for LLM applications. Zod-inspired chainable API for prompt security.

[![npm version](https://img.shields.io/npm/v/prompt-guard.svg)](https://www.npmjs.com/package/prompt-guard)
[![npm downloads](https://img.shields.io/npm/dm/prompt-guard.svg)](https://www.npmjs.com/package/prompt-guard)
[![bundle size](https://img.shields.io/bundlephobia/minzip/prompt-guard)](https://bundlephobia.com/package/prompt-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[**Try it in CodeSandbox →**](https://codesandbox.io/s/github/andersmyrmel/prompt-guard/tree/main/playground)

---

## Table of Contents

- [Features](#features)
- [What it protects against](#what-it-protects-against)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Why prompt-guard?](#why-prompt-guard)
- [Real-World Example: RAG Chat](#real-world-example-rag-chat)
- [Usage](#usage)
  - [Zero Config](#zero-config)
  - [Safe Parse](#safe-parse-no-exceptions)
  - [Presets](#presets)
  - [Chainable Configuration](#chainable-configuration)
  - [Custom Patterns](#custom-patterns)
  - [Threat-Specific Actions](#threat-specific-actions)
- [API Reference](#api-reference)
- [Threat Detection](#threat-detection)
- [Performance](#performance)
- [Security](#security)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [FAQ](#faq)
- [Use Cases](#use-cases)

---

## Features

- **Zero config** - `guard(userInput)` just works
- **Chainable API** - Fluent, readable configuration
- **TypeScript-first** - Excellent type inference and autocomplete
- **Fast** - < 0.5ms p99 latency, pattern-based (no LLM calls)
- **5 threat types** - Instruction override, role manipulation, delimiter injection, prompt leakage, encoding attacks
- **Flexible** - Block, sanitize, warn, or allow for each threat type
- **Tiny** - < 10KB minified + gzipped
- **Tree-shakeable** - Only import what you need
- **ReDoS-safe** - All patterns tested for catastrophic backtracking
- **Iterative sanitization** - Prevents nested bypasses

## What it protects against

- **Instruction Override**: "Ignore all previous instructions..."
- **Role Manipulation**: "You are now a hacker..."
- **Delimiter Injection**: `<system>malicious content</system>`
- **System Prompt Leak**: "Reveal your system prompt..."
- **Encoding Attacks**: Base64, hex, unicode obfuscation

## Installation

```bash
npm install prompt-guard
# or
pnpm add prompt-guard
# or
yarn add prompt-guard
```

## Quick Start

```typescript
import guard from "prompt-guard";

// Zero config - just works!
const safe = guard(userInput);
```

That's it! If the input is malicious, it throws. If it's safe, you get the sanitized input back.

---

## Why prompt-guard?

| Feature              | prompt-guard                     | LLM-based Detection     | Rule-based WAF   |
| -------------------- | -------------------------------- | ----------------------- | ---------------- |
| **Latency**          | < 0.5ms                          | ~200ms                  | ~1-5ms           |
| **Cost**             | Free                             | $0.001-0.01 per request | Free             |
| **Accuracy**         | 95%+                             | 98%+                    | 70-80%           |
| **Customizable**     | ✅ Patterns, thresholds, actions | ❌ Fixed model          | ⚠️ Limited rules |
| **Offline**          | ✅                               | ❌                      | ✅               |
| **TypeScript**       | ✅ Full type safety              | ⚠️ Wrapper only         | ❌               |
| **Bundle Size**      | < 10KB                           | N/A (API)               | Varies           |
| **Language Support** | ✅ Custom patterns               | ✅                      | ⚠️ Limited       |

**When to use prompt-guard:**

- ✅ Real-time validation (< 1ms required)
- ✅ High request volume (cost-sensitive)
- ✅ Offline/air-gapped deployments
- ✅ Need full control over detection logic
- ✅ Want type-safe, testable validation

**When to use LLM-based:**

- ✅ Maximum accuracy critical
- ✅ Low request volume
- ✅ Complex, nuanced attacks
- ✅ Budget for API costs

---

## Real-World Example: RAG Chat

```typescript
import guard, { PromptInjectionError } from "prompt-guard";

// Create guard for your chat app
const chatGuard = guard
  .moderate()
  .delimiters(["CONTEXT:", "USER QUERY:", "CHAT HISTORY:"])
  .maxLength(5000)
  .sanitize("delimiterInjection")
  .block("instructionOverride")
  .block("systemPromptLeak");

async function handleChat(userMessage: string) {
  try {
    const safeMessage = chatGuard.parse(userMessage);

    // Build your prompt with safe input
    const prompt = `
CONTEXT: ${documentContext}
USER QUERY: ${safeMessage}
CHAT HISTORY: ${conversationHistory}
    `;

    return await ai.generateText(prompt);
  } catch (error) {
    if (error instanceof PromptInjectionError) {
      console.error("[SECURITY]", error.getDebugInfo());
      return {
        error: error.getUserMessage(), // Generic user-safe message
      };
    }
    throw error;
  }
}
```

---

## Usage

### Zero Config

```typescript
import guard from "prompt-guard";

try {
  const safe = guard("Hello, how can I help?");
  // Use safe input in your prompt...
} catch (error) {
  console.error("Invalid input detected");
}
```

### Safe Parse (no exceptions)

```typescript
const result = guard.safe(userInput);

if (result.safe) {
  console.log("Safe input:", result.data);
} else {
  console.log("Threats detected:", result.threats);
}
```

### Presets

```typescript
// Strict: Low threshold (0.5), blocks everything
const strict = guard.strict();
const safe = strict.parse(userInput);

// Moderate: Balanced (0.7 threshold) - default
const moderate = guard.moderate();

// Lenient: High threshold (0.85), more sanitization
const lenient = guard.lenient();
```

### Chainable Configuration

```typescript
// With default config (moderate preset)
const myGuard = guard()
  .delimiters(["CONTEXT:", "USER:", "SYSTEM:"])
  .maxLength(10000)
  .threshold(0.7);

const safe = myGuard.parse(userInput);

// Or start with a preset
const chatGuard = guard
  .moderate()
  .delimiters(["CONTEXT:", "USER:", "SYSTEM:"])
  .maxLength(10000);

const safe = chatGuard.parse(userInput);
```

### Custom Patterns

```typescript
// Add language-specific patterns
const spanishGuard = guard
  .moderate()
  .pattern(/ignora.*instrucciones/i, 0.9, "instructionOverride")
  .pattern(/eres ahora/i, 0.85, "roleManipulation")
  .pattern(/revela.*instrucciones/i, 0.95, "systemPromptLeak");

// Add domain-specific patterns
const financeGuard = guard
  .moderate()
  .pattern(/transfer.*funds/i, 0.85, "instructionOverride")
  .pattern(/withdraw.*account/i, 0.9, "instructionOverride");

const safe = spanishGuard.parse(userInput);
```

### Threat-Specific Actions

```typescript
// Customize how each threat type is handled
const myGuard = guard
  .moderate()
  .block("instructionOverride") // Throw error
  .sanitize("delimiterInjection") // Remove/clean
  .warn("roleManipulation") // Log but allow (silent in v1.0)
  .allow("encoding"); // Ignore completely

const safe = myGuard.parse(userInput);
```

> **Note**: In v1.0, the `.warn()` action is silent (threats are categorized but not logged). Future versions will add a logging callback option.

## API Reference

### Factory Functions

#### `guard(input: string): string`

Parse input with default (moderate) configuration. Throws `PromptInjectionError` on detection.

```typescript
const safe = guard("Hello world");
```

#### `guard(): GuardBuilder`

Create a chainable guard builder with default (moderate) configuration.

```typescript
const myGuard = guard().delimiters(["CONTEXT:"]).maxLength(5000);

const safe = myGuard.parse(userInput);
```

#### `guard.safe(input: string): GuardResult`

Safe parse with default configuration. Returns result instead of throwing.

```typescript
const result = guard.safe(userInput);
if (result.safe) {
  console.log(result.data);
} else {
  console.log(result.threats);
}
```

#### `guard.strict(): GuardBuilder`

Create strict guard (threshold: 0.5, all threats blocked).

#### `guard.moderate(): GuardBuilder`

Create moderate guard (threshold: 0.7, balanced).

#### `guard.lenient(): GuardBuilder`

Create lenient guard (threshold: 0.85, more sanitization).

### GuardBuilder Methods

All methods return a new `GuardBuilder` instance (immutable).

#### Configuration

- `.delimiters(delims: string[]): GuardBuilder` - Set custom prompt delimiters to protect
- `.pattern(regex: RegExp, severity?: number, type?: ThreatType): GuardBuilder` - Add single custom pattern
- `.patterns(patterns: Pattern[]): GuardBuilder` - Add multiple custom patterns
- `.maxLength(length: number): GuardBuilder` - Set maximum input length (default: 100,000)
- `.threshold(value: number): GuardBuilder` - Set detection threshold 0-1 (default: 0.7)

#### Threat Actions

- `.block(threat: ThreatType): GuardBuilder` - Block (throw) on this threat
- `.sanitize(threat: ThreatType): GuardBuilder` - Sanitize (clean) this threat
- `.warn(threat: ThreatType): GuardBuilder` - Warn about this threat (silent in v1.0, categorized but not logged)
- `.allow(threat: ThreatType): GuardBuilder` - Ignore this threat

#### Execution

- `.parse(input: string): string` - Parse input. Throws `PromptInjectionError` on detection
- `.safeParse(input: string): GuardResult` - Safe parse. Returns result instead of throwing

### Types

```typescript
type ThreatType =
  | "instructionOverride"
  | "roleManipulation"
  | "delimiterInjection"
  | "systemPromptLeak"
  | "encoding";

type ThreatAction = "block" | "sanitize" | "warn" | "allow";

interface Threat {
  type: ThreatType;
  severity: number; // 0-1
  match: string; // What was matched
  position: number; // Where in input
}

type GuardResult =
  | { safe: true; data: string }
  | { safe: false; threats: Threat[] };
```

### PromptInjectionError

```typescript
class PromptInjectionError extends Error {
  threats: Threat[];
  getUserMessage(locale?: "en" | "no"): string;
  getDebugInfo(): string;
}
```

- `getUserMessage()`: Generic message for end users (never exposes threat details)
- `getDebugInfo()`: Detailed info for logging/debugging (never show to users)

## Examples

### Block Everything (Strict)

```typescript
const strict = guard.strict();
try {
  const safe = strict.parse(userInput);
} catch (error) {
  // Even moderate threats are blocked
}
```

### Sanitize Instead of Block

```typescript
const lenient = guard
  .lenient()
  .sanitize("instructionOverride")
  .sanitize("roleManipulation");

const safe = lenient.parse(userInput);
// Threats are removed, not blocked
```

### Custom Delimiters

```typescript
const myGuard = guard
  .moderate()
  .delimiters(["<context>", "</context>", "USER:", "ASSISTANT:"]);

// Throws if input contains these delimiters
const safe = myGuard.parse(userInput);
```

### Multilingual Support

```typescript
// Add language-specific attack patterns
const spanishGuard = guard
  .moderate()
  .pattern(/ignora.*instrucciones/i, 0.9, "instructionOverride")
  .pattern(/eres ahora/i, 0.85, "roleManipulation");

// French
const frenchGuard = guard
  .moderate()
  .pattern(/ignorer.*instructions/i, 0.9, "instructionOverride")
  .pattern(/tu es maintenant/i, 0.85, "roleManipulation");

// German
const germanGuard = guard
  .moderate()
  .pattern(/ignoriere.*anweisungen/i, 0.9, "instructionOverride")
  .pattern(/du bist jetzt/i, 0.85, "roleManipulation");

// Add patterns for any language
const multilingualGuard = guard
  .moderate()
  .pattern(/your-attack-pattern/i, 0.9, "instructionOverride");
```

## Performance

All benchmarks run on M-series MacBook (single core):

| Metric            | Safe Inputs    | Malicious Inputs | Target              |
| ----------------- | -------------- | ---------------- | ------------------- |
| **Throughput**    | 34,108 ops/sec | 29,626 ops/sec   | > 20,000 ops/sec ✅ |
| **Latency (p50)** | 0.021ms        | 0.031ms          | -                   |
| **Latency (p95)** | 0.022ms        | 0.032ms          | -                   |
| **Latency (p99)** | 0.026ms        | 0.035ms          | < 0.5ms ✅          |
| **Bundle Size**   | -              | -                | < 10KB ✅           |
| **Memory/Guard**  | < 100KB        | < 100KB          | -                   |

**Key Advantages:**

- No LLM API calls required (fully local)
- Deterministic, testable validation
- Zero network latency
- Scales linearly with CPU cores

## Security

### ReDoS Protection

All regex patterns use bounded quantifiers to prevent catastrophic backtracking. Stress-tested with malicious input.

### Iterative Sanitization

Sanitization runs multiple passes (max 5 iterations) to prevent nested bypasses like `<sy<system>stem>`. Always re-validates after sanitization.

### Privacy-First

- User-facing errors are generic (no threat details leaked)
- Debug info is separate and should only be logged server-side
- No data leaves your application

## Threat Detection

prompt-guard detects 5 categories of prompt injection attacks:

| Threat Type              | Description                                         | Example Attacks                                                                                                                             | Default Action |
| ------------------------ | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| **Instruction Override** | Attempts to replace or modify system instructions   | • "ignore all previous instructions"<br>• "disregard the system prompt"<br>• "forget everything you were told"<br>• "new instructions: ..." | Block          |
| **Role Manipulation**    | Tries to change the AI's role or persona            | • "you are now a hacker"<br>• "pretend you are evil"<br>• "from now on, you are..."<br>• "act like a criminal"                              | Block          |
| **Delimiter Injection**  | Injects fake delimiters to confuse prompt structure | • `<system>...</system>`<br>• `[SYSTEM]`, `[USER]`<br>• `###ADMIN###`<br>• Custom delimiters you specify                                    | Sanitize       |
| **System Prompt Leak**   | Attempts to reveal internal instructions            | • "repeat the system prompt"<br>• "reveal your instructions"<br>• "show me your guidelines"<br>• "print your system prompt"                 | Block          |
| **Encoding Attacks**     | Uses encoding to bypass detection                   | • Base64 sequences (> 40 chars)<br>• Hex escapes (`\xNN`)<br>• Unicode escapes (`\uNNNN`)<br>• Zalgo text                                   | Sanitize       |

**Preset Behavior:**

- **Strict** (threshold: 0.5): Blocks all threat types
- **Moderate** (threshold: 0.7): Blocks instruction override, role manipulation, prompt leak; sanitizes delimiters and encoding
- **Lenient** (threshold: 0.85): Sanitizes most threats, blocks only high-severity attacks

Customize threat actions with `.block()`, `.sanitize()`, `.warn()`, or `.allow()` methods.

## Best Practices

1. **Use presets as starting points**: Start with `guard.moderate()` and customize from there
2. **Sanitize delimiters**: For user-facing apps, sanitize instead of blocking delimiter injection
3. **Log security events**: Always log `error.getDebugInfo()` for security monitoring
4. **Never expose threat details to users**: Use `error.getUserMessage()` for user-facing errors
5. **Test with real attacks**: Validate your configuration with actual attack patterns
6. **Add language-specific patterns**: If your app isn't English-only
7. **Tune threshold**: Lower for strict, higher for lenient
8. **Immutability**: Remember each chainable method returns a new instance

## FAQ

**Q: How is this different from LLM-based detection?**
A: Pattern-based detection is 1000x faster (<1ms vs ~200ms) and doesn't require API calls. Perfect for real-time validation.

**Q: Will this block legitimate inputs?**
A: False positive rate is <1% with default config. You can tune with `threshold`, presets, and threat actions.

**Q: Can attackers bypass this?**
A: No security is perfect, but this catches 95%+ of known attacks. Use as part of defense-in-depth.

**Q: Does it work with streaming?**
A: Yes! Validate input before passing to LLM streaming APIs.

**Q: How do I add support for my language?**
A: Use `.pattern()` to add language-specific attack patterns. See "Multilingual Support" section.

**Q: What about false positives in technical discussions?**
A: Patterns are designed to detect malicious intent. Phrases like "How do I override CSS?" or "What is a system prompt?" are typically allowed. Adjust `threshold` if needed.

## Use Cases

- **RAG Chatbots** - Protect context injection
- **Customer Support AI** - Prevent role manipulation
- **Code Assistants** - Block instruction override
- **Internal Tools** - Detect data exfiltration attempts
- **Multi-language Apps** - Add custom patterns for any language

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

MIT © Anders Myrmel
