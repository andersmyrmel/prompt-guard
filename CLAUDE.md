# CLAUDE.md

> Developer guide for AI assistants (Claude, etc.) working on the vard codebase

## What is vard?

**vard** is a TypeScript-first prompt injection detection library with a Zod-inspired chainable API. It provides fast (<0.5ms p99), pattern-based validation for LLM applications without requiring external API calls.

**Philosophy**: Security + Developer Experience + Performance + Minimalism

---

## Quick Start Commands

```bash
# Install dependencies
pnpm install

# Development
pnpm dev              # Watch mode with auto-rebuild
pnpm build            # Production build (ESM + types)

# Testing
pnpm test             # Run tests in watch mode
pnpm test:run         # Run tests once
pnpm test:coverage    # Generate coverage report

# Quality
pnpm typecheck        # TypeScript type checking (no emit)
pnpm lint             # ESLint validation
pnpm format           # Format with Prettier
pnpm format:check     # Check formatting without writing
```

---

## Project Structure

```
vard/
├── src/
│   ├── index.ts              # Main exports (vard, v, createVard)
│   ├── types.ts              # All TypeScript types/interfaces
│   ├── vard.ts               # VardBuilder class (core logic)
│   ├── presets.ts            # Preset configurations (strict/moderate/lenient)
│   ├── errors.ts             # PromptInjectionError class
│   ├── patterns/             # Threat detection patterns
│   │   ├── index.ts          # Pattern aggregation
│   │   ├── instruction.ts    # Instruction override patterns
│   │   ├── role.ts           # Role manipulation patterns
│   │   ├── delimiter.ts      # Delimiter injection patterns
│   │   ├── leak.ts           # System prompt leak patterns
│   │   └── encoding.ts       # Encoding attack patterns
│   ├── detectors/
│   │   └── index.ts          # Detection logic (pattern matching)
│   └── sanitizers/
│       └── index.ts          # Sanitization logic (iterative cleaning)
└── tests/
    ├── basic.test.ts         # Basic functionality tests
    ├── chainable.test.ts     # API chaining tests
    ├── attacks.test.ts       # Real-world attack tests
    ├── presets.test.ts       # Preset configuration tests
    ├── integration.test.ts   # Full integration tests
    ├── redos.test.ts         # ReDoS safety tests
    └── benchmarks.test.ts    # Performance benchmarks
```

**Interactive Playground**: https://vard-playground.vercel.app/ (by [@brrock](https://github.com/brrock))

---

## Core Architecture

### Entry Points (src/index.ts)

The library exports multiple ways to create vard instances:

1. **Zero-config**: `vard(input)` - Direct call with default (moderate) preset
2. **Safe mode**: `vard.safe(input)` - Returns result object instead of throwing
3. **Presets**: `vard.strict()`, `vard.moderate()`, `vard.lenient()`
4. **Builder**: `vard()` - Returns chainable VardBuilder
5. **Alias**: `v` - Short version for power users

### VardBuilder (src/vard.ts)

**Immutable chainable builder** - Every method returns a new instance:

- **Configuration**: `.delimiters()`, `.pattern()`, `.patterns()`, `.maxLength()`, `.threshold()`
- **Threat Actions**: `.block()`, `.sanitize()`, `.warn()`, `.allow()`
- **Execution**: `.parse()` (throws), `.safeParse()` (returns result)

**Important**: `VardBuilder.createCallable()` wraps the builder to enable both:

- Function call: `myVard(input)` → shorthand for `.parse()`
- Method call: `myVard.parse(input)` → explicit validation

### Detection Flow

1. **Length check**: Reject if `input.length > maxLength`
2. **Pattern matching**: Test input against all patterns (built-in + custom)
3. **Custom delimiters**: Exact string matching for user-defined delimiters
4. **Categorization**: Group threats by action (block/sanitize/warn/allow)
5. **Threshold filtering**: Only threats with `severity >= threshold` are processed
6. **Action execution**:
   - **Block**: Throw `PromptInjectionError`
   - **Sanitize**: Remove/clean threat → **re-validate** to catch nested attacks
   - **Warn**: Categorize but allow (use with `onWarn` callback)
   - **Allow**: Ignore completely

### Threat Types (src/types.ts)

```typescript
type ThreatType =
  | "instructionOverride" // "ignore all previous instructions"
  | "roleManipulation" // "you are now a hacker"
  | "delimiterInjection" // "<system>malicious</system>"
  | "systemPromptLeak" // "reveal your system prompt"
  | "encoding"; // Base64/hex/unicode obfuscation
```

### Patterns (src/patterns/)

Each pattern file exports an array of `Pattern` objects:

```typescript
interface Pattern {
  regex: RegExp; // Detection pattern (must use bounded quantifiers)
  severity: number; // 0-1 score (higher = more severe)
  type: ThreatType; // Which threat category
}
```

**ReDoS Safety**: All regex patterns use bounded quantifiers (`{n,m}`, `*?`, `+?`) to prevent catastrophic backtracking. Test with `tests/redos.test.ts`.

### Presets (src/presets.ts)

Three built-in configurations balancing security vs. usability:

| Preset     | Threshold | Behavior                                           |
| ---------- | --------- | -------------------------------------------------- |
| `strict`   | 0.5       | Block all threats, high false positive rate        |
| `moderate` | 0.7       | Block severe threats, sanitize delimiters/encoding |
| `lenient`  | 0.85      | Sanitize most, block only critical threats         |

---

## Code Principles

### 1. Minimalism & Performance

- **< 10KB bundle** - Zero dependencies, tree-shakeable
- **< 0.5ms p99 latency** - Pre-compiled regex, early exits
- **No allocations in hot paths** - Minimize object creation during detection
- **Every line must earn its place** - Delete more than you add

### 2. API Design (Zod-Inspired)

- **Chainable & immutable** - All config methods return new instances
- **Fluent & readable** - Code should read like English
- **TypeScript inference** - Types inferred, not declared
- **Discriminated unions** - `VardResult` for type-safe error handling
- **Sensible defaults** - `vard(input)` works for 90% of use cases

### 3. TypeScript Quality

```typescript
// ✅ DO
interface Threat {
  type: ThreatType;
  severity: number;
  match: string;
  position: number;
}

type VardResult =
  | { safe: true; data: string }
  | { safe: false; threats: Threat[] };

// ❌ DON'T
any                           // Never use `any` in production code
type VardResult = { ... }     // Always use discriminated unions for results
```

**Strict mode enabled**:

```json
{
  "strict": true,
  "noUncheckedIndexedAccess": true
}
```

### 4. Security-First Development

#### ReDoS Prevention

All regex patterns must use **bounded quantifiers**:

```typescript
// ✅ SAFE
/ignore\s+(?:all\s+)?(?:previous\s+)?instructions/i
/\b(?:you\s+are\s+now|act\s+as)\s+.{1,50}/i

// ❌ UNSAFE (catastrophic backtracking)
/(a+)+/
/(.*)+ instructions/
```

Test with `tests/redos.test.ts`:

```typescript
// Stress test with malicious input (should complete < 100ms)
const malicious = "a".repeat(10000) + "!";
expect(() => vard(malicious)).not.toThrow();
```

#### Iterative Sanitization

Prevent nested bypasses with multi-pass cleaning:

```typescript
// Attack: <sy<system>stem>
// Pass 1: Remove <system> → <system>
// Pass 2: Remove <system> → ""
// Max 5 iterations, always re-validate after sanitization
```

#### Privacy-First Errors

```typescript
// ✅ DO - Generic user message
error.getUserMessage(); // "Invalid input detected"

// ✅ DO - Detailed logging (server-side only)
console.error("[SECURITY]", error.getDebugInfo());

// ❌ DON'T - Leak threat details to users
throw new Error(`Detected: ${threat.match}`);
```

### 5. Immutability Pattern

**All chainable methods create new instances**:

```typescript
delimiters(delims: string[]): CallableVard {
  const newBuilder = new VardBuilder({
    ...this.config,
    customDelimiters: [...delims],  // Create new array
  });
  return VardBuilder.createCallable(newBuilder);
}
```

This enables:

```typescript
const base = vard.moderate();
const strict = base.threshold(0.5); // Doesn't modify `base`
const lenient = base.threshold(0.9); // Doesn't modify `base`
```

---

## Common Tasks

### Adding a New Threat Pattern

1. **Add pattern to appropriate file** (`src/patterns/`)

```typescript
// src/patterns/instruction.ts
export const instructionPatterns: Pattern[] = [
  {
    regex: /new\s+attack\s+pattern/i,
    severity: 0.85,
    type: "instructionOverride",
  },
  // ... existing patterns
];
```

2. **Test with real attacks** (`tests/attacks.test.ts`)

```typescript
it("detects new attack pattern", () => {
  expect(() => vard("new attack pattern")).toThrow(PromptInjectionError);
});
```

3. **Verify no ReDoS** (`tests/redos.test.ts`)

```typescript
it("new pattern is ReDoS-safe", () => {
  const malicious = "new ".repeat(1000) + "attack pattern!";
  expect(() => vard(malicious)).not.toThrow();
});
```

### Adding a New Threat Type

1. **Update `ThreatType` in `src/types.ts`**

```typescript
export type ThreatType =
  | "instructionOverride"
  | "roleManipulation"
  | "delimiterInjection"
  | "systemPromptLeak"
  | "encoding"
  | "newThreatType"; // Add here
```

2. **Create pattern file** (`src/patterns/new-threat.ts`)

```typescript
import type { Pattern } from "../types";

export const newThreatPatterns: Pattern[] = [
  {
    regex: /pattern/i,
    severity: 0.8,
    type: "newThreatType",
  },
];
```

3. **Export from `src/patterns/index.ts`**

```typescript
import { newThreatPatterns } from "./new-threat";

export const allPatterns = [
  ...instructionPatterns,
  ...rolePatterns,
  ...newThreatPatterns, // Add here
];
```

4. **Update presets** (`src/presets.ts`)

```typescript
export function getPreset(name: PresetName): VardConfig {
  const presets: Record<PresetName, VardConfig> = {
    strict: {
      threatActions: {
        newThreatType: "block", // Add action
        // ...
      },
    },
    // ...
  };
}
```

### Adding a New Configuration Method

1. **Add to `VardConfig` interface** (`src/types.ts`)
2. **Add method to `VardBuilder`** (`src/vard.ts`)
3. **Add to `CallableVard` type** (`src/types.ts`)
4. **Update `createCallable()`** to attach method

### Debugging Detection Issues

**Enable verbose logging**:

```typescript
// In src/vard.ts parse() method
const threats = detect(input, allPatternsToCheck);
console.log("Detected threats:", threats);

const { toBlock, toSanitize } = this.categorizeThreats(threats);
console.log("To block:", toBlock);
console.log("To sanitize:", toSanitize);
```

**Use `.safeParse()` for inspection**:

```typescript
const result = vard.moderate().safeParse(input);
if (!result.safe) {
  console.log("Threats:", result.threats);
  result.threats.forEach((t) => {
    console.log(
      `  ${t.type} (${t.severity}): "${t.match}" at position ${t.position}`,
    );
  });
}
```

---

## Testing Strategy

### Test Files

- **`basic.test.ts`** - Core functionality (parse, safeParse, presets)
- **`chainable.test.ts`** - API chaining, immutability
- **`attacks.test.ts`** - Real-world attack scenarios
- **`presets.test.ts`** - Preset behavior validation
- **`integration.test.ts`** - End-to-end workflows (RAG examples)
- **`redos.test.ts`** - ReDoS safety (stress tests with malicious input)
- **`benchmarks.test.ts`** - Performance validation (< 0.5ms p99)

### Performance Benchmarks

**Must pass on every commit**:

```typescript
// tests/benchmarks.test.ts
it("validates safe inputs in <0.5ms (p99)", () => {
  const iterations = 10000;
  const latencies = [];

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    vard(safeInput);
    latencies.push(performance.now() - start);
  }

  const p99 = latencies.sort()[Math.floor(iterations * 0.99)];
  expect(p99).toBeLessThan(0.5);
});
```

### Adding Tests

**Always test**:

1. **Happy path** - Valid input passes through
2. **Threat detection** - Invalid input is caught
3. **Edge cases** - Empty strings, very long input, special characters
4. **Immutability** - Config changes don't affect original instance
5. **Type safety** - Discriminated unions narrow correctly

---

## Build System

### TSUP Configuration

- **Format**: ESM only (`"type": "module"` in package.json)
- **Output**: `dist/index.js` + `dist/index.d.ts`
- **Tree-shakeable**: `"sideEffects": false`
- **Source maps**: Enabled for debugging

```bash
# package.json
{
  "scripts": {
    "build": "tsup src/index.ts --format esm --dts --clean",
    "dev": "tsup src/index.ts --format esm --dts --watch"
  }
}
```

### Exports

```json
{
  "main": "./dist/index.js",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  }
}
```

---

## Linting & Formatting

### ESLint (eslint.config.js)

- TypeScript-ESLint with recommended rules
- Custom rules:
  - `@typescript-eslint/no-explicit-any`: warn (prefer specific types)
  - `@typescript-eslint/no-unused-vars`: error (allow `_` prefix for unused args)

### Prettier

```bash
pnpm format       # Format all files
pnpm format:check # CI validation
```

### Pre-commit Hooks (Husky + lint-staged)

```json
{
  "lint-staged": {
    "*.{ts,js,json,md}": ["prettier --write"],
    "*.{ts,js}": ["eslint --fix"]
  }
}
```

---

## API Stability

### Public API (Stable)

**Exported from `src/index.ts`**:

- `vard()` function (all overloads)
- `vard.safe()`, `.strict()`, `.moderate()`, `.lenient()`
- `v` alias
- `createVard()`
- All types: `ThreatType`, `ThreatAction`, `Threat`, `VardResult`, `Pattern`, `VardConfig`, `PresetName`
- `PromptInjectionError` class

**VardBuilder methods**:

- `.delimiters()`, `.pattern()`, `.patterns()`, `.maxLength()`, `.threshold()`
- `.block()`, `.sanitize()`, `.warn()`, `.allow()`
- `.parse()`, `.safeParse()`

### Internal API (Subject to Change)

- `VardBuilder` constructor (use factory functions instead)
- `detect()`, `sanitize()` functions (may refactor)
- Pattern arrays (may reorganize)

---

## Performance Targets

| Metric          | Target      | Measured (M-series Mac) | Status  |
| --------------- | ----------- | ----------------------- | ------- |
| Latency p99     | < 0.5ms     | ~0.035ms                | ✅ Pass |
| Bundle size     | < 10KB      | ~8KB minified+gzipped   | ✅ Pass |
| Throughput      | > 20k ops/s | ~30k ops/s              | ✅ Pass |
| Memory per vard | < 100KB     | ~80KB                   | ✅ Pass |

**Optimization priorities**:

1. Pre-compile all regex patterns (done in pattern files)
2. Early exit on first blocking threat (done in `parse()`)
3. Avoid string allocations during detection (use `test()`, not `match()`)
4. Bounded quantifiers to prevent ReDoS backtracking

---

## Common Gotchas

### 1. Immutability

```typescript
// ❌ WRONG - Methods don't modify in-place
const myVard = vard();
myVard.threshold(0.8); // Returns new instance, doesn't modify myVard!

// ✅ CORRECT
const myVard = vard().threshold(0.8);
```

### 2. Threshold Behavior

```typescript
// Only threats with severity >= threshold are processed
const lenient = vard().threshold(0.9);
lenient.parse("ignore instructions"); // May pass if severity < 0.9
```

### 3. Sanitization Re-validation

```typescript
// Sanitization ALWAYS re-validates to catch nested attacks
const myVard = vard().sanitize("delimiterInjection");
myVard.parse("IG<SYSTEM>NORE"); // Sanitizes to "IGNORE", re-validates, may block!
```

### 4. Type Imports

```typescript
// ✅ DO - Use type imports for interfaces
import type { Threat, VardResult } from "@andersmyrmel/vard";

// ❌ DON'T - Unnecessarily import runtime code
import { Threat, VardResult } from "@andersmyrmel/vard";
```

### 5. Callable vs Builder

```typescript
// These are equivalent:
const safe1 = chatVard(input); // Shorthand
const safe2 = chatVard.parse(input); // Explicit

// createCallable() enables both patterns
```

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for:

- Code of Conduct
- Contribution workflow (fork, branch, PR)
- Code style guidelines
- Testing requirements

**Before submitting PR**:

1. ✅ All tests pass (`pnpm test:run`)
2. ✅ Type checking passes (`pnpm typecheck`)
3. ✅ Linting passes (`pnpm lint`)
4. ✅ Formatting applied (`pnpm format`)
5. ✅ Performance benchmarks pass
6. ✅ ReDoS tests pass for new patterns

---

## Future Roadmap (Do Not Implement Yet)

These features are planned but **not yet approved**:

- **Logging callback**: `onWarn?: (threat: Threat) => void` for `.warn()` action
- **Custom sanitizers**: Allow user-defined sanitization functions
- **Multi-language pattern packs**: Built-in support for Spanish, French, German, etc.
- **Streaming validation**: Incremental validation for SSE/streaming responses
- **Advanced analytics**: Threat severity distributions, false positive tracking

**Do not implement these without explicit approval from maintainers.**

---

## Questions?

- **Issues**: https://github.com/andersmyrmel/vard/issues
- **Discussions**: https://github.com/andersmyrmel/vard/discussions
- **Email**: anders@example.com (replace with actual email)

---

_This guide is for AI assistants working on vard. For user documentation, see [README.md](./README.md)._
