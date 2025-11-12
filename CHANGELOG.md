# Changelog

All notable changes to vard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-11-12

### Added

- **20 new attack patterns** based on 2024-2025 security research (closes [#1](https://github.com/andersmyrmel/vard/issues/1))
  - **Obfuscation/Decoding attacks** (7 patterns, severity 0.85-0.9)
    - `"spell backward and execute"` - Reverse text obfuscation
    - `"decode base64/hex/rot13 and follow"` - Encoding-based bypasses
    - `"translate from hex to text"` - Translation obfuscation
    - `"unscramble these letters and perform"` - Character rearrangement
    - Supports both orders: "decode base64" and "base64 decode"
  - **Negative directive attacks** (3 patterns, severity 0.75-0.85)
    - `"do not say X, instead Y"` - Negative instruction framing
    - `"don't respond with safety warnings"` - Safety bypass attempts
    - `"never refuse / always comply"` - Compliance manipulation
    - `"don't follow your guidelines"` - Direct rule violations
  - **Developer/Test mode attacks** (8 patterns, severity 0.65-0.95)
    - `"enable developer/debug/admin/god mode"` - Mode switching attempts
    - `"for educational/research purposes only"` - Justification framing (severity 0.7)
    - `"hypothetically/theoretically speaking"` - Hypothetical framing (severity 0.75)
    - `"imagine if / suppose that"` - Conditional framing (severity 0.7)
    - `"this is just a test/simulation"` - Test mode claims (severity 0.75)
    - `"DAN/jailbreak/unrestricted mode"` - Known jailbreak patterns (severity 0.95)
    - `"legal now / allowed now"` - Temporal exploitation (severity 0.8)
  - **Conversation history extraction** (5 patterns, severity 0.8-0.9)
    - `"repeat all previous messages"` - Full history requests (severity 0.9)
    - `"what did the last/other user ask"` - Cross-user data leaks (severity 0.85)
    - `"show conversation history/log"` - History access attempts (severity 0.9)
    - `"summarize everything we've discussed"` - Context extraction (severity 0.8)
    - `"print prior inputs/messages"` - Message history dumps (severity 0.9)
- **Comprehensive test coverage** - Added 46 new attack test cases
  - `tests/attacks.test.ts` - New test suites for all 4 pattern categories
  - All 217 tests passing with 100% success rate

### Research Sources

Patterns derived from peer-reviewed security research:

- [Lakera AI Prompt Injection Guide](https://www.lakera.ai/blog/guide-to-prompt-injection) - Obfuscation & negative directives
- [arXiv 2507.13169v1](https://arxiv.org/html/2507.13169v1) - "Prompt Injection 2.0: Hybrid AI Threats"
- [Kaspersky ChatGPT Jailbreaks](https://www.kaspersky.com/blog/chatgpt-jaibrakes/48216) - Developer mode & token smuggling
- [The Jailbreak Cookbook](https://www.generalanalysis.com/blog/jailbreak_cookbook) - Systematic attack patterns
- [Simon Willison on Prompt Injection](https://simonwillison.net/2025/Jan/29/prompt-injection-attacks-on-ai-systems/) - Context extraction attacks
- [arXiv 2308.03825](https://arxiv.org/abs/2308.03825) - "Do Anything Now" (DAN) jailbreak analysis

### Changed

- **Improved detection coverage** - Closed critical security gaps:
  - Obfuscation attacks: 0% → 100% detection rate
  - Conversation history: 0% → 100% detection rate
  - Developer/test mode: 43% → 100% detection rate
  - Negative directives: 60% → 100% detection rate

### Performance

- All benchmarks remain excellent with 20 additional patterns:
  - Throughput: 35,657 ops/sec (safe), 29,623 ops/sec (malicious)
  - Latency p99: 0.031ms (safe), 0.038ms (malicious)
  - Bundle size: 49.89 KB (unminified) - still <10KB gzipped
  - Memory: No leaks detected over 100,000 iterations

### Credits

- Research and pattern analysis conducted in response to community request
- Thanks to [@brrock](https://github.com/brrock) for opening [issue #1](https://github.com/andersmyrmel/vard/issues/1) and creating the [vard playground](https://vard-playground.vercel.app/)

---

## [1.1.0] - 2025-10-10

### Added

- **Obfuscation attack detection** - New pattern category for advanced evasion techniques
  - Zero-width character detection (U+200B, U+200C, U+200D, U+FEFF)
  - RTL/LTR override detection (U+202E, U+202D) - High severity (0.95)
  - Character insertion patterns (`i_g_n_o_r_e`, `i.g.n.o.r.e`)
  - Homoglyph detection (Greek Ι, Cyrillic і in "ignore")
  - Excessive spacing patterns (4+ spaces between words)
  - Full-width Unicode Latin letters (3+ in sequence)
  - Uncommon Unicode space variants (U+2000-U+200A, U+202F, U+205F)
- **`.onWarn()` callback method** - Set custom callback for warning-level threats
  - Real-time threat monitoring without blocking users
  - Perfect for analytics tracking and gradual rollout
  - Works with `.warn()` action to create monitoring-only mode
- **Enhanced sanitization** for encoding attacks
  - Zero-width character removal
  - Directional override character removal
  - Unicode space normalization (uncommon spaces → regular spaces)
  - Full-width character conversion (ＨＥＬＬＯ → HELLO)
- **Comprehensive test coverage** for new features
  - `tests/obfuscation.test.ts` - 24 tests for obfuscation patterns
  - `tests/onwarn.test.ts` - 17 tests for callback functionality
  - Performance benchmarks for obfuscation detection

### Changed

- **BREAKING**: Reduced default `maxLength` from 100,000 to 10,000 characters
  - **Migration**: Explicitly set `.maxLength(100000)` if you need longer inputs
  - **Rationale**: 10,000 chars ≈ 2,500 tokens, better default for DoS protection and typical chat use cases
  - Affects all presets: strict, moderate, lenient
- **README improvements** - Added Security Considerations and defense-in-depth guidance

### Performance

- All benchmarks still exceeding targets with obfuscation patterns:
  - Throughput: 58,561 ops/sec (safe), 41,489 ops/sec (malicious)
  - Latency p99: 0.018ms (safe), 0.027ms (malicious)

---

## [1.0.2] - 2025-10-08

### Changed

- Migrated from npm to pnpm for dependency management
- Updated CI workflow to use pnpm
- Restructured README for better flow and clarity
  - Improved table of contents
  - Better progressive disclosure of features
  - Clearer examples and use cases

### Added

- CONTRIBUTING.md with contribution guidelines
- CI status badge in README
- Improved badge styling in README

### Fixed

- Corrected npm package name in badge URL (`@andersmyrmel/vard`)

### Infrastructure

- pnpm workspace configuration
- Updated lock file format (pnpm-lock.yaml replaces package-lock.json)
- Optimized CI pipeline for pnpm

---

## [1.0.1] - 2025-10-08

### Added

- Husky pre-commit hooks for code quality
  - Automatic Prettier formatting on commit
  - ESLint validation on staged files
- Prettier configuration for consistent code style
- lint-staged for efficient pre-commit checks

### Changed

- All code formatted with Prettier
- Consistent code style across TypeScript, JavaScript, JSON, and Markdown files

### Infrastructure

- Husky v9 integration
- lint-staged configuration in package.json
- Pre-commit workflow ensures code quality before commits

---

## [1.0.0] - 2025-10-08

Initial release of vard (rebranded from prompt-guard).

### Features

- **Zero-config validation** - `vard(input)` just works
- **Chainable API** - Fluent, readable configuration inspired by Zod
- **TypeScript-first** - Full type safety and inference
- **5 threat types**:
  - Instruction override (`"ignore all previous instructions"`)
  - Role manipulation (`"you are now a hacker"`)
  - Delimiter injection (`<system>malicious</system>`)
  - System prompt leak (`"reveal your system prompt"`)
  - Encoding attacks (Base64, hex, unicode obfuscation)
- **Flexible threat actions**: block, sanitize, warn, allow
- **3 presets**: strict (0.5), moderate (0.7), lenient (0.85)
- **Fast**: <0.5ms p99 latency, 30k+ ops/sec throughput
- **Tiny**: <10KB minified + gzipped
- **ReDoS-safe**: All patterns use bounded quantifiers
- **Iterative sanitization**: Prevents nested bypass attempts (max 5 passes)

### API

- `vard(input)` - Direct validation with default config
- `vard.safe(input)` - Returns result object instead of throwing
- `vard.strict()`, `vard.moderate()`, `vard.lenient()` - Preset builders
- `.delimiters()` - Protect custom prompt delimiters
- `.pattern()` / `.patterns()` - Add custom detection patterns
- `.maxLength()` - Set maximum input length (default: 100,000)
- `.threshold()` - Adjust detection sensitivity (0-1)
- `.block()` / `.sanitize()` / `.warn()` / `.allow()` - Configure threat actions
- `.parse()` - Validate (throws on threat)
- `.safeParse()` - Validate (returns result object)

### Types

- `ThreatType` - 5 threat categories
- `ThreatAction` - 4 action types
- `Threat` - Individual threat detection result
- `VardResult` - Discriminated union for safe parsing
- `Pattern` - Custom pattern configuration
- `VardConfig` - Internal configuration object
- `PresetName` - Preset identifier
- `CallableVard` - Callable builder with chainable methods
- `PromptInjectionError` - Custom error with threat details

### Infrastructure

- GitHub Actions CI/CD pipeline
- Automated npm publishing on tag push
- Vitest test framework (169 tests)
- TypeScript strict mode
- ESLint with TypeScript rules
- TSUP build system (ESM only)
- MIT License

### Package

- npm: `@andersmyrmel/vard`
- Scoped package under @andersmyrmel
- GitHub: https://github.com/andersmyrmel/vard
- CodeSandbox playground available

---

## Links

- [npm package](https://www.npmjs.com/package/@andersmyrmel/vard)
- [GitHub repository](https://github.com/andersmyrmel/vard)
- [Issue tracker](https://github.com/andersmyrmel/vard/issues)
- [CodeSandbox playground](https://codesandbox.io/s/github/andersmyrmel/vard/tree/main/playground)
