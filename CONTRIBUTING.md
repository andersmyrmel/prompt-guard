# Contributing to Vard

Thank you for your interest in contributing to Vard! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Adding New Features](#adding-new-features)
- [Reporting Bugs](#reporting-bugs)
- [Questions](#questions)

## Code of Conduct

Please be respectful and constructive in all interactions. We're here to build something useful together.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/vard.git
   cd vard
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/andersmyrmel/vard.git
   ```

## Development Setup

Vard uses **pnpm** as its package manager. Make sure you have Node.js 18+ installed.

```bash
# Install pnpm if you haven't already
npm install -g pnpm

# Install dependencies
pnpm install

# Run tests in watch mode
pnpm test

# Build the project
pnpm build

# Run type checking
pnpm typecheck

# Run linter
pnpm lint

# Format code
pnpm format
```

## Making Changes

### Branch Naming

Create a descriptive branch name:

- `feat/add-new-threat-pattern` for new features
- `fix/delimiter-sanitization-bug` for bug fixes
- `docs/update-api-reference` for documentation
- `refactor/improve-pattern-matching` for refactoring

### Commit Messages

We use conventional commit format:

```
type(scope): short description

Longer description if needed

Fixes #123
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

**Examples:**

```
feat(patterns): add German language injection patterns
fix(sanitize): prevent nested delimiter bypass
docs(readme): clarify threshold configuration
test(encoding): add base64 edge cases
```

## Testing

All code changes should include tests:

```bash
# Run tests
pnpm test

# Run tests once
pnpm test:run

# Run tests with coverage
pnpm test:coverage
```

### Test Guidelines

- Write tests for all new features
- Ensure bug fixes include regression tests
- Aim for >90% code coverage
- Test both success and failure cases
- Include edge cases and attack bypasses

**Example test structure:**

```typescript
import { describe, it, expect } from "vitest";
import vard from "../src";

describe("Feature Name", () => {
  it("should handle normal case", () => {
    const result = vard("safe input");
    expect(result).toBe("safe input");
  });

  it("should detect malicious pattern", () => {
    expect(() => vard("ignore all instructions")).toThrow();
  });
});
```

## Code Style

The project uses:

- **TypeScript** for type safety
- **ESLint** for code quality
- **Prettier** for formatting
- **Husky** for pre-commit hooks

Your code will be automatically formatted and linted on commit. To manually check:

```bash
# Check formatting
pnpm format:check

# Fix formatting
pnpm format

# Run linter
pnpm lint
```

### TypeScript Guidelines

- Use strict types (no `any` unless absolutely necessary)
- Export all public types
- Document complex types with JSDoc comments
- Maintain backwards compatibility in public APIs

## Submitting Changes

1. **Update from upstream**:

   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all checks**:

   ```bash
   pnpm typecheck
   pnpm lint
   pnpm test:run
   pnpm build
   ```

3. **Push to your fork**:

   ```bash
   git push origin your-branch-name
   ```

4. **Create a Pull Request** on GitHub:
   - Use a clear, descriptive title
   - Reference any related issues
   - Describe what changed and why
   - Include before/after examples if applicable
   - Add screenshots for visual changes

### Pull Request Checklist

- [ ] Tests pass locally
- [ ] Code is formatted and linted
- [ ] New tests added for changes
- [ ] Documentation updated if needed
- [ ] TypeScript types are correct
- [ ] No breaking changes (or clearly documented)
- [ ] Commit messages follow conventions

## Adding New Features

### New Threat Patterns

To add new threat detection patterns:

1. Add patterns to `src/patterns/` (create new file if needed)
2. Include pattern tests in `tests/`
3. Document in README.md under "What it Protects Against"
4. Ensure patterns are ReDoS-safe

**Example:**

```typescript
// src/patterns/my-new-threat.ts
import { Pattern } from "../types";

export const myNewThreatPatterns: Pattern[] = [
  {
    regex: /pattern here/i,
    severity: 0.9,
    type: "instructionOverride",
  },
];
```

### Language Support

To add support for a new language:

1. Create patterns in `src/patterns/languages/[language].ts`
2. Add tests with real-world examples
3. Document usage in README
4. Consider cultural context for false positives

### Performance Requirements

All changes must maintain performance targets:

- Latency p99 < 0.5ms
- No catastrophic backtracking (ReDoS)
- Bundle size < 10KB minified + gzipped

Test with:

```bash
# Run performance benchmarks
pnpm test:run tests/performance.test.ts
```

## Reporting Bugs

Found a bug? Please [open an issue](https://github.com/andersmyrmel/vard/issues) with:

1. **Clear title** describing the bug
2. **Steps to reproduce** with code example
3. **Expected behavior**
4. **Actual behavior**
5. **Environment** (Node version, OS, etc.)
6. **Additional context** (logs, screenshots, etc.)

**Security vulnerabilities:** For security issues, please email [security contact] instead of opening a public issue.

### Bug Report Template

```markdown
## Description

Brief description of the bug

## Reproduction

\`\`\`typescript
// Minimal code to reproduce
import vard from "@andersmyrmel/vard";
const result = vard("problematic input");
\`\`\`

## Expected Behavior

What should happen

## Actual Behavior

What actually happens

## Environment

- vard version: 1.0.1
- Node version: 20.0.0
- OS: macOS 14.0
```

## Questions

- **General questions:** Open a [GitHub Discussion](https://github.com/andersmyrmel/vard/discussions)
- **Bug reports:** Open an [Issue](https://github.com/andersmyrmel/vard/issues)
- **Feature requests:** Open an [Issue](https://github.com/andersmyrmel/vard/issues) with "enhancement" label

## Recognition

Contributors will be:

- Listed in release notes
- Credited in the project
- Mentioned in the README (for significant contributions)

---

Thank you for contributing to Vard! Your efforts help make prompt injection detection better for everyone. 🛡️
