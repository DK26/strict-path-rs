# Ergonomics Overview

This section collects high-signal, copy-pasteable guidance for day-to-day use without re-explaining the security model. Each page is short and focused so you can jump directly to what you need.

## New to strict-path?

Start with **Daily Usage Patterns** for common workflows and real-world examples.

## Quick Reference

- **Builtin I/O Operations**: Complete guide to file/directory operations, when to use builtin methods vs `std::fs`
- **Generic Functions & Markers**: Write reusable functions with `<M>`, understand when to use generic vs specific markers
- **Daily Usage Patterns**: Common workflows (user input validation, config loading, per-user isolation, archive extraction, etc.)
- **Interop vs Display**: How to pass paths to std/third-party APIs vs how to render them for users
- **Function Signatures**: Encode guarantees in types; when to accept strict/virtual vs roots + segments
- **Escape Hatches**: Borrowing and ownership conversions; when to use them (sparingly)
- **Equality & Ordering**: How comparisons work; what to compare and what not to
- **Naming Conventions**: Domain-first naming that teaches intent in code review
- **Canonicalized vs Lexical**: Choosing the right solution for your use case

For in-depth design and security rationale, see Best Practices and Anti-Patterns. This section stays focused on ergonomics.
