# Ergonomics Overview

This section collects high-signal, copy-pasteable guidance for day-to-day use without re-explaining the security model. Each page is short and focused so you can jump directly to what you need.

- Interop vs Display: how to pass paths to std/third-party APIs vs how to render them for users.
- Function Signatures: encode guarantees in types; when to accept strict/virtual vs roots + segments.
- Escape Hatches: borrowing and ownership conversions; when to use them (sparingly).
- Equality & Ordering: how comparisons work; what to compare and what not to.
- Naming: domain-first naming that teaches intent in code review.

For in-depth design and security rationale, see Best Practices and Anti-Patterns. This section stays focused on ergonomics.
