# Design & Internals

> **⚠️ CONTRIBUTOR DOCUMENTATION**  
> This section is for contributors, library developers, and curious developers who want to understand how strict-path works internally.

If you're just using strict-path in your project, you probably want:
- [Getting Started](./chapter_1.md) - Learn the basic API
- [Real-World Examples](./examples.md) - See practical usage patterns

## What's in This Section

This section covers the internal design decisions and patterns that make strict-path secure and maintainable:

### Type-History Design Pattern
The core security mechanism that uses Rust's type system to enforce that paths go through required validation steps in the correct order. This prevents accidentally using unvalidated paths and makes security guarantees compile-time checked rather than runtime hopes.

[Read about Type-History →](./type_history_design.md)

## For Contributors

If you're contributing to strict-path, understanding these internals will help you:
- Maintain the security guarantees
- Add new features safely
- Understand why certain design decisions were made
- Write tests that verify the type-level constraints

The design patterns used here can also be applied to other security-critical Rust libraries where you need compile-time guarantees about data processing pipelines.
