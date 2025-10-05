# Design Decisions - Guide for the Frustrated Rustacean

Since this is a security crate, I took on myself more design decision liberties towards increased security, correctness and avoidance of misuse.

## The Journey: From Ergonomic to Secure

The initial prototype had straightforward ergonomics, with non-original, boring API. Which is normally good and required design. Easy transitions between types and common method names.

As I was generating code using different LLMs, a disaster unfolded. **The LLM did not use the API correctly at all!** It constantly worked its way around safety features and since it was generating a lot of code, it became harder to have code review and easy to miss an introduced vulnerability by the LLM.

That had me realize that since LLM Agents is all that is happening nowadays, I had to think carefully about how to guide it towards correct usage of my API in a way that a human will also benefit from.

## Security Measures Taken

### LLM-Aware Documentation
- **Complete API summary file dedicated to an LLM** - [`LLM_API_REFERENCE.md`](https://github.com/DK26/strict-path-rs/blob/main/LLM_API_REFERENCE.md) provides usage-first guidance
- **Code comments in a style that tooling agents can reason with** - Explicit function documentation with SUMMARY/PARAMETERS/RETURNS/ERRORS/EXAMPLE sections

### API Design Philosophy
- **Highly explicit API** - Easy to review and detect errors by method names
  - `strictpath_display()` vs `virtualpath_display()` instead of generic `display()`
  - `strict_join()` vs `virtual_join()` instead of generic `join()`
  - `interop_path()` for third-party integration instead of hidden `AsRef<Path>` impls
- **Best practices vs anti-patterns in docs** - Clear guidance on what to do and what to avoid
- **Minimal API surface** - Less ways to get it wrong
- **Safe built-in I/O operations** - `read_to_string()`, `write()`, `create_file()` on the secure types
- **Type-based security** - Markers enforce boundaries at compile time

## The Path Extension Trait Decision

I was thinking about having an extension trait for `Path`/`PathBuf`, to introduce built-in I/O methods just like we have in our `StrictPath` and `VirtualPath`. The idea was to keep the code nice and consistent, since using `Path` and `PathBuf` are legit in some contexts.

However, I realized **it is far quicker to notice we are using the wrong Path type**. The moment we see old-style code for I/O, it helps ask questions like:

> "Why do we use regular Path here? Is this legit?"

And that's awesome for code review and overall security! 🛡️

## Why This Matters for You

### Human Benefits
- **Code review clarity** - Suspicious patterns are immediately visible
- **Intention signaling** - Method names communicate security guarantees
- **Compile-time safety** - Type system prevents mixing secure and insecure paths

### LLM Agent Benefits
- **Explicit guidance** - Clear documentation prevents misuse
- **Fewer escape hatches** - Limited ways to bypass security
- **Pattern recognition** - Consistent naming helps AI understand correct usage

## Examples of Security-First Design

### ❌ What We Could Have Done (Ergonomic but Dangerous)
```rust
// Hypothetical "ergonomic" design - DON'T DO THIS
let path: StrictPath<_> = boundary.join(user_input)?;  // Generic method
let content = std::fs::read_to_string(path)?;          // Easy to bypass
```

### ✅ What We Actually Do (Explicit and Secure)
```rust
// Actual secure design - explicit and reviewable
let path: StrictPath<_> = boundary.strict_join(user_input)?;  // Clearly strict
let content = path.read_to_string()?;                        // Built-in secure I/O
```

The second example makes it immediately clear:
1. We're operating in strict mode (`strict_join`)
2. We're using built-in secure I/O (no raw `std::fs`)
3. The path type carries security guarantees

## The Result

This design philosophy has proven effective in practice:
- **Reduced vulnerabilities** - Harder to accidentally introduce path traversal
- **Better code reviews** - Security issues are immediately visible  
- **LLM-compatible** - AI agents use the API correctly when following the documentation
- **Human-friendly** - Developers understand the security implications at a glance

Remember: **Security-critical crates should prioritize correctness over ergonomics**. A slightly more verbose API that prevents vulnerabilities is infinitely better than an elegant API that's easy to misuse.