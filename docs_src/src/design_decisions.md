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

---

## Comparison with Alternatives

Understanding how `strict-path` compares to other path-handling solutions helps you choose the right tool for your needs.

### strict-path vs soft-canonicalize

`soft-canonicalize` is the foundation that `strict-path` builds upon. Think of it as the difference between a low-level graphics library and a game engine.

| Feature                  | `strict-path`                                                             | `soft-canonicalize`                                     |
| ------------------------ | ------------------------------------------------------------------------- | ------------------------------------------------------- |
| **Level**                | High-level security API                                                   | Low-level path resolution                               |
| **Purpose**              | Enforce boundaries + authorization                                        | Normalize & canonicalize paths                          |
| **Returns**              | `StrictPath<Marker>` / `VirtualPath<Marker>` with compile-time guarantees | `PathBuf`                                               |
| **I/O operations**       | Complete filesystem API (read, write, rename, copy, etc.)                 | Not included (just path resolution)                     |
| **Boundary enforcement** | Built-in: `strict_join()` / `virtual_join()` validate against boundaries  | Manual: you implement checks yourself                   |
| **Authorization**        | Compile-time marker proofs (type system verifies auth)                    | Not applicable                                          |
| **Use case**             | Application-level security (validate external paths, enforce policies)    | Building custom path security logic                     |
| **Complexity**           | High-level, opinionated (fewer decisions to make)                         | Low-level, flexible (more control, more responsibility) |

**When to use `strict-path`:**
- ✅ You need comprehensive path security out of the box
- ✅ You want compile-time guarantees about path boundaries
- ✅ You're validating paths from external sources (HTTP, CLI, LLM, config)
- ✅ You want authorization encoded in types
- ✅ You prefer opinionated security over custom logic

**When to use `soft-canonicalize`:**
- ✅ You're building custom path security abstractions
- ✅ You need just canonicalization without boundary enforcement
- ✅ You want maximum flexibility to design your own security model
- ✅ You're implementing path comparison/deduplication logic
- ✅ You need canonicalization for non-existing paths

**Example: The Relationship**

```rust
// soft-canonicalize: low-level resolution
use soft_canonicalize::soft_canonicalize;
let resolved = soft_canonicalize("config/../data/file.txt")?;
// You get: PathBuf - now manually check if it's within bounds

// strict-path: high-level security (uses soft-canonicalize internally)
use strict_path::StrictPath;
let safe_path = StrictPath::with_boundary("data")?
    .strict_join("../file.txt")?;  // Returns Err if outside "data"
safe_path.read_to_string()?;       // Built-in secure I/O
```

---

### strict-path vs path_absolutize

`path_absolutize` offers different security philosophies. Understanding these differences is critical for choosing the right approach.

| Feature                | `strict-path`                                                                                      | `path_absolutize::absolutize_virtually`                                |
| ---------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **Escape handling**    | **StrictPath:** Returns `Err(PathEscapesBoundary)`<br>**VirtualPath:** Silently clamps to boundary | Returns `Err` on escape attempts (rejection model only)                |
| **Symlink resolution** | **Full filesystem-based** - Follows symlinks, resolves targets                                     | **Lexical only** - Does NOT follow symlinks (faster but less accurate) |
| **Security model**     | **Two modes:**<br>1. Detect escapes (StrictPath)<br>2. Contain escapes (VirtualPath)               | **One mode:** Reject invalid paths                                     |
| **Canonicalization**   | Full canonicalization (resolves `.`, `..`, symlinks, Windows short names)                          | Lexical normalization (string manipulation, no filesystem I/O)         |
| **Authorization**      | Compile-time marker proofs                                                                         | Not applicable                                                         |
| **I/O operations**     | Complete built-in API                                                                              | Not included                                                           |
| **Use when**           | Security boundaries where symlinks exist or accuracy is critical                                   | Performance-critical paths where symlinks are guaranteed not to exist  |

**Critical Distinction: Symlink Behavior**

The symlink handling difference is **security-critical**:

```rust
// Setup: Create symlink that escapes boundary
// /safe/link -> /etc/passwd

// path_absolutize (lexical only - DANGEROUS if symlinks exist):
use path_absolutize::Absolutize;
let abs = Path::new("/safe/link").absolutize_virtually("/safe")?;
// Result: /safe/link (string looks safe, but symlink escapes!)
// Reading this symlink gives you /etc/passwd content!

// strict-path StrictPath (filesystem-based - SAFE):
use strict_path::PathBoundary;
let boundary = PathBoundary::try_new("/safe")?;
let validated = boundary.strict_join("link")?;  // Follows symlink, sees target is /etc/passwd
// Result: Err(PathEscapesBoundary) - attack detected!

// strict-path VirtualPath (filesystem-based with clamping):
use strict_path::VirtualRoot;
let vroot = VirtualRoot::try_new("/safe")?;
let contained = vroot.virtual_join("link")?;  // Follows symlink, clamps target to /safe/etc/passwd
// Result: Ok - target rewritten to stay within boundary, user sees "/etc/passwd" in virtual space
```

**When lexical (path_absolutize) is safe:**
- ✅ You can **guarantee** no symlinks exist in your paths
- ✅ Performance is critical and you've validated the environment
- ✅ You control all path creation (e.g., build artifacts, codegen)

**When filesystem-based (strict-path) is required:**
- ✅ Any possibility of symlinks existing
- ✅ Handling user-provided paths (HTTP, CLI, config, archives)
- ✅ Security is more important than performance
- ✅ You need to detect attacks (escapes are malicious)
- ✅ You need to contain escapes (multi-tenant isolation)

**Performance vs Security Trade-off:**

- **Lexical resolution (path_absolutize):** ~10-100x faster (no filesystem I/O), but vulnerable to symlink attacks
- **Filesystem-based (strict-path):** Slower (requires stat calls), but mathematically secure against symlink escapes

**Which One Should You Use?**

Ask yourself: **"Can I guarantee no symlinks will ever exist in these paths?"**

- **No / Not sure** → Use `strict-path` (security over performance)
- **Yes, absolutely certain** → Consider `path_absolutize` (performance)
- **Need to detect attacks** → Use `strict-path` with `StrictPath`
- **Need to contain escapes** → Use `strict-path` with `VirtualPath` (unique to this crate)

---

### Decision Matrix: Choosing the Right Tool

| Scenario                                | Choose                                   | Rationale                                                   |
| --------------------------------------- | ---------------------------------------- | ----------------------------------------------------------- |
| Web server serving user-requested files | `strict-path` (StrictPath)               | Symlinks may exist, escapes are attacks                     |
| LLM agent file operations               | `strict-path` (StrictPath)               | AI-generated paths are untrusted, need boundary enforcement |
| Archive extraction (Zip, TAR)           | `strict-path` (StrictPath)               | Archives may contain malicious symlinks (Zip Slip attacks)  |
| Multi-tenant cloud storage              | `strict-path` (VirtualPath)              | Each user needs isolated virtual filesystem                 |
| Build system artifacts                  | `path_absolutize` OR `soft-canonicalize` | You control creation, no symlinks, performance matters      |
| Custom security abstractions            | `soft-canonicalize`                      | Build your own policy on stable foundation                  |
| Path comparison/deduplication           | `soft-canonicalize`                      | Just need canonicalization, no boundary enforcement         |

**Bottom Line:**

- **Need high-level security?** → `strict-path`
- **Need low-level building blocks?** → `soft-canonicalize`
- **Need fast lexical paths in controlled environments?** → `path_absolutize` (but be careful!)
- **Not sure?** → Start with `strict-path` and optimize later if needed