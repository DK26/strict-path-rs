# Best Practices & Guidelines

> *Your complete guide to using strict-path correctly and ergonomically.*

This page provides the **essential decision matrices, core principles, and quick references** for daily use. For deeper dives, we've split detailed content into focused chaptersâ€”each covering a single topic so you can digest one concept at a time.

---

## ðŸ“š Focused Chapters (Deep Dives)

For detailed explanations and comprehensive examples, see these focused chapters:

- **[Why Naive Approaches Fail â†’](./best_practices/why_naive_approaches_fail.md)** - The 5 broken approaches and why path security is hard
- **[Real-World Patterns â†’](./best_practices/real_world_patterns.md)** - Production-ready examples you can copy-paste (LLM agents, archives, web servers, config, multi-tenant)
- **[Common Operations â†’](./best_practices/common_operations.md)** - Complete reference for joins, parents, renames, deletion, metadata, copy operations
- **[Policy & Reuse â†’](./best_practices/policy_and_reuse.md)** - When to use VirtualRoot/PathBoundary types vs sugar constructors (performance, testing, serde)
- **[Authorization Architecture â†’](./best_practices/authorization_architecture.md)** - Compile-time authorization with marker types (basic auth, permissions, dynamic elevation)

**Start here for fundamentals, then jump to focused chapters when you need details.**

---

## Why strict-path Exists (TL;DR)

**Path security isn't one problemâ€”it's a class of interacting problems.** Every "simple" approach (check for `../`, canonicalize then check, normalize, allowlist chars, combine checks) creates new attack surface:
- Encoding bypasses (URL encoding, double encoding, Unicode normalization)
- Race conditions (TOCTOU with symlinks: CVE-2022-21658)
- Platform gaps (Windows 8.3 names, UNC paths, ADS: CVE-2019-9855, CVE-2017-17793)
- Performance costs (repeated filesystem calls)
- Future CVEs (new attack vectors require updating every check)

**strict-path solved this problem class once, correctly, so you don't have to.**

â†’ **[Full analysis with CVE examples â†’](./best_practices/why_naive_approaches_fail.md)**

---

## Pick The Right Type (Quick Reference)

### 30-Second Decision Guide

**External/untrusted segments** (HTTP, DB, manifests, LLM output, archive entries):
- **Detection (90% of cases):** `StrictPath::with_boundary(..).strict_join(..)` â€” detects escapes, rejects attacks
- **Containment (10% of cases):** `VirtualPath::with_root(..).virtual_join(..)` â€” silently clamps escapes, isolates users

**Internal/trusted paths** (hardcoded, CLI, env): Use `Path`/`PathBuf`; only validate when combining with untrusted segments.

**For policy reuse across many joins:** Keep a `PathBoundary` or `VirtualRoot` and call `strict_join(..)`/`virtual_join(..)` repeatedly.

### Decision Matrix by Source

| Source                  | Typical Input             | Default Choice            | Notes                                                 |
| ----------------------- | ------------------------- | ------------------------- | ----------------------------------------------------- |
| ðŸŒ **HTTP/Web**          | URL segments, form fields | VirtualPath or StrictPath | VirtualPath for UI display, StrictPath for system I/O |
| âš™ï¸ **Config/DB**         | Paths in config/database  | StrictPath                | Storage â‰  safety; validate on use                     |
| ðŸ“‚ **CLI/External APIs** | Args, webhooks, payloads  | StrictPath                | Never trust external input                            |
| ðŸ¤– **LLM/AI**            | Generated paths/filenames | StrictPath                | LLM output is untrusted by default                    |
| ðŸ“¦ **Archives**          | ZIP/TAR entry names       | **StrictPath ONLY**       | Detect malicious paths, reject bad archives           |
| ðŸ¢ **Multi-tenant**      | Per-user file operations  | VirtualPath               | Isolate users with virtual roots                      |

### Security Philosophy: Detect vs. Contain

**The fundamental distinction: Are path escapes attacks or expected behavior?**

#### StrictPath â€” Detect & Reject (Default, 90%)

- **Philosophy**: "If it tries to escape, I want to know"
- **Returns:** `Err(PathEscapesBoundary)` on escape attempts
- **Use for:** Archives, file uploads, config loading, security boundaries
- **Always available** (no feature flag)

#### VirtualPath â€” Contain & Redirect (Opt-in, 10%)

- **Philosophy**: "Let it try to escape, but silently contain it"
- **Behavior:** Silently clamps escapes within boundary
- **Use for:** Multi-tenant systems, malware sandboxes, security research, user isolation
- **Requires:** `virtual-path` feature in `Cargo.toml`

#### How They Differ

Attempting `../../../etc/passwd`:
- **StrictPath**: `Err(PathEscapesBoundary)` â†’ log, alert, reject
- **VirtualPath**: Silently clamped to boundary â†’ contained, not reported

Symlink to `/etc/passwd`:
- **StrictPath**: Follows, validates target â†’ **Error** if outside boundary
- **VirtualPath**: Treats as relative â†’ clamped to `vroot/etc/passwd`

**Critical Rule**: Use **StrictPath for archives** to detect attacks. VirtualPath hides them.

**Golden Rule**: If you didn't create the path yourself, secure it first.

â†’ **[Full comparison with examples â†’](./best_practices/real_world_patterns.md#archive-extraction-detect-vs-contain)**

---

## When to Use Policy Types vs. Sugar

**Sugar constructors** (`StrictPath::with_boundary(..)`, `VirtualPath::with_root(..)`) are great for simple, one-off operations.

**Policy types** (`PathBoundary`, `VirtualRoot`) matter when you need:
- **Policy reuse** (canonicalize once, join many times)
- **Performance** (1 canonicalization vs 1000 in loops)
- **Testability** (inject test boundaries)
- **Serde integration** (contextual deserialization)
- **Clear signatures** (encode guarantees in types)

**Quick Example:**
```rust
use strict_path::PathBoundary;

// âŒ SLOW: 1000 canonicalizations
for name in files {
    let boundary = PathBoundary::try_new(base)?;
    boundary.strict_join(name)?;
}

// âœ… FAST: 1 canonicalization
let boundary = PathBoundary::try_new(base)?;
for name in files {
    boundary.strict_join(name)?; // Reuses canonical state
}
```

**Rule of thumb**: Start with sugar; upgrade to policy types when you need reuse, performance, or testing.

â†’ **[Full guide with benchmarks, serde patterns, and testing examples â†’](./best_practices/policy_and_reuse.md)**

---

## Encode Guarantees In Function Signatures

Helpers that touch the filesystem must encode safety in their signatures:

**Two canonical patterns:**
1. **Accept validated path** when validation already happened: `fn save(p: &StrictPath) -> io::Result<()>`
2. **Accept boundary + segment** when validation happens inside: `fn load(b: &PathBoundary, name: &str) -> io::Result<String>`

**Don't construct boundaries/roots inside helpers** â€” boundary choice is policy; make it explicit at call sites.

â†’ **[Full patterns with examples â†’](./best_practices/policy_and_reuse.md#clear-function-signatures-stronger-guarantees)**

---

## Multiâ€‘User Isolation (VirtualPath)

**VirtualPath** (opt-in via `virtual-path` feature) is for **containment scenarios**: multi-tenant systems, malware sandboxes, security research.

- **Per-user**: Create `VirtualRoot` per user, call `virtual_join(..)` for all operations
- **Share helpers**: Borrow strict view with `vpath.as_unvirtual()`
- **Use for**: Multi-tenant isolation, observing malicious behavior safely

**NOT for**: Archive extraction (use StrictPath to detect attacks, not hide them)

â†’ **[Full multi-tenant example â†’](./best_practices/real_world_patterns.md#multi-tenant-cloud-storage)**

---

## Interop & Display

**Interop** (pass to `AsRef<Path>` APIs): `path.interop_path()` â€” no allocations

**Display:**
- System paths: `strictpath_display()` on `PathBoundary`/`StrictPath`
- User-facing: `virtualpath_display()` on `VirtualPath`

**Never**: `interop_path().to_string_lossy()` for display

---

## Directory Discovery vs Validation

**Discovery** (walking): Use `.read_dir()`, collect names via `entry.file_name()`

**Validation**: Re-join discovered names through `strict_join`/`virtual_join` before I/O

```rust
for entry in boundary.read_dir()? {
    let name = entry?.file_name();
    let validated = boundary.strict_join(&name.to_string_lossy())?; // Validate!
    // Now safe to use validated path
}
```

**Don't validate constants** like `"."` â€” only validate untrusted segments.

---

## Multiâ€‘User Isolation (VirtualPath for Containment)

**Note**: VirtualPath is opt-in via the `virtual-path` feature. Use it when you need **containment** (multi-tenant isolation, sandboxes) rather than **detection** (security boundaries).

- Perâ€‘user/tenant: for small flows, construct a root via `VirtualPath::with_root(..)` and join untrusted names with `virtual_join(..)`. For larger flows and reuse, create a `VirtualRoot` per user and call `virtual_join(..)`.
- Share strict helpers by borrowing the strict view: `vpath.as_unvirtual()`.

```rust
fn upload(user_root: &VirtualRoot, filename: &str, bytes: &[u8]) -> std::io::Result<()> {
  let vpath = user_root.virtual_join(filename)?;
  vpath.create_parent_dir_all()?;
  vpath.write(bytes)
}

// Sugar-first call site (one-off):
// let vroot = VirtualPath::with_root(format!("./cloud/user_{user_id}"))?;
// let vpath = vroot.virtual_join(filename)?; // same guarantees; keep VirtualRoot for reuse
```

**When to use each for archives**:
- **StrictPath for production archive extraction** â€” detect malicious paths, reject compromised archives, alert users
- **VirtualPath for sandbox/research** â€” safely analyze suspicious archives by containing escapes while observing behavior
- **StrictPath for file uploads to shared storage** â€” reject attacks at the security boundary
- **StrictPath for config loading** â€” fail explicitly on untrusted paths that try to escape

The key: use **StrictPath to detect attacks** in production; use **VirtualPath to contain behavior** in research/analysis scenarios.

## Interop & Display

- Interop (pass into `AsRef<Path>` APIs): `path.interop_path()` (no allocations).
- Display:
  - Systemâ€‘facing: `strictpath_display()` on `PathBoundary`/`StrictPath`
  - Userâ€‘facing: `virtualpath_display()` on `VirtualPath`
- Never use `interop_path().to_string_lossy()` for display.

## Directory Discovery vs Validation

- Discovery (walking): call `boundary.read_dir()` (or `vroot.read_dir()`), collect names via `entry.file_name()`, then reâ€‘join with `strict_join`/`virtual_join` to validate before I/O.
- Validation: join those relatives via `boundary.strict_join(..)` or `vroot.virtual_join(..)` before I/O. For small flows without a reusable root, you can construct via `StrictPath::with_boundary(..)` or `VirtualPath::with_root(..)` and then join.
- Donâ€™t validate constants like `"."`; only validate untrusted segments.

## Common Operations (Quick Reference)

Always use **dimension-specific methods** (`strict_*` / `virtualpath_*`). Never use `std::path` methods on leaked paths.

**Available operations:**
- **Joins**: `strict_join(..)` / `virtual_join(..)` â€” validate and combine paths
- **Parents**: `strictpath_parent()` / `virtualpath_parent()` â€” navigate up directory tree
- **Filenames**: `strictpath_with_file_name(..)` / `strictpath_with_extension(..)` â€” modify names/extensions
- **Rename**: `strict_rename(..)` / `virtual_rename(..)` â€” move/rename within boundary
- **Deletion**: `.remove_file()`, `.remove_dir()`, `.remove_dir_all()` â€” safe deletion
- **Metadata**: `.metadata()`, `.exists()`, `.is_file()`, `.is_dir()` â€” inspect properties
- **Copy**: `.copy(&dest)` â€” duplicate files
- **I/O**: `.read()`, `.read_to_string()`, `.write()`, `.create_file()` â€” file operations

â†’ **[Complete operations guide with examples â†’](./best_practices/common_operations.md)**

## Naming Conventions

**Variables reflect domain, not type:**
- âœ… Good: `config_dir`, `uploads_root`, `archive_src`, `tenant_vroot`
- âŒ Bad: `boundary`, `jail`, `source_` prefix, `_path` suffix

**Keep names consistent** with the directory they represent.

---

## Do / Donâ€™t

- Do: validate once at the boundary, pass types through helpers.
- Do: use `VirtualRoot` for perâ€‘user isolation; borrow strict view for shared helpers.
- Do: prefer `impl AsRef<Path>` in helper params where you forward to validation.
- Donâ€™t: wrap secure types in `Path::new`/`PathBuf::from`.
- Donâ€™t: use `interop_path().as_ref()` or `as_unvirtual().interop_path()` (use `interop_path()` directly).
- Donâ€™t: use lossy strings for display or comparisons.

## Testing & Doctests

- Encode guarantees in function signatures
- Use `*_create` constructors for temp directories in tests
- Prefer offline simulations with deterministic inputs
- Clean up test directories after tests

---

## Learn More

All detailed content has been moved to focused chapters for digestibility:

**Core Concepts:**
- **[Why Naive Approaches Fail â†’](./best_practices/why_naive_approaches_fail.md)** - 5 broken approaches with CVE examples
- **[Real-World Patterns â†’](./best_practices/real_world_patterns.md)** - Production-ready examples:
  - LLM Agent File Manager
  - Archive Extraction (detect vs contain patterns)
  - Web File Server with marker types
  - Configuration Manager
  - Multi-Tenant Cloud Storage

**Practical Guides:**
- **[Common Operations â†’](./best_practices/common_operations.md)** - Complete reference for joins, parents, rename, delete, metadata, copy
- **[Policy & Reuse â†’](./best_practices/policy_and_reuse.md)** - When to use VirtualRoot/PathBoundary vs sugar (performance, testing, serde)

**Advanced Topics:**
- **[Authorization Architecture â†’](./best_practices/authorization_architecture.md)** - Compile-time authorization with marker types

---

## Quick Reference Card

### Type Selection (30 seconds)

| Input Source           | Default Choice | Notes                               |
| ---------------------- | -------------- | ----------------------------------- |
| HTTP/Web/LLM/Archives  | `StrictPath`   | Detect attacks, reject bad input    |
| Multi-tenant isolation | `VirtualPath`  | Contain per-user, clean UI paths    |
| Trusted/hardcoded      | `Path/PathBuf` | Only validate when mixing untrusted |

### Sugar vs Policy Types

| Need                     | Use                                          |
| ------------------------ | -------------------------------------------- |
| One-off operation        | Sugar: `with_boundary(..)` / `with_root(..)` |
| Reuse, performance, test | Policy: `PathBoundary` / `VirtualRoot`       |

### Core Operations

```rust
// Validate
let file = boundary.strict_join("path")?;

// I/O
file.write(b"data")?;
let content = file.read_to_string()?;

// Metadata
if file.exists() && file.metadata()?.len() > 0 { }

// Rename/Move
let renamed = file.strict_rename("newpath")?;

// Display
println!("System: {}", file.strictpath_display());
println!("User: {}", vpath.virtualpath_display()); // VirtualPath only
```

### Do / Don't Checklist

âœ… **DO:**
- Validate untrusted segments before I/O
- Pass `&StrictPath` / `&VirtualPath` to encode guarantees
- Use dimension-specific methods (`strict_*` / `virtualpath_*`)
- Call `interop_path()` only for `AsRef<Path>` APIs
- Name variables by domain (`uploads_root`, `config_dir`)

âŒ **DON'T:**
- Wrap secure types in `Path::new()` / `PathBuf::from()`
- Use `std::path` methods on leaked paths
- Use `interop_path()` for display (use `*_display()`)
- Construct boundaries inside helpers
- Validate constants like `"."` (only untrusted segments)

---

## Anti-Patterns Reference

For detailed anti-patterns and fixes, see: **[Anti-Patterns Guide â†’](../anti_patterns.md)**

---

That's it! This page is your quick reference. Dive into the focused chapters when you need details.

For source-level API documentation: **[API Reference (strict-path crate docs) â†’](../../strict_path/index.html)**
