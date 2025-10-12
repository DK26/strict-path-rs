# Best Practices & Guidelines

This page distills how to use strict-path correctly and ergonomically. Pair it with the Anti‑Patterns page for tell‑offs to avoid.

## Why Every "Simple" Solution Fails

The path security rabbit hole is deeper than you think. Here's why every naive approach creates new vulnerabilities:

### Approach 1: "Just check for `../`"
```rust
if path.contains("../") { return Err("Invalid path"); }
// ✅ Blocks: "../../../etc/passwd"
// ❌ Bypassed by: "..%2F..%2F..%2Fetc%2Fpasswd" (URL encoding)
// ❌ Bypassed by: "....//....//etc//passwd" (double encoding)
// ❌ Bypassed by: "..\\..\\..\etc\passwd" (Windows separators)
```

### Approach 2: "Use canonicalize() then check"
```rust
let canonical = fs::canonicalize(path)?;
if !canonical.starts_with("/safe/") { return Err("Escape attempt"); }
// ✅ Blocks: Most directory traversal
// ❌ CVE-2022-21658: Race condition - symlink created between canonicalize and check
// ❌ CVE-2019-9855: Windows 8.3 names ("PROGRA~1" → "Program Files")
// ❌ Fails on non-existent files (can't canonicalize what doesn't exist)
```

### Approach 3: "Normalize the path first"
```rust
let normalized = path.replace("\\", "/").replace("../", "");
// ✅ Blocks: Basic traversal
// ❌ Bypassed by: "....//" → "../" after one replacement
// ❌ CVE-2020-12279: Unicode normalization attacks
// ❌ CVE-2017-17793: NTFS Alternate Data Streams ("file.txt:hidden")
// ❌ Misses absolute path replacement: "/etc/passwd" completely replaces base
```

### Approach 4: "Use a allowlist of safe characters"
```rust
if !path.chars().all(|c| c.is_alphanumeric() || c == '/') { return Err("Invalid"); }
// ✅ Blocks: Most special characters
// ❌ Still vulnerable to: "/etc/passwd" (absolute path replacement)
// ❌ Too restrictive: blocks legitimate files like "report-2025.pdf"
// ❌ CVE-2025-8088: Misses platform-specific issues (Windows UNC, device names)
```

### Approach 5: "Combine multiple checks"
```rust
// Check for ../, canonicalize, validate prefix, sanitize chars...
// ✅ Blocks: Many attack vectors
// ❌ Complex = Buggy: 20+ edge cases, hard to maintain
// ❌ Platform-specific gaps: Windows vs Unix behavior differences  
// ❌ Performance cost: Multiple filesystem calls per validation
// ❌ Future CVEs: New attack vectors require updating every check
```

### The Fundamental Problem
**Each "fix" creates new attack surface.** Path security isn't a single problem—it's a class of problems that interact in complex ways. You need:

1. **Encoding normalization** (but not breaking legitimate files)
2. **Symlink resolution** (but preventing race conditions)  
3. **Platform consistency** (Windows ≠ Unix ≠ Web)
4. **Boundary enforcement** (mathematical, not string-based)
5. **Future-proof design** (resistant to new attack vectors)

**This is why strict-path exists.** We solved this problem class once, correctly, so you don't have to.

## Pick The Right Type

### Quick Decision Guide

- **External/untrusted segments** (HTTP/DB/manifest/LLM/archive entry):
  - UI/virtual flows: start with `VirtualPath::with_root(..).virtual_join(..)` for clamped joins and user‑facing display. For reuse across many joins, keep either the virtual root path value (`let root = VirtualPath::with_root(..)?;`) or a `VirtualRoot` and call `virtual_join(..)` — both take `&self` and return a new `VirtualPath` (no ownership taken).
  - System flows: start with `StrictPath::with_boundary(..).strict_join(..)` to reject unsafe joins and for system display. For reuse across many joins, keep a `PathBoundary` and call `strict_join(..)`.
- **Internal/trusted paths** (hardcoded/CLI/env): use `Path`/`PathBuf`; only validate when combining with untrusted segments.

### Detailed Decision Matrix

| Source                      | Typical Input                  | Use VirtualPath For                       | Use StrictPath For                      | Notes                                                   |
| --------------------------- | ------------------------------ | ----------------------------------------- | --------------------------------------- | ------------------------------------------------------- |
| 🌐 **HTTP requests**         | URL path segments, file names  | Display/logging, safe virtual joins       | System-facing interop/I/O               | Always clamp user paths via `VirtualPath::virtual_join` |
| 🌍 **Web forms**             | Form file fields, route params | User-facing display, UI navigation        | System-facing interop/I/O               | Treat all form inputs as untrusted                      |
| ⚙️ **Configuration files**   | Paths in config                | UI display and I/O within boundary        | System-facing interop/I/O               | Validate each path before I/O                           |
| 💾 **Database content**      | Stored file paths              | Rendering paths in UI dashboards          | System-facing interop/I/O               | Storage does not imply safety; validate on use          |
| 📂 **CLI arguments**         | Command-line path args         | Pretty printing, I/O within boundary      | System-facing interop/I/O               | Validate args before touching filesystem                |
| 🔌 **External APIs**         | Webhooks, 3rd-party payloads   | Present sanitized paths to logs           | System-facing interop/I/O               | Never trust external systems                            |
| 🤖 **LLM/AI output**         | Generated file names/paths     | Display suggestions, I/O within boundary  | System-facing interop/I/O               | LLM output is untrusted by default                      |
| 📨 **Inter-service msgs**    | Queue/event payloads           | Observability output, I/O within boundary | System-facing interop/I/O               | Validate on the consumer side                           |
| 📱 **Apps (desktop/mobile)** | Drag-and-drop, file pickers    | Show picked paths in UI                   | System-facing interop/I/O               | Validate selected paths before I/O                      |
| 📦 **Archive contents**      | Entry names from ZIP/TAR       | N/A (use StrictPath to detect attacks)    | Detect malicious paths, reject archives | Validate each entry; return error on escape attempts    |
| 🔧 **File format internals** | Embedded path strings          | Diagnostics, I/O within boundary          | System-facing interop/I/O               | Never dereference without validation                    |

### Security Philosophy: Detect vs. Contain

**The fundamental distinction is whether path escapes are attacks or expected behavior.**

#### StrictPath — Detect & Reject (Default, 90% of use cases)

**Philosophy**: "If something tries to escape, I want to know about it"

- Returns `Err(PathEscapesBoundary)` when escape is attempted
- Use when path escapes indicate **malicious intent**:
  - 🗜️ **Archive extraction** — detect malicious paths; reject compromised archives
  - 📤 **File uploads** — reject user paths with traversal attempts
  - ⚙️ **Config loading** — fail on untrusted config paths that try to escape
  - 📝 **System resources** — logs, cache, assets with strict boundaries
  - 🔧 **Development tools** — build systems, CLI utilities, single-user apps
  - 🛡️ **Any security boundary** — where escapes are attacks to detect

**No feature required** — always available.

#### VirtualPath — Contain & Redirect (Opt-in, 10% of use cases)

**Philosophy**: "Let things try to escape, but silently contain them"

- Silently clamps/redirects escape attempts within the virtual boundary
- Use when path escapes are **expected but must be controlled**:
  - 🔬 **Malware analysis sandboxes** — observe behavior while containing escapes
  - 🏢 **Multi-tenant systems** — each user sees isolated `/` without real paths
  - 📦 **Container-like plugins** — modules get their own filesystem view
  - 🧪 **Security research** — simulate contained environments for testing
  - 👥 **User content isolation** — when users shouldn't see real system paths

**Requires feature**: Enable `virtual-path` in `Cargo.toml`.

#### Critical Distinction - How Escapes Are Handled

When attempting to access `../../../etc/passwd`:
- **`StrictPath`:** Returns `Err(PathEscapesBoundary)` — application can log, alert, reject
- **`VirtualPath`:** Silently clamps to boundary — escape is contained, not reported

When a symlink points to an absolute path (e.g., `mylink -> /etc/passwd`):
- **`StrictPath`:** Follows symlink and validates target. If outside boundary → **Error**
- **`VirtualPath`:** Treats absolute target as relative to virtual root → **Clamped** to `vroot/etc/passwd`

**Common Mistake**: Using VirtualPath for archive extraction. This **hides attacks** instead of detecting them. Always use StrictPath to detect malicious paths and reject compromised archives.

**The Golden Rule**: If you didn't create the path yourself, secure it first.

## Why Keep `VirtualRoot` and `PathBoundary` (Even With Sugar)

The sugar constructors (`StrictPath::with_boundary(..)`, `VirtualPath::with_root(..)`) are great for simple flows, but the root/boundary types still matter for correctness, reuse, and ergonomics as your code grows.

- Policy reuse and separation of concerns
  - Roots/boundaries represent the security policy (the restriction) while paths represent validated values within that policy.
  - Construct once, reuse everywhere: join many untrusted segments against the same `&PathBoundary`/`&VirtualRoot` without re‑choosing policy.
  - Don’t construct boundaries inside helpers — boundary choice is policy; encoding it at call sites improves reviewability and testing.

- Clear function signatures (stronger guarantees)
  - Two canonical patterns that make intent obvious:
    - Take `&StrictPath<_>` / `&VirtualPath<_>` when the call site has already validated the input.
    - Take `&PathBoundary<_>` / `&VirtualRoot<_>` plus the untrusted segment when the helper performs validation.
  - These signatures prevent helpers from “picking a root” silently and make security rules visible in code review.

- Contextual deserialization (serde)
  - `StrictPath`/`VirtualPath` can’t implement a blanket `Deserialize` safely — they need runtime context (the boundary/root) to validate.
  - The serde seeds live on the context types: `serde_ext::WithBoundary(&boundary)` and `serde_ext::WithVirtualRoot(&vroot)`.
  - This makes deserialization explicit and auditable: where did the policy come from? what are we validating against?

- Interop and trait boundaries
  - We intentionally do not implement `AsRef<Path>` on path types; this prevents leaking raw paths into APIs without review.
  - Roots/boundaries do implement `AsRef<Path>` so you can discover/walk directories at the root while keeping joins validated.
  - Display stays explicit: system display via `strictpath_display()`, virtual display via `virtualpath_display()`.

- OS directories and RAII helpers
  - Discovery helpers (`try_new_os_*`, feature `dirs`) and temporary roots (`try_new_temp*`, feature `tempfile`) are on the root types.
  - Sugar constructors build on these — you can still start simple and “upgrade” to explicit roots when needed.

- Performance and canonicalization
  - Canonicalize the root once; strict/virtual joins reuse that canonicalized state.
  - Virtual joins use anchored canonicalization to apply virtual semantics safely and consistently.

- Auditability and testing
  - Centralizing the policy in a root value simplifies logging, tracing, and tests (e.g., pass `&vroot` into helpers).
  - Debug for `VirtualPath` is intentionally verbose (system path + virtual view + restriction root) to aid audits.

When not to use them: if your flow is small and local, the sugar constructors are perfectly fine. Start with sugar; keep `PathBoundary`/`VirtualRoot` handy for policy reuse, serde, and shared helpers.

## Encode Guarantees In Signatures

- Helpers that touch the filesystem must encode safety:
  - Accept `&StrictPath<_>` or `&VirtualPath<_>` directly, or
  - Accept `&PathBoundary<_>` / `&VirtualRoot<_>` + the untrusted segment.
- Don’t construct boundaries/roots inside helpers — boundary choice is policy.

```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

fn save_to_storage(p: &StrictPath) -> std::io::Result<()> { p.write("ok") }
fn load_from_storage(p: &VirtualPath) -> std::io::Result<String> { p.read_to_string() }

fn create_config(boundary: &PathBoundary, name: &str) -> std::io::Result<()> {
  boundary.strict_join(name)?.write("cfg")
}
```

## Multi‑User Isolation (VirtualPath for Containment)

**Note**: VirtualPath is opt-in via the `virtual-path` feature. Use it when you need **containment** (multi-tenant isolation, sandboxes) rather than **detection** (security boundaries).

- Per‑user/tenant: for small flows, construct a root via `VirtualPath::with_root(..)` and join untrusted names with `virtual_join(..)`. For larger flows and reuse, create a `VirtualRoot` per user and call `virtual_join(..)`.
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
- **StrictPath for production archive extraction** — detect malicious paths, reject compromised archives, alert users
- **VirtualPath for sandbox/research** — safely analyze suspicious archives by containing escapes while observing behavior
- **StrictPath for file uploads to shared storage** — reject attacks at the security boundary
- **StrictPath for config loading** — fail explicitly on untrusted paths that try to escape

The key: use **StrictPath to detect attacks** in production; use **VirtualPath to contain behavior** in research/analysis scenarios.

## Interop & Display

- Interop (pass into `AsRef<Path>` APIs): `path.interop_path()` (no allocations).
- Display:
  - System‑facing: `strictpath_display()` on `PathBoundary`/`StrictPath`
  - User‑facing: `virtualpath_display()` on `VirtualPath`
- Never use `interop_path().to_string_lossy()` for display.

## Directory Discovery vs Validation

- Discovery (walking): call `boundary.read_dir()` (or `vroot.read_dir()`), collect names via `entry.file_name()`, then re‑join with `strict_join`/`virtual_join` to validate before I/O.
- Validation: join those relatives via `boundary.strict_join(..)` or `vroot.virtual_join(..)` before I/O. For small flows without a reusable root, you can construct via `StrictPath::with_boundary(..)` or `VirtualPath::with_root(..)` and then join.
- Don’t validate constants like `"."`; only validate untrusted segments.

## Operations (Use Explicit Methods)

- Joins: `strict_join(..)` / `virtual_join(..)`
- Parents: `strictpath_parent()` / `virtualpath_parent()`
- With file name/ext: `strictpath_with_file_name()` / `virtualpath_with_file_name()`, etc.
- Rename/move: `strict_rename(..)` / `virtual_rename(..)`
- Deletion: `remove_file()` / `remove_dir()` / `remove_dir_all()`
- Metadata: `metadata()` (inspect filesystem info without leaking boundaries)
- Avoid std `Path::join`/`parent` on leaked paths — they ignore strict/virtual semantics.

Example (rename):
```rust
use strict_path::{PathBoundary, StrictPath, VirtualPath};

fn rotate_log(boundary: &PathBoundary) -> std::io::Result<()> {
    let current = boundary.strict_join("logs/app.log")?;
    current.create_parent_dir_all()?;
  current.write("ok")?;

    // Strict rename within same directory
    let rotated = current.strict_rename("logs/app.old")?;
    assert!(rotated.exists());

    // Virtual rename (user-facing path)
    let vp = rotated.clone().virtualize();
    let vp2 = vp.virtual_rename("app.archived")?;
    assert!(vp2.exists());
    Ok(())
}
```

## Naming (from AGENTS.md)

- Variables reflect domain, not type:
  - Good: `config_dir`, `uploads_root`, `archive_src`, `mirror_src`, `user_vroot`
  - Bad: `boundary`, `jail`, `source_` prefix
- Keep names consistent with the directory they represent (e.g., `archive_src` for `./archive_src`).

## Do / Don’t

- Do: validate once at the boundary, pass types through helpers.
- Do: use `VirtualRoot` for per‑user isolation; borrow strict view for shared helpers.
- Do: prefer `impl AsRef<Path>` in helper params where you forward to validation.
- Don’t: wrap secure types in `Path::new`/`PathBuf::from`.
- Don’t: use `interop_path().as_ref()` or `as_unvirtual().interop_path()` (use `interop_path()` directly).
- Don’t: use lossy strings for display or comparisons.

## Testing & Doctests

- Make doctests encode guarantees (signatures) and use the explicit ops.
- Create temporary roots via `PathBoundary::try_new_create(..)` / `VirtualRoot::try_new_create(..)` in setup; clean up afterwards. Or use the sugar constructors for tests: `StrictPath::with_boundary_create(..)` / `VirtualPath::with_root_create(..)`.
- For archive/HTTP examples, prefer offline simulations with deterministic inputs.

## Quick Patterns

- Validate + write:
```rust
fn write(boundary: &PathBoundary, name: &str, data: &[u8]) -> std::io::Result<()> {
    let sp = boundary.strict_join(name)?;
    sp.create_parent_dir_all()?;
    sp.write(data)
}
```

- Validate archive entry:
```rust
fn extract(vroot: &VirtualRoot, entry: &str, data: &[u8]) -> std::io::Result<()> {
    let vp = vroot.virtual_join(entry)?;
    vp.create_parent_dir_all()?;
    vp.write(data)
}
```

## Ergonomics Cheatsheet

- Built-in I/O: prefer `StrictPath`/`VirtualPath` methods over exposing raw `Path`
- Interop: use `interop_path()` when passing into `AsRef<Path>` APIs (no allocations)
- Avoid anti-patterns: never wrap secure types in `Path::new()` / `PathBuf::from()`
- Function signatures: encode policy via marker types in `StrictPath<MyMarker>` / `VirtualPath<MyMarker>`
- Equality/ordering: rely on the types’ derived semantics; don’t convert to strings for comparison
- Escape hatch (borrow): `as_unvirtual()`; ownership conversions: `virtualize()` / `unvirtual()` / `unstrict()` (use sparingly)

- Share logic across strict/virtual:
```rust
fn consume_strict(p: &StrictPath) -> std::io::Result<String> { p.read_to_string() }
fn consume_virtual(p: &VirtualPath) -> std::io::Result<String> { consume_strict(p.as_unvirtual()) }
```

See the dedicated Ergonomics section for deeper guidance:
- Overview: ./ergonomics/overview.md
- Interop vs Display: ./ergonomics/interop_display.md
- Function Signatures: ./ergonomics/signatures.md
- Escape Hatches: ./ergonomics/escape_hatches.md
- Equality & Ordering: ./ergonomics/equality_ordering.md
- Naming: ./ergonomics/naming.md
