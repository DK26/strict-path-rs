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
  - UI/virtual flows: `VirtualRoot` + `VirtualPath` (clamped joins, user‑facing display)
  - System flows: `PathBoundary` + `StrictPath` (rejected joins, system display)
- **Internal/trusted paths** (hardcoded/CLI/env): use `Path`/`PathBuf`; only validate when combining with untrusted segments.

### Detailed Decision Matrix

| Source                      | Typical Input                  | Use VirtualPath For                       | Use StrictPath For        | Notes                                                   |
| --------------------------- | ------------------------------ | ----------------------------------------- | ------------------------- | ------------------------------------------------------- |
| 🌐 **HTTP requests**         | URL path segments, file names  | Display/logging, safe virtual joins       | System-facing interop/I/O | Always clamp user paths via `VirtualRoot::virtual_join` |
| 🌍 **Web forms**             | Form file fields, route params | User-facing display, UI navigation        | System-facing interop/I/O | Treat all form inputs as untrusted                      |
| ⚙️ **Configuration files**   | Paths in config                | UI display and I/O within boundary        | System-facing interop/I/O | Validate each path before I/O                           |
| 💾 **Database content**      | Stored file paths              | Rendering paths in UI dashboards          | System-facing interop/I/O | Storage does not imply safety; validate on use          |
| 📂 **CLI arguments**         | Command-line path args         | Pretty printing, I/O within boundary      | System-facing interop/I/O | Validate args before touching filesystem                |
| 🔌 **External APIs**         | Webhooks, 3rd-party payloads   | Present sanitized paths to logs           | System-facing interop/I/O | Never trust external systems                            |
| 🤖 **LLM/AI output**         | Generated file names/paths     | Display suggestions, I/O within boundary  | System-facing interop/I/O | LLM output is untrusted by default                      |
| 📨 **Inter-service msgs**    | Queue/event payloads           | Observability output, I/O within boundary | System-facing interop/I/O | Validate on the consumer side                           |
| 📱 **Apps (desktop/mobile)** | Drag-and-drop, file pickers    | Show picked paths in UI                   | System-facing interop/I/O | Validate selected paths before I/O                      |
| 📦 **Archive contents**      | Entry names from ZIP/TAR       | Progress UI, virtual joins                | System-facing interop/I/O | Validate each entry to block zip-slip                   |
| 🔧 **File format internals** | Embedded path strings          | Diagnostics, I/O within boundary          | System-facing interop/I/O | Never dereference without validation                    |

### Security Philosophy

**Think of it this way:**
- `StrictPath` = **Security Filter** — validates and rejects unsafe paths
- `VirtualPath` = **Complete Sandbox** — clamps any input to stay safe

**The Golden Rule**: If you didn't create the path yourself, secure it first.

## Encode Guarantees In Signatures

- Helpers that touch the filesystem must encode safety:
  - Accept `&StrictPath<_>` or `&VirtualPath<_>` directly, or
  - Accept `&PathBoundary<_>` / `&VirtualRoot<_>` + the untrusted segment.
- Don’t construct boundaries/roots inside helpers — boundary choice is policy.

```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

fn save_to_storage(p: &StrictPath) -> std::io::Result<()> { p.write_string("ok") }
fn load_from_storage(p: &VirtualPath) -> std::io::Result<String> { p.read_to_string() }

fn create_config(boundary: &PathBoundary, name: &str) -> std::io::Result<()> {
    boundary.strict_join(name)?.write_string("cfg")
}
```

## Multi‑User Isolation (VirtualRoot)

- Per‑user/tenant: create a `VirtualRoot` per user and join untrusted names with `virtual_join`.
- Share strict helpers by borrowing the strict view: `vpath.as_unvirtual()`.

```rust
fn upload(user_root: &VirtualRoot, filename: &str, bytes: &[u8]) -> std::io::Result<()> {
    let vpath = user_root.virtual_join(filename)?;
    vpath.create_parent_dir_all()?;
    vpath.write_bytes(bytes)
}
```

## Interop & Display

- Interop (pass into `AsRef<Path>` APIs): `path.interop_path()` (no allocations).
- Display:
  - System‑facing: `strictpath_display()` on `PathBoundary`/`StrictPath`
  - User‑facing: `virtualpath_display()` on `VirtualPath`
- Never use `interop_path().to_string_lossy()` for display.

## Directory Discovery vs Validation

- Discovery (walking): call `read_dir(boundary.interop_path())` and `strip_prefix(boundary.interop_path())` to get relatives.
- Validation: join those relatives via `boundary.strict_join(..)` or `vroot.virtual_join(..)` before I/O.
- Don’t validate constants like `"."`; only validate untrusted segments.

## Operations (Use Explicit Methods)

- Joins: `strict_join(..)` / `virtual_join(..)`
- Parents: `strictpath_parent()` / `virtualpath_parent()`
- With file name/ext: `strictpath_with_file_name()` / `virtualpath_with_file_name()`, etc.
- Avoid std `Path::join`/`parent` on leaked paths — they ignore strict/virtual semantics.

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
- Create temporary roots via `PathBoundary::try_new_create(..)` / `VirtualRoot::try_new_create(..)` in setup; clean up afterwards.
- For archive/HTTP examples, prefer offline simulations with deterministic inputs.

## Quick Patterns

- Validate + write:
```rust
fn write(boundary: &PathBoundary, name: &str, data: &[u8]) -> std::io::Result<()> {
    let sp = boundary.strict_join(name)?;
    sp.create_parent_dir_all()?;
    sp.write_bytes(data)
}
```

- Validate archive entry:
```rust
fn extract(vroot: &VirtualRoot, entry: &str, data: &[u8]) -> std::io::Result<()> {
    let vp = vroot.virtual_join(entry)?;
    vp.create_parent_dir_all()?;
    vp.write_bytes(data)
}
```

- Share logic across strict/virtual:
```rust
fn consume_strict(p: &StrictPath) -> std::io::Result<String> { p.read_to_string() }
fn consume_virtual(p: &VirtualPath) -> std::io::Result<String> { consume_strict(p.as_unvirtual()) }
```
