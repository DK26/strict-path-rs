# strict-path — LLM Context

**Handle paths from external or unknown sources securely.** Uses Rust's type system to mathematically prove paths stay within defined boundaries—no escapes, symlinks included. API is minimal, restrictive, and explicit to prevent human and LLM API misuse.

This document provides a "Context7" style explanation on how to use this crate (fewer tokens than LLM_CONTEXT_FULL.md).

- Core types: `PathBoundary<Marker>`, `StrictPath<Marker>`; with feature `virtual-path`: `VirtualRoot<Marker>`, `VirtualPath<Marker>`.
- Golden rule: "Restrict every external path." Validate user/LLM/config/archive input using `strict_join` or `virtual_join` before touching the filesystem.
- Interop vs display: use `.interop_path()` only for third‑party APIs requiring `AsRef<Path>`; use `*_display()` for human‑readable output.
- Trade‑off: Security > performance. Verifies paths on disk and follows symlinks. For symlink‑free + max performance, consider lexical solutions.
- Built on `soft-canonicalize` + `proc-canonicalize` (Linux container realpath support). Full walkthrough: **[mdBook Guide](https://dk26.github.io/strict-path-rs/)**

**🚨 CRITICAL for LLM code generation:**
- NEVER validate hardcoded string literals — this defeats the entire purpose of the crate
- ALWAYS use variable names that clearly show untrusted input: `user_input`, `requested_file`, `attack_input`
- AVOID generic names like `filename`, `path`, `name` — they hide security intent
- Include comments showing input source: `// User input from HTTP request, CLI args, etc.`

## Install

```toml
[dependencies]
strict-path = "*"
# Virtual sandboxes (optional)
# strict-path = { version = "*", features = ["virtual-path"] }
```

## Choose your mode

- StrictPath (default, 90% cases): Detects escape attempts. Best for archive extraction, config loading, shared system areas, file uploads to shared storage (admin panels, CMS assets).
- VirtualPath (opt‑in): Clamps escape attempts within a virtual root. Best for multi‑tenant file uploads (SaaS per‑user storage), per‑user sandboxes, malware analysis.

## Quickstart

Strict (detect & reject):
```rust
use strict_path::{PathBoundary, StrictPath};

let uploads: PathBoundary = PathBoundary::try_new_create("./uploads")?;
let username = "alice";
let avatar: StrictPath = uploads.strict_join(format!("users/{username}/avatar.png"))?;
avatar.create_parent_dir_all()?;
avatar.write(b"<png>")?;
println!("stored: {}", avatar.strictpath_display());
```

Virtual (contain & clamp) — requires feature `virtual-path`:
```rust
use strict_path::VirtualPath;

let user_root: VirtualPath = VirtualPath::with_root_create("tenants/acme/alice")?;
let doc: VirtualPath = user_root.virtual_join("../../etc/passwd")?; // "/etc/passwd"
doc.create_parent_dir_all()?;
doc.write(b"hello")?;
println!("user sees: {}", doc.virtualpath_display());
```

## Contract (what this guarantees)

- Inputs: Untrusted segments (user/LLM/CLI/config/archive).
- Output: `StrictPath<T>`/`VirtualPath<T>` that cannot escape their boundary/root.
- I/O: Use built‑ins (`read`, `write`, `create_dir_all`, `metadata`, etc.) safely on these types.
- Errors (`StrictPathError`):
  - `InvalidRestriction` — boundary/root cannot be created or is invalid
  - `PathResolutionError` — resolution/canonicalization failure
  - `PathEscapesBoundary` — attempted traversal or symlink/junction escape

## Do / Don't

- Do: `boundary.strict_join(user_input)` or `vroot.virtual_join(user_input)`.
- Do: pass `&StrictPath<_>`/`&VirtualPath<_>` into helpers; or pass policy roots + segment.
- Do: use `*_display()` for users; `.interop_path()` only for `AsRef<Path>` adapters.
- Do: use variable names that clearly show untrusted input: `user_input`, `requested_file`, `attack_input`, `uploaded_data`.
- Don't: wrap `.interop_path()` in `Path::new()` or `PathBuf::from()` — it's already `AsRef<Path>`.
- Don't: use std path operations (`Path::join`, `Path::parent`) on untrusted input — use `.strict_join()` instead.
- Don't: Construct boundaries/roots inside helpers; inject policy via parameters.
- Don't: use generic variable names like `filename`, `path`, `name` that hide the fact you're validating untrusted input.

## Quick recipes

- File uploads to shared storage (Strict) — admin panels, CMS, single-tenant:
```rust
let uploads = PathBoundary::try_new_create("./uploads")?;
let file = uploads.strict_join(filename)?; // traversal ⇒ error
file.create_parent_dir_all()?;
file.write(bytes)?;
```

- Multi-tenant file uploads (Virtual) — SaaS per-user storage:
```rust
let vroot = strict_path::VirtualPath::with_root_create(format!("users/{id}"))?;
let vfile = vroot.virtual_join(user_path)?; // traversal ⇒ clamped
vfile.write(data)?;
println!("{}", vfile.virtualpath_display());
```

- Config loading (Strict):
```rust
struct ConfigFiles;
let cfg_dir: PathBoundary<ConfigFiles> = PathBoundary::try_new_create("./config")?;
let cfg = cfg_dir.strict_join(user_selected_name)?;
let text = cfg.read_to_string()?;
```

## Markers in 60 seconds

- Purpose: encode storage domains (and optionally permissions) at compile time.
- Examples: `struct PublicAssets;`, `struct UserUploads;`, `StrictPath<(SystemFiles, ReadOnly)>`.
- Rules:
  - Name markers by what lives under the root (domain nouns). Avoid `Marker/Type/Root` suffixes.
  - Accept `&StrictPath<Marker>`/`&VirtualPath<Marker>` in function signatures.
  - Use `change_marker()` only after authorization proof; conversions between types preserve markers automatically.
  - Keep tuple markers FLAT with the resource first, then capabilities: `StrictPath<(SystemFiles, ReadOnly)>`. Avoid nested tuples and human-centric labels unless the directory literally stores those artifacts.

## Interop vs display

- Interop: `path.interop_path()` only when a third‑party API requires `AsRef<Path>` (e.g., `WalkDir::new(path.interop_path())`).
- Display: `strictpath_display()` (system) and `virtualpath_display()` (virtual). No implicit Display — you must opt in.

## Feature notes

- `virtual-path`: enables `VirtualRoot`/`VirtualPath` and virtual operations.
- `junctions` (Windows): Built-in NTFS junction helpers for strict/virtual paths.

## Ecosystem integration

Use ecosystem crates directly with `PathBoundary` for maximum flexibility:
- `tempfile` — RAII temporary directories: `tempfile::tempdir()` → `PathBoundary::try_new()`
- `dirs` — OS standard directories: `dirs::config_dir()` → `PathBoundary::try_new_create()`
- `app-path` — Portable app paths: `AppPath::with("subdir")` → `PathBoundary::try_new_create()`
- `serde` — `PathBoundary`/`VirtualRoot` implement `FromStr` for automatic deserialization; serialize paths as display strings

## Decision guide (what to use when)

| Scenario                                 | Use           | Why                                                                 |
| ---------------------------------------- | ------------- | ------------------------------------------------------------------- |
| Archive extraction                       | `StrictPath`  | Detect malicious names; fail fast on escape (`PathEscapesBoundary`) |
| File uploads to shared storage           | `StrictPath`  | Admin panels, CMS assets — all users share one boundary             |
| Config loading, system assets/logs/cache | `StrictPath`  | System‑facing, explicit boundaries                                  |
| LLM/CLI/HTTP inputs for system I/O       | `StrictPath`  | Turn arbitrary segments into validated paths before I/O             |
| Multi‑tenant file uploads                | `VirtualPath` | SaaS per‑user storage — each user/tenant isolated                   |
| Multi‑tenant per‑user files              | `VirtualPath` | Rooted “/” UX, clamped containment                                  |
| Malware/sandbox analysis                 | `VirtualPath` | Observe escapes safely (clamped)                                    |
| UI display only                          | `VirtualPath` | User‑friendly rooted strings (`/a/b.txt`)                           |

Notes:
- For archives, prefer `StrictPath` so compromised archives are rejected instead of silently clamped. Use `VirtualPath` only for sandboxes where clamping is the objective.
- Unified helpers: accept `&StrictPath<_>`; call with `vpath.as_unvirtual()` when you have `VirtualPath`.

## Quick method reference

Use these when writing or generating code. Names make the dimension explicit.

- PathBoundary<T> (policy root; strict/system dimension)
  - Constructors: `try_new(path)`, `try_new_create(path)`
  - Validation: `strict_join(input) -> Result<StrictPath<T>>`
  - Conversions: `into_strictpath()` (dir must exist)
  - Display & interop: `strictpath_display()`, `interop_path()`
  - I/O at root: `strict_read_dir()`, `read_dir()`, `remove_dir()`, `remove_dir_all()`, `metadata()`
  - Links: `strict_symlink<P: AsRef<Path>>(link_path)`, `strict_hard_link<P: AsRef<Path>>(link_path)`

- StrictPath<T> (validated system path)
  - Sugar roots: `with_boundary(path)`, `with_boundary_create(path)`
  - Join/mutate: `strict_join(..)`, `strictpath_parent()`, `strictpath_with_file_name(..)`, `strictpath_with_extension(..)`
  - Display & interop: `strictpath_display()`, `interop_path()`
  - Conversions: `try_into_boundary(_create)`, `virtualize()` [feature: virtual-path], `unstrict()` (escape hatch)
- I/O: `exists()`, `try_exists()`, `is_file()`, `is_dir()`, `metadata()`, `read_dir()`, `strict_read_dir()`
    - File ops: `read()`, `read_to_string()`, `write(..)`, `append(..)`, `create_file()`, `open_file()`, `open_with()`, `touch()`
    - Dir ops: `create_dir()`, `create_dir_all()`, `create_parent_dir()`, `create_parent_dir_all()`, `remove_file()`, `remove_dir()`, `remove_dir_all()`
    - Permissions: `set_permissions(perm)`
    - Symlink-safe: `symlink_metadata()`, `strict_read_link()`
  - Copy/move/links: `strict_copy(..)`, `strict_rename(..)`, `strict_symlink<P: AsRef<Path>>(link_path)`, `strict_hard_link<P: AsRef<Path>>(link_path)`

- VirtualRoot<T> (policy root; virtual dimension) [feature: virtual-path]
  - Constructors: `try_new(path)`, `try_new_create(path)`
  - Validation: `virtual_join(input) -> Result<VirtualPath<T>>`
  - Conversions: `into_virtualpath()` (dir must exist), `as_unvirtual() -> &PathBoundary<T>`, `unvirtual() -> PathBoundary<T>`
  - Display & interop: `interop_path()`, root I/O: `virtual_read_dir()`, `read_dir()`, `remove_dir()`, `remove_dir_all()`, `metadata()`
  - Links: `virtual_symlink<P: AsRef<Path>>(link_path)`, `virtual_hard_link<P: AsRef<Path>>(link_path)`

- VirtualPath<T> (clamped virtual path; user-facing) [feature: virtual-path]
  - I/O includes: `read_dir()`, `virtual_read_dir()` (auto-validated iterator), `virtual_read_link()`
  - Sugar roots: `with_root(path)`, `with_root_create(path)`
  - Join/mutate: `virtual_join(..)`, `virtualpath_parent()`, `virtualpath_with_file_name(..)`, `virtualpath_with_extension(..)`
  - Display & interop: `virtualpath_display()`, `interop_path()`, `as_unvirtual() -> &StrictPath<T>`
  - Conversions: `unvirtual() -> StrictPath<T>`, `change_marker()`
  - I/O: same helpers as `StrictPath` (delegated to strict/system path)

### Feature semantics

- virtual-path: Enables all VirtualRoot/VirtualPath types and methods; `StrictPath` remains available without the feature.
- junctions (Windows): Built-in NTFS junction helpers for directory links on Windows.

### Ecosystem integration patterns

**Temporary directories** (`tempfile` crate):
```rust
let temp = tempfile::tempdir()?;
let boundary = PathBoundary::try_new(temp.path())?;
// RAII cleanup from tempfile, security from strict-path
```

**OS standard directories** (`dirs` crate):
```rust
let config_base = dirs::config_dir().ok_or("No config")?;
let boundary = PathBoundary::try_new_create(config_base.join("myapp"))?;
```

**Portable app paths** (`app-path` crate):
```rust
use app_path::AppPath;
let app_path = AppPath::with("config");  // Relative to executable directory
let boundary = PathBoundary::try_new_create(&app_path)?;
```

**Serialization** (`serde`):
- `PathBoundary`/`VirtualRoot` implement `FromStr`, enabling automatic deserialization
- Serialize paths as display strings: `boundary.strictpath_display().to_string()`
- For untrusted path fields, deserialize as `String` and validate manually via `boundary.strict_join()`

## Critical behaviors

- Absolute joins are safe:
  - `StrictPath::strict_join("/abs")` validates containment; errors if it would escape.
  - `VirtualPath::virtual_join("/abs")` treats it as a virtual‑absolute; result is clamped under the same virtual root (e.g., `/etc/hosts` maps to `<vroot>/etc/hosts`).
- Symlinks/junctions: Resolved during validation. Traversals that would leave the boundary/root return `PathEscapesBoundary` (strict) or are clamped (virtual).
- Display is explicit: no `Display` impl on path types; use `strictpath_display()` / `virtualpath_display()`.
- Interop is explicit: prefer crate I/O; use `interop_path()` only for third‑party APIs that insist on `AsRef<Path>`.

## Golden rules (memorize these)

1) Never wrap `.interop_path()` in `Path::new()` to use `Path::join`/`parent`; always use `strict_*` / `virtual_*` operations instead.
2) Validate every external segment with `strict_join`/`virtual_join` at the boundary. Accept `&StrictPath<_>`/`&VirtualPath<_>` in downstream functions.
3) Don’t convert secure types back to `Path`/`PathBuf` for I/O; prefer crate I/O. Use `interop_path()` only when a library insists on `AsRef<Path>`.
4) Use explicit display methods. Do not format secure types directly.
5) Don’t construct boundaries/roots inside helpers. Inject policy via parameters.
6) Don’t call `strict_join("")` or `virtual_join("")` to get the root. Use `into_strictpath()` / `into_virtualpath()` instead.
7) Use `change_marker()` only immediately after proving authorization; never as a convenience.

## Naming rules (avoid confusion)

- Name variables by domain/purpose, not by type:
  - Good: `user_uploads_root`, `static_assets_root`, `config_dir`, `tenant_vroot`
  - Avoid: `boundary`, `jail`, `root1`, one-letter names
- For untrusted input, use names that make it obvious:
  - Good: `user_input`, `requested_file`, `attack_input`, `uploaded_data`, `config_input`
  - Avoid: `filename`, `path`, `name`, `config_name` (hides that it's untrusted)
- Markers describe stored content (and optional capability), not people/teams.

## Error-handling playbook

```rust
use strict_path::{PathBoundary, StrictPathError};

let boundary = PathBoundary::try_new_create("./uploads")?;
match boundary.strict_join(user_input) {
  Ok(sp) => {
    sp.create_parent_dir_all()?;
    sp.write(bytes)?;
  }
  Err(StrictPathError::PathEscapesBoundary { attempted_path, restriction_boundary }) => {
    // Security signal: traversal/symlink escape attempt
    log::warn!("blocked traversal: {}", attempted_path.display());
    // return 400/403 or skip entry (archives)
  }
  Err(StrictPathError::InvalidRestriction { source, .. }) => {
    // Misconfiguration/permissions; surface to operator
    return Err(source.into());
  }
  Err(StrictPathError::PathResolutionError { source, .. }) => {
    // Malformed path or I/O error during canonicalization
    return Err(source.into());
  }
}
```

## Discovery vs validation (directory iteration)

Discover names, then validate each before use:
```rust
let root = PathBoundary::try_new_create("./public")?;
for entry in root.read_dir()? {
  let entry = entry?;
  let name = entry.file_name();
  // Do not trust `entry.path()` blindly; re-validate name
  // OsStr/OsString implements AsRef<Path>, so pass directly
  let sp = root.strict_join(&name)?; // safe path
  println!("{}", sp.strictpath_display());
}
```

## Root conversions (don’t use empty joins)

```rust
// Strict root as a path value
let root_boundary = PathBoundary::try_new_create("./assets")?;
let root_path = root_boundary.into_strictpath()?; // preferred

// Virtual root as a path value (feature: virtual-path)
let tenant_id = "acme";
let vroot = strict_path::VirtualRoot::try_new_create(format!("tenants/{tenant_id}"))?;
let vroot_path = vroot.into_virtualpath()?; // preferred
```

## Parent creation semantics

- `create_parent_dir()` creates only the immediate parent, errors if grandparents are missing.
- `create_parent_dir_all()` creates the full chain to the immediate parent (recursive).

```rust
let file = boundary.strict_join("a/b/c.txt")?;
file.create_parent_dir_all()?; // ensures a/ and a/b/ exist
file.write(b"ok")?;
```

## Edge cases handled (security surface)

- Symlinks/junctions inside the boundary that point outside → rejected in strict (`PathEscapesBoundary`), clamped in virtual.
- `..`, `.` components, mixed separators, redundant separators → normalized during resolution.
- Windows specifics: 8.3 short names (e.g., `PROGRA~1`), UNC and `\\?\` extended paths, drive‑relative forms, junction points, NTFS ADS (e.g., `file.txt:stream`) are handled by the resolution pipeline.
- TOCTOU concerns: canonicalization occurs as part of validation before producing safe types.

## Practical patterns (copy/paste)

### Archive extraction (Strict — detect & reject)
```rust
use strict_path::PathBoundary;

fn extract_zip(entries: impl IntoIterator<Item=(String, Vec<u8>)>) -> std::io::Result<()> {
  let extract_dir = PathBoundary::try_new_create("./extract")?;
  for (name, data) in entries {
    // Malicious: "../../etc/passwd" ⇒ Err(PathEscapesBoundary)
    let sp = match extract_dir.strict_join(&name) {
      Ok(p) => p,
      Err(strict_path::StrictPathError::PathEscapesBoundary { .. }) => continue, // skip/flag
      Err(e) => return Err(e.into()),
    };
    sp.create_parent_dir_all()?;
    sp.write(&data)?;
  }
  Ok(())
}
```

### Web/static server (Strict)
```rust
struct StaticFiles;
use strict_path::{PathBoundary, StrictPath};

async fn serve(static_root: &PathBoundary<StaticFiles>, req_path: &str) -> std::io::Result<Vec<u8>> {
  let file: StrictPath<StaticFiles> = static_root.strict_join(req_path)?;
  file.read()
}
```

### LLM agent file ops (Strict)
```rust
use strict_path::PathBoundary;

fn llm_write(workspace: &PathBoundary, filename: &str, bytes: &[u8]) -> std::io::Result<()> {
  let path = workspace.strict_join(filename)?; // attack ⇒ error
  path.create_parent_dir_all()?;
  path.write(bytes)
}
```

### Multi‑tenant per‑user storage (Virtual)
```rust
use strict_path::VirtualPath; // feature: virtual-path

fn save_user_file(user_root_fs: &str, user_path: &str, data: &[u8]) -> std::io::Result<()> {
  let vroot = VirtualPath::with_root_create(user_root_fs)?;
  let vfile = vroot.virtual_join(user_path)?; // traversal ⇒ clamped
  vfile.create_parent_dir_all()?;
  vfile.write(data)
}
```

## Serde and config (safe deserialization)

```rust
use serde::Deserialize;
use strict_path::PathBoundary;

#[derive(Deserialize)]
struct AppConfig {
  // PathBoundary implements FromStr, enabling automatic deserialization
  upload_dir: PathBoundary,
  // Validate untrusted path fields manually
  user_paths: Vec<String>,
}

fn load_config(json: &str) -> Result<(), Box<dyn std::error::Error>> {
  let config: AppConfig = serde_json::from_str(json)?;
  
  // Boundaries are ready to use
  for path_str in &config.user_paths {
    match config.upload_dir.strict_join(path_str) {
      Ok(safe_path) => safe_path.write(b"data")?,
      Err(e) => eprintln!("Blocked: {}", e),
    }
  }
  Ok(())
}
```

## OS/app/temp recipes (feature‑gated)

```rust

```

## Interop cookbook

Use `interop_path()` when a third‑party crate insists on `AsRef<Path>`.

```rust
use walkdir::WalkDir;
let safe = boundary.strict_join("data")?;
for entry in WalkDir::new(safe.interop_path()) { /* ... */ }
```

Prefer crate I/O when possible:
```rust
let bytes = safe.read()?;
safe.write(b"new")?;
```

## Unified helper pattern (works for both Strict and Virtual)

Write helpers against `&StrictPath<_>`; call with a `StrictPath` directly or borrow the strict view from a `VirtualPath`:

```rust
use strict_path::StrictPath;

fn process_bytes<M>(p: &StrictPath<M>) -> std::io::Result<Vec<u8>> {
  p.read()
}

// Call sites
let strict = boundary.strict_join("a.txt")?;
let _ = process_bytes(&strict)?;

let user_id = "alice";
let vroot = strict_path::VirtualPath::with_root_create(format!("users/{user_id}"))?; // feature: virtual-path
let vfile = vroot.virtual_join("docs/a.txt")?;
let _ = process_bytes(vfile.as_unvirtual())?; // borrow strict view
```

## Authorization markers with `change_marker()` (capability upgrade)

Use tuple markers `(Resource, Capability)` and change the capability only after proving authorization.

```rust
use strict_path::StrictPath;

struct UserUploads; struct ReadOnly; struct ReadWrite;

fn grant_write(
  file: StrictPath<(UserUploads, ReadOnly)>,
  user_can_write: bool,
) -> Result<StrictPath<(UserUploads, ReadWrite)>, &'static str> {
  if user_can_write { Ok(file.change_marker()) } else { Err("denied") }
}
```

Rules reminder:
- Do not use `change_marker()` when converting between path types; conversions preserve markers automatically.
- Only use `change_marker()` immediately after a successful authorization check.

## I/O return values (matches std::fs)

All I/O helpers return the same types as their `std::fs` counterparts to preserve OS signals and avoid extra probes.

```rust
// Copy returns number of bytes
let n: u64 = src.strict_copy(dest.interop_path())?;

// Rename/symlink/hard_link return ()
dst.strict_rename("new_name.txt")?; // io::Result<()>

// Metadata and existence checks
let meta = file.metadata()?;
let exists = file.exists();
```

## Hard links (platform behavior)

Creating directory hard links is forbidden on many platforms (e.g., Linux, macOS). Expect `io::ErrorKind::PermissionDenied` in those cases. File hard links typically work within the same filesystem.

```rust
// Link a file to another safe location within the same restriction
let src = boundary.strict_join("a.txt")?;
let dst = boundary.strict_join("alias.txt")?;
src.strict_hard_link(&dst)?; // io::Result<()>
```

## Equality/traits at a glance

- `StrictPath<T>` and `VirtualPath<T>` compare/order/hash by their underlying strict/system path (same marker type).
- Cross‑type equality: `VirtualPath<T> == StrictPath<T>` is true when the resolved system path is the same restriction‑validated path. Borrow the strict view with `as_unvirtual()` when needed by helpers.
- No `AsRef<Path>` on secure path values; prefer `interop_path()` for third‑party adapters. Roots and boundaries provide their own interop methods.

## Pitfalls (and fixes)

- Anti‑pattern: validate constants only → Fix: validate actual untrusted segments.
- Anti‑pattern: `std::fs::*` on `interop_path()` → Fix: prefer crate I/O (`read`, `write`, …).
- Anti‑pattern: wrapping `.interop_path()` in `Path::new()` to use `Path::join` → Fix: use `strict_join`/`virtual_join` instead.
- Anti‑pattern: convert `StrictPath`→`VirtualPath` just to print → Fix: use `strictpath_display()`; start with virtual if you need virtual UX.
- Anti‑pattern: `strict_join("")` / `virtual_join("")` to get the root → Fix: use `into_strictpath()` / `into_virtualpath()`.
- Anti‑pattern: `interop_path().as_ref()` or wrapping `interop_path()` in `Path::new`/`PathBuf::from` → Fix: pass `interop_path()` directly to APIs accepting `AsRef<Path>`.
- Anti‑pattern: validate then immediately convert back to unsafe types and call `std::fs` → Fix: keep using crate I/O on the secure types; only use `interop_path()` for adapters.
