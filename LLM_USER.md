# strict-path — Context7 user prompt

Security‑first path handling for Rust apps. Validate every untrusted path segment into restriction‑enforced types before any I/O. Choose Strict (detect & reject) or Virtual (contain & clamp).

- Core types: `PathBoundary<Marker>`, `StrictPath<Marker>`; with feature `virtual-path`: `VirtualRoot<Marker>`, `VirtualPath<Marker>`.
- Golden rule: “Restrict every external path.” Validate user/LLM/config/archive input using `strict_join` or `virtual_join` before touching the filesystem.
- Interop vs display: use `.interop_path()` only for third‑party APIs requiring `AsRef<Path>`; use `*_display()` for human‑readable output.

## Install

```toml
[dependencies]
strict-path = "*"
# Virtual sandboxes (optional)
# strict-path = { version = "*", features = ["virtual-path"] }
```

## Choose your mode

- StrictPath (default, 90% cases): Detects escape attempts. Best for archive extraction, file uploads, config loading, shared system areas.
- VirtualPath (opt‑in): Clamps escape attempts within a virtual root. Best for per‑user sandboxes, multi‑tenant UX, malware analysis.

## Quickstart

Strict (detect & reject):
```rust
use strict_path::{PathBoundary, StrictPath};

let uploads: PathBoundary = PathBoundary::try_new_create("uploads")?;
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
- Don't: wrap `.interop_path()` in `Path::new()` or `PathBuf::from()` — it's already `AsRef<Path>`.
- Don't: use std path operations (`Path::join`, `Path::parent`) on untrusted input — use `.strict_join()` instead.
- Don't: Construct boundaries/roots inside helpers; inject policy via parameters.

## Quick recipes

- File uploads (Strict):
```rust
let uploads = PathBoundary::try_new_create("uploads")?;
let file = uploads.strict_join(filename)?; // traversal ⇒ error
file.create_parent_dir_all()?;
file.write(bytes)?;
```

- Per‑user storage (Virtual):
```rust
let vroot = strict_path::VirtualPath::with_root_create(format!("users/{id}"))?;
let vfile = vroot.virtual_join(user_path)?; // traversal ⇒ clamped
vfile.write(data)?;
println!("{}", vfile.virtualpath_display());
```

- Config loading (Strict):
```rust
struct ConfigFiles;
let cfg_dir: PathBoundary<ConfigFiles> = PathBoundary::try_new_create("config")?;
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
- `serde`: Serialize secure paths (`StrictPath` → system path string; `VirtualPath` → rooted string like "/a/b.txt").
- OS/app/temp helpers are available behind features in the crate; see crate docs for exact APIs.

## Decision guide (what to use when)

| Scenario                                 | Use           | Why                                                                 |
| ---------------------------------------- | ------------- | ------------------------------------------------------------------- |
| Archive extraction, file uploads         | `StrictPath`  | Detect malicious names; fail fast on escape (`PathEscapesBoundary`) |
| Config loading, system assets/logs/cache | `StrictPath`  | System‑facing, explicit boundaries                                  |
| LLM/CLI/HTTP inputs for system I/O       | `StrictPath`  | Turn arbitrary segments into validated paths before I/O             |
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
  - I/O at root: `read_dir()`, `remove_dir()`, `remove_dir_all()`, `metadata()`
  - Links: `strict_symlink(&StrictPath<T>)`, `strict_hard_link(&StrictPath<T>)`

- StrictPath<T> (validated system path)
  - Sugar roots: `with_boundary(path)`, `with_boundary_create(path)`
  - Join/mutate: `strict_join(..)`, `strictpath_parent()`, `strictpath_with_file_name(..)`, `strictpath_with_extension(..)`
  - Display & interop: `strictpath_display()`, `interop_path()`
  - Conversions: `try_into_boundary(_create)`, `virtualize()` [feature: virtual-path], `unstrict()` (escape hatch)
  - I/O: `exists()`, `is_file()`, `is_dir()`, `metadata()`, `read_dir()`
    - File ops: `read()`, `read_to_string()`, `write(..)`, `create_file()`, `open_file()`
    - Dir ops: `create_dir()`, `create_dir_all()`, `create_parent_dir()`, `create_parent_dir_all()`, `remove_file()`, `remove_dir()`, `remove_dir_all()`
  - Copy/move/links: `strict_copy(..)`, `strict_rename(..)`, `strict_symlink(&Self)`, `strict_hard_link(&Self)`

- VirtualRoot<T> (policy root; virtual dimension) [feature: virtual-path]
  - Constructors: `try_new(path)`, `try_new_create(path)`
  - Validation: `virtual_join(input) -> Result<VirtualPath<T>>`
  - Conversions: `into_virtualpath()` (dir must exist), `as_unvirtual() -> &PathBoundary<T>`, `unvirtual() -> PathBoundary<T>`
  - Display & interop: `interop_path()`, root I/O: `read_dir()`, `remove_dir()`, `remove_dir_all()`, `metadata()`
  - Links: `virtual_symlink(&VirtualPath<T>)`, `virtual_hard_link(&VirtualPath<T>)`

- VirtualPath<T> (clamped virtual path; user-facing) [feature: virtual-path]
  - Sugar roots: `with_root(path)`, `with_root_create(path)`
  - Join/mutate: `virtual_join(..)`, `virtualpath_parent()`, `virtualpath_with_file_name(..)`, `virtualpath_with_extension(..)`
  - Display & interop: `virtualpath_display()`, `interop_path()`, `as_unvirtual() -> &StrictPath<T>`
  - Conversions: `unvirtual() -> StrictPath<T>`, `change_marker()`
  - I/O: same helpers as `StrictPath` (delegated to strict/system path)

### Feature semantics

- virtual-path: Enables all VirtualRoot/VirtualPath types and methods; `StrictPath` remains available without the feature.
- app-path: App‑relative roots with env override; when the env var is set, its value becomes the final root (do not append the provided subdir).
- dirs: OS directory constructors (e.g., config/data/cache/home/desktop/documents/downloads/etc.) exposed as `try_new_os_*` on both `PathBoundary` and `VirtualRoot`.
- tempfile: Temporary directories with RAII roots; `try_new_temp()` and `try_new_temp_with_prefix(..)` on both root types.
- serde: Serialize support for `StrictPath` (system string) and `VirtualPath` (rooted `/a/b`). For safe deserialization, use seeds: `serde_ext::WithBoundary(&boundary)` → `StrictPath`, `serde_ext::WithVirtualRoot(&vroot)` → `VirtualPath`.

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
- Markers describe stored content (and optional capability), not people/teams.

## Error-handling playbook

```rust
use strict_path::{PathBoundary, StrictPathError};

let boundary = PathBoundary::try_new_create("uploads")?;
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
let root = PathBoundary::try_new_create("public")?;
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
let root_boundary = PathBoundary::try_new_create("assets")?;
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
  let extract_dir = PathBoundary::try_new_create("extract")?;
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

Enable `serde` (and `virtual-path` if needed). Validate using seeds so runtime policy is applied while deserializing.

```rust
// Cargo.toml
// strict-path = { version = "*", features = ["serde", "virtual-path"] }

use serde::Deserialize;
use strict_path::{serde_ext, PathBoundary, StrictPath};

#[derive(Deserialize)]
struct AppCfg { filename: String }

fn load_cfg(json: &str, cfg_dir: &PathBoundary) -> Result<StrictPath, Box<dyn std::error::Error>> {
  let raw: AppCfg = serde_json::from_str(json)?;
  let path = cfg_dir.strict_join(&raw.filename)?; // validate after plain deserialize
  Ok(path)
}

// Or deserialize directly with a seed at the call site using the boundary/root:
// let strict_path: StrictPath<_> = serde_ext::WithBoundary(&cfg_dir).deserialize(deserializer)?;
// let virtual_path: VirtualPath<_> = serde_ext::WithVirtualRoot(&vroot).deserialize(deserializer)?; // feature: virtual-path
```

For virtual paths use `serde_ext::WithVirtualRoot(&vroot)` similarly.

## OS/app/temp recipes (feature‑gated)

```rust
// app-path: app‑relative directory with env override
// The env var VALUE becomes the final root (no subdir append when set)
// strict-path = { version = "*", features = ["app-path"] }
use strict_path::PathBoundary;
let cfg = PathBoundary::try_new_app_path_with_env("config", "MYAPP_CONFIG_DIR")?;
let file = cfg.strict_join("settings.toml")?;

// dirs: standard OS directories
// strict-path = { version = "*", features = ["dirs"] }
let downloads = PathBoundary::try_new_os_downloads()?;
let dl = downloads.strict_join("report.pdf")?;

// tempfile: temporary roots with RAII
// strict-path = { version = "*", features = ["tempfile"] }
let tmp = PathBoundary::try_new_temp()?; // ephemeral root
let scratch = tmp.strict_join("scratch.txt")?;
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
