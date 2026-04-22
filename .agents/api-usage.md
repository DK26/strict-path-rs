# API Usage & Internals

How to write code using `strict-path` types correctly.

## Type Selection

| Type | When to use |
|---|---|
| `Path`/`PathBuf` (std) | Safe source within your control, not external input |
| `StrictPath` (90%) | Restrict to boundary, **error** on escape (archives, config, uploads) |
| `VirtualPath` (10%) | Isolate under virtual root, **silently clamp** escapes (multi-tenant, sandboxes) |

**Common mistake**: Using VirtualPath for archive extraction — it hides attacks. Use StrictPath.

## Library vs Application Boundary

- **Applications & internal code**: Use `StrictPath`/`VirtualPath`/`PathBoundary`/`VirtualRoot` freely.
- **Library public APIs**: Hide `strict-path` behind your own API by default. Accept `&str`/`&Path`/`PathBuf` publicly, validate internally.
- **Exception**: Security frameworks or file-management SDKs may expose strict-path types deliberately.

## Encoding Guarantees in Signatures

- Accept `&StrictPath<Marker>` / `&VirtualPath<Marker>` (or structs containing them), or
- Accept `&PathBoundary<Marker>` / `&VirtualRoot<Marker>` plus the untrusted segment.
- Never construct boundaries/roots inside helpers — boundary choice is policy.

## Sugar vs Policy Types

- **Small/local flows**: Sugar constructors + explicit joins:
  - `StrictPath::with_boundary(_create)(root)?.strict_join(segment)?`
  - `VirtualPath::with_root(_create)(root)?.virtual_join(segment)?`
- **Larger/reusable flows**: Policy types (`PathBoundary`/`VirtualRoot`) in signatures and modules.

## Interop vs Display

- **Interop** (`interop_path()`): Returns `&OsStr`. Use ONLY when a third-party API requires `AsRef<Path>`. Pass directly — never wrap in `Path::new()` or `PathBuf::from()`.
- **SECURITY**: `interop_path()` returns the real host path. NEVER expose to end-users.
- **Display**: `strictpath_display()` for system/admin; `virtualpath_display()` for user-facing (hides real paths).
- **Junctions** (feature `junctions`): Prefer built-in helpers over direct junction crate calls.

## Escape Hatches

- Borrow strict view from virtual: `vpath.as_unvirtual()` → `&StrictPath`
- Owned escape: `.unstrict()` / `.unvirtual()` — use sparingly, isolate in dedicated sections.

## Constructor Parameter Design

Constructors accept `AsRef<Path>` for ergonomics (`&str`, `String`, `&Path`, `PathBuf`, `TempDir`).
Prefer borrowing; avoid allocations when passing into constructors.

## Variable Naming Rules

Name by domain/purpose, NEVER by type:
- ✅ `user_uploads_root`, `config_dir`, `archive_src`, `profile_file`
- ❌ `boundary`, `jail`, `root`, `vroot`, one-letter names

**Per-user VirtualRoot**: Construct with trusted identifier segment:
`VirtualRoot::try_new_create(format!("uploads/{user_id}"))?`
— one per user/tenant, never a single global root.

### Marker Naming

- Describe the resource: `struct UserUploads;`, `struct MediaLibrary;`
- No suffixes: ❌ `UserUploadsMarker`, `MediaLibraryRoot`
- Authorization tuples: `StrictPath<(BrandEditorWorkspace, ReadWrite)>`

## Serde Guidelines

- Runtime `Cli` / `Config` fields are typed `PathBoundary<Marker>` /
  `VirtualRoot<Marker>` — never raw `PathBuf`. The typed field IS the
  ingestion boundary.
- `FromStr` forwards to `try_new_create` (creates if missing, then
  canonicalizes and validates). clap `#[arg]` fields of the typed form
  work directly via `FromStr`.
- Boundary/root types do not implement `Deserialize`. Wiring them to
  serde is the caller's integration choice (serde's own `deserialize_with`,
  `serde_with`, user-defined wrappers). Do not teach serde mechanisms in
  crate docs — point to the `FromStr` contract and let users pick.
- In hand-written code, prefer named constructors (`try_new` /
  `try_new_create`) over `.parse()` so the policy is visible at the call
  site. `FromStr` exists for framework-invoked contexts.
- Serialize paths as display strings: `boundary.strictpath_display().to_string()`
  or `vpath.virtualpath_display()`.
- Untrusted per-request path segments (filenames, archive entries, HTTP
  body fields) stay as `String` and are validated at the use site via
  `strict_join` / `virtual_join` — they are not `FromStr` input.
- Never add `Deserialize` for `StrictPath` / `VirtualPath` — they need
  runtime boundary context to be meaningful.

## Symlinks vs Junctions in Tests (Windows)

- Symlink creation may fail without Developer Mode. Tests must handle gracefully.
- Fallback chain: try symlink helper → junction helper (feature `junctions`) → third-party junction (last resort, tests only).
- Verify with built-in I/O (`read_dir()`, `exists()`), not `std::fs` on `interop_path()`.

## Usage Anti-Patterns (Consolidated)

- ❌ Validating only constants: `boundary.strict_join("hardcoded.txt")?`
- ❌ Generic variable names hiding untrusted input (`filename`, `path`, `name`)
- ❌ Constructing boundaries/roots inside helpers
- ❌ Wrapping `interop_path()` in `Path::new()`/`PathBuf::from()`
- ❌ Using `std::fs` on `interop_path()` instead of built-in helpers
- ❌ `interop_path().as_ref()` dance — call directly
- ❌ Mixing interop and display
- ❌ `strict_join("")`/`virtual_join("")` — use `into_strictpath()`/`into_virtualpath()`
- ❌ Single-user demo flows for multi-user services
- ❌ `change_marker()` without authorization or when conversion preserves marker

## Internal Design: PathHistory Type-State

PathHistory performs normalization, canonicalization, clamping, and boundary
checks in a single auditable pipeline. Not exposed publicly.

**States**: Raw → Canonicalized → BoundaryChecked (strict) or
Raw → AnchoredCanonicalized → BoundaryChecked (virtual)

**Key flows:**
- `PathBoundary::try_new(_create)`: Raw → Canonicalized → Exists
- `strict_join(candidate)`: Raw → Canonicalized → BoundaryChecked → `StrictPath`
- `virtual_join(candidate)`: Raw → AnchoredCanonicalized → BoundaryChecked → `VirtualPath`

**Windows**: Canonicalization resolves 8.3 short names automatically. UNC, ADS,
drive-relative forms normalized; path validation prevents escapes.

**Error mapping**: All errors wrapped as `StrictPathError::{InvalidRestriction, PathResolutionError, PathEscapesBoundary}`.

**Eq/Ord/Hash**: Based on underlying system path. `VirtualPath` equals `StrictPath` with same system path in same restriction.

**Display**: `virtualpath_display()` → rooted forward-slash view. `VirtualRoot::Display` shows `"/"` (never real path). `Debug` for `VirtualPath` is verbose by design.

**Arc ownership**: Every `StrictPath` carries `Arc<PathBoundary>` for re-validation on mutations — pointer-width atomic increment, not deep copy.
