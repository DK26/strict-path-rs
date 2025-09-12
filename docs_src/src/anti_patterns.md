# Anti‑Patterns (Tell‑offs and Fixes)

This page collects the most common smells that indicate strict-path is being misused, why they’re wrong, and how to fix them. Use this as a quick checklist during review.

## Tell‑offs and why they’re wrong

- Validating only constants (no real external input ever passes through validation)
  - Smell: The code builds a `PathBoundary`/`VirtualRoot` and only ever calls joins with literals like `"docs"` or `"."`, never with user/DB/archive inputs.
  - Why wrong: If no untrusted segment flows through `strict_join`/`virtual_join`, the crate adds no security value and may mislead readers about protections.
  - Fix: Validate actual external segments (e.g., HTTP param, manifest/DB strings, archive entry names). For discovery of the root, use `interop_path()`; do not validate constants just to “use the API”.

- Constructing boundaries/roots inside helpers
  - Smell: `fn load_config() { let cfg = PathBoundary::try_new(...); cfg.strict_join(name) ... }`.
  - Why wrong: Boundary selection is policy; helpers should not decide it. It also hides where validation happens.
  - Fix: Accept `&PathBoundary` (or `&VirtualRoot`) and an untrusted segment; or accept `&StrictPath`/`&VirtualPath` directly.

- Wrapping secure types in `Path::new` / `PathBuf::from`
  - Smell: `Path::new(spath.interop_path())`, `PathBuf::from(vpath.interop_path())`.
  - Why wrong: It bypasses the secure API, reintroduces std joins/parents, and is redundant for interop.
  - Fix: Pass `interop_path()` directly to `AsRef<Path>` APIs or use strict/virtual methods for ops.

- Mixing interop and display
  - Smell: `println!("{}", path.interop_path().to_string_lossy())`.
  - Why wrong: Interop is for external APIs; display requires stable, intentful formatting.
  - Fix: Use `strictpath_display()` or `virtualpath_display()`.

- `interop_path().as_ref()` chaining
  - Smell: `external_api(path.interop_path().as_ref())`.
  - Why wrong: `interop_path()` already implements `AsRef<Path>`; `.as_ref()` is redundant and a design smell.
  - Fix: Call `external_api(path.interop_path())` directly.

- `as_unvirtual().interop_path()` when `interop_path()` exists
  - Smell: `vroot.as_unvirtual().interop_path()`; `vpath.as_unvirtual().interop_path()`.
  - Why wrong: Both `VirtualRoot` and `VirtualPath` implement `interop_path()`.
  - Fix: Call `vroot.interop_path()` or `vpath.interop_path()`.

- Using std joins/parents on leaked paths
  - Smell: `leaked_path.join("child")`, `Path::parent()` on an unwrapped secure type.
  - Why wrong: std ops ignore virtual/strict semantics and can escape boundaries.
  - Fix: Use `strict_join`/`virtual_join`, `strictpath_parent`/`virtualpath_parent`.

- Function signatures that accept raw paths when safety is required
  - Smell: `fn process(path: &str)` then validating internally.
  - Why wrong: Every caller must remember to validate; easy to misuse.
  - Fix: Accept `&StrictPath<_>` or `&VirtualPath<_>`; or accept `&PathBoundary/_` + untrusted segment.

- Single‑user patterns for multi‑user services
  - Smell: Global `PathBoundary` for “uploads” in a multi‑user context.
  - Why wrong: It doesn’t encode per‑user isolation and invites mixing.
  - Fix: Use a per‑user `VirtualRoot`; helpers can take `&StrictPath` for shared logic via `as_unvirtual()`.

- Lossy string conversions for logic
  - Smell: Using `to_string_lossy()` for comparisons or display of secure types.
  - Why wrong: Lossy and breaks on non‑UTF8; conflates display with logic.
  - Fix: For display, use display helpers; for logic, rely on secure ops (starts_with/joins) or std Path values where appropriate.

## Quick fixes (bad → good)

- `path.strict_join(".")` → use `path_boundary.interop_path()` to discover; validate only external segments.
- `fn helper() { PathBoundary::try_new("..."); }` → `fn helper(boundary: &PathBoundary, name: &str)`.
- `Path::new(sp.interop_path())` → `external_api(sp.interop_path())`.
- `println!("{}", sp.interop_path().to_string_lossy())` → `println!("{}", sp.strictpath_display())`.
- `vroot.as_unvirtual().interop_path()` → `vroot.interop_path()`.
- `fn process(path: &str)` → `fn process(path: &StrictPath<_>)` (or `&VirtualPath<_>`).
- `uploads_dir.strict_join(name)` (multi‑user) → `user_vroot.virtual_join(name)`; call `as_unvirtual()` only for strict‑typed helpers.

## Naming tell‑offs (from AGENTS.md)

- Variables must reflect their domain (config_dir, uploads_root, archive_src), not types (boundary, jail) or generic prefixes (source_).
- Path variables for boundaries/roots should match their actual content (e.g., `archive_src`, `mirror_src`, `uploads_root`).
