# AGENTS.md

Operational guide for AI assistants, bots, and automation working in this repository.

## Project Overview

- Purpose: Prevent directory traversal with type‑safe path boundaries and safe symlinks.
- Core APIs: `PathBoundary<Marker>`, `StrictPath<Marker>`, `VirtualRoot<Marker>`, `VirtualPath<Marker>`, `StrictPathError` (see API_REFERENCE.md).
- Security model: “Restrict every external path.” Any path from untrusted inputs (user I/O, config, DB, LLMs, archives) must be validated into a restriction‑enforced type (`StrictPath` or `VirtualPath`) before I/O.
- Foundation: Built on `soft-canonicalize` for resolution; Windows 8.3 short‑name handling is considered a security surface.

Do not implement leaky trait impls for secure types:
- Forbidden: `AsRef<Path>`, `Deref<Target = Path>`, implicit `From/Into` conversions for `StrictPath`/`VirtualPath`.
- Rationale: They would bypass validation and blur dimension semantics (strict vs virtual).

## Repository Layout

- Root workspace: `[workspace].members = ["strict-path"]`, `exclude = ["demos"]`.
- `strict-path/`: library crate; MSRV‑bound.
- `demos/`: real‑world demo binaries; decoupled from MSRV; `publish = false`.
- `.github/workflows/`: CI configs; stable + MSRV split.
- Local CI parity: `ci-local.ps1` (Windows), `ci-local.sh` (Unix/WSL).
- Docs: `README.md`, `API_REFERENCE.md`, mdBook source at `docs_src/` (built to `docs/`).

## CI Workflows (GitHub Actions)

- Stable job (linux/windows/macos):
  - `cargo fmt --all -- --check` and `cargo clippy --all-targets --all-features -- -D warnings` (library).
  - Build demos separately: `cd demos && cargo build --bins --features with-zip`.
  - Lint demos: `cd demos && cargo clippy --all-targets --features with-zip -- -D warnings`.
  - `cargo test -p strict-path --all-features` (library only).
- MSRV job (linux, Rust 1.71.0):
  - `check`/`clippy`/`test` scoped to `-p strict-path --lib --locked` using separate target dir.

## MSRV Policy (Library Only)

- MSRV: Rust 1.71.0 (declared in `strict-path/Cargo.toml`).
- Avoid dependencies or features that raise MSRV without discussion.
- Forbid unsafe code; pass clippy with `-D warnings`.

## Demos Policy (Non‑MSRV)

- `demos/` is a separate crate (`publish = false`), path‑dep on `../strict-path`.
- Built only on latest stable CI; demos may use newer ecosystem crates/features.
- Keep heavy deps optional with namespaced features (e.g., `with-zip = ["dep:zip", "dep:flate2"]`).
- Demo projects must model real scenarios; avoid “API‑only” snippets (those belong in `strict-path/examples/`).

## Examples vs Demos (Critical)

- API usage examples → `strict-path/examples/*.rs` (built with the library). Run with `cargo run --example <name>` from `strict-path/`.
- Real demo projects → `demos/src/bin/<category>/<name>.rs`. Run with `cd demos && cargo run --bin <name>`.

Directory convention for demos:
- Web servers: `demos/src/bin/web/...`
- Security/archives: `demos/src/bin/security/...`
- CLI/tools: `demos/src/bin/cli/...` or `.../tools/...`
- Config/OS dirs: `demos/src/bin/config/...`

## Code & API Usage Guidelines

- Encode guarantees in function signatures:
  - Accept `&StrictPath<Marker>` / `&VirtualPath<Marker>` (or structs containing them), or
  - Accept `&PathBoundary<Marker>` / `&VirtualRoot<Marker>` plus the untrusted segment.
  - Do not construct boundaries/roots inside helpers — boundary choice is policy.
- Interop vs display:
  - Interop (`AsRef<Path>`): `interop_path()` on `StrictPath`/`VirtualPath`/`PathBoundary`/`VirtualRoot` (no allocations).
  - Display: `strictpath_display()` (system) / `virtualpath_display()` (virtual).
- Explicit operations by dimension:
  - `strict_join`/`virtual_join`, `strictpath_parent`/`virtualpath_parent`, `strictpath_with_*`/`virtualpath_with_*`.
  - Do not use std `Path::join`/`parent` on leaked paths.
- Escape hatches only where needed:
  - Prefer borrowing: `vpath.as_unvirtual()` to pass `&StrictPath`.
  - Avoid `.unvirtual()`/`.unstrict()` unless ownership is required; isolate in dedicated “escape hatches” sections.
- Variable naming:
  - Name by domain/purpose, not type. Examples: `config_dir`, `uploads_root`, `archive_src`, `mirror_src`, `user_vroot`.
  - Avoid `boundary`, `jail`, `source_` prefixes and one‑letter names.

### Internal Design: PathHistory & Type‑State

PathHistory is the internal engine that performs normalization, canonicalization, clamping and boundary checks in a single, auditable pipeline. It is deliberately not exposed in public APIs, but agents need to understand it to reason about behavior and place fixes in the right layer.

- States (type‑state markers):
  - `Raw`: Constructed from any input (`AsRef<Path>`).
  - `Canonicalized`: After full canonicalization (resolves `.`/`..`, symlinks/junctions, prefixes).
  - `AnchoredCanonicalized`: Canonicalized relative to a specific jail/root (virtual anchoring).
  - `Exists`: Canonicalized path verified to exist (used for PathBoundary roots).
  - `BoundaryChecked`: Canonicalized path proven to be within the PathBoundary.

- Typical flows:
  - PathBoundary::try_new(_create): `Raw -> Canonicalized -> Exists` (errors if not dir or missing when `try_new`).
  - PathBoundary::strict_join(candidate): compose; `Raw -> Canonicalized -> BoundaryChecked` then wrap in `StrictPath`.
  - VirtualRoot::virtual_join(candidate): virtual compose; `Raw -> AnchoredCanonicalized -> BoundaryChecked`, then construct `StrictPath` and wrap as `VirtualPath` (computes virtual view for Display).
  - VirtualPath mutations (`virtual_join`, `virtualpath_parent`, `virtualpath_with_*`): compute candidate in virtual space; `Raw -> AnchoredCanonicalized -> BoundaryChecked` with the same restriction.

- Anchored canonicalization (virtual dimension):
  - `canonicalize_anchored(&PathBoundary)` canonicalizes with the jail as the anchor root and produces `AnchoredCanonicalized`.
  - After `boundary_check(...)`, anchor is erased when constructing `StrictPath`, keeping public surface types narrow.

- Windows specifics (8.3 short‑name handling):
  - Pre‑filter relative inputs for segments that look like DOS 8.3 short names (`PROGRA~1`) to avoid aliasing‑based escapes prior to filesystem calls. Keep this logic in the centralized validator used by `strict_join`.
  - UNC paths, ADS (`file.txt:stream`) and drive‑relative forms are normalized in PathHistory; ADS are not special‑cased beyond OS behavior, but path validation prevents escapes.

- Error mapping:
  - All I/O/canonicalization errors are wrapped as `StrictPathError::{InvalidRestriction, PathResolutionError, PathEscapesBoundary, WindowsShortName (windows)}` at the outer layer. Avoid exposing raw `io::Error` from internal steps.

- Equality/Ordering/Hashing (public types):
  - `StrictPath`/`VirtualPath` Eq/Ord/Hash are based on the underlying system path; `VirtualPath` equals a `StrictPath` with the same system path within the same restriction.

- Display semantics:
  - `VirtualPath::virtualpath_display()` returns rooted, forward‑slashed user view (e.g., `"/a/b.txt"`).
  - `StrictPath::strictpath_display()` shows the real system path. `Debug` for `VirtualPath` is verbose by design (system path + virtual view + restriction root + marker type).

### Constructor Parameter Design: `AsRef<Path>`

- Constructors (`PathBoundary::try_new(_create)`, `VirtualRoot::try_new(_create)`) accept `AsRef<Path>` for ergonomics and to enable the clean TempDir shadowing pattern in examples.
- Prefer borrowing (`&Path`, `&str`, `&TempDir`) and avoid allocations when passing into constructors.

Constructor parameter design:
- Prefer `AsRef<Path>` for constructors like `PathBoundary::try_new(_create)` / `VirtualRoot::try_new(_create)`.
- Rationale: maximizes ergonomics (`&str`, `String`, `&Path`, `PathBuf`, `TempDir`), supports clean shadowing in examples, matches std conventions.

Escape hatches:
- Borrow strict view from virtual with `as_unvirtual()` for shared helpers.
- Use `.unvirtual()` and `.unstrict()` only when ownership is required; isolate in dedicated “escape hatches” sections.

## Anti‑Patterns (Tell‑offs)

- Validating only constants (no untrusted segment ever flows through validation).
- Constructing boundaries/roots inside helpers.
- Wrapping secure types in `Path::new()` / `PathBuf::from()`.
- `interop_path().as_ref()` or `as_unvirtual().interop_path()` — use `interop_path()` directly.
- Mixing interop and display (use `*_display()` for display).
- Using std path ops on leaked values (`join`/`parent`).
- Raw path parameters in safe helpers — use types/signatures that encode guarantees.
- Single‑user demo flows for multi‑user services — use per‑user `VirtualRoot`.

Path handling rules (very important):
- Do not expose raw `Path`/`PathBuf` from `StrictPath`/`VirtualPath` in public APIs or examples.
- Avoid std path methods on leaked paths; always use the explicit strict/virtual variants.
- Stay in one dimension per flow; if you need the other, upgrade/downgrade explicitly.

String formatting rules (Rust 1.58+ captured identifiers):
- Avoid bare `{}`; prefer captured identifiers (`format!("{value}")`, `println!("{display}")`).
- Bind locals for repeated or long expressions; improves readability and prevents mistakes.

See also mdBook pages:
- Best Practices & Guidelines: `docs_src/src/best_practices.md`
- Anti‑Patterns (Tell‑offs): `docs_src/src/anti_patterns.md`

## Documentation Guidelines

- Keep README focused on why, core features, and simple‑to‑advanced examples.
- Align README examples with `strict-path/src/lib.rs` doc examples where appropriate.
- Use doctested examples in source whenever possible; examples must compile and follow path‑handling rules.
- For multi‑user flows, prefer `VirtualRoot`/`VirtualPath`; for shared strict logic, borrow `as_unvirtual()`.

mdBook documentation system:
- Source: `docs_src/` (markdown), built to `docs/` (published via GitHub Pages).
- Build locally: `cd docs_src && mdbook build`; serve: `mdbook serve`.
- Pages of interest: Best Practices, Anti‑Patterns, Getting Started, Features/OS directories, Archive Extractors.

## Contributing Rules (for agents)

- Do not invent new surface APIs without prior discussion.
- Do not add helper functions ad‑hoc; propose design (scope, signature, naming, tests, security notes) first.
- Follow existing module layout: `src/error`, `src/path`, `src/validator`, public re‑exports in `src/lib.rs`.
- Respect MSRV in the library; demos may use newer crates behind features.

## Local CI Parity

- Windows: `./ci-local.ps1`.
- Unix/WSL: `bash ./ci-local.sh`.
- Scripts auto‑fix format/clippy where safe and mirror CI behavior (including mdBook build).

## Quick Do/Don’t

- Do: validate untrusted segments via `strict_join`/`virtual_join`.
- Do: pass `&StrictPath`/`&VirtualPath` into helpers; or pass boundaries/roots + segment.
- Do: use explicit operations and display helpers.
- Don’t: wrap secure types in std paths or use std ops on leaked values.
- Don’t: validate constants “just to use the API”.

---

If in doubt, prefer examples in `strict-path/src/lib.rs` and mdBook pages as the source of truth.
