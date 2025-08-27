# AGENTS.md

Operational guide for AI assistants, bots, and automation working in this repository.

## Project Overview

- Purpose: Prevent directory traversal with type‑safe path jails and safe symlinks.
- Core APIs: `Jail<Marker>`, `JailedPath<Marker>`, `VirtualRoot<Marker>`, `VirtualPath<Marker>`, `JailedPathError` (see API_REFERENCE.md).
- Security model: “Jail every external path.” Any path from untrusted inputs (HTTP, CLI, config, DB, LLMs, archives) must be validated into a `JailedPath` before I/O.
- Design notes: See `VIRTUAL_PATH_DESIGN.md` for concepts; library built on `soft-canonicalize` for resolution; Windows 8.3 short-name handling is considered a security surface.

## Repository Layout

- Root virtual workspace (Cargo):
  - `Cargo.toml` with `[workspace].members = ["jailed-path"]` and `exclude = ["examples"]`.
  - `jailed-path/`: library crate to publish to crates.io (MSRV‑bound).
  - `examples/`: real‑world binaries (non‑publishable), decoupled from MSRV.
  - `.github/workflows/`: CI for stable, MSRV, release, and audit.
  - `ci-local.ps1`, `ci-local.sh`: local parity CI runners (Windows/WSL/Linux).
  - Docs: `README.md` (human intro), `API_REFERENCE.md` (concise API).

## MSRV Policy (Library Only)

- MSRV: Rust 1.70.0 (declared in `jailed-path/Cargo.toml`).
- CI (GitHub Actions) `msrv` job:
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.70.0 cargo check --locked -p jailed-path --lib --verbose`
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.70.0 cargo clippy --locked -p jailed-path --lib --all-features -- -D warnings`
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.70.0 cargo test --locked -p jailed-path --lib --verbose`
- Local scripts mirror the same MSRV behavior (see `ci-local.ps1`/`.sh`).

## Examples Policy (Non‑MSRV)

- `examples/` is a separate crate with `publish = false` and a path dependency on `../jailed-path`.
- Built only on the latest stable CI; examples may use newer ecosystem crates/features.
- Feature gating:
  - Use optional deps and namespaced features (e.g., `with-zip = ["dep:zip", "dep:flate2"]`).
  - Avoid implicit feature names removed in newer releases (e.g., `zip` 4.x no longer has an implicit `flate2` feature).
- Stable CI explicitly builds examples:
  - `cd examples && cargo build --bins --features with-zip`

## Why Split Examples From The Workspace?

- Preserve MSRV: The library enforces Rust 1.70 with `--locked` in CI; examples often require newer crates that would otherwise raise the workspace MSRV via lockfile/feature coupling.
- Independent lifecycles: Examples evolve fast to showcase real integrations on latest stable; the library remains conservative for downstream users.
- Predictable CI: Stable job builds examples separately; MSRV job scopes to `-p jailed-path --lib` only. See `.github/workflows/ci.yml` for the split.

## CI Workflows (GitHub Actions)

- `ci.yml` (Test on stable):
  - Validates UTF‑8 encodings (no BOM) for critical files.
  - Formats (`cargo fmt --check`) and lints (`cargo clippy -D warnings`).
  - Builds examples on stable (`cd examples && cargo build --bins …`).
  - Runs tests for the workspace (library only) and builds docs with `-D warnings`.
- `ci.yml` (MSRV):
  - Installs Rust 1.70.0 + clippy; runs check/clippy/test against `-p jailed-path` with `--locked`.
- `audit.yml`:
  - Installs `cargo-audit`; runs audit and uploads JSON results.
- `release.yml`:
  - On `v*` tags, publishes with `cargo publish -p jailed-path` (requires `CRATES_IO_TOKEN`).

## Local CI Parity

- Windows: `./ci-local.ps1`.
- Linux/WSL: `bash ci-local.sh`.
- Behavior mirrors GitHub CI: stable job builds examples; MSRV job targets only the library.
- Notes:
  - PowerShell functions avoid returning booleans to prevent stray `True` prints.
  - Ensure `rustup` toolchain `1.70.0` and clippy component are installed for MSRV.

### Before Committing

- On Windows, run `./ci-local.ps1`.
- On Unix/WSL, run `bash ci-local.sh`.
- Assume only staged changes are intended for commit; run `git diff --staged` and write a message that summarizes intent and impact (not a mechanical diff narration). Do not mention anything not present in the staged diff.

## Coding & Dependency Guidelines

- Library (`jailed-path`):
  - Maintain MSRV 1.70.0; avoid deps that raise MSRV without discussion.
  - Keep the dependency graph small and stable; forbid unsafe code; pass clippy with `-D warnings`.
  - Follow current module layout: `src/error`, `src/path`, `src/validator`, public re‑exports in `src/lib.rs`.
- Examples (`examples`):
  - It’s OK to use newer crates; keep heavy deps optional with namespaced features.
  - Do not add `examples` back into the workspace; keep `publish = false`.

### Code Style

- Clippy: `cargo clippy --all-targets --all-features -- -D warnings` (MSRV job uses scoped flags; keep code clean).
- Formatting: `cargo fmt --all -- --check`.
- Follow Rust API Guidelines and best practices.

### Linting, Doctests, and Hygiene

- Do not suppress lints via `#[allow(..)]` (exception: long type names when using internal `StatedPath` in tests where unavoidable).
- Doctests must compile and run — do not use `no_run`. Provide minimal setup and ensure teardown.
- Tests and doctests must clean up any files or directories they create. Prefer `tempfile::tempdir()` for unit tests; remove any persistent paths at the end of doctests (e.g., `std::fs::remove_dir_all(..).ok()`).

### Documentation Guidelines (README.md / lib.rs / API docs)

- Keep README focused on why, core features, and simple-to-advanced examples; keep structure consistent across docs.
- When updating README.md, align relevant sections in `jailed-path/src/lib.rs` crate docs where appropriate.
- Document APIs so both humans and LLMs can use them correctly and safely; emphasize misuse-resistant patterns.
- Before removing/changing established docs, consider rationale and align with design docs; prefer discussion for non-trivial changes.

### README Code Examples Policy

- Prefer reusing examples from source code comments (crate docs or module docs) that are doctested and compile.
- If you need a new README example:
  - First implement it as a real, compiling example (e.g., under `examples/`) or a doctested snippet in source comments.
  - Ensure it builds and passes locally (and on MSRV if applicable) before copying to README.
  - When transposing to README, keep the example faithful to the working version; omit only noisy setup/teardown that is not essential to illustrate usage.
  - Keep the working example around in the repo so future changes don’t drift (prefer `examples/` or doctests in `lib.rs`).
- Never invent or paste untested snippets in README. README examples must reflect current API, follow Path handling rules (no raw `Path`/`PathBuf` leaks; use `systempath_as_os_str()` for `AsRef<Path>`), and compile when provided the minimal context.

### Path Handling Rules (Very Important)

- Do not expose raw `Path`/`PathBuf` from `JailedPath`/`VirtualPath` in public APIs or examples.
- Avoid using std path methods (`Path::join`, `Path::parent`, etc.) on leaked paths;
  these ignore virtual-root clamping and jail checks and can cause confusion or unsafe behavior.
- Use explicit, jail-aware operations instead:
  - `JailedPath::join_systempath`, `JailedPath::systempath_parent`
  - `VirtualPath::join_virtualpath`, `VirtualPath::virtualpath_parent`
- When passing to external APIs that accept `AsRef<Path>`, prefer borrowing the inner system path:
  - `jailed_path.systempath_as_os_str()` (allocation-free, OS-native string, preserves data)
- Only demonstrate ownership escape hatches in a dedicated example section:
  - `.unvirtual()` (to go from VirtualPath -> JailedPath)
  - `.unjail()` (to obtain an owned `PathBuf`, losing guarantees)
  - `.unvirtual().unjail()` (explicit two-step escape)
  Everywhere else, prefer borrowing with `systempath_as_os_str()`.

### API & Conversion Rules (Important)

- `JailedPath` MUST NOT implement `AsRef<Path>`/`Deref<Target = Path>` and MUST NOT expose raw `&Path`.
- Conversions are explicit only — do not add `From`/`Into` between `JailedPath` and `VirtualPath`.
  - `Jail::try_path(..) -> JailedPath`
  - `JailedPath::virtualize() -> VirtualPath`
  - `VirtualPath::unvirtual() -> JailedPath`
  - `JailedPath::unjail() -> PathBuf` (escape hatch)
- `Jail::path()` exposure is acceptable (jail root is not secret and does not bypass validation).
- Jails are immutable — do not mutate the jail root after creation.

### Display & String Semantics

- `VirtualPath` display and `virtualpath_to_string()` are rooted (e.g., `"/a/b.txt"`); no borrowed string accessors are exposed.
- For system-facing strings/interop use `JailedPath::systempath_*` (and `VirtualPath` delegates to the same for the underlying system path).
- Do not reintroduce `virtualpath_to_str()` or `virtualpath_as_os_str()`.

### Internal Implementation Notes

- `StatedPath` is strictly internal — do not reference it in public docs, examples, or APIs.
- Windows 8.3 short-name handling is part of the validator; platform-specific tests may exist, but keep public surface platform-agnostic.

### Jail Creation

- `Jail::try_new(..)` requires the directory to exist; use `Jail::try_new_create(..)` when the directory should be created automatically.

## Known Pitfalls & Gotchas

- Cargo flags after `--` go to `rustc`/`clippy-driver`. Put cargo flags (like `--locked`) before `--`.
- Workspace lockfile coupling: excluding `examples` from the workspace avoids MSRV lock/feature conflicts.
- Windows short names (8.3) are treated as a potential escape vector; errors include `WindowsShortName`.
- Encoding: CI enforces UTF‑8 (no BOM) for key files.

## Common Commands

- Stable (root):
  - `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --workspace --verbose`
  - `cd examples && cargo build --bins --features with-zip`
- MSRV (library only):
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.70.0 cargo check --locked -p jailed-path --lib`
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.70.0 cargo clippy --locked -p jailed-path --lib --all-features -- -D warnings`
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.70.0 cargo test --locked -p jailed-path --lib`

## Do / Don’t (For Agents)

- Do:
  - Keep MSRV isolated to the library; build examples only on stable.
  - Add examples under `examples/src/bin/<category>/…` with descriptive names.
  - Use type‑state markers in examples to demonstrate compile‑time separation of jails.
  - Reference `API_REFERENCE.md` and `VIRTUAL_PATH_DESIGN.md` when updating APIs.
  - Prefer `systempath_as_os_str()` for `AsRef<Path>` interop; avoid leaking `Path`/`PathBuf`.
  - Use `join_systempath` / `join_virtualpath` instead of std `Path::join`.
  - For release/version bumps: update CHANGELOG with user-facing highlights, bump versions in Cargo.toml/lib.rs/README, tag the release, and include a concise PR summary (markdown, no code examples).
  - When crafting commit messages, summarize the staged diff by intent and impact.
- Don’t:
  - Reintroduce `examples` into `[workspace.members]`.
  - Move cargo flags after `--` (they won’t be recognized by cargo).
  - Use `.unjail()` / `.unvirtual()` in examples unless demonstrating escape hatches explicitly.
  - Invent new surface APIs without discussion; follow existing design patterns.
  - Deprecate APIs pre-0.1.0 — remove them cleanly instead when agreed.

## When In Doubt

- Favor smallest, safest change that:
  - Preserves MSRV 1.70.0 for the library.
  - Keeps examples compiling on stable.
  - Passes clippy/doc builds with `-D warnings` and keeps CI green on all OSes.
  - Aligns with the repository’s documentation and design files.
