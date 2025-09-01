# AGENTS.md

Operational guide for AI assistants, bots, and automation working in this repository.

## Project Overview

- Purpose: Prevent directory traversal with type‑safe path jails and safe symlinks.
- Core APIs: `Jail<Marker>`, `JailedPath<Marker>`, `VirtualRoot<Marker>`, `VirtualPath<Marker>`, `JailedPathError` (see API_REFERENCE.md).
- Security model: “Jail every external path.” Any path from untrusted inputs (HTTP, CLI, config, DB, LLMs, archives) must be validated into a jail‑enforced type (`JailedPath` or `VirtualPath`) before I/O.
- Library built on `soft-canonicalize` for resolution; Windows 8.3 short-name handling is considered a security surface.

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
  - Examples:
    - API usage examples: `cargo run --example <name>` (from main crate root)
    - Demo projects: `cd examples && cargo run --bin <name>` (from examples subcrate)
- Local scripts mirror the same MSRV behavior (see `ci-local.ps1`/`.sh`).

## Examples Policy (Non‑MSRV)

- `examples/` is a separate crate with `publish = false` and a path dependency on `../jailed-path`.
- Built only on the latest stable CI; examples may use newer ecosystem crates/features.
- Feature gating:
  - Use optional deps and namespaced features (e.g., `with-zip = ["dep:zip", "dep:flate2"]`).
  - Avoid implicit feature names removed in newer releases (e.g., `zip` 4.x no longer has an implicit `flate2` feature).
- Stable CI explicitly builds examples:
  - `cd examples && cargo build --bins --features with-zip` (local-only optional feature sets like `with-aws`, `with-app-path` may be enabled by developers but are not required in CI).
  - Demo projects must not require external services during CI. Provide offline simulations and guard servers or network calls behind env toggles (e.g., `EXAMPLES_RUN_SERVER=1`, `RUN_SERVER=1`, `EXAMPLES_S3_RUN=1`). Default behavior is offline/mock.
  - Demo projects must pass clippy with `-D warnings` on stable (lint all targets: `cd examples && cargo clippy --all-targets -- -D warnings`).

### Docs vs. Demo Projects (Very Important)

- Crate docs/README/lib.rs examples: teach the API. Keep them minimal, assertion-backed where helpful, and encode guarantees in function signatures (`&JailedPath<..>` / `&VirtualPath<..>`). These are doctested snippets.
- `examples/` subcrate: real‑world demo projects. No assertions in the flow; show realistic control paths and I/O. Use the type system in function signatures to encode guarantees, but avoid thin wrappers that mirror built‑ins — favor purposeful functions and coherent flows.
- Don’t over‑engineer demos. Keep them idiomatic and focused on integrating the API into a plausible application scenario.
 - Do not convert a `JailedPath` to `VirtualPath` just to print a user-facing path. For UI/display flows, construct a `VirtualPath` from a `VirtualRoot` and keep it; for system logs/interop, print the `JailedPath` directly.

### Examples Directory Structure (Critical)

**Two distinct types of examples with different locations:**

#### 1. API Usage Examples → `jailed-path/examples/`
- **Purpose**: Teach the API with minimal, focused code
- **Location**: `jailed-path/examples/*.rs` (main crate examples directory)
- **Run with**: `cargo run --example <name>` (from main crate root)
- **Content**: One-liners, basic usage patterns, API demonstrations

#### 2. Real Demo Projects → `examples/src/bin/`
- **Purpose**: Complete, realistic applications showing integration
- **Location**: `examples/src/bin/<category>/<name>.rs` (separate examples crate)
- **Run with**: `cargo run --bin <name>` (from examples/ directory)
- **Content**: Web servers, CLI tools, security demos, real-world scenarios

**Key Rules:**
- ✅ **API usage examples** go in `jailed-path/examples/` (main crate)
- ✅ **Demo projects** go in `examples/src/bin/<category>/` (examples subcrate)
- ❌ **Never mix them** - snippets don't belong in `examples/src/bin/`
- ❌ **Never move demo projects** to main crate examples

## Why Split Examples From The Workspace?

- Preserve MSRV: The library enforces Rust 1.70 with `--locked` in CI; examples often require newer crates that would otherwise raise the workspace MSRV via lockfile/feature coupling.
- Independent lifecycles: Examples evolve fast to showcase real integrations on latest stable; the library remains conservative for downstream users.
- Predictable CI: Stable job builds examples separately; MSRV job scopes to `-p jailed-path --lib` only. See `.github/workflows/ci.yml` for the split.

## CI Workflows (GitHub Actions)

- `ci.yml` (Test on stable):
  - Validates UTF‑8 encodings (no BOM) for critical files.
  - Formats (`cargo fmt --check`) and lints (`cargo clippy -D warnings`).
  - Builds examples on stable (`cd examples && cargo build --bins …`).
  - Runs tests for the library with all features enabled and builds docs with `-D warnings`.
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
- String formatting (Rust 1.58+): Never use bare `{}`. Always use captured identifiers: `format!("{path}")`, `println!("{vp}")`, `write!(f, "{item:?}")`. If no identifier exists, bind a short local and then use it (e.g., `let bytes = data.len(); println!("{bytes}")`). Prefer locals + captured identifiers when expressions are long or repeated.
- `*_to_string_lossy()` returns `Cow<'_, str>`; call `.into_owned()` only when an owned `String` is required.
- AsRef<Path> interop: never pass strings; use `systempath_as_os_str()` (allocation‑free, OS‑native) from `JailedPath`/`VirtualPath`.

### Anti-Patterns (Question First)

- JailedPath -> VirtualPath for printing: Converting just to display a virtual string is a smell. Prefer starting with `VirtualRoot::virtualpath_join(..)` and keeping a `VirtualPath` for user-facing flows, or print the `JailedPath` (system view) directly. Ask whether to refactor the flow to the correct dimension.
- String interop to AsRef<Path>: Passing `*_to_string_lossy()`, `*_to_str()`, or `PathBuf` where `AsRef<Path>` is expected. Use `systempath_as_os_str()` instead. Ask before changing signatures or behavior.
- std path ops on leaked paths: Using `Path::join`/`Path::parent`/etc. on values outside the jail types. Replace with jail-aware ops (`systempath_*` / `virtualpath_*`). Confirm scope of refactor.
- Formatting with bare {}: Use captured identifiers (`"{name}"`). If found, ask whether to update to locals + captured identifiers for readability or keep as-is if it’s truly a one-off expression.
- Forcing ownership from `Cow`: Calling `.into_owned()` on `*_to_string_lossy()` without a hard requirement for `String`. Ask if borrowing is acceptable; avoid extra allocations in hot paths.
- Leaky trait impls: Implementing `AsRef<Path>`, `Deref<Target = Path>`, or implicit `From/Into` conversions for jail types. These are forbidden; ask before any API surface changes that could weaken invariants.
- Escape hatches in examples: Using `.unvirtual()` / `.unjail()` outside a dedicated “escape hatches” section. Ask before introducing such flows.
- Exposing system paths in UI/JSON unintentionally: Prefer virtual paths for user-facing output. Ask when system paths are included for observability.
- Examples relying on external services by default: Must be guarded with env toggles and default to offline/mock. Ask before adding network dependencies.

### Linting, Doctests, and Hygiene

- Do not suppress lints via `#[allow(..)]` (exception: long type names when using internal `StatedPath` in tests where unavoidable).
- Doctests must compile and run — do not use `no_run` or `ignore`. Provide minimal setup and ensure teardown.
- Prefer verifying expected outputs in examples with Rust assertions (`assert!`, `assert_eq!`, etc.) instead of comment-only output; this both documents behavior and ensures examples are exercised by doctests.
- Tests and doctests must clean up any files or directories they create. Prefer `tempfile::tempdir()` for unit tests; remove any persistent paths at the end of doctests (e.g., `std::fs::remove_dir_all(..).ok()`).
- Feature‑gated tests: When adding optional features (e.g., `serde`), include targeted tests under `#[cfg(feature = "...")]` and ensure stable CI runs `--all-features` for the library.
 - When writing to nested paths in doctests/examples, create parent directories first using the dimension-appropriate parent:
   - VirtualPath: `if let Some(p) = vp.virtualpath_parent()? { p.create_dir_all()?; }`
   - JailedPath: `if let Some(p) = jp.systempath_parent()? { p.create_dir_all()?; }`
 - Doctests that use context-sensitive traits (e.g., serde `DeserializeSeed`) must import those traits explicitly inside the doctest.

### Documentation Guidelines (README.md / lib.rs / API docs)

- Keep README focused on why, core features, and simple-to-advanced examples; keep structure consistent across docs.
- When updating README.md, align relevant sections in `jailed-path/src/lib.rs` crate docs where appropriate.
- Document APIs so both humans and LLMs can use them correctly and safely; emphasize misuse-resistant patterns. Favor assertion-backed examples that encode correct usage and expected results to reduce ambiguity and prevent misuse.
- Before removing/changing established docs, consider rationale and align with design docs; prefer discussion for non-trivial changes.
- Integrations should be documented concisely (serde, Axum, app‑path):
  - Serde: `Serialize` for `JailedPath`/`VirtualPath`; deserialization is context‑aware via `serde_ext::WithJail(&jail)` / `serde_ext::WithVirtualRoot(&vroot)` or by deserializing to `String` and validating explicitly.
  - Axum: Keep library framework‑agnostic; show extractors/state patterns in examples.
  - app‑path: Use `app_path::app_path!(...)` and then jail the discovered directory before I/O.

### README Code Examples Policy

- Prefer reusing examples from source code comments (crate docs or module docs) that are doctested and compile.
- Examples must encode guarantees in function signatures: accept `&JailedPath<Marker>` / `&VirtualPath<Marker>` (or structs containing them) rather than operating on raw inputs. Treat built‑in I/O methods as convenience; do not present them as the primary security mechanism.
- When demonstrating expected output or behavior, present it using assertions (e.g., `assert_eq!(vpath.virtualpath_to_string_lossy(), "/a/b.txt");`) rather than comments like `// prints: ...`, whenever feasible. This keeps examples truthful, prevents drift, and proves behavior in doctests/CI.
- If you need a new README example:
  - First implement it as a real, compiling example (e.g., under `examples/`) or a doctested snippet in source comments.
  - Ensure it builds and passes locally (and on MSRV if applicable) before copying to README.
  - When transposing to README, keep the example faithful to the working version; omit only noisy setup/teardown that is not essential to illustrate usage.
  - Keep the working example around in the repo so future changes don’t drift (prefer `examples/` or doctests in `lib.rs`).
- Never invent or paste untested snippets in README. README examples must reflect current API, follow Path handling rules (no raw `Path`/`PathBuf` leaks; use `systempath_as_os_str()` for `AsRef<Path>`), and compile when provided the minimal context.
 - Do not add assertions in `examples/` subcrate demo projects; those are not tests.

### Path Handling Rules (Very Important)

- Do not expose raw `Path`/`PathBuf` from `JailedPath`/`VirtualPath` in public APIs or examples.
- Avoid using std path methods (`Path::join`, `Path::parent`, etc.) on leaked paths;
  these ignore virtual-root clamping and jail checks and can cause confusion or unsafe behavior.
- Use explicit, jail-aware operations instead:
  - `JailedPath::systempath_join`, `JailedPath::systempath_parent`
  - `VirtualPath::virtualpath_join`, `VirtualPath::virtualpath_parent`
 - Parent creation follows the active dimension — do not unvirtualize just for parent ops:
   - Virtual flow: use `virtualpath_parent()` and operate on the returned `VirtualPath`.
   - System flow: use `systempath_parent()` and operate on the returned `JailedPath`.
- Switching views: prefer staying in one dimension (system vs virtual) for a given flow. If you need an operation from the other dimension, explicitly upgrade with `JailedPath::virtualize()` or downgrade with `VirtualPath::unvirtual()` for that edge case.
- When passing to external APIs that accept `AsRef<Path>`, prefer borrowing the inner system path:
  - `jailed_path.systempath_as_os_str()` (allocation-free, OS-native string, preserves data)
- Only demonstrate ownership escape hatches in a dedicated example section:
  - `.unvirtual()` (to go from VirtualPath -> JailedPath)
  - `.unjail()` (to obtain an owned `PathBuf`, losing guarantees)
  - `.unvirtual().unjail()` (explicit two-step escape)
  Everywhere else, prefer borrowing with `systempath_as_os_str()`.

### Preferred vs. Anti-Patterns

- Preferred: `fs::copy(src.systempath_as_os_str(), dst.systempath_as_os_str())`
  - Anti-pattern: `fs::copy(src.systempath_to_string_lossy().as_ref(), ..)` (string interop; loses fidelity/allocates).
- Preferred: `let vp = vroot.virtualpath_join("a/b.txt")?; println!("{vp}");`
  - Anti-pattern: `jp.clone().virtualize()` just to print; start with `VirtualPath` for UI flows.
- Preferred: `jp.systempath_join("child.txt")?` or `vp.virtualpath_join("child.txt")?`
  - Anti-pattern: `leaked_path.join("child.txt")` (std join ignores jail/virtual semantics).
- Preferred: Borrow `Cow<'_, str>` from `*_to_string_lossy()`; convert only when required
  - Anti-pattern: Calling `.into_owned()` eagerly with no `String` requirement.
- Preferred: Small locals + captured identifiers for readability
  - Anti-pattern: Bare `{}` or long inline expressions; use `let bytes = data.len(); println!("{bytes}")`.

### Naming Rationale (Explicit Ops)

- Be explicit so mistakes are visible at a glance. Method names encode the dimension they operate on (this applies to all explicit variants, not just `join`):
  - `Path::join(..)` or `xpath.join(..)`: unsafe std join (can escape the jail); avoid on untrusted inputs.
  - `JailedPath::systempath_join(..)`: safe system-path join (validated to not escape the jail).
  - `VirtualPath::virtualpath_join(..)`: safe virtual join (clamped to the virtual root).
- **CRITICAL SECURITY DISTINCTION**: `std::path::Path::join("/absolute")` completely replaces the base path, making it the #1 cause of path traversal vulnerabilities. Our types prevent this:
  - `systempath_join("/absolute")`: validates the result stays within jail bounds, returns error if not.
  - `virtualpath_join("/absolute")`: clamps absolute paths to virtual root (e.g., "/etc/passwd" → "/").
- The same pattern holds for other operations: `systempath_parent`/`virtualpath_parent`, `systempath_with_file_name`/`virtualpath_with_file_name`, `systempath_with_extension`/`virtualpath_with_extension`, `systempath_starts_with`/`virtualpath_starts_with`, etc.
- This convention helps reviewers spot API abuse without hunting for type declarations in scope.

### API & Conversion Rules (Important)

- `JailedPath` MUST NOT implement `AsRef<Path>`/`Deref<Target = Path>` and MUST NOT expose raw `&Path`.
- Conversions are explicit only — do not add `From`/`Into` between `JailedPath` and `VirtualPath`.
  - `Jail::systempath_join(..) -> JailedPath`
  - `JailedPath::virtualize() -> VirtualPath`
  - `VirtualPath::unvirtual() -> JailedPath`
  - `JailedPath::unjail() -> PathBuf` (escape hatch)
- `Jail::path()` exposure is acceptable (jail root is not secret and does not bypass validation).
- Jails are immutable — do not mutate the jail root after creation.

### Display & String Semantics

- `VirtualPath` display and `virtualpath_to_string()` are rooted (e.g., `"/a/b.txt"`); no borrowed string accessors are exposed.
- For system-facing strings/interop use `JailedPath::systempath_*` (and `VirtualPath` delegates to the same for the underlying system path).
- Do not reintroduce `virtualpath_to_str()` or `virtualpath_as_os_str()`.
- `Debug` for `VirtualPath` is developer-facing and verbose: shows system path, virtual view, jail root, and marker type. `Display` shows the rooted virtual view for users.
- `Debug` for `Jail` and `VirtualRoot` shows the real root path and marker type. `Display` shows the real root path.

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
  - `cargo test -p jailed-path --all-features --verbose`
  - `cd examples && cargo build --bins --features with-zip` (locally, you may add `--features with-aws,with-app-path` as needed)
- MSRV (library only):
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.70.0 cargo check --locked -p jailed-path --lib`
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.70.0 cargo clippy --locked -p jailed-path --lib --all-features -- -D warnings`
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.70.0 cargo test --locked -p jailed-path --lib`

## Do / Don’t (For Agents)

- Do:
  - Keep MSRV isolated to the library; build examples only on stable.
  - Add demo projects under `examples/src/bin/<category>/…` with descriptive names.
  - Add API usage examples under `jailed-path/examples/*.rs` for teaching the API.
- Use type‑state markers in examples to demonstrate compile‑time separation of jails.
  - Note on inference: core types default to `Marker = ()`. Let-bindings often suffice for inference (e.g., `let vroot: VirtualRoot = ...; let vp = vroot.virtualpath_join("a.txt")?;`). When the compiler needs help, prefer adding an explicit type or an empty turbofish (`VirtualRoot::<()>::try_new(..)`). Avoid turbofish unless necessary or clearer.
  - Reference `API_REFERENCE.md` when updating APIs.
  - Prefer `systempath_as_os_str()` for `AsRef<Path>` interop; avoid leaking `Path`/`PathBuf`.
  - Use `systempath_join` / `virtualpath_join` instead of std `Path::join`.
  - For release/version bumps: update CHANGELOG with user-facing highlights, bump versions in Cargo.toml/lib.rs/README, tag the release, and include a concise PR summary (markdown, no code examples).
  - When crafting commit messages, summarize the staged diff by intent and impact.
- Don't:
  - Reintroduce `examples` into `[workspace.members]`.
  - Move cargo flags after `--` (they won't be recognized by cargo).
  - Use `.unjail()` / `.unvirtual()` in examples unless demonstrating escape hatches explicitly.
  - Put API usage examples in `examples/src/bin/` - they belong in `jailed-path/examples/`.
  - Put demo projects in `jailed-path/examples/` - they belong in `examples/src/bin/<category>/`.
  - Invent new surface APIs without discussion; follow existing design patterns.
  - Deprecate APIs pre-0.1.0 — remove them cleanly instead when agreed.

## When In Doubt

- Favor smallest, safest change that:
  - Preserves MSRV 1.70.0 for the library.
  - Keeps examples compiling on stable.
  - Passes clippy/doc builds with `-D warnings` and keeps CI green on all OSes.
  - Aligns with the repository’s documentation and design files.


