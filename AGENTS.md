# AGENTS.md

Operational guide for AI assistants, bots, and automation working in this repository.

## Project Overview

- Purpose: Prevent directory travers- Leaky trait impls: Implementing `AsRef<Path>`, `Deref<Target = Path>`, or implicit `From/Into` conversions for restriction types. These are forbidden; ask before any API surface changes that could weaken invariants.
- Escape hatches in examples: Using `.unvirtual()` / `.unrestrict()` outside a dedicated "escape hatches" section. Ask before introducing such flows. with type‑safe path restrictions and safe symlinks.
- Core APIs: `RestrictionPath<Marker>`, `StrictPath<Marker>`, `VirtualRoot<Marker>`, `VirtualPath<Marker>`, `StrictPathError` (see API_REFERENCE.md).
- Security model: "Restrict every external path." Any path from untrusted inputs (user I/O, config, DB, LLMs, archives) must be validated into a restriction‑enforced type (`StrictPath` or `VirtualPath`) before I/O.
- Library built on `soft-canonicalize` for resolution; Windows 8.3 short-name handling is considered a security surface.

## Don't:

  - **CRITICAL: Never wrap secure types in `Path::new()` or `PathBuf::from()`**. This defeats all security guarantees and is a critical anti-pattern. Use `interop_path()` directly for external APIs.
  - Reintroduce `examples` into `[workspace.members]`.
  - Move cargo flags after `--` (they won't be recognized by cargo).
  - Do not create new helper functions without prior approval. If a helper seems unavoidable, do not just create it — offer the design, explain why it's needed, and ask to implement it (scope, signature, naming, tests, and security notes).
  - Use `.unrestrict()` / `.unvirtual()` in examples unless demonstrating escape hatches explicitly.
  - Put API usage examples in `examples/src/bin/` - they belong in `jailed-path/examples/`.
  - Put demo projects in `jailed-path/examples/` - they belong in `examples/src/bin/<category>/`.
  - Use verbose variable names in TempDir examples; always use the clean shadowing pattern: `let tmp_dir = tempfile::tempdir()?; let tmp_dir = RestrictionPath::try_new(tmp_dir)?;`
  - Invent new surface APIs without discussion; follow existing design patterns.
  - Deprecate APIs pre-0.1.0 — remove them cleanly instead when agreed.
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

- MSRV: Rust 1.71.0 (declared in `jailed-path/Cargo.toml`).
- CI (GitHub Actions) `msrv` job:
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo check --locked -p jailed-path --lib --verbose`
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo clippy --locked -p jailed-path --lib --all-features -- -D warnings`
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo test --locked -p jailed-path --lib --verbose`
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

- Crate docs/README/lib.rs examples: teach the API. Keep them minimal, assertion-backed where helpful, and encode guarantees in function signatures (`&StrictPath<..>` / `&VirtualPath<..>`). These are doctested snippets.
- `examples/` subcrate: real‑world demo projects. No assertions in the flow; show realistic control paths and I/O. Use the type system in function signatures to encode guarantees, but avoid thin wrappers that mirror built‑ins — favor purposeful functions and coherent flows.
- Don’t over‑engineer demos. Keep them idiomatic and focused on integrating the API into a plausible application scenario.
 - Do not convert a `StrictPath` to `VirtualPath` just to print a user-facing path. For UI/display flows, construct a `VirtualPath` from a `VirtualRoot` and keep it; for system logs/interop, print the `StrictPath` directly.

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

- Preserve MSRV: The library enforces Rust 1.71 with `--locked` in CI; examples often require newer crates that would otherwise raise the workspace MSRV via lockfile/feature coupling.
- Independent lifecycles: Examples evolve fast to showcase real integrations on latest stable; the library remains conservative for downstream users.
- Predictable CI: Stable job builds examples separately; MSRV job scopes to `-p jailed-path --lib` only. See `.github/workflows/ci.yml` for the split.

## CI Workflows (GitHub Actions)

- `ci.yml` (Test on stable):
  - Validates UTF‑8 encodings (no BOM) for critical files.
  - Formats (`cargo fmt --check`) and lints (`cargo clippy -D warnings`).
  - Builds examples on stable (`cd examples && cargo build --bins …`).
  - Runs tests for the library with all features enabled and builds docs with `-D warnings`.
- `ci.yml` (MSRV):
  - Installs Rust 1.71.0 + clippy; runs check/clippy/test against `-p jailed-path` with `--locked`.
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
  - Ensure `rustup` toolchain `1.71.0` and clippy component are installed for MSRV.

### Before Committing

- On Windows, run `./ci-local.ps1`.
- On Unix/WSL, run `bash ci-local.sh`.
- Assume only staged changes are intended for commit; run `git diff --staged` and write a message that summarizes intent and impact (not a mechanical diff narration). Do not mention anything not present in the staged diff.

## Coding & Dependency Guidelines

- Library (`jailed-path`):
  - Maintain MSRV 1.71.0; avoid deps that raise MSRV without discussion.
  - Keep the dependency graph small and stable; forbid unsafe code; pass clippy with `-D warnings`.
  - Follow current module layout: `src/error`, `src/path`, `src/validator`, public re‑exports in `src/lib.rs`.
- Examples (`examples`):
  - It’s OK to use newer crates; keep heavy deps optional with namespaced features.
  - Do not add `examples` back into the workspace; keep `publish = false`.

### Code Style

- Clippy: `cargo clippy --all-targets --all-features -- -D warnings` (MSRV job uses scoped flags; keep code clean).
- Formatting: `cargo fmt --all -- --check`.
- Follow Rust API Guidelines and best practices.
- Import style: Avoid overly verbose fully qualified paths in code. Use proper `use` statements at the top of modules/files instead of long paths like `crate::validator::restriction_path::RestrictionPath::<Type>`. This improves readability and maintainability.
- **Function signatures enforce safety**: Functions should accept `&StrictPath<Marker>` or `&VirtualPath<Marker>` instead of `String`/`&str`/`PathBuf` for path parameters. This makes functions safe by design - validation happens once at the boundary creation, and the type system prevents unsafe usage. ❌ `fn process(path: String)` ✅ `fn process(path: &StrictPath<Files>)`. The caller handles validation once when creating the path from external input.
- **Variable naming**: Use descriptive variable names that clearly indicate the purpose and domain, not just the type. **CRITICAL: `PathBoundary` variables should be named based on what they represent, not that they're boundaries** (e.g., `config_dir`, `user_data`, `temp_dir`, `uploads_dir`, `static_files_dir`). This makes code read naturally: `config_dir.strict_join("app.toml")` reads as "config directory strict join app.toml". For individual files use descriptive names (e.g., `logo_file`, `config_file`). **NEVER** use type-based names like `boundary`, `restriction`, `jail` as variable names - these tell you nothing about what the variable represents. Avoid meaningless prefixes like `jail_`, `boundary_`, `restriction_` or ambiguous abbreviations like `img`, `usr`, `cfg` that don't clearly indicate the variable's purpose or domain.
- String formatting (Rust 1.58+): Never use bare `{}`. Always use captured identifiers: `format!("{path}")`, `println!("{vp}")`, `write!(f, "{item:?}")`. If no identifier exists, bind a short local and then use it (e.g., `let bytes = data.len(); println!("{bytes}")`). Prefer locals + captured identifiers when expressions are long or repeated.
- `*_to_string_lossy()` returns `Cow<'_, str>`; call `.into_owned()` only when an owned `String` is required.
- Preferred for AsRef<Path> interop: use `interop_path()` on `StrictPath`/`VirtualPath` (allocation-free, OS-native). Older references to `strictpath_as_os_str()` refer to the same concept.
- **For displaying paths**: Use `strictpath_display()` for `RestrictionPath`/`StrictPath`, or `virtualpath_display()` for `VirtualPath`. For `VirtualRoot`, use `vroot.as_unvirtual().strictpath_display()`. NOT `.interop_path().to_string_lossy()`. The `interop_path()` method is for external API interop, while `*_display()` methods are specifically for human-readable output.
- AsRef<Path> interop: never pass strings; use `interop_path()` (allocation-free, OS-native) from `StrictPath`/`VirtualPath`.
 - **Never wrap paths in `Path::new()` unnecessarily**: APIs that accept `AsRef<Path>` (like `PathBoundary::try_new()`) can take `&str` directly. ❌ `PathBoundary::try_new(Path::new(&path))?` ✅ `PathBoundary::try_new(&path)?` or `PathBoundary::try_new(path_var)?`. Only use `Path::new()` when you need `Path` methods like `.parent()` or `.file_name()`.
 - Tests/Examples readability: never wrap `interop_path()` in `Path::new(..)` or `PathBuf::from(..)`.
   - Prefer passing `interop_path()` directly to APIs taking `AsRef<Path>`.
   - For equality in assertions, compare `interop_path()` to `canonicalize().unwrap().as_os_str()` when matching a concrete filesystem path.

### Anti-Patterns (Question First)

- **Type-based variable naming**: Naming variables after their types instead of their purpose. ❌ `let boundary = PathBoundary::try_new("./config")?;` ✅ `let config_dir = PathBoundary::try_new("./config")?;`. ❌ `extract_boundary` ✅ `extract_dir` or `extraction_dir`. The variable name should describe what domain/purpose it serves, not just that it's a PathBoundary.
- **Functions accepting raw strings instead of safe types**: ❌ `fn serve_file(path: String)` then validating inside ✅ `fn serve_file(path: &StrictPath<StaticFiles>)`. **CRITICAL PRINCIPLE: Make functions safe by design through their signatures, not through runtime validation inside the function.** The type system should enforce safety, preventing unsafe calls at compile time. Functions that accept `String`/`&str`/`PathBuf` for paths are inherently unsafe and shift validation burden to every caller.
- Using `.interop_path().to_string_lossy()` for display: This mixes interop concerns with display concerns. Use `strictpath_display()` or `virtualpath_display()` for human-readable output. Reserve `interop_path()` for external API interop only.
- StrictPath -> VirtualPath for printing: Converting just to display a virtual string is a smell. Prefer starting with `VirtualRoot::virtual_join(..)` and keeping a `VirtualPath` for user-facing flows, or print the `StrictPath` (system view) directly. Ask whether to refactor the flow to the correct dimension.
- String interop to AsRef<Path>: Passing `*_to_string_lossy()`, `*_to_str()`, or `PathBuf` where `AsRef<Path>` is expected. Use `interop_path()` instead. Ask before changing signatures or behavior.
- std path ops on leaked paths: Using `Path::join`/`Path::parent`/etc. on values outside the restriction types. Replace with restriction-aware ops (`strictpath_*` / `virtualpath_*`). Confirm scope of refactor.
- Formatting with bare {}: Use captured identifiers (`"{name}"`). If found, ask whether to update to locals + captured identifiers for readability or keep as-is if it’s truly a one-off expression.
- Forcing ownership from `Cow`: Calling `.into_owned()` on `*_to_string_lossy()` without a hard requirement for `String`. Ask if borrowing is acceptable; avoid extra allocations in hot paths.
- Leaky trait impls: Implementing `AsRef<Path>`, `Deref<Target = Path>`, or implicit `From/Into` conversions for jail types. These are forbidden; ask before any API surface changes that could weaken invariants.
- Escape hatches in examples: Using `.unvirtual()` / `.unrestrict()` outside a dedicated “escape hatches” section. Ask before introducing such flows.
- Exposing system paths in UI/JSON unintentionally: Prefer virtual paths for user-facing output. Ask when system paths are included for observability.
- Examples relying on external services by default: Must be guarded with env toggles and default to offline/mock. Ask before adding network dependencies.

### Linting, Doctests, and Hygiene

- Do not suppress lints via `#[allow(..)]` (exception: long type names when using internal `PathHistory` in tests where unavoidable).
- Doctests must compile and run — do not use `no_run` or `ignore`. Provide minimal setup and ensure teardown.
- Prefer verifying expected outputs in examples with Rust assertions (`assert!`, `assert_eq!`, etc.) instead of comment-only output; this both documents behavior and ensures examples are exercised by doctests.
- Tests and doctests must clean up any files or directories they create. Prefer `tempfile::tempdir()` for unit tests; remove any persistent paths at the end of doctests (e.g., `std::fs::remove_dir_all(..).ok()`).
- Feature‑gated tests: When adding optional features (e.g., `serde`), include targeted tests under `#[cfg(feature = "...")]` and ensure stable CI runs `--all-features` for the library.
 - When writing to nested paths in doctests/examples, create parent directories first using the dimension-appropriate parent:
   - VirtualPath: `if let Some(p) = vp.virtualpath_parent()? { p.create_dir_all()?; }`
   - StrictPath: `if let Some(p) = jp.strictpath_parent()? { p.create_dir_all()?; }`
 - Doctests that use context-sensitive traits (e.g., serde `DeserializeSeed`) must import those traits explicitly inside the doctest.

### Documentation Guidelines (README.md / lib.rs / API docs)

- Keep README focused on why, core features, and simple-to-advanced examples; keep structure consistent across docs.
- When updating README.md, align relevant sections in `jailed-path/src/lib.rs` crate docs where appropriate.
- Document APIs so both humans and LLMs can use them correctly and safely; emphasize misuse-resistant patterns. Favor assertion-backed examples that encode correct usage and expected results to reduce ambiguity and prevent misuse.
- Before removing/changing established docs, consider rationale and align with design docs; prefer discussion for non-trivial changes.
- Integrations should be documented concisely (serde, Axum, app‑path):
  - Serde: `Serialize` for `StrictPath`/`VirtualPath`; deserialization is context‑aware via `serde_ext::WithRestriction(&restriction)` / `serde_ext::WithVirtualRoot(&vroot)` or by deserializing to `String` and validating explicitly.
  - Axum: Keep library framework‑agnostic; show extractors/state patterns in examples.
  - app‑path: Use `app_path::app_path!(...)` and then restrict the discovered directory before I/O.

### README Code Examples Policy

- Prefer reusing examples from source code comments (crate docs or module docs) that are doctested and compile.
- Examples must encode guarantees in function signatures: accept `&StrictPath<Marker>` / `&VirtualPath<Marker>` (or structs containing them) rather than operating on raw inputs. Treat built‑in I/O methods as convenience; do not present them as the primary security mechanism.
- When demonstrating expected output or behavior, present it using assertions (e.g., `assert_eq!(vpath.virtualpath_to_string_lossy(), "/a/b.txt");`) rather than comments like `// prints: ...`, whenever feasible. This keeps examples truthful, prevents drift, and proves behavior in doctests/CI.
- If you need a new README example:
  - First implement it as a real, compiling example (e.g., under `examples/`) or a doctested snippet in source comments.
  - Ensure it builds and passes locally (and on MSRV if applicable) before copying to README.
  - When transposing to README, keep the example faithful to the working version; omit only noisy setup/teardown that is not essential to illustrate usage.
  - Keep the working example around in the repo so future changes don’t drift (prefer `examples/` or doctests in `lib.rs`).
- Never invent or paste untested snippets in README. README examples must reflect current API, follow Path handling rules (no raw `Path`/`PathBuf` leaks; use `interop_path()` for `AsRef<Path>`), and compile when provided the minimal context.
 - Do not add assertions in `examples/` subcrate demo projects; those are not tests.

### Path Handling Rules (Very Important)

- Do not expose raw `Path`/`PathBuf` from `StrictPath`/`VirtualPath` in public APIs or examples.
- Avoid using std path methods (`Path::join`, `Path::parent`, etc.) on leaked paths;
  these ignore virtual-root clamping and restriction checks and can cause confusion or unsafe behavior.
- Use explicit, restriction-aware operations instead:
  - `StrictPath::strict_join`, `StrictPath::strictpath_parent`
  - `VirtualPath::virtual_join`, `VirtualPath::virtualpath_parent`
 - Parent creation follows the active dimension — do not unvirtualize just for parent ops:
   - Virtual flow: use `virtualpath_parent()` and operate on the returned `VirtualPath`.
   - System flow: use `strictpath_parent()` and operate on the returned `StrictPath`.
- Switching views: prefer staying in one dimension (system vs virtual) for a given flow. If you need an operation from the other dimension, explicitly upgrade with `StrictPath::virtualize()` or downgrade with `VirtualPath::unvirtual()` for that edge case.
- When passing to external APIs that accept `AsRef<Path>`, prefer borrowing the inner system path:
  - `jailed_path.interop_path()` (allocation-free, OS-native string, preserves data)
- Only demonstrate ownership escape hatches in a dedicated example section:
  - `.unvirtual()` (to go from VirtualPath -> StrictPath)
  - `.unrestrict()` (to obtain an owned `PathBuf`, losing guarantees)
  - `.unvirtual().unrestrict()` (explicit two-step escape)
  Everywhere else, prefer borrowing with `interop_path()`.

### Constructor Parameter Design: `AsRef<Path>` Choice

**Design Decision**: All constructors (`RestrictionPath::try_new*`, `VirtualRoot::try_new*`) use `AsRef<Path>` for maximum ergonomics and compatibility.

**Rationale**:
- **Maximum Ergonomics**: Accepts all common path types (`&str`, `String`, `&Path`, `PathBuf`, `TempDir`, etc.)
- **Clean Shadowing Pattern**: Enables elegant variable shadowing with `TempDir`:
  ```rust
  let tmp_dir = tempfile::tempdir()?;
  let tmp_dir = RestrictionPath::try_new(tmp_dir)?; // Clean transition from TempDir to RestrictionPath
  ```
- **Standard Library Consistency**: Follows the same pattern as `std::fs` functions
- **Broad Compatibility**: Works with any type that can be borrowed as `&Path`

**Alternative Considered**: `Into<PathBuf>` was evaluated for potential performance benefits (single conversion, no allocations in error paths), but the ergonomic advantages of `AsRef<Path>` outweighed the performance considerations, especially for the common TempDir usage pattern in tests and examples.

**Usage Examples**:
```rust
// All of these work seamlessly:
RestrictionPath::try_new("/tmp")?;                    // &str
RestrictionPath::try_new(String::from("/tmp"))?;      // String  
RestrictionPath::try_new(Path::new("/tmp"))?;         // &Path
RestrictionPath::try_new(PathBuf::from("/tmp"))?;     // PathBuf
RestrictionPath::try_new(tempfile::tempdir()?)?;      // TempDir (key advantage!)

// Enables clean variable shadowing:
let tmp_dir = tempfile::tempdir()?;
let tmp_dir = RestrictionPath::try_new(tmp_dir)?;  // Elegant transition
```

### Preferred vs. Anti-Patterns

- Preferred: `fs::copy(src.interop_path(), dst.interop_path())`
  - Anti-pattern: `fs::copy(src.strictpath_to_string_lossy().as_ref(), ..)` (string interop; loses fidelity/allocates).
- Preferred: `let vp = vroot.virtual_join("a/b.txt")?; println!("{vp}");`
  - Anti-pattern: `jp.clone().virtualize()` just to print; start with `VirtualPath` for UI flows.
- Preferred: `jp.strict_join("child.txt")?` or `vp.virtual_join("child.txt")?`
  - Anti-pattern: `leaked_path.join("child.txt")` (std join ignores jail/virtual semantics).
- Preferred: Borrow `Cow<'_, str>` from `*_to_string_lossy()`; convert only when required
  - Anti-pattern: Calling `.into_owned()` eagerly with no `String` requirement.
- Preferred: Small locals + captured identifiers for readability
  - Anti-pattern: Bare `{}` or long inline expressions; use `let bytes = data.len(); println!("{bytes}")`.

### Code Style for Examples and Tests

**TempDir Variable Shadowing Pattern** (REQUIRED for all examples):
Use clean variable shadowing when transitioning from `TempDir` to `RestrictionPath`/`VirtualRoot`:

```rust
// ✅ PREFERRED: Clean variable shadowing pattern
let tmp_dir = tempfile::tempdir()?;
let tmp_dir = RestrictionPath::try_new(tmp_dir)?;  // Shadow the variable name

let tmp_dir = tempfile::tempdir()?;
let tmp_dir = VirtualRoot::try_new(tmp_dir)?;      // Also works for VirtualRoot
```

```rust
// ❌ AVOID: Verbose variable names that don't show the pattern
let temp_dir = tempfile::tempdir()?;
let restriction = RestrictionPath::try_new(temp_dir)?;
let vroot = VirtualRoot::try_new(temp_dir.path())?;
```

**One-Liner Pattern Extensions**:
For "one-liner" examples, extend the clean shadowing pattern to complete method chains, eliminating ALL intermediate variables:

```rust
// ✅ TRUE ONE-LINER: Complete method chain with single variable lifecycle
let tmp_dir = tempfile::tempdir()?;
let tmp_dir = RestrictionPath::try_new(tmp_dir)?.strict_join("file.txt")?.write_string("content")?;

// ❌ NOT A ONE-LINER: Multiple variables break the pattern
let tmp_dir = tempfile::tempdir()?;
let safe_dir = RestrictionPath::try_new(tmp_dir.path())?;  // Unnecessary intermediate variable
safe_dir.strict_join("file.txt")?.write_string("content")?;
```

**Rationale**: 
- Shows the clean transition from raw directory to restricted type
- Prevents accidental use of the raw `TempDir` after restriction creation
- Demonstrates the ergonomic benefits of our `AsRef<Path>` API design
- Makes examples more readable and highlights the security upgrade

**Implementation**: This pattern is enabled by our `AsRef<Path>` constructor design, which accepts `TempDir` directly without requiring `.path()` or `.as_ref()` calls.

### Naming Rationale (Explicit Ops)

- Be explicit so mistakes are visible at a glance. Method names encode the dimension they operate on (this applies to all explicit variants, not just `join`):
  - `Path::join(..)` or `xpath.join(..)`: unsafe std join (can escape the restriction); avoid on untrusted inputs.
  - `StrictPath::strict_join(..)`: safe system-path join (validated to not escape the restriction).
  - `VirtualPath::virtual_join(..)`: safe virtual join (clamped to the virtual root).
- **CRITICAL SECURITY DISTINCTION**: `std::path::Path::join("/absolute")` completely replaces the base path, making it the #1 cause of path traversal vulnerabilities. Our types prevent this:
  - `strict_join("/absolute")`: validates the result stays within restriction bounds, returns error if not.
  - `virtual_join("/absolute")`: clamps absolute paths to virtual root (e.g., "/etc/passwd" → "/").
- The same pattern holds for other operations: `strictpath_parent`/`virtualpath_parent`, `strictpath_with_file_name`/`virtualpath_with_file_name`, `strictpath_with_extension`/`virtualpath_with_extension`, `strictpath_starts_with`/`virtualpath_starts_with`, etc.
- This convention helps reviewers spot API abuse without hunting for type declarations in scope.

### Design Rationale: Strict vs Virtual Terminology

**Why "Strict" vs "Virtual"**: The naming choice is based on behavioral expectations:
- **`strict_join()`**: Suggests strict validation that **rejects** operations that would escape boundaries. This aligns with the security-first approach where potentially dangerous operations fail explicitly.
- **`virtual_join()`**: Suggests virtualization that **clamps/constrains** operations to stay within boundaries. This aligns with filesystem virtualization where paths are transparently redirected.

**User Experience Benefits**:
- Method names telegraph expected behavior: `strict_*` methods will error on boundary violations, `virtual_*` methods will clamp/redirect
- Reduces cognitive load when choosing between jail vs virtual root patterns
- Makes security reviews easier by making failure modes explicit in method names

### API & Conversion Rules (Important)

- **NEVER wrap secure types in `Path::new()` or `PathBuf::from()`** — this is a critical security anti-pattern that completely bypasses validation. Use `interop_path()` directly for external APIs.
- `StrictPath` MUST NOT implement `AsRef<Path>`/`Deref<Target = Path>` and MUST NOT expose raw `&Path`.
- Conversions are explicit only — do not add `From`/`Into` between `StrictPath` and `VirtualPath`.
  - `RestrictionPath::strict_join(..) -> StrictPath`
  - `StrictPath::virtualize() -> VirtualPath`
  - `VirtualPath::unvirtual() -> StrictPath`
  - `StrictPath::unrestrict() -> PathBuf` (escape hatch)
- `RestrictionPath::interop_path()` exposure is acceptable (restriction root is not secret and does not bypass validation).
- Restrictions are immutable — do not mutate the restriction root after creation.

### Display & String Semantics

- `VirtualPath` display and `virtualpath_to_string()` are rooted (e.g., `"/a/b.txt"`); no borrowed string accessors are exposed.
- For system-facing strings/interop use `StrictPath::strictpath_*` and `interop_path()` (and `VirtualPath` delegates to `interop_path()` for the underlying system path).
- Do not reintroduce `virtualpath_to_str()` or `virtualpath_as_os_str()`.
- `Debug` for `VirtualPath` is developer-facing and verbose: shows system path, virtual view, restriction root, and marker type. `Display` shows the rooted virtual view for users.
- `Debug` for `RestrictionPath` and `VirtualRoot` shows the real root path and marker type. `Display` shows the real root path.

### Internal Implementation Notes

- `PathHistory` is strictly internal - do not reference it in public docs, examples, or APIs.
- Windows 8.3 short-name handling is part of the validator; platform-specific tests may exist, but keep public surface platform-agnostic.

### PathHistory Usage (Internal)

- Scope: internal only; never expose `PathHistory` in public APIs, examples, or docs.
- Why: provides a single source of truth for path normalization, clamping, canonicalization, and boundary checks. Avoids duplication across validators and keeps security fixes centralized.
- States: `Raw`, `Virtualized`, `AnchoredCanonicalized`, `Canonicalized`, `Exists`, `BoundaryChecked` — use the type state to document progress.
- Naming: for the history generic, prefer `H` in code (e.g., `PathHistory<H>`). If you use a descriptive generic in prose/examples, prefer `History` over `State` (e.g., `SomeTypeHistory<History>`).
- Typical flows:
  - Construct: `let raw = PathHistory::<Raw>::new(input_path);`
  - UI/Virtual flow: `let a = raw.canonicalize_anchored(&restriction)?; let b = a.boundary_check(restriction.interop_path())?;`
  - System flow: `let c = raw.canonicalize()?;`
  - Verify exists (for restriction roots): `let e = c.verify_exists().ok_or(..)?;`
  - Boundary check: `let b = c.boundary_check(restriction.interop_path())?;`
- Where to use:
  - `RestrictionPath::try_new`: `Raw -> Canonicalized -> Exists` for the restriction root.
  - `RestrictionPath::strict_join`: canonicalize + boundary check (system flows).
  - `VirtualRoot::virtual_join`: `Raw -> AnchoredCanonicalized -> BoundaryChecked` then construct `StrictPath` and `VirtualPath`.
  - `VirtualPath` mutations (`virtual_join`, `virtualpath_parent`, `virtualpath_with_*`): compute candidate virtual path, then `Raw -> AnchoredCanonicalized -> BoundaryChecked` with the same restriction.
- Don’t:
  - Re-implement virtual clamping or boundary logic in free functions - call `PathHistory` methods instead.
  - Re‑export internal helpers; prefer instance methods (`RestrictionPath::strict_join`).

### Anchored Canonicalization Type-State

- `canonicalize_anchored(&restriction)` returns `PathHistory<(H, AnchoredCanonicalized)>` to distinguish anchored resolution from plain `Canonicalized`.
- After boundary check, convert to the canonicalized marker only when constructing `StrictPath` using `erase_anchor()` to avoid widening public surface types.
- Do not use raw `PathBuf` where `PathHistory` can preserve the type-state; avoid side-stepping the type system.
- Windows note: 8.3 short-name detection is enforced in the internal helper used by `RestrictionPath::strict_join`; keep the platform-specific guard centralized there rather than duplicating in `PathHistory`.

### Generics & Imports

- Prefer crate re-exports: import from the crate root to keep examples readable.
  - `use jailed_path::{Jail, JailedPath, VirtualRoot, VirtualPath};`
  - Avoid deep module paths like `crate::validator::virtual_root::VirtualRoot` in examples/tests.
- Default marker `()`:
  - Prefer left-hand type annotation when you need to spell the type: `let vroot: VirtualRoot = VirtualRoot::try_new(path)?;` (defaults to `VirtualRoot<()>`).
  - Use turbofish only when necessary (e.g., no LHS type to guide inference, or a non-default marker): `let vroot = VirtualRoot::<()>::try_new(path)?;` or `VirtualRoot::<MyMarker>::try_new(..)`.
  - For one-liners that don’t bind a variable, turbofish with `::<()>` is acceptable.
- Custom markers: declare a marker type and annotate where clarity matters: `struct Uploads; let root: VirtualRoot<Uploads> = VirtualRoot::try_new("uploads")?;`.

### Helper Functions Policy

- First choice: use existing APIs - compose `PathHistory` methods with `RestrictionPath::strict_join` and `VirtualRoot::virtual_join` instead of adding new helpers.
- Avoid redundancy: do not duplicate logic already covered by `PathHistory` (virtualization, canonicalization, boundary checks) or by instance methods.
- No vague helpers: avoid generic names like `validate`; names must encode dimension and intent (e.g., `strict_join`, `virtual_join`).
- Ask before adding: if a helper truly seems unavoidable, do not implement it outright. Propose it first with:
  - What gap it fills and why existing APIs aren’t sufficient.
  - Exact signature, receiver vs free function, visibility (`pub(crate)` minimum), placement, and naming rationale.
  - Example call sites, tests, and how it reuses `PathHistory` (not reimplements) to prevent drift.
  - Security notes (Windows 8.3, symlinks) and MSRV impact.
- Scope and exposure: prefer adding a method on an existing type over a free function; keep helpers private or `pub(crate)` and do not re‑export.
- Centralize behavior: helpers should orchestrate calls to `PathHistory`/instance methods, not introduce new resolution rules.

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
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo check --locked -p jailed-path --lib`
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo clippy --locked -p jailed-path --lib --all-features -- -D warnings`
  - `CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo test --locked -p jailed-path --lib`

## Security Testing & CVE Validation

Purpose: treat this crate as the new standard for safe path handling. Security tests must prove we are not vulnerable to past, real-world filesystem/path issues. Tests should be grounded in concrete CVE write-ups and authoritative advisories, not guesses.

### Mindset and point of view

- Assume attacker control over any path-like input (CLI args, HTTP fields, config/include paths, archive entries, DB values, LLM tool output).
- Validate both dimensions of our API:
  - System-facing (Jail/JailedPath): canonicalize and strictly enforce jail boundaries against aliasing/symlinks.
  - UI/virtual (VirtualRoot/VirtualPath): clamp lexically to virtual root, never escape via absolute, drive-relative, or namespace forms.
- Prefer black-box tests that simulate realistic attack flows and white-box tests that directly exercise edge conditions.
- Platform-aware: behavior differs on Windows vs. Unix; test each family’s quirks explicitly behind cfgs.

### Research workflow (don’t guess)

1. Identify and read at least two sources per issue:
   - MITRE/NVD CVE entries and CWE classifications.
   - Vendor advisories (e.g., MSRC, Apple, Android/Google, Git, npm, pkg maintainers).
   - Technical post-mortems or exploit write-ups that explain the root cause and exact input payloads.
2. Extract the concrete failure mode:
   - Input shape (path string, encoding, normalization form, namespace prefix, archive entry name, etc.).
   - Vulnerable behavior (e.g., std::path::join replaced the base on absolute, canonicalization done after writes, symlink/junction traversal, short-name alias bypass, ADS trick, Unicode normalization confusion).
   - Preconditions (filesystem type, OS version, privileges, archive format nuances, feature flags).
3. Translate into testable acceptance criteria for this crate (see below) and document the mapping in comments.

### PoC-to-test translation (contract)

For each CVE class create tests that:
- Use the exact or equivalent payloads but operate entirely in isolated temp dirs.
- Verify at least one of:
  - System path resolution remains within the jail boundary (`as_unvirtual().jailedpath_starts_with(vroot/jail .interop_path())`).
  - Virtual display is rooted and forward-slashed; absolute/namespace inputs clamp to `/`.
  - Attempts that would escape are rejected with a specific error (PathEscapesBoundary/PathResolutionError).
  - No files are created/modified outside the jail base.
- Cover positive and negative cases and include platform-gated variants when applicable.

### Safety rules

- Never touch real system locations; all tests must use `tempfile::tempdir()`-backed sandboxes.
- Don’t assume symlink/junction creation will succeed; skip gracefully on permission/OS limits.
- When simulating archive extraction, never write outside the jail; assert non-existence outside base.
- Avoid network and external services; tests must be offline and deterministic.

### Coverage checklist (expand as new cases emerge)

- Traversal encodings: `..`, `....//....`, `%2e`/`%2F`, mixed separators, leading `./`.
- Absolute/clamping: `/abs`, `\absolute`, Windows drive-relative (`C:..\..`), namespace prefixes (`\\?\`, `\\.\`, `\\??\`), UNC forms.
- Windows specifics: 8.3 short names (`PROGRA~1`), reserved device names (CON/NUL/PRN/COM1/LPT1), trailing dots/spaces normalization, ADS (`file.txt:stream`, `::$DATA`), junctions/reparse points.
- Unix specifics: symlinks (absolute/relative), mount/parent traversal, hard-link behavior (documented limitations).
- Unicode/encoding: NFC/NFD normalization, dot look-alikes, RTL/LRM, non‑UTF‑8 components, embedded NUL handling.
- Race/TOCTOU: parent replaced with symlink after validation; parents/nesting created safely.
- Archives: Zip Slip/Tar Slip patterns; entry names with paths intended to write outside extraction root.

### Acceptance criteria (per test)

- State the CVE or vulnerability class in a comment header with a one-sentence root cause.
- Prove containment (stays within jail) or proper rejection; include a negative assertion preventing outside writes.
- Be explicit about OS gating and acceptable outcomes (e.g., clean rejection on filesystems lacking ADS support).

### Test comment template

```
// CVE-YYYY-XXXX (or Vulnerability class: <name>)
// Root cause: <short explanation of what went wrong in the original product>
// Payload shape: <example input/path form>
// Preconditions: <OS/filesystem/permissions>
// Expected here: <clamped inside jail | rejected with PathEscapesBoundary | safe error>
```

### Adding a new CVE-driven test (step-by-step)

1. Research and collect references (links in PR description; don’t paste large excerpts into code).
2. Reproduce the input shape inside a `tempfile::tempdir()` sandbox.
3. Choose system vs virtual flow appropriately for the original bug.
4. Assert our guarantees per “Acceptance criteria”.
5. Gate with `#[cfg(windows)]`/`#[cfg(unix)]` as needed and skip symlink/junction creation on permission failure.
6. Include the comment template at the head of the test and a brief rationale.

### Documentation in PRs

- List the CVE(s) or class, link authoritative sources, and summarize how our model prevents that failure mode.
- Note any platform limitations or acceptable rejections (e.g., ADS unavailable).
- Update this section with new classes discovered during research.

## Do / Don’t (For Agents)

- Do:
  - Keep MSRV isolated to the library; build examples only on stable.
  - Add demo projects under `examples/src/bin/<category>/…` with descriptive names.
  - Add API usage examples under `jailed-path/examples/*.rs` for teaching the API.
- Prefer existing APIs over new helpers. Compose `PathHistory` + `RestrictionPath::strict_join` / `VirtualRoot::virtual_join` first.
- Use type‑state markers in examples to demonstrate compile‑time separation of jails.
  - Note on inference: core types default to `Marker = ()`. Let-bindings often suffice for inference (e.g., `let vroot: VirtualRoot = ...; let vp = vroot.virtual_join("a.txt")?;`). When the compiler needs help, prefer adding an explicit type or an empty turbofish (`VirtualRoot::<()>::try_new(..)`). Avoid turbofish unless necessary or clearer.
  - Reference `API_REFERENCE.md` when updating APIs.
- Prefer `interop_path()` for `AsRef<Path>` interop; avoid leaking `Path`/`PathBuf`.
  - Use `strict_join` / `virtual_join` instead of std `Path::join`.
  - For release/version bumps: update CHANGELOG with user-facing highlights, bump versions in Cargo.toml/lib.rs/README, tag the release, and include a concise PR summary (markdown, no code examples).
  - When crafting commit messages, summarize the staged diff by intent and impact.
- Don't:
  - Reintroduce `examples` into `[workspace.members]`.
  - Move cargo flags after `--` (they won't be recognized by cargo).
  - Do not create new helper functions without prior approval. If a helper seems unavoidable, do not just create it — offer the design, explain why it’s needed, and ask to implement it (scope, signature, naming, tests, and security notes).
  - Use `.unrestrict()` / `.unvirtual()` in examples unless demonstrating escape hatches explicitly.
  - Put API usage examples in `examples/src/bin/` - they belong in `jailed-path/examples/`.
  - Put demo projects in `jailed-path/examples/` - they belong in `examples/src/bin/<category>/`.
  - Invent new surface APIs without discussion; follow existing design patterns.
  - Deprecate APIs pre-0.1.0 — remove them cleanly instead when agreed.

## When In Doubt

- Favor smallest, safest change that:
  - Preserves MSRV 1.71.0 for the library.
  - Keeps examples compiling on stable.
  - Passes clippy/doc builds with `-D warnings` and keeps CI green on all OSes.
  - Aligns with the repository’s documentation and design files.
