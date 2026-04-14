# AGENTS.md

Operational guide for AI assistants and automation working in this repository.

## Maintaining This File

AGENTS.md is read by stateless agents with no memory of prior sessions.
Every rule must stand on its own without session context.

- **Only non-inferable content.** Do not duplicate what an agent can learn
  by reading the code. Redundant content increases token cost and hurts
  retrieval precision.
- **General, not reactive.** Do not add rules to address a single past
  mistake.  Only codify patterns that could recur across sessions.
- **Context-free.** No references to specific conversations, resolved issues,
  commit hashes, or session artifacts.  A future agent must understand the
  rule without knowing what prompted it.
- **Principles over examples.** Prefer abstract guidance.  If an example is
  needed, make it generic — never name a specific module or function as the
  motivating case.
- **No stale specifics.** If a rule names a concrete item (file, function,
  feature), it must be because the item is structurally important (e.g. the
  repository layout table), not because it was the subject of a past debate.

## ⛔ Read Before Any Code Changes

Before writing or suggesting any code:

1. **Read the relevant source files.** Never modify code you haven't read and understood.
2. **Search before implementing.** Verify the functionality doesn't already exist.
3. **Critical design constraint — canonicalization always resolves symlinks.** You can never get a `StrictPath`/`VirtualPath` pointing to a symlink itself. Any API that assumes a path might be a symlink is fundamentally incompatible with this crate. See [Critical Design Implication](#critical-design-implication-strictpathvirtualpath-are-always-resolved) below.

## Build & Test

```bash
cargo build -p strict-path --all-features
cargo test -p strict-path --all-features
cargo test --doc -p strict-path --all-features
cargo clippy -p strict-path --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo doc -p strict-path --no-deps --document-private-items --all-features
```

MSRV: `rustup run 1.76 cargo build -p strict-path --all-features`

Local CI (full pipeline): `./ci-local.ps1` (Windows) or `bash ./ci-local.sh` (Unix/WSL).

## Project Overview

- Purpose: Handle paths from external or unknown sources securely, preventing directory traversal with safe path boundaries and safe symlinks.
- Core APIs: `PathBoundary<Marker>`, `StrictPath<Marker>`, `VirtualRoot<Marker>`, `VirtualPath<Marker>`, `StrictPathError`.
- Security model: "Restrict every external path." Any path from untrusted inputs (user I/O, config, DB, LLMs, archives) must be validated into a restriction‑enforced type (`StrictPath` or `VirtualPath`) before I/O.
- Foundation: Built on `soft-canonicalize` (with `proc-canonicalize` for Linux container realpath support); canonicalization handles Windows 8.3 short names transparently.
- **CRITICAL DESIGN PRINCIPLE**: Canonicalization **always resolves symlinks** to their targets. You can NEVER get a `StrictPath` or `VirtualPath` that points to a symlink itself — only to the resolved target. This is by design: it's what proves the path is truly within the boundary. See "Critical Design Implication: StrictPath/VirtualPath Are Always Resolved" section for details.
- API philosophy: Minimal, restrictive, and explicit—designed to prevent human and LLM API misuse. Security is prioritized above performance.
- **TOCTOU scope**: This crate validates at join-time (canonicalization + boundary check). Filesystem changes that occur *between* validation and subsequent I/O are outside scope — the same limitation as SQL prepared statements, which prevent injection but don't protect against concurrent schema changes. TOCTOU is an inherent OS-level concern that no user-space path library can fully eliminate.

### Which Type Should I Use?

**`Path`/`PathBuf` (std)** — When the path comes from a safe source within your control, not external input.

**`StrictPath`** — When you want to restrict paths to a specific boundary and error if they escape.
- Use for: Archive extraction, config loading, shared system resources, file uploads to shared storage (admin panels, CMS assets)
- Behavior: Returns `Err(PathEscapesBoundary)` on escape attempts (detect attacks)
- Coverage: 90% of use cases

**`VirtualPath`** (feature `virtual-path`) — When you want to provide path freedom under isolation.
- Use for: Multi-tenant file uploads (SaaS per-user storage), malware sandboxes, security research, per-user filesystem views
- Behavior: Silently clamps/redirects escapes within virtual boundary (contain behavior)
- Coverage: 10% of use cases

### StrictPath vs VirtualPath: Detect vs. Contain

**Critical distinction**: Choose based on whether path escapes are attacks or expected behavior.

**StrictPath (default, 90% of use cases)**: Detects and rejects escape attempts
- Philosophy: "If something tries to escape, I want to know about it"
- Returns `Err(PathEscapesBoundary)` when escape is attempted
- Use cases:
  - **Archive extraction** — detect malicious paths, reject compromised archives
  - **File uploads to shared storage** — admin panels, CMS assets, single-tenant apps where all users share one storage area
  - **Config loading** — fail on untrusted config paths that try to escape
  - Shared system resources (logs, cache, assets)
  - Development tools, build systems, single-user applications
  - Any security boundary where escapes indicate malicious intent
- No feature required — always available

**VirtualPath (opt-in, 10% of use cases)**: Contains and redirects escape attempts
- Philosophy: "Let things try to escape, but silently contain them"
- Silently clamps/redirects escape attempts within the virtual boundary
- Use cases:
  - **Multi-tenant file uploads** — SaaS per-user storage where each user has isolated directories
  - **Multi-tenant systems** — each user sees isolated `/` root without real paths
  - **Malware analysis sandboxes** — observe malicious behavior while containing it
  - **Container-like plugins** — modules get their own filesystem view
  - **Security research** — simulate contained environments for testing
  - User content isolation where users shouldn't see real system paths
- Requires `virtual-path` feature in Cargo.toml

**Common mistake**: Using VirtualPath for archive extraction. This is WRONG — it hides attacks instead of detecting them. Always use StrictPath to detect malicious paths and reject compromised archives.

Escape hatches:
- Borrow strict view from virtual with `as_unvirtual()` for shared helpers.
- Use `.unvirtual()` and `.unstrict()` only when ownership is required; isolate in dedicated "escape hatches" sections.

### Marker Transformation with `change_marker()`

`StrictPath<Marker>` and `VirtualPath<Marker>` provide `change_marker::<NewMarker>()` to transform the compile-time marker while keeping the validated path.

**When to use `change_marker()`:**
- After authenticating/authorizing a user and granting them different permissions (e.g., ReadOnly → ReadWrite)
- When escalating or downgrading access levels based on runtime checks
- When reinterpreting a path's security context (e.g., TempStorage → UserUploads after validation)

**When NOT to use `change_marker()`:**
- When converting between path types - conversions preserve markers automatically
- When the current marker already represents the correct permissions - no transformation needed
- Without verifying authorization first - NEVER change markers speculatively or "just because"

**Key insight:** Conversions preserve markers by design. Use `change_marker()` only when you need a *different* marker type, typically after performing authorization checks in your application logic.

**Example:**
```rust
// ✅ Correct: change_marker() after authorization check
fn grant_write_access(
    path: StrictPath<(Documents, ReadOnly)>,
    user: &User
) -> Result<StrictPath<(Documents, ReadWrite)>> {
    if user.has_write_permission() {
        Ok(path.change_marker())  // Transform after verifying authorization
    } else {
        Err(AccessDenied)
    }
}

// ❌ Wrong: change_marker() when conversion preserves marker anyway
let boundary = strict_path.change_marker::<NewMarker>().try_into_boundary()?;
// Should be: let boundary = strict_path.try_into_boundary()?;
// (Marker is already preserved; change_marker() does nothing useful here)
```

## Anti‑Patterns (Tell‑offs)

Quick reminder of core principles:
- Purpose: Handle paths from external or unknown sources securely, preventing directory traversal with safe path boundaries and safe symlinks.
- Core APIs: `PathBoundary<Marker>`, `StrictPath<Marker>`, `VirtualRoot<Marker>`, `VirtualPath<Marker>`, `StrictPathError`.
- Security model: "Restrict every external path." Any path from untrusted inputs (user I/O, config, DB, LLMs, archives) must be validated into a restriction‑enforced type (`StrictPath` or `VirtualPath`) before I/O.
- Foundation: Built on `soft-canonicalize` (with `proc-canonicalize` for Linux container realpath support); Windows 8.3 short‑name handling is considered a security surface.

Do not implement leaky trait impls for any crate type:
- Forbidden: `AsRef<Path>`, `Deref<Target = Path>`, implicit `From/Into` conversions for `StrictPath`/`VirtualPath`/`PathBoundary`/`VirtualRoot`.
- Rationale: They bypass the `interop_path()` gate, let callers silently escape the secure API, and blur dimension semantics (strict vs virtual).

### `interop_path()` Returns `&OsStr` — Design Decision (Settled)

`.interop_path()` on all four core types returns `&std::ffi::OsStr` directly. This is a deliberate, settled design choice. Do not propose wrapper types, newtypes, or returning `&Path`.

**Why `&OsStr` (not `&Path`):**
- `OsStr` has no `.join()`, `.parent()`, `.starts_with()` — this prevents callers from accidentally re-entering path manipulation after leaving the secure API.
- `&OsStr` implements `AsRef<Path>`, so it can be passed directly to any third-party API that expects `impl AsRef<Path>` (the sole purpose of interop).
- To get `&Path`, callers must write `Path::new(x.interop_path())` — a visible, deliberate step that signals the code has left strict-path's security scope.

**Why NOT a newtype wrapper (settled — do not revisit):**
- A newtype around `&OsStr` that only adds `AsRef<Path>` provides zero additional security value — `&OsStr` already satisfies `AsRef<Path>` and already lacks path manipulation methods.
- Once a user calls `interop_path()`, they have explicitly chosen to leave strict-path's scope. Policing what they do with the returned reference is not this crate's responsibility.
- The wrapper adds maintenance cost (type definition, trait impls, documentation, re-exports) with no practical benefit.
- This was tried (as `InteropPath<'a>`) and deliberately removed after evaluation.

**The ONLY thing you should do** with the `&OsStr` from `interop_path()` is pass it to a function that accepts `impl AsRef<Path>`. For display, use `strictpath_display()` / `virtualpath_display()`. For everything else, use the crate's built-in safe operations.

### One Way Principle (Non-Negotiable)

There must be exactly **one correct way** to accomplish each operation. Redundant methods that achieve the same thing create confusion, dilute documentation, and make the API harder to learn.

**Canonical operations:**

| Goal | The ONE way | Notes |
| --- | --- | --- |
| Path as string (display/comparison) | `strictpath_display().to_string()` | Returns `std::path::Display<'_>` |
| Path for third-party `AsRef<Path>` APIs | `.interop_path()` | Returns `&OsStr` (is `AsRef<Path>`) |
| Virtual path as user-visible string | `virtualpath_display()` | Rooted forward-slash view |
| Escape to owned `PathBuf` | `.unstrict()` / `.unvirtual()` | Explicit escape hatch, use sparingly |

**Do not add** alternative string conversion methods (e.g., `to_string_lossy()`, `to_str()`, `as_path()` wrappers) that provide a second way to achieve the same goal. If a method exists solely as a convenience wrapper around an existing canonical operation, it should not exist.

### Helper API Restrictions (Unbreakable)

- Never introduce new `pub` helper functions or constructors. Public API additions must come from explicit maintainer direction, not autonomous agent judgment.
- Before adding *any* new helper that is `fn`, `pub(crate) fn`, or otherwise widening internal surface area, pause and request maintainer approval. Document the need in the PR description rather than committing speculative helpers.

### Critical Design Implication: StrictPath/VirtualPath Are Always Resolved

**This is the most important design principle to understand before adding ANY new API.**

`strict_join()` and `virtual_join()` perform full canonicalization, which **always resolves symlinks and junctions to their targets**. This means:

1. **You can NEVER obtain a `StrictPath` or `VirtualPath` that points to a symlink itself** — the path always points to the resolved target.
2. **Any API that assumes it can operate "on the symlink" is fundamentally broken** — by the time you have a `StrictPath`, the symlink has already been resolved.
3. **This is by design** — canonicalization is what provides the security guarantee that the path is truly within the boundary.

**Example of a broken API design:**
```rust
// ❌ BROKEN: This API cannot work as designed
fn strict_read_link(&self) -> io::Result<PathBuf>
// Why broken: `self` already points to the target, not the symlink.
// `std::fs::read_link(target)` returns EINVAL because target isn't a symlink.
```

**Example of correct design:**
```rust
// ✅ CORRECT: Test if symlink target escapes during strict_join
let result = boundary.strict_join("symlink_name");
// If the symlink's target escapes, strict_join returns PathEscapesBoundary.
// If it succeeds, you get a StrictPath to the resolved target (within boundary).
```

**Before proposing ANY filesystem API, ask:**
1. Does this API need to operate on a symlink itself (not its target)? → **Cannot be implemented with StrictPath/VirtualPath**
2. Does this API assume the path might be a symlink? → **It won't be — canonicalization already resolved it**
3. Does this API wrap a `std::fs` function that behaves differently on symlinks vs regular files? → **Verify behavior with resolved paths only**

### Mandatory API Addition Checklist

Before adding ANY new public or internal API, you MUST complete this checklist:

**1. Design Compatibility Check:**
- [ ] Have I read and understood the PathHistory type-state flow? (Raw → Canonicalized → BoundaryChecked)
- [ ] Does my API work correctly given that symlinks are ALWAYS resolved?
- [ ] Does my API work correctly given that the path is ALWAYS canonicalized (no `.`, `..`, or relative components)?
- [ ] Have I verified the API makes sense for BOTH `StrictPath` and `VirtualPath`?

**2. Semantic Verification:**
- [ ] Have I tested the underlying `std::fs` function with resolved paths (not symlinks)?
- [ ] Have I tested on BOTH Windows and Linux (or documented platform-specific behavior)?
- [ ] Does the API preserve the security guarantee that paths cannot escape the boundary?

**3. Existing Functionality Check:**
- [ ] Have I searched the codebase to verify this functionality doesn't already exist?
- [ ] Have I checked if a similar API exists with a different name?
- [ ] Is there a design reason this API was NOT already implemented?

**4. Approval Gate:**
- [ ] Have I requested explicit maintainer approval before implementing?
- [ ] Have I documented why this API is needed and how it fits the design?

**If ANY checkbox cannot be checked, STOP and discuss with the maintainer.**

## Repository Layout

- Root workspace: `[workspace].members = ["strict-path", "benches"]`, `exclude = ["demos"]`.
- `strict-path/`: library crate; MSRV‑bound.
- `benches/`: performance benchmarks; workspace member at project root; latest stable (not MSRV-bound); `publish = false`.
- `demos/`: real‑world demo binaries; decoupled from MSRV; `publish = false`.
- `.github/workflows/`: CI configs; stable + MSRV split.
- Local CI parity: `ci-local.ps1` (Windows), `ci-local.sh` (Unix/WSL).
- **mdBook documentation (authoritative source)**:
  - Live on branch `docs` under `docs_src/` (built to `docs/`).
  - **For agents/LLMs**: Use `.docs/` worktree to read and edit mdBook content.
  - Set up once: `git worktree add .docs docs` (or `git worktree add -B docs .docs origin/docs` if remote only).
  - Read/edit: `.docs/docs_src/src/*.md` files.
  - Preview: `cd .docs/docs_src && mdbook serve -o`.
- Docs: `README.md`, `LLM_CONTEXT_FULL.md` (full API reference for LLMs), `LLM_CONTEXT.md` (Context7-style guide for LLMs).

## Benchmarks Structure (Workspace-Level)

**Location:** `benches/` at project root (NOT in `strict-path/benches/`)

**Why at workspace root:**
- Rust convention: workspace-level benchmarks go in `<workspace>/benches/`
- Benchmarks compare approaches and aren't "part of" the library API
- Parallel structure to `demos/` (both at root, both excluded/member)
- Cleaner separation of concerns

**Directory structure:**
```
benches/
├── Cargo.toml              # Separate workspace member
├── src/lib.rs              # Dummy lib (Cargo requirement)
├── benches/                # Actual benchmark files (Cargo convention)
│   ├── performance_comparison.rs   # Overhead measurement
│   └── caching_benefits.rs         # Real-world performance gains
├── docs/                   # Benchmark analysis and reports
│   ├── OVERHEAD_QUICK_REFERENCE.md
│   ├── PERFORMANCE_OVERHEAD_ANALYSIS.md
│   ├── CACHING_BENEFITS_REPORT.md
│   └── BENCHMARK_ANALYSIS.md
└── README.md               # Benchmark usage guide
```

**Key points:**
- `benches/Cargo.toml` declares dependency on `strict-path = { path = "../strict-path", features = ["virtual-path"] }`
- Features enabled in benches/Cargo.toml, so no `--features` needed when running
- `benches/src/lib.rs` is a dummy file to satisfy Cargo's requirement for a target
- Actual benchmarks go in `benches/benches/*.rs` (Cargo convention)
- Benchmarks use latest stable Rust (not MSRV-bound like library)

**Running benchmarks:**
```powershell
# From repository root
cd benches
cargo bench                               # Run all benchmarks
cargo bench --bench performance_comparison  # Overhead only
cargo bench --bench caching_benefits        # Real-world gains only
cargo bench -- --save-baseline main         # Save baseline for regression testing
```

**Never run from library directory:**
```powershell
# ❌ Wrong (old location):
cd strict-path
cargo bench --features virtual-path

# ✅ Correct (new location):
cd benches
cargo bench
```

**Benchmark dependencies:**
- `criterion = "0.7.0"` — professional benchmarking framework
- `soft-canonicalize = { version = "0.5.2", features = ["anchored"] }` — baseline comparison
- `tempfile = "3.22"` — test fixtures
- NO `criterion` in `strict-path/Cargo.toml` dev-dependencies (moved to benches)

**Documentation structure:**
- `benches/README.md` — usage guide, what each benchmark measures, how to run
- `benches/docs/OVERHEAD_QUICK_REFERENCE.md` — at-a-glance tables (StrictPath +11%, VirtualPath +35%)
- `benches/docs/PERFORMANCE_OVERHEAD_ANALYSIS.md` — comprehensive 500+ line analysis with 6 tables
- `benches/docs/CACHING_BENEFITS_REPORT.md` — real-world batch scenarios (VirtualPath 2-3x faster!)
- `benches/docs/BENCHMARK_ANALYSIS.md` — initial benchmark analysis and methodology notes

**Adding new benchmarks:**
1. Create `benches/benches/your_benchmark.rs`
2. Add `[[bench]]` entry to `benches/Cargo.toml`
3. Use `black_box()` to prevent compiler optimizations
4. Ensure all approaches do equivalent work (fair comparison)
5. Document expected results in comments
6. Update `benches/README.md` with new benchmark description

**Benchmark methodology (critical):**
- All approaches must receive SAME inputs (relative path segments)
- Measure full workflow: "untrusted string" → "validated path"
- Include validation cost + I/O cost (if applicable)
- Use `black_box()` around inputs and outputs
- Setup costs (boundary creation) happen OUTSIDE benchmark loop
- Throughput set correctly (matches operations per iteration)

**Anti-patterns:**
- ❌ Benchmarking with absolute paths (not fair comparison)
- ❌ Measuring I/O only without validation cost
- ❌ Validating outside the benchmark loop
- ❌ Comparing different workloads (must be equivalent)
- ❌ Forgetting `black_box()` (compiler may optimize away work)

**See also:** `benches/docs/PERFORMANCE_OVERHEAD_ANALYSIS.md` for detailed methodology and validation notes.

## CI Workflows (GitHub Actions)

- Stable job (linux/windows/macos):
  - `cargo fmt --all -- --check` and `cargo clippy --all-targets --all-features -- -D warnings` (library).
  - Demos are linted only (not built/run): `cd demos && cargo clippy --all-targets --features "with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp" -- -D warnings`.
    - Heavier integrations like `with-aws` are included when toolchain prerequisites (e.g., `cmake`, `nasm`) are available on runners.
  - `cargo test -p strict-path --all-features` (library only).
- MSRV job (linux, Rust 1.76.0):
  - `check`/`clippy`/`test` scoped to `-p strict-path --lib --locked` using separate target dir.

## MSRV Policy (Library Only)

- MSRV: Rust 1.76.0 (declared in `strict-path/Cargo.toml`).
- Avoid dependencies or features that raise MSRV without discussion.
- Forbid unsafe code; pass clippy with `-D warnings`.

## Demos Policy (Non‑MSRV)

- `demos/` is a separate crate (`publish = false`), path‑dep on `../strict-path`.
- Linted on latest stable CI; demos may use newer ecosystem crates/features.
- Do not build or run demos in CI by default. Keep binaries runnable locally: `cd demos && cargo run --features <...> --bin <name>`.
- Keep heavy deps optional with namespaced features (e.g., `with-zip = ["dep:zip", "dep:flate2"]`).
- Demo projects must model real scenarios; avoid “API‑only” snippets (those belong in `strict-path/examples/`).
- Realism is mandatory: Prefer integrating the official ecosystem crates instead of hand‑rolled stubs when demonstrating protocols, runtimes, or services. It’s acceptable to add small “offline fallbacks” only when explicitly justified, but flagship demos must default to the real integration.

## Examples vs Demos (Critical)

- API usage examples → `strict-path/examples/*.rs` (built with the library). Run with `cargo run --example <name>` from `strict-path/`.
- Real demo projects → `demos/src/bin/<category>/<name>.rs`. Run with `cd demos && cargo run --bin <name>`.

### Realistic, Teach‑Through Demos (Important)

- Demos must be production‑authentic: use the same protocols and official crates that real teams would pick (avoid ad‑hoc mocks for protocol/runtime concerns).
- Demos must encode strict/virtual path guarantees in handlers so users learn the correct integration patterns (validate received paths → operate through `StrictPath`/`VirtualPath`).
- **Demos must validate actual external input**: Show validation of data from HTTP requests, CLI args, config files, etc. Never validate hardcoded string literals. Use descriptive variable names (`user_input`, `requested_file`, `uploaded_data`) that make it clear the data is untrusted.
- No #[allow(...)] in demos — fix the code and naming to pass clippy with `-D warnings`.
- Use domain names for variables (e.g., `user_project_root`, `system_root`, `entry_path`) — never one‑letter variables for paths.
- Demonstrate directory discovery vs. validation: call the strict helper (`let entries = root.strict_join("")?.read_dir()?;`) to enumerate, then re‑join each discovered name through `strict_join`/`virtual_join`. Reserve `.interop_path()` for third‑party crates that require `AsRef<Path>`.

Directory convention for demos:
- Web servers: `demos/src/bin/web/...`
- Security/archives: `demos/src/bin/security/...`
- CLI/tools: `demos/src/bin/cli/...` or `.../tools/...`
- Config/OS dirs: `demos/src/bin/config/...`


## Variable Naming Rules (VirtualRoot & PathBoundary)

When naming variables, treat `VirtualRoot` and `PathBoundary` as representations of paths, not as types to be suffixed. Name variables by their domain and role in the flow:
- If a variable represents a file, name it by its domain and purpose (e.g., `profile_file`, `config_file`, `avatar_file`).
- If a variable represents a directory/root, name it by its domain and role (e.g., `user_uploads_root`, `public_assets_root`, `config_dir`, `archive_src`).
Avoid generic names like `boundary`, `jail`, or type-based suffixes. This applies to all boundaries, roots, and path values—use descriptive, context-rich names that reflect their role in the application, not their type.

Per-user VirtualRoot construction (web/multi-tenant best practice):
- Construct roots with a trusted identifier segment, e.g.: `let user_uploads_root: VirtualRoot<UserUploads> = VirtualRoot::try_new_create(format!("uploads/{user_id}"))?;`.
- Treat `user_id`/`tenant_id` as identifiers, not paths. Do not pass raw user strings containing separators; sanitize or map to a slug first.
- Do not use a single global `VirtualRoot` for all users; create one per user/tenant and pass it where needed (avoid constructing inside helpers).

### Marker Naming Rules

- Marker types must describe the resource stored under the restriction, not the caller or the type system. Use concrete domain nouns such as `struct UserUploads;`, `struct BrandEditorWorkspace;`, or `struct BrandDirectorArchive;`.
- Avoid suffixes like `Marker`, `Type`, `Root`, or `Context`—they add no meaning. `struct MediaLibrary;` is preferred over `struct MediaLibraryMarker;`.
- When encoding authorization, pair the domain marker with a permission marker in a tuple: `StrictPath<(BrandEditorWorkspace, ReadWrite)>`. The first element names the storage root; the second names the permission being granted.
- Do not use human-centric labels (personas, job titles, teams) unless the directory truly stores those artifacts. Names must reflect the filesystem contents or policy boundary/virtual root so reviewers can infer the restriction from the type alone.

## Code & API Usage Guidelines

### Library vs Application Boundary (External API Design)

All guidance in this file — encoding guarantees in signatures, accepting `&StrictPath<Marker>`, using policy types — applies to **applications** and to a **library's internal logic**. It does **not** mean library authors should force their downstream users to depend on `strict-path`.

- **Applications and internal library code**: Use `StrictPath`/`VirtualPath`/`PathBoundary`/`VirtualRoot` freely in signatures, structs, and module boundaries.
- **Library public APIs**: Authors should be mindful about whether to expose `strict-path` types in their own public surface. By default, hide `strict-path` behind your own API boundary so your users are not required to import it as a direct dependency. Accept standard types (`&str`, `&Path`, `PathBuf`) in your public API and validate internally.
- **Exception**: If the library's explicit purpose benefits from having its users work with `strict-path` types (e.g., a security framework, a file-management SDK), then exposing `StrictPath`/`VirtualPath` in the public API is appropriate — but this should be a deliberate design choice, not the default.

- Encode guarantees in function signatures:
  - Accept `&StrictPath<Marker>` / `&VirtualPath<Marker>` (or structs containing them), or
  - Accept `&PathBoundary<Marker>` / `&VirtualRoot<Marker>` plus the untrusted segment.
  - Do not construct boundaries/roots inside helpers — boundary choice is policy.
- Sugar vs policy types (when to use which):
  - Small/local flows: use sugar constructors, then explicit joins:
    - `StrictPath::with_boundary(_create)(root)?.strict_join(segment)?`
    - `VirtualPath::with_root(_create)(root)?.virtual_join(segment)?`
    - Both `virtual_join`/`strict_join` take `&self` and return new values; you can call them multiple times off the same root value.
  - Larger/reusable flows: prefer policy types in signatures and modules:
    - Keep a `PathBoundary`/`VirtualRoot` and call `strict_join`/`virtual_join` repeatedly.
    - Use policy types whenever passing “the root” across module boundaries, or when serde/OS-dirs/temp RAII are involved.
- Interop vs display:
  - Interop: Call `.interop_path()` on `StrictPath`/`VirtualPath`/`PathBoundary`/`VirtualRoot` **only** when a third-party crate (including stdlib adapters that you cannot wrap) insists on an `AsRef<Path>` argument. No type in this crate implements `AsRef<Path>` — `.interop_path()` returns `&OsStr` (which satisfies `AsRef<Path>`) and is the single explicit gate for leaving the secure API. If you reach for `.interop_path()` in any other context, pause and re-evaluate—the crate almost certainly already exposes a strict helper for that operation.
  - **SECURITY CRITICAL**: `interop_path()` returns the **real host filesystem path**. NEVER expose it to end-users (API responses, error messages, user-visible logs). In multi-tenant or cloud scenarios, this leaks internal server structure, tenant IDs, and infrastructure details. Use `virtualpath_display()` for user-facing output.
  - Display: `strictpath_display()` (system/admin) / `virtualpath_display()` (user-facing, hides real paths).
  - Windows junctions (feature = `junctions`): Prefer built-in helpers (`StrictPath::strict_junction`, `VirtualPath::virtual_junction`, and root/boundary wrappers) instead of direct calls to junction crates in application code. Tests may still call third-party crates when simulating environment-specific behavior.

#### Test design principles: symlinks vs junctions on Windows

- Symlink creation often fails on CI without Developer Mode/admin. Tests must handle this gracefully.
- Where a link creation is part of the test intent:
  - First attempt the regular symlink helper (e.g., `strict_symlink`).
  - If you receive Windows ERROR_PRIVILEGE_NOT_HELD (1314), prefer falling back to the built-in junction helper when `feature = "junctions"` is enabled:
    - `StrictPath::strict_junction(&link)` or wrappers on `PathBoundary`/`VirtualRoot`/`VirtualPath`.
  - Only as a last resort in tests (not app code), use third-party junction creation to simulate malicious preexisting links that cannot be represented as `StrictPath` targets (e.g., a link inside the boundary pointing to an outside path).
- Always use built-in I/O (e.g., `read_dir()`, `exists()`) to verify link behavior; avoid `std::fs` calls on `.interop_path()`.
- Explicit operations by dimension:
  - `strict_join`/`virtual_join`, `strictpath_parent`/`virtualpath_parent`, `strictpath_with_*`/`virtualpath_with_*`.
  - `.interop_path()` returns `&OsStr` (implements `AsRef<Path>`) — pass directly to third-party APIs; never wrap it in `Path::new()` to use std path operations.
- Escape hatches only where needed:
  - Prefer borrowing: `vpath.as_unvirtual()` to pass `&StrictPath`.
  - Avoid `.unvirtual()`/`.unstrict()` unless ownership is required; isolate in dedicated “escape hatches” sections.
- Variable naming:
  - Name by domain/purpose, not type. Examples: `config_dir`, `uploads_root`, `archive_src`, `mirror_src`, `user_vroot`.
  - Avoid `boundary`, `jail`, `source_` prefixes and one‑letter names.
  - For demos, prioritize names that explain the role in the real flow (e.g., `user_project_root`, `tenant_vroot`, `system_root`, `ingest_dir`).

### Serde Guidelines

- `PathBoundary` and `VirtualRoot` implement `FromStr`, enabling automatic deserialization.
- Serialize paths as display strings: `boundary.strictpath_display().to_string()` for system paths, `vpath.virtualpath_display()` for virtual paths.
- For config structs: deserialize `PathBoundary`/`VirtualRoot` directly (via `FromStr`); deserialize untrusted path fields as `String` and validate manually by calling `strict_join` or `virtual_join`.
- Never add `Deserialize` impls for `StrictPath`/`VirtualPath` — they need a runtime boundary/root context which only the application can provide.

### Internal Design: PathHistory & Type‑State

PathHistory is the internal engine that performs normalization, canonicalization, clamping and boundary checks in a single, auditable pipeline. It is deliberately not exposed in public APIs, but agents need to understand it to reason about behavior and place fixes in the right layer.

**⚠️ CRITICAL: Canonicalization resolves symlinks. See "Critical Design Implication: StrictPath/VirtualPath Are Always Resolved" section above.**

- States (type‑state markers):
  - `Raw`: Constructed from any input (`AsRef<Path>`).
  - `Canonicalized`: After full canonicalization (resolves `.`/`..`, symlinks/junctions, prefixes). **This means symlinks are ALWAYS resolved to their targets.**
  - `AnchoredCanonicalized`: Canonicalized relative to a specific jail/root (virtual anchoring).
  - `Exists`: Canonicalized path verified to exist (used for PathBoundary boundary directories).
  - `BoundaryChecked`: Canonicalized path proven to be within the PathBoundary.

- Typical flows:
  - PathBoundary::try_new(_create): `Raw -> Canonicalized -> Exists` (errors if not dir or missing when `try_new`).
  - PathBoundary::strict_join(candidate): compose; `Raw -> Canonicalized -> BoundaryChecked` then wrap in `StrictPath`.
  - VirtualRoot::virtual_join(candidate): virtual compose; `Raw -> AnchoredCanonicalized -> BoundaryChecked`, then construct `StrictPath` and wrap as `VirtualPath` (computes virtual view for Display).
  - VirtualPath mutations (`virtual_join`, `virtualpath_parent`, `virtualpath_with_*`): compute candidate in virtual space; `Raw -> AnchoredCanonicalized -> BoundaryChecked` with the same restriction.

- Anchored canonicalization (virtual dimension):
  - `canonicalize_anchored(&PathBoundary)` canonicalizes with the jail as the anchor root and produces `AnchoredCanonicalized`.
  - After `boundary_check(...)`, anchor is erased when constructing `StrictPath`, keeping public surface types narrow.

- Windows specifics:
  - Canonicalization automatically resolves Windows 8.3 short names (e.g., `PROGRA~1` → `Program Files`). No explicit rejection needed; the mathematical proof (canonicalized path within canonicalized boundary) provides security.
  - UNC paths, ADS (`file.txt:stream`) and drive‑relative forms are normalized in PathHistory; ADS are not special‑cased beyond OS behavior, but path validation prevents escapes.

- Error mapping:
  - All I/O/canonicalization errors are wrapped as `StrictPathError::{InvalidRestriction, PathResolutionError, PathEscapesBoundary}` at the outer layer. Avoid exposing raw `io::Error` from internal steps.

- Equality/Ordering/Hashing (public types):
  - `StrictPath`/`VirtualPath` Eq/Ord/Hash are based on the underlying system path; `VirtualPath` equals a `StrictPath` with the same system path within the same restriction.

- Display semantics:
  - `VirtualPath::virtualpath_display()` returns rooted, forward‑slashed user view (e.g., `"/a/b.txt"`).
  - `StrictPath::strictpath_display()` shows the real system path. `Debug` for `VirtualPath` is verbose by design (system path + virtual view + restriction root + marker type).
  - `VirtualRoot::Display` shows `"/"` (the virtual root), never the real system path. This prevents accidental leakage of host filesystem structure in user-facing output.

- Arc ownership tradeoff:
  - Every `StrictPath` carries an `Arc<PathBoundary>` so it can re-validate on mutations (`strict_join`, `strictpath_parent`, `strictpath_with_*`), support `change_marker()`, and provide boundary context for error messages.
  - Processing N files from the same boundary means N `Arc` refs to the same allocation — correct by design, not a leak. The clone is a pointer-width atomic increment, not a deep copy.
  - This is a conscious tradeoff: security correctness (every path carries its proof of origin) over minimal per-path overhead.

### Constructor Parameter Design: `AsRef<Path>`

- Constructors (`PathBoundary::try_new(_create)`, `VirtualRoot::try_new(_create)`) accept `AsRef<Path>` for ergonomics and to enable the clean TempDir shadowing pattern in examples.
- Prefer borrowing (`&Path`, `&str`, `&TempDir`) and avoid allocations when passing into constructors.

Constructor parameter design:
- Prefer `AsRef<Path>` for constructors like `PathBoundary::try_new(_create)` / `VirtualRoot::try_new(_create)`.
- Rationale: maximizes ergonomics (`&str`, `String`, `&Path`, `PathBuf`, `TempDir`), supports clean shadowing in examples, matches std conventions.

Escape hatches:
- Borrow strict view from virtual with `as_unvirtual()` for shared helpers.
- Use `.unvirtual()` and `.unstrict()` only when ownership is required; isolate in dedicated “escape hatches” sections.

## Usage Anti‑Patterns (Path Handling & Examples)

- **Validating only constants (CRITICAL)**: `boundary.strict_join("hardcoded.txt")?` — no untrusted segment ever flows through validation. This completely defeats the purpose of the crate and is misleading in examples.
- **Using generic variable names that hide intent**: Variables must clearly indicate they represent untrusted external input (e.g., `user_input`, `requested_file`, `uploaded_data`) not generic names like `filename`, `path`, `name`.
- Constructing boundaries/roots inside helpers.
- Wrapping secure types in `Path::new()` / `PathBuf::from()`.
- Performing filesystem I/O via `std::fs` on `.interop_path()` paths instead of the built-in strict helpers (e.g., `StrictPath::create_file`, `StrictPath::read_to_string`).
- `interop_path().as_ref()` or `as_unvirtual().interop_path()` — when adapting third-party crates, call `.interop_path()` directly; no extra `.as_ref()` dance.
- Mixing interop and display (use `*_display()` for display).
- Wrapping `.interop_path()` in `Path::new()` or `PathBuf::from()` to use std path operations.
- Raw path parameters in safe helpers — use types/signatures that encode guarantees.
- Single‑user demo flows for multi‑user services — use per‑user `VirtualRoot`.
- Calling `strict_join("")` or `virtual_join("")` to grab the root. Prefer the dedicated conversions (`PathBoundary::into_strictpath()`, `VirtualRoot::into_virtualpath()`) so empty segments never creep into reviewer-approved flows.
- Using `change_marker()` without authorization checks or when converting between path types — conversions preserve markers automatically; only use `change_marker()` when you need a *different* marker after verification.

Path handling rules (very important):
- Do not expose raw `Path`/`PathBuf` from `StrictPath`/`VirtualPath` in public APIs or examples.
- `.interop_path()` returns `&OsStr` (implements `AsRef<Path>`) — pass directly to external APIs, never wrap in `Path::new()` or `PathBuf::from()`.
- Never wrap `.interop_path()` to use std path operations — that defeats all security. Use dimension-specific operations instead.
- `.unstrict()` is the explicit escape hatch — after calling it, you own a `PathBuf` and leave safety guarantees.
- Stay in one dimension per flow; if you need the other, upgrade/downgrade explicitly.

String formatting rules (Rust 1.58+ captured identifiers):
- Avoid bare `{}`; prefer captured identifiers (`format!("{value}")`, `println!("{display}")`).
- Bind locals for repeated or long expressions; improves readability and prevents mistakes.

See also mdBook pages (access via `.docs/` worktree):
- `.docs/docs_src/src/best_practices.md` — detailed decision matrix and patterns
- `.docs/docs_src/src/anti_patterns.md` — common mistakes with fixes

## Documentation Guidelines

- Keep README focused on why, core features, and simple‑to‑advanced examples.
- Align README examples with `strict-path/src/lib.rs` doc examples where appropriate.
- Use doctested examples in source whenever possible; examples must compile and follow path‑handling rules.
- Examples should be runnable and realistic: prefer end‑to‑end flows over contrived snippets; show policy types for reusable flows.
- **Examples MUST demonstrate actual input validation**: Every example showing `strict_join()`/`virtual_join()` must validate external/untrusted input, not hardcoded string literals. Use variable names that clearly indicate the source (e.g., `user_input`, `requested_file`, `attack_input`) with comments showing where the input comes from (HTTP request, CLI args, form data, etc.).
- Doctests and examples must not rely on `#[allow(..)]` to pass lints; fix code and naming instead.
- Fenced code blocks in docs must execute as doctests. Do not use `no_run`, `ignore`, or similar escape hatches. If an example needs to show a failure path, structure it as a regular doctest that asserts the failure (or mark it `compile_fail` when the compiler should reject it).
- Lead with sugar for ergonomics in simple flows; demonstrate policy types for reuse, serde context, OS dirs, and temp RAII.
- For multi‑user flows, prefer `VirtualRoot`/`VirtualPath`; for shared strict logic, borrow `as_unvirtual()`.

### README.md and mdBook Code Examples: Validation Requirements

**Critical Rule**: All code examples in `README.md` and mdBook (`.docs/docs_src/src/*.md`) must be validated by automated tests.

**README.md validation**:
- All code examples in `README.md` must have corresponding tests in `strict-path/src/tests/readme_examples.rs`
- Tests must exactly match README examples (same code, same flow, same results)
- If you fix compilation errors in tests, **update README.md to match the working code**
- Do not include test scaffolding (cleanup, setup) in README unless it teaches something
- Feature-gated examples (`#[cfg(feature = "virtual-path")]`) should be hidden in tests but visible as comments in README

**Test naming convention**:
- Test function names should be descriptive: `readme_policy_types_example`, `readme_one_liner_sugar_example`
- One test per major README section/example block

**Synchronization workflow**:
1. When adding/changing README examples, add/update corresponding test in `readme_examples.rs`
2. When fixing test compilation errors, update README.md with the corrected code
3. Run `cargo test -p strict-path readme_examples --all-features` to validate
4. Examples must be complete and copy-pasteable (no `...` placeholders or incomplete flows)

**mdBook validation** (future):
- mdBook examples should eventually be extracted and tested similarly
- For now, ensure mdBook examples follow the same principles as README examples
- Prefer linking to validated demos over embedding untested code in mdBook

**Anti-patterns to avoid**:
- ❌ README shows `#[cfg(feature = "virtual-path")] { }` in visible code — hide cfg blocks with `#` comment prefix
- ❌ Incomplete examples that can't be compiled (missing imports, missing file creation)
- ❌ Tests diverge from README (different APIs, different flow, different behavior)
- ❌ README uses `unreachable!()` but tests use `panic!()` — keep consistent
- ❌ Variables with generic names (`filename`, `path`, `name`) that hide the fact they represent untrusted input

**Variable naming for examples (CRITICAL)**:
- **ALWAYS** use variable names that make it crystal clear the data represents untrusted external input
- ✅ **Good**: `user_input`, `requested_file`, `uploaded_avatar`, `attack_input`, `config_input`
- ❌ **Bad**: `filename`, `path`, `name`, `config_name`, `user_doc_path`
- Include comments showing the source: `// User input from HTTP request, CLI args, form data, etc.`
- For attack scenarios, use names like `attack_input`, `malicious_path` to make intent obvious
- Variable names must "scream" that validation is happening on external data

**Test file structure example**:
```rust
// strict-path/src/tests/readme_examples.rs

#[test]
fn readme_policy_types_example() -> Result<(), Box<dyn std::error::Error>> {
    use crate::PathBoundary;
    #[cfg(feature = "virtual-path")]
    use crate::VirtualRoot;

    // Copy exact code from README.md here
    let uploads_boundary: crate::PathBoundary = PathBoundary::try_new_create("./uploads")?;
    // ... rest of example ...
    
    // Add assertions to verify behavior
    assert_eq!(contents, "file contents");
    
    // Cleanup (not shown in README)
    uploads_boundary.into_strictpath()?.remove_dir_all().ok();
    Ok(())
}
```

**Validation commands**:
```bash
# Run README tests only
cargo test -p strict-path readme_examples --all-features

# Run all tests (includes README tests)
cargo test -p strict-path --all-features
```

### Rustdoc formatting rules (prevent invalid HTML and broken links)

To keep `cargo doc` green with `-D warnings`:

- Wrap type/generic expressions in backticks to avoid invalid HTML parsing:
  - Prefer `AsRef<Path>`, `PathBoundary<Marker>`, `StrictPath<Marker>`, `&PathBoundary<Marker>` in backticks.
  - In PARAMETERS lists use: `- root (`AsRef<Path>`): ...` instead of `- root (AsRef<Path>): ...`.
- Use intra-doc links only for public items and with correct paths:
  - Items: [`PathBoundary`](crate::PathBoundary), [`StrictPath`](crate::path::strict_path::StrictPath), [`VirtualRoot`](crate::validator::virtual_root::VirtualRoot).
  - Methods: [`PathBoundary::strict_join`](crate::PathBoundary::strict_join).
  - When unsure, prefer backticks without a link over risking a broken link.
- Do not reference or link to private symbols in docs or examples; doctests can’t access them.
- Avoid raw HTML in comments; use Markdown lists, code ticks, and fenced code blocks.
- Validate locally after edits: `cargo doc --no-deps --document-private-items --all-features`.

### LLM_CONTEXT_FULL.md — Purpose and Audience

## Fast local debugging (be efficient)

When a specific step fails locally or in CI, run only what’s needed first. Prefer targeted commands over the full pipeline:

- Lints for the library only:
  - Quick fix and lint all targets, all features:
    - Windows PowerShell:
      - `cargo clippy -p strict-path --fix --allow-dirty --allow-staged --all-targets --all-features`
  - Non‑fixing lint pass (diagnostics only):
    - `cargo clippy -p strict-path --all-targets --all-features -- -D warnings`
- Tests for the library only:
  - `cargo test -p strict-path --all-features`
  - Single test file or pattern:
    - `cargo test -p strict-path --all-features cve_2025_11001`
- Docs (validate rustdoc warnings):
  - `cargo doc -p strict-path --no-deps --document-private-items --all-features`

When to run full pipeline:
- Before pushing a series of changes or opening a PR
- After modifying multiple areas (API surface, docs, tests)
- When reproducing CI parity locally: use `./ci-local.ps1` on Windows or `./ci-local.sh` on Unix/WSL

Windows‑specific notes:
- Symlink creation can fail without Developer Mode/admin (ERROR_PRIVILEGE_NOT_HELD = 1314). Tests must handle this gracefully and may fall back to junctions when the `junctions` feature is enabled.
- When adapting third‑party crates that require `AsRef<Path>`, pass `.interop_path()` directly; do not wrap it in `Path::new()`.


LLM_CONTEXT_FULL.md is written purely for external LLM consumption. It is usage‑first and should prioritize:
- Which types to use and when (`PathBoundary`, `StrictPath`, `VirtualRoot`, `VirtualPath`).
- How to validate untrusted input via `strict_join`/`virtual_join` before any I/O.
- Interop vs display rules (`interop_path()` vs `*_display()`), and dimension‑specific operations.
- Feature‑gated entry points (e.g., `dirs`, `tempfile`, `app-path`) and their semantics, including environment override behavior for app‑path (env var NAME is resolved to the final root path; no subdir append when override is set).
- Short, copy‑pasteable recipes and explicit anti‑patterns to avoid.

Non‑goals for LLM_CONTEXT_FULL.md:
- Internal design details (type‑state, `PathHistory`, platform specifics) — those live in the mdBook (`.docs/docs_src/src/internals.md`) and source docs.
- Contributor guidance (coding standards, doc comment style, defensive programming) — keep that in AGENTS.md.

Keep LLM_CONTEXT_FULL.md concise and stable. When APIs evolve, update it alongside public docs and demos; prefer linking to realistic `demos/` over embedding long examples that are hard to maintain.

### Doctest setup vs. visible guidance (exception rule)

- Prefer using the crate's safe I/O helpers and the `*_create` constructors (`with_root_create`, `with_boundary_create`) in visible example code.
- Exception: It is acceptable to demonstrate the regular constructors (`with_root`, `with_boundary`) in examples to teach their semantics.
  - In such cases, create the required directories in doctest hidden lines using `std::fs::create_dir_all(...)` so the example compiles and runs:
    - Hidden setup line style: `# std::fs::create_dir_all("some_dir")?;`
  - In the visible code, include a brief note that these constructors require the directory to exist and must be a directory; advise using the `*_create` variants when creation is desired.
- When demonstrating anti-patterns, keep the code runnable: capture the failure in a helper (`if let Err(e) = example() { panic!("{e}"); }`) or assert on the error instead of relying on `no_run` fences.
- Do not use `std::fs` in visible example code unless strictly demonstrating interop via `interop_path()`; keep raw filesystem calls confined to hidden setup/cleanup.

mdBook documentation (authoritative source — NEVER use `book/` directory):
- **Always use `.docs/` worktree** for reading and editing mdBook content.
- Setup: `git worktree add .docs docs` (creates `.docs/` checked out to `docs` branch).
- Read/edit: All content is in `.docs/docs_src/src/*.md` files.
- Build locally: `cd .docs/docs_src && mdbook build`; serve: `cd .docs/docs_src && mdbook serve -o`.
- Key pages: `.docs/docs_src/src/{best_practices,anti_patterns,getting_started,security_methodology}.md`.

### Docs Worktree (Live mdBook on `docs` branch)

- Purpose: Edit and preview mdBook while coding on `main` without mixing branches.
- One‑time setup (from repo root):
  - If `docs` exists locally: `git worktree add .docs docs`
  - If only remote exists: `git fetch origin && git worktree add -B docs .docs origin/docs`
  - Ensure ignore: add `.docs/` to root `.gitignore` (keep worktree untracked on `main`).
- Daily use:
  - Edit docs in `.docs/` (branch `docs`), code in repo root (branch `main`).
  - Live preview: `cd .docs/docs_src && mdbook serve -o` (builds to `.docs/docs`).
  - One‑off build: `cd .docs/docs_src && mdbook build`.
  - Commit/push from inside `.docs` when changing docs.
- Worktree admin:
  - List: `git worktree list`
  - Remove (optional): `git worktree remove .docs` (after committing/cleaning)
  - Prune stale entries: `git worktree prune`
- Notes for agents:
  - Do not create nested clones; prefer a worktree.
  - mdBook `{{#include}}` is restricted to the book root; avoid coupling to files on `main`. If you must include generated snippets, copy them into `.docs/docs_src` via a pre‑build step.

## Contributing Rules (for agents)

- Do not invent new surface APIs without prior discussion.
- Do not add helper functions ad‑hoc; propose design (scope, signature, naming, tests, security notes) first.
- Follow existing module layout: `src/error`, `src/path`, `src/validator`, public re‑exports in `src/lib.rs`.
- Respect MSRV in the library; demos may use newer crates behind features.

## Git Usage Policy (for agents)

### Read-Only Git Operations Only

Agents are **only permitted to run read-only git commands**. Never run any git command that modifies the working tree, index, or history. This includes, but is not limited to:

**Banned (write) operations:**
- `git add`, `git stage`
- `git commit`, `git commit --amend`
- `git restore`, `git checkout -- <file>`
- `git reset` (any form)
- `git stash`, `git stash pop`
- `git merge`, `git rebase`
- `git push`, `git pull`, `git fetch`
- `git rm`, `git mv`
- `git tag`, `git branch -d`

**Allowed (read) operations:**
- `git status`, `git diff`, `git diff --staged`
- `git log`, `git show`, `git blame`
- `git ls-files`, `git stash list`

If you need to stage, commit, or modify git state, **ask the user to do it** or wait for an explicit instruction. Never take git write actions on your own initiative, even to "clean up" or "fix" something you changed.

### Git Commit Workflow

**ALWAYS check staged files before committing.** If the user explicitly instructs you to commit, you MUST:

1. **Run `git status`** to see what files are staged vs unstaged
2. **Run `git diff --staged --stat`** to see exactly what will be committed
3. **Review the staged changes** — ensure they match the intended commit scope
4. **If unrelated files are staged**, either:
   - Unstage them with `git reset HEAD <file>` before committing, OR
   - Ask the user if they should be included

**Never blindly run `git add <file>; git commit`** without checking what was already staged. The user may have staged files for a different purpose.

**Commit message must match staged content.** If the staged diff contains files unrelated to your commit message, STOP and clarify with the user.

## GitHub Issue Management (for agents)

Before implementing features or fixes, agents must verify against existing GitHub issues to ensure work aligns with project priorities and avoid duplication.

### Communication Rules (CRITICAL)

**DO NOT spam issue comments with progress updates.** Agents must communicate primarily with the user directly, not via GitHub comments.

**Issue comments must be CONCISE and FOCUSED:**
- Maximum 15 lines per comment
- Use bullet points, not paragraphs
- No verbose explanations or status reports
- Link to commits/PRs instead of describing changes

**Allowed GitHub interactions:**
- **ONE initial comment** when starting work on an issue (< 10 lines, stating you're beginning)
- **Editing that same comment** to update checkpoints (keep it concise)
- **ONE final comment** when complete (< 15 lines: what was done + commit links)

**Forbidden:**
- Multiple progress update comments
- Verbose explanations (save for commit messages/code comments)
- "Awaiting guidance" or "Question for maintainer" comments without explicit user approval
- Status reports that should be communicated directly to the user instead
- Long-form documentation in issues (belongs in code/docs)

**Preferred workflow:**
1. Tell the user directly what you're working on
2. Make ONE comment on the issue when you start
3. Edit that comment with checkpoint updates as you progress
4. Communicate all questions/blockers to the user directly
5. Make final summary comment when complete

### Issue Verification Workflow

#### Before Starting Work
- [ ] **Search existing issues**: Check if the problem/feature is already tracked
- [ ] **Review issue status**: Open, assigned, in-progress, or completed
- [ ] **Check issue priority**: Labels, milestones, and project boards
- [ ] **Verify scope alignment**: Ensure proposed work matches issue requirements

#### During Implementation
- [ ] **Reference issue numbers**: Include `Fixes #N` or `Addresses #N` in commit messages
- [ ] **Update issue progress**: Edit your initial comment with checkpoints (do not create new comments)
- [ ] **Request clarification**: Ask the user directly; only post to issue if user approves
- [ ] **Document decisions**: Explain technical choices in code comments or commit messages

#### After Completion
- [ ] **Verify issue resolution**: Ensure all acceptance criteria are met
- [ ] **Update issue status**: Edit your initial comment with final status, or create ONE completion comment
- [ ] **Link to implementation**: Reference PRs, commits, or documentation changes
- [ ] **Validate in context**: Test that the fix/feature works as intended

### When to Create New Issues

If you identify work that should be tracked as an issue, **make an offer and explain in detail** why it should be created:

#### Offer Template
```
I've identified [problem/opportunity]: [brief description]

**Why this should be an issue:**
- [Impact on users/developers]
- [Alignment with project goals]  
- [Complexity/effort required]
- [Dependencies or related work]

**Proposed scope:**
- [Specific deliverables]
- [Acceptance criteria]
- [Timeline considerations]

**Alternative approaches:**
- [Other solutions considered]
- [Trade-offs and implications]

Would you like me to create this issue? I can provide:
- Detailed problem statement
- Technical requirements
- Implementation suggestions
- Testing criteria
```

#### Issue Creation Criteria
Create issues for work that is:
- **Substantial**: Requires multiple commits or touches multiple files
- **User-impacting**: Affects API, documentation, or functionality
- **Discussion-worthy**: Needs input on approach or requirements
- **Trackable**: Benefits from progress tracking and milestone planning
- **Referenceable**: Other issues, PRs, or discussions might reference it

#### Do NOT create issues for:
- Trivial fixes (typos, formatting, small refactors)
- Work that's already in progress or completed
- Vague ideas without clear scope or acceptance criteria
- Duplicate concerns already covered by existing issues

### Issue Quality Standards

When creating issues, ensure they include:
- **Clear title**: Describes the problem/feature concisely
- **Problem statement**: What issue are we solving and why
- **Acceptance criteria**: How do we know when it's complete
- **Context**: Background information and related work
- **Scope boundaries**: What's included/excluded
- **Labels**: Appropriate categorization (bug, enhancement, documentation, etc.)

### Examples & Tests Principles

- Examples:
  - **Must be real-world and immediately demonstrate value**: Start with complete, realistic scenarios (e.g., archive extraction, web file uploads) that show the crate solving an actual problem. Avoid contrived "hello world" snippets that don't teach anything meaningful.
  - **Path strings must be obviously paths**: Use full paths like `"/var/app/uploads"` or multi-segment relative paths like `"./data/user_files"` — never bare names like `"uploads"` that could be mistaken for any string. The path structure must be immediately readable.
  - **Variable names must reveal untrusted input**: Name variables to show the data source (e.g., `archive_entry_name`, `user_uploaded_file`, `http_request_path`) — never generic names like `filename` or `path` that hide the validation purpose.
  - Compile and run (doctests or `cargo run --example ...`); no `#[allow(..)]`.
  - Use domain‑based variable names and explicit strict/virtual API calls; never wrap `.interop_path()` to use std path operations.
  - Demonstrate discovery vs. validation patterns clearly.
- Tests:
  - Library: thorough unit/integration tests for new behavior (e.g., rename semantics across strict/virtual, cross‑platform differences).
  - Demos: generally do not compile or run in CI; keep any demo tests to minimal smoke checks and run them locally as needed. CI enforces lint‑clean code only for demos.

## Local CI Parity

- Windows: `./ci-local.ps1`.
- Unix/WSL: `bash ./ci-local.sh`.
- Scripts auto‑fix format/clippy where safe and mirror CI behavior (including mdBook build).

### Local CI scripts: roles and when to use each

We provide three complementary local CI entry points to keep feedback fast and focused. Use these from the repository root unless noted.

- `ci-check.ps1` / `ci-check.sh` — fast core library validation (no demos)
  - Scope: `strict-path/` crate only; MSRV-aligned behavior.
  - What it does: `cargo fmt -p strict-path -- --check`, `cargo clippy -p strict-path --all-targets --all-features -D warnings`, and doc checks without compiling dependencies (`cargo doc -p strict-path --no-deps`).
  - When to use: Editing core library code or docs and you want a quick signal without building demos or pulling extra crates.

- `ci-check-demos.ps1` / `ci-check-demos.sh` — selective demos validation
  - Scope: `demos/` crate only; does not build or run demo binaries by default.
  - Default behavior: Auto-format changed demo files and validate style without compiling. It detects changes from both `git diff` and `git diff --staged`, and only checks the demo files that changed.
  - Safe features: Clippy runs are gated to lightweight features by default (`with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp`) to avoid heavy toolchain deps (e.g., `cmake`, `nasm`).
  - When to use: You modified one or a few demo binaries and want quick feedback without compiling the entire demos crate.

- `ci-local.ps1` / `ci-local.sh` — orchestrated local pipeline (full pass)
  - Scope: Orchestrates format and clippy auto-fixes for both the core library and demos. Mirrors CI intent while remaining fast locally.
  - Split clippy steps: Runs `cargo clippy --fix` separately for the library (`-p strict-path --all-features`) and for demos (from `demos/` with the safe feature set). This avoids unnecessary heavy deps unless explicitly opted in.
  - When to use: Before committing/pushing to get a near-CI signal and apply safe auto-fixes across the workspace.

Notes
- All scripts default to “auto-fix where safe,” especially formatting. Prefer running them before committing to keep diffs clean.
- The demos checker focuses solely on demo changes; core edits won’t force demos checks unless you explicitly choose to run the orchestrator.
- Heavy demo feature sets (e.g., cloud SDKs) should be opted into explicitly when you need to compile/run those demos locally.

### When a CI Step Fails: Targeted Isolation Workflow

Always reproduce and fix the failure on the same platform where it occurred (Windows vs. Linux/macOS) before re‑running the full pipeline.

- Windows (PowerShell): run only the failing test
  - Command pattern:
    - `cargo test [-p <package>] <test_filter> --all-features -- --nocapture`
  - Notes:
    - Use `-p <package>` only in workspaces or when multiple packages are present.
    - You may scope to `--lib` or `--bin <name>` when helpful.

- Linux/macOS/WSL (bash): run only the failing test
  - Command pattern:
    - `cargo test [-p <package>] <test_filter> --all-features -- --nocapture`

Other targeted checks (when applicable):
- Lints: `cargo clippy [-p <package>] --all-targets -- -D warnings`
- Formatting: `cargo fmt --all -- --check` (and `cargo fmt --all` to fix)
- Doc-tests: `cargo test --doc [-p <package>] <test_filter> -- --nocapture`

Guidelines:
- Keep the test’s intent intact; don’t weaken semantics to “make it pass.”
- Prefer MSRV‑ and cross‑platform‑safe assertions; avoid unstable variants and, if needed, check raw OS error codes alongside stable kinds.
- Once the targeted run is green, re‑run the full local CI script for that platform to validate end‑to‑end.

## Quick Do/Don’t

- Do: validate untrusted segments via `strict_join`/`virtual_join`.
- Do: pass `&StrictPath`/`&VirtualPath` into helpers; or pass boundaries/roots + segment.
- Do: use explicit operations and display helpers.
- Don't: wrap `.interop_path()` in `Path::new()` or `PathBuf::from()` to use std path operations — that defeats all security.
- Don’t: validate constants “just to use the API”.
- Don't: add redundant ways to achieve the same thing --- one correct way per operation.
- Don't: use `pub(crate)` methods in tests as shortcuts around the public API.

---

If in doubt, prefer examples in `strict-path/src/lib.rs` and mdBook pages as the source of truth.

## Doctest and Lint Suppression Policy (Non‑Negotiable)

This repository enforces a zero‑tolerance policy for skipped doctests and warning suppressions. These rules are binding for all contributors and automation.

What is forbidden (will be rejected):
- Rustdoc code‑fence flags that avoid execution: `no_run`, `ignore`, `should_panic` (unless the example explicitly demonstrates a panic as part of API semantics).
- `doctest: false` in manifests or docs config.
- Any `#[allow(...)]` used to bypass warnings, with a single, explicit whitelist: `#[allow(clippy::type_complexity)]` for verbose type expressions only (e.g., internal `PathHistory` typing). No other `allow` is acceptable.

Why this exists:
- Doctests that don’t run are untrustworthy and silently rot; they mislead users and mask integration gaps.
- Warning suppressions hide problems instead of fixing them; that’s not acceptable for a security‑critical crate.

What to do instead:
- Make doctests runnable: set up minimal hidden scaffolding lines in the example (e.g., create directories/files) and execute the real code path.
- If the intent is to show a compile‑time failure, use `compile_fail`. If demonstrating a runtime error, assert on the error value in a regular test.
- Remove or rework unused/dead code; do not mute the warning.

PR acceptance gates (hard requirements):
- Doctests: runnable with no skip flags; no `doctest: false`.
- Lints: no new `#[allow(...)]` beyond `#[allow(clippy::type_complexity)]` where justified.
- If an example or code path cannot be made to run, it must be simplified or removed—green by avoidance is not permitted.

Reviewer template (paste into PRs when violations occur):
> This repo does not accept skipped doctests or warning suppressions. Please:
> - Remove `no_run`/`ignore`/`should_panic` flags and make the example execute (use `compile_fail` only when the compiler must reject the code).
> - Remove `#[allow(...)]` suppressions. The only exception is `#[allow(clippy::type_complexity)]` for long type expressions; justify its use in the PR.
> We do not hide problems to get a green check—fix the issue or cut the code.

## IO Return Value Policy

- All built-in IO helpers return the same value as their `std::fs` counterparts (`rename`/`symlink`/`hard_link` -> `io::Result<()>`, `copy` -> `io::Result<u64>`, etc.).
- This preserves the exact signal from the OS (including byte counts) and avoids extra filesystem probes when callers need those results.
- Ergonomic chaining wrappers can exist on top, but the primary APIs stay faithful to the standard library to avoid surprise.

## Hard Link Helpers

- `PathBoundary::strict_hard_link` and `VirtualRoot::virtual_hard_link` simply forward to the underlying `StrictPath` helpers.
- Many platforms forbid directory hard links (e.g., Linux, macOS); expect `io::ErrorKind::PermissionDenied` in those cases and treat it as an acceptable outcome.


## Defensive Programming (addendum)

This crate is security‑critical. Agents must practice defensive programming to prevent subtle regressions:

- Prefer non‑panicking APIs; return `Result<_, StrictPathError>` or `io::Result<_>` and map errors explicitly. Never `unwrap()`/`expect()` in library code or examples (tests may use them sparingly when the intent is to fail fast).
- Fail closed: default to rejecting input on ambiguity (unknown prefixes, invalid components, resolution anomalies). Document the error variant you return.
- Validate invariants at module boundaries. Keep normalization + checks centralized (PathHistory) and avoid “local fixes” that split the pipeline.
- Guard platform specifics. For Windows short‑name handling and UNC quirks, add targeted tests and prefer explicit error variants over silent acceptance.
- Keep examples and docs exploit‑aware: demonstrate discovery vs. validation, and prefer `*_create` constructors for visibility. Never show std path ops on untrusted input.
- Add regression tests for every bugfix in the validator or join logic. Cover both strict and virtual flows, including env‑override paths behind `app-path`.
- Treat `Display`/string conversions as sensitive. Use explicit `*_display()` helpers; avoid accidental path leaks in logs or UI.

When in doubt, choose clarity and correctness over cleverness. Small helpers are acceptable if they preserve the security model and reduce misuse.


## Coding Guidelines

### Compiler Diagnostic Annotations (`#[must_use]`)

This crate uses `#[must_use]` annotations systematically to create a
compiler-driven feedback loop — especially for AI agents and LLMs that
consume compiler warnings as their primary signal.

**Principle:** Every public method or type whose return value carries
security or correctness significance must have `#[must_use]`, with a
descriptive message that tells the caller _what to do next_.

#### Categorization Rules

| Category | Annotation | Examples |
| --- | --- | --- |
| **Structs** (core validated types) | `#[must_use = "...guidance..."]` | `StrictPath`, `VirtualPath`, `PathBoundary`, `VirtualRoot`, `StrictOpenOptions` |
| **Error enums** | `#[must_use = "...guidance..."]` | `StrictPathError` |
| **Validation / join methods** (return `Result`) | `#[must_use = "...guidance..."]` | `strict_join()`, `virtual_join()`, `try_new()`, `try_new_create()` |
| **Consuming methods** (take `self`) | `#[must_use = "...guidance..."]` | `change_marker()`, `unstrict()`, `unvirtual()`, `into_strictpath()`, `into_virtualpath()` |
| **Security-critical accessors** | `#[must_use = "...guidance..."]` | `interop_path()`, `strictpath_display()`, `virtualpath_display()`, `as_unvirtual()` |
| **Sugar constructors** (return `Result`) | `#[must_use = "...guidance..."]` | `StrictPath::with_boundary()`, `VirtualPath::with_root()` |
| **Builder entry points** | `#[must_use = "...guidance..."]` | `open_with()` |
| **Pure query methods** (return `bool`, `Option`) | `#[must_use]` (no message) | `exists()`, `is_file()`, `is_dir()`, `file_name()`, `file_stem()`, `extension()`, `starts_with()`, `ends_with()` |
| **I/O methods returning `io::Result`** | **No `#[must_use]`** | `metadata()`, `read_to_string()`, `read()`, `read_dir()`, `try_exists()` |
| **Side-effect methods** (return `()` or `io::Result<()>`) | **No `#[must_use]`** | `write()`, `create_file()`, `create_dir()`, `remove_file()`, `touch()`, `set_permissions()` |
| **Builder chainable methods** (return `Self` on a `#[must_use]` struct) | **No `#[must_use]`** | `StrictOpenOptions::read()`, `.write()`, `.create()` |

**Why no `#[must_use]` on `io::Result` methods?** `Result` already has
`#[must_use]` in the standard library. Adding a plain `#[must_use]` on the
method triggers `clippy::double_must_use`. Only add `#[must_use = "message"]`
with a descriptive message if the method has security implications beyond
what `Result`'s built-in warning conveys.

**Why no `#[must_use]` on builder chain methods?** The builder struct itself
already carries `#[must_use]`. Adding it on each `.read()`, `.write()` etc.
triggers `clippy::double_must_use` since they return `Self`.

#### Message Format Guidelines

Messages should be actionable and tell the caller what to do next:

```rust
// ✅ Good: tells the agent what to do with the result
#[must_use = "strict_join() validates untrusted input against the boundary — always handle the Result to detect path traversal attacks"]

// ✅ Good: explains the consuming semantics
#[must_use = "unstrict() consumes self — use the returned PathBuf for interop, or prefer .interop_path() to borrow without consuming"]

// ✅ Good: warns about security-critical output
#[must_use = "pass interop_path() directly to third-party APIs requiring AsRef<Path> — never wrap it in Path::new() or PathBuf::from(); NEVER expose this in user-facing output (use .virtualpath_display() instead)"]

// ❌ Bad: no guidance
#[must_use]  // on a method returning Result — triggers double_must_use
#[must_use = "returns a value"]  // too vague, doesn't help
```

#### Checklist for New Public APIs

When adding any new public method, check:

- [ ] Does it return a value? → Needs `#[must_use]` consideration
- [ ] Does it return `Result` or `io::Result`? → **Do NOT add plain `#[must_use]`**; add `#[must_use = "message"]` only if it has security implications beyond what `Result` already warns about
- [ ] Does it return `Self` on a `#[must_use]` struct? → **Do NOT add `#[must_use]`** (struct already warns)
- [ ] Does it return `bool`, `Option`, or non-`must_use` types? → Add `#[must_use]` (plain is OK for simple queries)
- [ ] Is it a consuming method (`self`)? → Add `#[must_use = "...consumes self..."]`
- [ ] Is it security-critical (`interop_path`, display helpers)? → Add `#[must_use = "...security guidance..."]`
- [ ] Is it a side-effect method? → **No `#[must_use]`**

### Safe Indexing — No Direct Indexing in Production Code

Production code must **never** use direct indexing on **any type** —
`&[u8]`, `&str`, `Vec<T>`, `&[T]`, or any other indexable container.
This applies regardless of whether the index "feels safe" (e.g. derived
from `.find()` or bounded by a loop guard).  Direct indexing panics on
out-of-bounds access, which is a denial-of-service vector in a
security‑critical crate.

**Banned patterns (all of these panic on OOB):**

```rust
parts[i]              // slice element access
data[start..end]      // slice range
line[pos..]           // string slicing
content[..colon_pos]  // string slicing with find()-derived index
value.as_bytes()[0]   // first-byte access
```

**Required replacements:**

| Banned                | Replacement                                               |
| --------------------- | --------------------------------------------------------- |
| `parts[i]`           | `parts.get(i).ok_or(…)?` or `parts.get(i).map(…)`        |
| `data[start..end]`   | `data.get(start..end).ok_or(…)?`                          |
| `slice[i..]`         | `slice.get(i..).unwrap_or_default()`                      |
| `&line[..pos]`       | `line.get(..pos).unwrap_or(line)`                         |
| `value.as_bytes()[0]`| `value.as_bytes().first()`                                |

**Prior bounds checks do not exempt direct indexing.**  A manual check
immediately before the access — `if end > data.len() { return Err(…) }` or
a `while i < slice.len()` loop guard — does **not** satisfy this rule.  The
replacement must be at the call site:

```rust
// Wrong — reader must trace the preceding guard to verify safety:
if end > data.len() { return Err(…); }
let slice = &data[offset..end];

// Correct — safety is self-evident at the call site:
let slice = data.get(offset..end).ok_or(…)?;
```

For **sequential processing**, prefer iterators (`.iter()`, `.enumerate()`,
`.windows()`, `.chunks()`, `.split()`) over index-based loops.

**Test code** (`#[cfg(test)]` blocks, `tests/`) may use direct indexing when
the test controls the input and panic-on-bug is acceptable.

### Heap Allocation Awareness

While security is prioritized above raw performance in this crate, unnecessary
heap allocations should still be avoided in hot paths (path component iteration,
validation checks, normalization helpers).  Use stack buffers, iterators, and
streaming operations instead of intermediate `Vec`, `String`, or `Box` where
practical.

For necessary allocations (variable-length output):
- Use `Vec::with_capacity(known_size)` to avoid reallocation.
- Prefer `Vec::extend_from_slice` over N × `push` for bulk copies.

### Type Safety

- Prefer `Option` / `Result` over sentinel values.  Never use empty strings,
  `-1`, or null-equivalent magic values to signal absence.
- Prefer `match` over `if let` when handling enums so that adding a new variant
  produces a compile error at every call site, rather than silently falling
  through.
- Keep struct fields private when invariants must be enforced.  Expose
  transition methods that enforce them.

### Lifetime Naming

- Lifetime parameter names must be meaningful: name the lifetime after the
  item whose lifetime it represents (for example `'boundary` for a borrowed
  boundary, `'path` for a path reference, `'input` for untrusted input
  data).  Avoid vague single-letter names like `'a` in public APIs;
  single-letter lifetimes may be acceptable in very small local scopes or
  short-lived closures.
- Prefer descriptive lifetime names in structs and function signatures so
  reviewers and automated tools can immediately identify what is being
  borrowed and why.  This improves readability and reduces confusion when
  multiple lifetimes are present.

### No Unsafe Code

This crate must never contain `unsafe` blocks, `unsafe fn`, or `unsafe impl`.
If a dependency requires an unsafe interface, wrap it in a dedicated dependency
crate — never bring `unsafe` into this crate's source.

### Module Independence

- **One concept per file.** Each module should be independently understandable
  — its purpose, invariants, and failure modes must be clear without reading
  the rest of the crate.
- **DAG dependencies only.** Dependencies between modules flow through explicit
  public APIs, not shared mutable state, implicit ordering, or circular imports.
  If module A calls module B and B calls A, the design is wrong — restructure
  until the dependency graph is a DAG.
- **Testable in isolation.** Extract pure logic from side-effectful functions.
  If a function mixes computation with I/O, split it: a pure function that
  takes inputs and returns outputs, and a thin wrapper that handles I/O
  and delegates to the pure function. The pure function gets unit-tested
  without mocks.

### RAG / LLM-Friendly File Size

Keep source files under **~600 lines** (production or test) to fit within a
single LLM context window and improve RAG retrieval precision.

- When a production file grows past ~600 lines, split into focused submodules
  (e.g. `foo.rs` → `foo/mod.rs` + `foo/helpers.rs`).
- When a test file grows past ~600 lines, split into thematic files
  (e.g. `tests_validation.rs`, `tests_security.rs`).
- Favour a stable top-to-bottom layout so any reader knows where to look:
  module docs → imports → constants → types → impl blocks → functions → tests.

## Coding Session Discipline

### Trust the Code — Ask Before "Fixing"

When you encounter a design choice that seems unusual, wrong, or suboptimal:

1. **Assume it was intentional.** This crate has deliberate, security-motivated
   design decisions. What looks like an oversight is usually a conscious
   constraint.
2. **Read surrounding code and docs** to understand the rationale before
   forming an opinion.
3. **ASK the maintainer** if you still don't understand the "why." Present
   your confusion as a question, not a fix.
4. **Never "fix" design choices unilaterally.** Changing established patterns
   without understanding them breaks invariants and wastes time undoing the
   damage.

This applies especially to:
- API surface restrictions (why a type deliberately lacks a trait impl or method)
- Seemingly "missing" convenience methods (they may have been removed on purpose)
- Internal visibility choices (`pub(crate)` vs `pub` vs private)
- Type design decisions (why `interop_path()` returns `&OsStr` instead of `&Path`)

**The rule:** If something looks wrong but already exists in committed code,
the default hypothesis is "the maintainer had a reason." Verify before acting.

### Tests Must Use Public API Only

Tests exist to validate the experience that real users have with the crate's
public API. Using internal-only methods in tests defeats this purpose.

**Forbidden in tests:**
- Calling `pub(crate)` methods to get path data, compare values, or bypass
  the public API surface.
- Accessing private fields or internal representations that users cannot reach.
- Any pattern that "works in tests" but would fail for a downstream consumer.

**Required approach:**
- Use `strictpath_display().to_string()` for string comparisons.
- Use `interop_path()` where `AsRef<Path>` is needed (e.g., `std::fs` calls
  in test setup/verification).
- Use the crate's built-in I/O helpers (`read_to_string()`, `exists()`,
  `read_dir()`, etc.) for filesystem assertions.

**Rationale:** If a test cannot be written using the public API, that is a
signal the public API is missing something — fix the API, do not add an
internal shortcut. Tests that cheat with internal methods hide usability
problems that only real users would discover.

### Test-First / Proof-First

- For every non-trivial behavior change, bug fix, or regression fix:
  **write or update the tests first** so the expected behavior is explicit
  before implementation changes begin.
- The intended workflow is **red → green → refactor**:
  1. Encode the requirement in a test.
  2. Observe the old implementation fail or lack the behavior.
  3. Implement the change.
  4. Rerun the tests to prove the new behavior.
- If a task is purely structural (rename, move, formatting) and has no
  behavioral delta, a new failing test is not required.
- Every problem or bug fixed must include a regression test as part of the
  same change set.

### Evidence Rule

Do not claim a feature or fix is complete without evidence:

- Tests (unit, integration, or doctests) proving the behavior.
- CI output showing clean build + test pass.
- Manual verification notes (if no automation exists yet).

"Implemented" or "fixed" without proof is not acceptable.

## Handling External Feedback & Reviews

Treat feedback as input, not instruction. Validate every claim before acting.

1. **Check against established principles first.** Before applying any fix —
   whether from a reviewer, from your own analysis, or from a pragmatic
   shortcut — ask: "Does this change violate a design principle we already
   settled?" If yes, the change is wrong regardless of how reasonable it
   sounds. Fix the surrounding code to uphold the principle; never weaken
   the principle to match the surrounding code.

2. **Use git history to resolve contradictions.** When two representations
   disagree, run `git log -S "<term>" --oneline -- <file>` on both sides to
   determine which text is newer. The newer commit represents the more
   recent design decision. Always upgrade stale text to match the newer
   decision, never the reverse.

3. **Verify the factual claim.** Read the text being criticized. Is the
   characterization accurate? Quote the actual text. If the reviewer
   misread or mischaracterized the code/doc, say so and reject the finding.

4. **Independently assess severity.** Do not accept a reviewer's severity
   rating at face value. Assign your own and state it if it differs.

5. **Distinguish bugs from preferences.** A factual contradiction or
   invariant violation is a bug — fix it. "The code could be cleaner" is a
   preference — evaluate against the cost of the change.

6. **Reject or downgrade with justification.** If a finding is invalid,
   reject it explicitly and state the reason. Do not implement changes just
   because someone flagged something.

7. **Check for cascade inconsistencies.** When fixing a confirmed finding,
   search for the same pattern in other files. Fix all occurrences in one
   pass — but only where the same error actually exists.

## PR Checklist (agent self-check)

Before considering any change complete, verify:

- Security guarantees preserved: paths cannot escape boundaries; no new `AsRef<Path>` / `Deref` leaks.
- All CI steps in `ci-local.ps1` / `ci-local.sh` pass locally.
- New/changed logic covered by unit and/or integration tests, plus doctests if public behavior changed.
- Docs updated (README, lib.rs, LLM_CONTEXT_FULL.md) if user-visible behavior changed.
- No new runtime dependencies; MSRV respected; no unstable features.
- No `#[allow(...)]` beyond the approved `clippy::type_complexity` exception.
- Doctests runnable with no skip flags.
- Regression tests included for every bug fix.


## Commenting Style

### Comments Are the Permanent Record

Every comment — doc comment, module comment, inline comment — must carry
**full context in place**. Do not assume the reader has read other files,
git history, issue trackers, or the original author's mind. The moment
you write code for a reason, that reason must be written down **next to
the code**, because:

* **Memory is unreliable.** The original author will forget why they did
  something. Six months later they will "fix" it and reintroduce the bug
  the code was written to prevent.
* **Git blame is fragile.** Refactors, moves, and reformats break the
  trail. A comment survives all of them.
* **External references rot.** Issue links close, wikis move, Slack
  threads scroll away. The code outlives them all.

If the reason for a piece of code is not written next to it, treat it
as if the reason does not exist.

### Why > What > How

Every non-trivial block of code must carry comments that answer up to
three questions, **in this order**:

1. **Why** — the design decision, domain rationale, or constraint that
   motivated this code. **Lead with this.** A reader who knows why
   something exists can decide instantly whether they need the details.
2. **What** — a plain-language summary of what the code does, now that
   the reader knows why it matters.
3. **How** (when non-obvious) — algorithm steps, domain-specific
   mechanics, or interaction with external crates that a reader
   unfamiliar with the ecosystem would not immediately grasp.

Not every block needs all three. Trivial code needs none. But when in
doubt, over-explain the **why** — it is never obvious in hindsight.

### Rules

- Use `///` doc comments on every public item. Every module must open
  with `//!` stating why the module exists, what it provides, and how
  it fits into the crate.
- Don't restate the type signature in English. Rust's type system and
  `cargo doc` already convey parameters, return types, and error variants.
- Constants and magic numbers must document their origin and meaning.
- Safety-critical paths must have an inline comment explaining **what
  attack or failure** the check prevents.
- Use section headers (`// \u2500\u2500 Section name \u2500\u2500\u2500`) to visually separate
  logical phases within long functions.
- When modifying a function, update its comments to match this style.
  Don't rewrite comments in bulk — only update what you touch.
- Always use imperative style in the summary ("Join child onto strict
  path"), not descriptive ("This function joins...").
- Show at least one compilable example in doc comments; add a failure
  case if common. Do not hide invariants: state guarantees such as
  "never escapes boundary".
