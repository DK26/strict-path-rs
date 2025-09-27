# AGENTS.md

Operational guide for AI assistants, bots, and automation working in this repository.

## Project Overview

- Purpose: Prevent directory traversal with type‑safe path boundaries and safe symlinks.
- Core APIs: `PathBoundary<Marker>`, `StrictPath<Marker>`, `VirtualRoot<Marker>`, `VirtualPath<Marker>`, `StrictPathError` (see LLM_API_REFERENCE.md).
- Security model: “Restrict every external path.” Any path from untrusted inputs (user I/O, config, DB, LLMs, archives) must be validated into a restriction‑enforced type (`StrictPath` or `VirtualPath`) before I/O.
- Foundation: Built on `soft-canonicalize` for resolution; Windows 8.3 short‑name handling is considered a security surface.

Do not implement leaky trait impls for secure types:
- Forbidden: `AsRef<Path>`, `Deref<Target = Path>`, implicit `From/Into` conversions for `StrictPath`/`VirtualPath`.
- Rationale: They would bypass validation and blur dimension semantics (strict vs virtual).

### Helper API Restrictions (Unbreakable)

- Never introduce new `pub` helper functions or constructors. Public API additions must come from explicit maintainer direction, not autonomous agent judgment.
- Before adding *any* new helper that is `fn`, `pub(crate) fn`, or otherwise widening internal surface area, pause and request maintainer approval. Document the need in the PR description rather than committing speculative helpers.

## Repository Layout

- Root workspace: `[workspace].members = ["strict-path"]`, `exclude = ["demos"]`.
- `strict-path/`: library crate; MSRV‑bound.
- `demos/`: real‑world demo binaries; decoupled from MSRV; `publish = false`.
- `.github/workflows/`: CI configs; stable + MSRV split.
- Local CI parity: `ci-local.ps1` (Windows), `ci-local.sh` (Unix/WSL).
- Docs: `README.md`, `LLM_API_REFERENCE.md`.
  - mdBook sources live on branch `docs` (not on `main`).
  - Use a local Git worktree at `.docs/` to edit/serve docs side‑by‑side.

## CI Workflows (GitHub Actions)

- Stable job (linux/windows/macos):
  - `cargo fmt --all -- --check` and `cargo clippy --all-targets --all-features -- -D warnings` (library).
  - Demos are linted only (not built/run): `cd demos && cargo clippy --all-targets --features "with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp" -- -D warnings`.
    - Heavier integrations like `with-aws` are included when toolchain prerequisites (e.g., `cmake`, `nasm`) are available on runners.
  - `cargo test -p strict-path --all-features` (library only).
- MSRV job (linux, Rust 1.71.0):
  - `check`/`clippy`/`test` scoped to `-p strict-path --lib --locked` using separate target dir.

## MSRV Policy (Library Only)

- MSRV: Rust 1.71.0 (declared in `strict-path/Cargo.toml`).
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

## Code & API Usage Guidelines

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
  - Interop (`AsRef<Path>`): Call `.interop_path()` on `StrictPath`/`VirtualPath`/`PathBoundary`/`VirtualRoot` **only** when a third-party crate (including stdlib adapters that you cannot wrap) insists on an `AsRef<Path>` argument. If you reach for `.interop_path()` in any other context, pause and re-evaluate—the crate almost certainly already exposes a strict helper for that operation.
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
  - For demos, prioritize names that explain the role in the real flow (e.g., `user_project_root`, `tenant_vroot`, `system_root`, `ingest_dir`).

### Serde Guidelines

- Feature `serde` adds `Serialize` for `StrictPath`/`VirtualPath`.
- Safe deserialization requires runtime policy; use seeds on policy types:
  - `serde_ext::WithBoundary(&boundary)` → `StrictPath`
  - `serde_ext::WithVirtualRoot(&vroot)` → `VirtualPath`
- For config structs: deserialize raw `String`/path-like fields and validate by calling `strict_join` or `virtual_join` using either a sugar-constructed root or a policy root.
- Do not add blanket `Deserialize` impls for the secure path types; they need context.

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
- Performing filesystem I/O via `std::fs` on `.interop_path()` paths instead of the built-in strict helpers (e.g., `StrictPath::create_file`, `StrictPath::read_to_string`).
- `interop_path().as_ref()` or `as_unvirtual().interop_path()` — when adapting third-party crates, call `.interop_path()` directly; no extra `.as_ref()` dance.
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
- Examples should be runnable and realistic: prefer end‑to‑end flows over contrived snippets; show policy types for reusable flows.
- Doctests and examples must not rely on `#[allow(..)]` to pass lints; fix code and naming instead.
- Fenced code blocks in docs must execute as doctests. Do not use `no_run`, `ignore`, or similar escape hatches. If an example needs to show a failure path, structure it as a regular doctest that asserts the failure (or mark it `compile_fail` when the compiler should reject it).
- Lead with sugar for ergonomics in simple flows; demonstrate policy types for reuse, serde context, OS dirs, and temp RAII.
- For multi‑user flows, prefer `VirtualRoot`/`VirtualPath`; for shared strict logic, borrow `as_unvirtual()`.

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

### LLM_API_REFERENCE.md — Purpose and Audience

LLM_API_REFERENCE.md is written purely for external LLM consumption. It is usage‑first and should prioritize:
- Which types to use and when (`PathBoundary`, `StrictPath`, `VirtualRoot`, `VirtualPath`).
- How to validate untrusted input via `strict_join`/`virtual_join` before any I/O.
- Interop vs display rules (`interop_path()` vs `*_display()`), and dimension‑specific operations.
- Feature‑gated entry points (e.g., `dirs`, `tempfile`, `app-path`) and their semantics, including environment override behavior for app‑path (env var NAME is resolved to the final root path; no subdir append when override is set).
- Short, copy‑pasteable recipes and explicit anti‑patterns to avoid.

Non‑goals for LLM_API_REFERENCE.md:
- Internal design details (type‑state, `PathHistory`, platform specifics) — those live in the mdBook (`docs_src/`) and source docs.
- Contributor guidance (coding standards, doc comment style, defensive programming) — keep that in AGENTS.md.

Keep LLM_API_REFERENCE.md concise and stable. When APIs evolve, update it alongside public docs and demos; prefer linking to realistic `demos/` over embedding long examples that are hard to maintain.

### Doctest setup vs. visible guidance (exception rule)

- Prefer using the crate's safe I/O helpers and the `*_create` constructors (`with_root_create`, `with_boundary_create`) in visible example code.
- Exception: It is acceptable to demonstrate the regular constructors (`with_root`, `with_boundary`) in examples to teach their semantics.
  - In such cases, create the required directories in doctest hidden lines using `std::fs::create_dir_all(...)` so the example compiles and runs:
    - Hidden setup line style: `# std::fs::create_dir_all("some_dir")?;`
  - In the visible code, include a brief note that these constructors require the directory to exist and must be a directory; advise using the `*_create` variants when creation is desired.
- When demonstrating anti-patterns, keep the code runnable: capture the failure in a helper (`if let Err(e) = example() { panic!("{e}"); }`) or assert on the error instead of relying on `no_run` fences.
- Do not use `std::fs` in visible example code unless strictly demonstrating interop via `interop_path()`; keep raw filesystem calls confined to hidden setup/cleanup.

mdBook documentation system:
- Sources live on the `docs` branch under `docs_src/` (built to `docs/`).
- Preferred local layout: add a Git worktree at `.docs/` checked out to `docs`.
- Build locally: `cd .docs/docs_src && mdbook build`; serve: `cd .docs/docs_src && mdbook serve -o`.
- Pages of interest: Best Practices, Anti‑Patterns, Getting Started, Features/OS directories, Archive Extractors.

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

## GitHub Issue Management (for agents)

Before implementing features or fixes, agents must verify against existing GitHub issues to ensure work aligns with project priorities and avoid duplication.

### Issue Verification Workflow

#### Before Starting Work
- [ ] **Search existing issues**: Check if the problem/feature is already tracked
- [ ] **Review issue status**: Open, assigned, in-progress, or completed
- [ ] **Check issue priority**: Labels, milestones, and project boards
- [ ] **Verify scope alignment**: Ensure proposed work matches issue requirements

#### During Implementation
- [ ] **Reference issue numbers**: Include `Fixes #N` or `Addresses #N` in commit messages
- [ ] **Update issue progress**: Comment on implementation approach and progress
- [ ] **Request clarification**: Ask questions if requirements are unclear
- [ ] **Document decisions**: Explain technical choices that affect the issue

#### After Completion
- [ ] **Verify issue resolution**: Ensure all acceptance criteria are met
- [ ] **Update issue status**: Comment with resolution details and close if appropriate
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
  - Compile and run (doctests or `cargo run --example ...`); no `#[allow(..)]`.
  - Use domain‑based variable names and explicit strict/virtual API calls; never ad‑hoc std path ops on leaked values.
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
- Don’t: wrap secure types in std paths or use std ops on leaked values.
- Don’t: validate constants “just to use the API”.

---

If in doubt, prefer examples in `strict-path/src/lib.rs` and mdBook pages as the source of truth.

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


## Commenting Standard for Functions (LLM-Friendly)

To ensure LLMs can use this crate’s API correctly, every function must follow this doc-comment style:

```rust
/// SUMMARY:
/// One–two sentences describing what the function does. Use **imperative form**
/// and mention its dimension (strict or virtual) if relevant.
///
/// PARAMETERS:
/// - `param_name` (Type): What it is, constraints, and if it’s user input.
///
/// RETURNS:
/// - Type: What the function returns and its guarantees (e.g., “always inside boundary”).
///
/// ERRORS:
/// - VariantName: Condition when it occurs.
/// - VariantName: Condition when it occurs.
///
/// EXAMPLE:
/// ```rust
/// let out = boundary.strict_join("etc/config.toml")?;
/// println!("{}", out.strictpath_display());
/// ```
```

**Rules:**
- Always use imperative style in the summary (“Join child onto strict path”), not descriptive (“This function joins...”).
- Cover *all parameters*, *returns*, and *error variants* explicitly.
- Show at least one success example; add a failure case if common.
- Do not hide invariants: state guarantees such as “never escapes boundary”.
- Avoid vague terms like “etc.” or “magic”.
