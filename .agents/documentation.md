# Documentation & Examples

Policies for docs, examples, demos, and doctests in `strict-path`.

## Documentation Guidelines

- README: focused on why, core features, simple-to-advanced examples.
- Align README examples with `strict-path/src/lib.rs` doc examples.
- Use doctested examples in source whenever possible.
- Lead with sugar for ergonomics; show policy types for reuse.
- For multi-user flows, prefer `VirtualRoot`/`VirtualPath`.
- **Examples MUST validate actual external input** — not hardcoded literals.

## README & mdBook Validation (Critical)

All code examples must have corresponding tests in `strict-path/src/tests/readme_examples.rs`.

- Tests must exactly match README examples (same code, flow, results).
- If tests are fixed, update README.md to match the working code.
- Feature-gated examples hidden with `#` prefix in tests, visible in README.
- Run: `cargo test -p strict-path readme_examples --all-features`

**Anti-patterns:**
- ❌ README diverges from tests
- ❌ Incomplete examples that can't compile
- ❌ `#[cfg(feature)]` visible in README code blocks

## Variable Naming in Examples (CRITICAL)

- ✅ `user_input`, `requested_file`, `uploaded_avatar`, `attack_input`
- ❌ `filename`, `path`, `name`, `config_name`
- Include source comments: `// User input from HTTP request`
- Variable names must "scream" that validation is happening on external data

## Examples vs Demos

- **API examples** → `strict-path/examples/*.rs` — run with `cargo run --example <name>`
- **Demo projects** → `demos/src/bin/<category>/<name>.rs` — run with `cd demos && cargo run --bin <name>`

## Demos Policy

- Separate crate (`publish = false`), non-MSRV, path-dep on `../strict-path`.
- Linted on latest stable CI; not built/run in CI by default.
- Heavy deps optional with namespaced features (`with-zip = ["dep:zip", "dep:flate2"]`).
- Must model real scenarios with actual external input validation.
- Production-authentic: use official ecosystem crates, not hand-rolled stubs.
- No `#[allow(...)]`; domain-based variable names; demonstrate discovery vs validation.

Directory convention:
- `demos/src/bin/web/` — web servers
- `demos/src/bin/security/` — security/archives
- `demos/src/bin/cli/` or `tools/` — CLI tools
- `demos/src/bin/config/` — config/OS dirs

## Examples Principles

- Real-world, immediately demonstrate value — no contrived "hello world".
- Path strings must be obviously paths (`"/var/app/uploads"`, `"./data/user_files"`).
- Compile and run (doctests or `cargo run --example`).
- Demonstrate discovery vs validation patterns clearly.

## Rustdoc Formatting Rules

- Wrap type/generic expressions in backticks: `` `AsRef<Path>` ``, `` `PathBoundary<Marker>` ``
- Intra-doc links only for public items with correct paths.
- Do not reference private symbols in docs.
- Validate: `cargo doc --no-deps --document-private-items --all-features`

## Doctest Setup vs Visible Code

- Prefer `*_create` constructors in visible example code.
- When showing `with_root`/`with_boundary` (non-create), use hidden setup: `# std::fs::create_dir_all("dir")?;`
- Anti-patterns: keep runnable — assert on errors instead of `no_run` fences.
- No `std::fs` in visible code unless demonstrating interop via `interop_path()`.

## mdBook (Authoritative Docs Source)

- Lives on branch `docs` via `.docs/` worktree.
- Setup: `git worktree add .docs docs`
- Edit: `.docs/docs_src/src/*.md`
- Preview: `cd .docs/docs_src && mdbook serve -o`
- Build: `cd .docs/docs_src && mdbook build`
- Key pages: `best_practices.md`, `anti_patterns.md`, `getting_started.md`, `security_methodology.md`
- Never use `book/` directory. Don't create nested clones — use worktree.

## LLM_CONTEXT_FULL.md — Purpose

Written for external LLM consumption. Usage-first, prioritizing:
- Which types to use and when
- How to validate untrusted input
- Interop vs display rules
- Feature-gated entry points and semantics

Non-goals: internal design details, contributor guidance (those stay in AGENTS.md / satellites).
