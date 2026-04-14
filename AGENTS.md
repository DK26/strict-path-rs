# AGENTS.md

Operational hub for AI assistants working in this repository.
Topic-specific depth lives in `.agents/*.md` satellites — read on demand.

## Satellite Index

| File | When to read |
|---|---|
| [`.agents/design-decisions.md`](.agents/design-decisions.md) | Adding/modifying APIs, questioning design choices |
| [`.agents/coding-standards.md`](.agents/coding-standards.md) | Writing Rust code (must_use, indexing, comments, safety) |
| [`.agents/api-usage.md`](.agents/api-usage.md) | Using strict-path types, naming, internals |
| [`.agents/documentation.md`](.agents/documentation.md) | Writing docs, examples, demos, doctests |
| [`.agents/ci-workflow.md`](.agents/ci-workflow.md) | CI, local scripts, debugging, benchmarks |
| [`.agents/agent-behavior.md`](.agents/agent-behavior.md) | Git policy, issues, contributing, PR checklist |

Also read: `LLM_CONTEXT_FULL.md` (usage-first API reference for LLMs).

---

## Maintaining This File

AGENTS.md is read by stateless agents with no memory of prior sessions.
Every rule must stand on its own.

- **Only non-inferable content.** Don't duplicate what code reveals.
- **General, not reactive.** No rules for single past mistakes.
- **Context-free.** No references to specific conversations or commits.
- **Principles over examples.** Prefer abstract guidance.

## ⛔ Read Before Any Code Changes

1. **Read the relevant source files.** Never modify code you haven't read.
2. **Search before implementing.** Verify functionality doesn't already exist.
3. **Canonicalization always resolves symlinks.** You can never get a
   `StrictPath`/`VirtualPath` pointing to a symlink. Any API assuming
   otherwise is fundamentally incompatible. See [`.agents/design-decisions.md`](.agents/design-decisions.md).

## Build & Test

```bash
cargo build -p strict-path --all-features
cargo test  -p strict-path --all-features
cargo clippy -p strict-path --all-targets --all-features -- -D warnings
cargo fmt   --all -- --check
cargo doc   -p strict-path --no-deps --document-private-items --all-features
```

MSRV: Rust 1.76.0 — `rustup run 1.76 cargo build -p strict-path --all-features`

Local CI: `./ci-local.ps1` (Windows) or `bash ./ci-local.sh` (Unix/WSL).

## Project Overview

- **Purpose**: Prevent directory traversal from external/unknown sources with safe path boundaries and safe symlinks.
- **Core APIs**: `PathBoundary<Marker>`, `StrictPath<Marker>`, `VirtualRoot<Marker>`, `VirtualPath<Marker>`, `StrictPathError`.
- **Security model**: "Restrict every external path." Untrusted inputs (user I/O, config, DB, LLMs, archives) must be validated into `StrictPath` or `VirtualPath` before I/O.
- **Foundation**: Built on `soft-canonicalize`; canonicalization handles Windows 8.3 short names transparently.
- **CRITICAL**: Canonicalization **always resolves symlinks** to targets — by design.
- **TOCTOU scope**: Validates at join-time. Post-validation filesystem changes are outside scope (same limitation as SQL prepared statements).
- **API philosophy**: Minimal, restrictive, explicit. Security over performance.

### StrictPath vs VirtualPath: Detect vs Contain

| | StrictPath (90%) | VirtualPath (10%) |
|---|---|---|
| **Philosophy** | Error on escape (detect attacks) | Silently clamp escapes (contain behavior) |
| **Use cases** | Archives, config, uploads, shared resources | Multi-tenant SaaS, sandboxes, security research |
| **On escape** | `Err(PathEscapesBoundary)` | Redirects within virtual boundary |
| **Feature** | Always available | Requires `virtual-path` feature |

**Common mistake**: VirtualPath for archive extraction — hides attacks. Use StrictPath.

## Critical Design Principles (Non-Negotiable)

These are stated once here. Satellites reference back.

1. **No leaky traits**: Never `AsRef<Path>`, `Deref<Target=Path>`, implicit `From`/`Into` on crate types.
2. **`interop_path()` → `&OsStr`**: The single gate for leaving the secure API. Pass directly to `AsRef<Path>` APIs. Never wrap in `Path::new()`/`PathBuf::from()`. Never expose to end-users (leaks real paths). Use `*_display()` for output.
3. **One Way Principle**: Exactly one correct way per operation. No redundant convenience methods.
4. **No new public APIs without maintainer approval.**

## Repository Layout

| Path | Purpose | Notes |
|---|---|---|
| `strict-path/` | Library crate | MSRV-bound (1.76.0) |
| `benches/` | Performance benchmarks | Workspace member, latest stable |
| `demos/` | Real-world demo binaries | Excluded from workspace, non-MSRV |
| `.github/workflows/` | CI configs | Stable + MSRV split |
| `.agents/` | AGENTS.md satellite files | Topic-specific agent guidance |
| `.docs/` | mdBook worktree (branch `docs`) | `git worktree add .docs docs` |

Docs: `README.md`, `LLM_CONTEXT_FULL.md`, `LLM_CONTEXT.md`.

## Quick Do/Don't

**Do:**
- Validate untrusted segments via `strict_join`/`virtual_join`
- Pass `&StrictPath`/`&VirtualPath` into helpers; or boundaries/roots + segment
- Use `strictpath_display()`/`virtualpath_display()` for output
- Use built-in I/O helpers, not `std::fs` on `interop_path()`

**Don't:**
- Wrap `interop_path()` in `Path::new()` or `PathBuf::from()`
- Validate constants "just to use the API"
- Add redundant ways to achieve the same thing
- Use `pub(crate)` methods in tests as shortcuts around public API
- Use generic variable names (`filename`, `path`) — name by domain/purpose
- Add `#[allow(...)]` (except `clippy::type_complexity`)
- Use `no_run`/`ignore` doctest fences

---

*For deeper guidance on any topic, read the relevant `.agents/*.md` satellite.*
