## strict-path-rs — Copilot instructions (single source: AGENTS.md)

This repository uses `AGENTS.md` as the single source of truth for AI agents. To avoid duplication, this file is a thin pointer with only quickstart links.

Read next (authoritative guidance)
- `AGENTS.md` — operational guidance, security model, CI workflows, demos policy
- `LLM_CONTEXT_FULL.md` — usage-first API cheatsheet for `PathBoundary`/`StrictPath`/`VirtualRoot`/`VirtualPath`
- `strict-path/src/lib.rs` docs and `strict-path/examples/` — compilable examples and doctests

Quickstart (Windows PowerShell)
```powershell
./ci-local.ps1           # Auto-fix fmt/clippy; mirrors CI intent
./ci-check.ps1           # Fast library-only checks
./ci-check-demos.ps1     # Lint changed demo files only
cargo test -p strict-path --all-features
cargo doc -p strict-path --no-deps --document-private-items
```

Minimal usage reminder (see AGENTS.md for details)
- Validate untrusted segments via `strict_join`/`virtual_join` before any I/O
- Use `interop_path()` for OS calls; `strictpath_display()`/`virtualpath_display()` for user output
- Encode guarantees in signatures by accepting `&StrictPath<_>`/`&VirtualPath<_>` or a policy root plus the untrusted segment
