# CI, Workflow & Benchmarks

CI workflows, local scripts, MSRV policy, debugging, and benchmarks.

## Build & Test (Quick Reference)

```bash
cargo build -p strict-path --all-features
cargo test  -p strict-path --all-features
cargo test  --doc -p strict-path --all-features
cargo clippy -p strict-path --all-targets --all-features -- -D warnings
cargo fmt   --all -- --check
cargo doc   -p strict-path --no-deps --document-private-items --all-features
```

MSRV: `rustup run 1.76 cargo build -p strict-path --all-features`

## CI Workflows (GitHub Actions)

- **Stable** (linux/windows/macos): fmt, clippy, test for library. Demos linted only (not built/run).
- **MSRV** (linux, Rust 1.76.0): check/clippy/test scoped to `-p strict-path --lib --locked`.

## MSRV Policy

- Rust 1.76.0 (declared in `strict-path/Cargo.toml`).
- Avoid deps that raise MSRV without discussion.
- Forbid unsafe; pass clippy with `-D warnings`.

## Local CI Scripts

| Script | Scope | When to use |
|---|---|---|
| `ci-check.ps1` / `.sh` | Library only | Editing core code/docs, want quick signal |
| `ci-check-demos.ps1` / `.sh` | Demos only (changed files) | Modified demo binaries |
| `ci-local.ps1` / `.sh` | Full pipeline | Before commit/push, multi-area changes |

All scripts auto-fix format/clippy where safe. Run from repository root.

## Fast Local Debugging

Prefer targeted commands over full pipeline:

```powershell
# Quick fix + lint
cargo clippy -p strict-path --fix --allow-dirty --allow-staged --all-targets --all-features
# Diagnostics only
cargo clippy -p strict-path --all-targets --all-features -- -D warnings
# Single test
cargo test -p strict-path --all-features <test_filter> -- --nocapture
# Validate docs
cargo doc -p strict-path --no-deps --document-private-items --all-features
```

Run full pipeline only before pushing or after multi-area changes.

## When CI Fails: Targeted Isolation

1. Reproduce on the same platform (Windows vs Linux/macOS).
2. Run only the failing test: `cargo test [-p pkg] <filter> --all-features -- --nocapture`
3. Keep test intent intact — don't weaken semantics.
4. Once green, re-run full local CI to validate end-to-end.

**Windows note**: Symlink creation may fail without Developer Mode (error 1314).
Tests must handle gracefully; prefer junction fallback when `junctions` feature is enabled.

## Benchmarks

**Location**: `benches/` at project root (workspace member, NOT inside `strict-path/`).

```powershell
cd benches
cargo bench                               # All benchmarks
cargo bench --bench performance_comparison  # Overhead only
cargo bench --bench caching_benefits        # Real-world gains only
```

**Key rules:**
- All approaches receive same inputs (relative path segments)
- Measure full workflow: "untrusted string" → "validated path"
- Use `black_box()` around inputs and outputs
- Setup costs outside benchmark loop
- No `criterion` in `strict-path/Cargo.toml` (lives in `benches/Cargo.toml`)

**Adding benchmarks:**
1. Create `benches/benches/your_benchmark.rs`
2. Add `[[bench]]` to `benches/Cargo.toml`
3. Update `benches/README.md`

See `benches/README.md` and `benches/docs/` for methodology, analysis, and reports.
