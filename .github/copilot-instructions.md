# strict-path-rs Copilot Instructions

This codebase provides **type-safe path restriction** to prevent directory traversal attacks through comprehensive security architecture.

## Core Architecture (Security-Critical)

**Four Core Types** (understand their relationships):
- `PathBoundary<Marker>`: Creates and validates system paths within boundaries
- `StrictPath<Marker>`: The fundamental security primitive - mathematically proven safe paths  
- `VirtualRoot<Marker>`: Policy type for creating virtual user-facing paths
- `VirtualPath<Marker>`: Extends `StrictPath` with virtual "/" root semantics for sandboxing

**Security Model**: If you have a `StrictPath<Marker>`, it CANNOT reference anything outside its boundary - this is enforced by type system + cryptographic canonicalization.

**Internal Engine**: `PathHistory` performs normalization/canonicalization/validation in a single auditable pipeline with type-state markers (`Raw` → `Canonicalized` → `BoundaryChecked`).

## Code Patterns & Conventions

**When to use which type:**
```rust
// ✅ User isolation/sandboxing → VirtualRoot/VirtualPath
let vroot: VirtualRoot<UserUploads> = VirtualRoot::try_new_create(user_dir)?;
let safe_file: VirtualPath<UserUploads> = vroot.virtual_join(untrusted_filename)?;

// ✅ Shared system spaces → PathBoundary/StrictPath  
let boundary: PathBoundary<Config> = PathBoundary::try_new_create("./app-config")?;
let config_path: StrictPath<Config> = boundary.strict_join(config_name)?;
```

**Function Signatures (Encode Guarantees):**
```rust
// ✅ Accept policy types + untrusted segment
fn handle_upload(uploads: &VirtualRoot<UserUploads>, filename: &str) -> Result<()>

// ✅ Accept validated paths directly
fn process_file(file: &StrictPath<UserData>) -> Result<()>
```

**Path Operations by Dimension:**
- Use explicit dimension methods: `strict_join()`/`virtual_join()`, `strictpath_parent()`/`virtualpath_parent()`
- Interop: `interop_path()` for `AsRef<Path>` (no allocations)
- Display: `strictpath_display()`/`virtualpath_display()` for user output
- **Never** use std `Path::join`/`parent` on leaked paths

## Project Structure & Workflows

**Workspace Split Strategy** (CRITICAL):
- `strict-path/`: Library crate, MSRV Rust 1.71, enforced with `--locked`
- `demos/`: **Separate crate** (not in workspace), latest stable, real-world examples
- This avoids lockfile coupling while keeping library MSRV-stable and demos current

**Local CI**: `./ci-local.ps1` (Windows) or `bash ./ci-local.sh` (Unix/WSL) - auto-fixes format/clippy and mirrors exact CI behavior

**Demo Categories**: `demos/src/bin/{web,security,cli,config}/` - must model **real scenarios** with official ecosystem crates, not toy examples

## Security & Anti-Patterns

**Anti-Patterns** (Tell-offs):
- Wrapping secure types in `Path::new()`/`PathBuf::from()`
- Using `interop_path().as_ref()` instead of direct `interop_path()`
- Constructing boundaries/roots inside helpers (policy should be passed in)
- Validating only constants (no untrusted input flows through validation)
- Raw path parameters in safe helpers - use typed signatures

**Path Handling Rules**:
- All external paths (user input, config, DB, LLMs, archives) MUST be validated into `StrictPath`/`VirtualPath` before I/O
- No leaky trait impls: forbidden `AsRef<Path>`, `Deref<Target = Path>` on secure types
- Stay in one dimension per flow; upgrade/downgrade explicitly if needed

**Comprehensive Reference**: See `AGENTS.md` for complete operational guidance, including PathHistory internals, serde patterns, Windows 8.3 handling, and contribution rules.  
