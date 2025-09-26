# strict-path — LLM API Reference 

**Security-first path handling**: Prevent directory traversal with type-safe boundaries.

Audience and usage: This page is a minimal-context, copy/paste guide for tool-calling LLMs. Prefer the bullets and short recipes here; link to README and mdBook for longer explanations.

## Essential Flow (Start Here)
1. **Create boundary**: `PathBoundary::try_new_create(dir)` → secure foundation
2. **Validate input**: `boundary.strict_join(user_input)` → `StrictPath<T>` 
3. **Use safely**: All I/O methods available - `read()`, `write()`, `create_dir_all()`

**Core Security Promise**: If you have `StrictPath<T>` or `VirtualPath<T>`, path traversal is impossible.

## Core Security Foundation: `StrictPath`

- `StrictPath<Marker>` is the core safe path type used for system-facing I/O.
- If a function receives `&StrictPath<_>`, the path is already validated — no extra checks needed.
- Create `StrictPath` via `PathBoundary::strict_join(..)` or borrow from `VirtualPath` via `.as_unvirtual()`.

## Type Selection Guide

**Choose based on use case:**
- **User sandboxes**: `VirtualRoot`/`VirtualPath` - Clean UI paths like "/file.txt"
- **Shared boundaries**: `PathBoundary`/`StrictPath` - System paths within validated boundaries  
- **Multiple contexts**: Use marker types `StrictPath<UserFiles>` vs `StrictPath<ConfigFiles>`

### Marker playbook (LLM must follow)

- **Domain markers**: Define markers that describe what lives under the boundary (e.g., `struct PublicAssets;`, `struct UserUploads;`). Create boundaries with those markers so helpers can accept `&StrictPath<PublicAssets>` vs `&StrictPath<UserUploads>` and the compiler blocks cross-domain mix-ups.
- **Authorization markers**: Wrap a proof type in your marker when you need auth guarantees for shared system directories. Example: `struct UserHome { _proof: () }` with `fn authenticate_user_home(...) -> Result<UserHome, AuthError>`. After authentication, create a `PathBoundary<UserHome>` and call `.strict_join(...)` so every `StrictPath<UserHome>` proves both the boundary and the authorization.
- **Permission tuples**: Combine resource + capability in a tuple marker: `StrictPath<(SystemFiles, ReadOnly)>` vs `StrictPath<(SystemFiles, AdminPermission)>`. Authentication helpers should return the tuple so the LLM propagates the compiler-checked permission.
- **Function signatures**: Accept either the validated path (`&StrictPath<Marker>`) or accept the policy root plus raw segment (`&PathBoundary<Marker>`, `&VirtualRoot<Marker>`). Never take raw `Path`/`String` parameters for untrusted input.
- **Naming rule**: Use domain-based names (`public_assets_dir`, `user_uploads_dir`, `system_logs_dir`) for `PathBoundary`/`VirtualRoot` variables so the intent survives into code review.

## Quick Specs (LLM-friendly)

- PathBoundary<T>
	- Purpose: Policy root for safe strict paths (create → validate → use)
	- `PathBoundary::try_new_create<P: AsRef<Path>>(path: P) -> Result<PathBoundary<T>>`
		- Errors: `InvalidRestriction`
		- Example: `let boundary = PathBoundary::try_new_create("./config")?;`
	- `PathBoundary::strict_join<P: AsRef<Path>>(&self, candidate: P) -> Result<StrictPath<T>>`
		- Errors: `PathEscapesBoundary`, `PathResolutionError`, `WindowsShortName`
		- Security: Validates against boundary; prevents traversal/symlink escapes
		- Example: `let file = boundary.strict_join(user_input)?; file.read()?;`

- StrictPath<T>
	- Purpose: Proven-safe system path (within its boundary)
	- `StrictPath::strict_join<P: AsRef<Path>>(&self, path: P) -> Result<StrictPath<T>>`
		- Errors: `PathEscapesBoundary`, `PathResolutionError`, `WindowsShortName`
	- `StrictPath::interop_path(&self) -> &OsStr` (for `AsRef<Path>` APIs)
	- `StrictPath::strictpath_display(&self) -> Display`

- VirtualRoot<T>
	- Purpose: Policy root for user-facing sandbox with rooted virtual "/" semantics
	- `VirtualRoot::try_new_create<P: AsRef<Path>>(dir: P) -> Result<VirtualRoot<T>>`
		- Errors: `InvalidRestriction`
	- `VirtualRoot::virtual_join<P: AsRef<Path>>(&self, candidate: P) -> Result<VirtualPath<T>>`
		- Errors: `PathEscapesBoundary`, `PathResolutionError`, `WindowsShortName`

- VirtualPath<T>
	- Purpose: Virtual path with rooted "/" view; safe virtual operations mapped to a strict path
	- `VirtualPath::with_root<P: AsRef<Path>>(root: P) -> Result<VirtualPath<T>>`
	- `VirtualPath::with_root_create<P: AsRef<Path>>(root: P) -> Result<VirtualPath<T>>`
	- `VirtualPath::virtual_join<P: AsRef<Path>>(&self, path: P) -> Result<VirtualPath<T>>`
	- `VirtualPath::interop_path(&self) -> &OsStr` (for `AsRef<Path>` APIs)
	- `VirtualPath::virtualpath_display(&self) -> Display` (e.g., "/file.txt")
	- `VirtualPath::as_unvirtual(&self) -> &StrictPath<T>` (borrow strict/system view)

## Architecture Overview

All security flows through `StrictPath`:
- `PathBoundary` → validates external input → produces `StrictPath`  
- `VirtualPath` → extends `StrictPath` with user-friendly semantics
- `VirtualRoot` → provides root context for creating `VirtualPath` instances

Uses canonicalization + boundary checks to prevent directory traversal attacks.

### PathBoundary — usage in one glance

- Policy root for strict/system paths; construct once, pass around.
- Validate untrusted input with `boundary.strict_join(input)` to get `StrictPath<T>`.
- Do not build raw `Path` from user input; always validate via `strict_join()`.
- For details, see the mdBook Best Practices; keep helpers accepting `&StrictPath<_>` or `&PathBoundary<_>`.

## Quick Method Reference

**PathBoundary<T>**: Secure boundary creation and validation
Use when: validating untrusted segments into a system-facing path within a known root (policy).
- `::try_new_create(path)` → Create boundary (mkdir if needed)  
- `.strict_join(input)` → Validate untrusted input → `StrictPath<T>`

**StrictPath<T>**: Proven-safe system paths
Use when: passing proven-safe paths to I/O and helpers; no extra validation inside the function.
- `.strict_join(path)` → Chain additional safe joins
- `.interop_path()` → `&OsStr` for `AsRef<Path>` APIs
- `.read()/.write(data)` → I/O operations  
- `.strictpath_display()` → Display for logging

**VirtualRoot<T>**: User-friendly sandbox policy root
Use when: creating a per-user sandbox root that produces `VirtualPath` with rooted "/" UX.
- `VirtualRoot::try_new_create(dir)` → Create user sandbox root
- `.virtual_join(input)` → Validate/clamp user input → `VirtualPath<T>`
- `.interop_path()` → `&OsStr` for `AsRef<Path>` APIs at the root
- `.read_dir()` / `.remove_dir()` / `.remove_dir_all()` → Root-level discovery and cleanup

**VirtualPath<T>**: User-facing clamped path
Use when: handling user-facing paths; clamp via `.virtual_join()`; borrow strict view with `.as_unvirtual()` for shared helpers.
- `.virtual_join(input)` → Chain additional safe virtual joins
- `.virtualpath_display()` → Virtual display (e.g., "/file.txt")
- `.as_unvirtual()` → Borrow underlying `StrictPath<T>` for shared helpers
- `.interop_path()` → Pass into APIs expecting `AsRef<Path>`
- I/O helpers available: `.read()`, `.write(..)`, `.create_parent_dir_all()`

### Core Security Rules

- ❌ **Never**: `std::path::Path::join(user_input)` - vulnerable to traversal  
- ✅ **Always**: `boundary.strict_join(user_input)` or `vroot.virtual_join(user_input)`
- ✅ **For `AsRef<Path>` APIs**: use `.interop_path()` not `.unstrict()`
- Do not bypass: never call std fs ops on raw `Path`/`PathBuf` built from untrusted input.
- Marker types prevent mixing distinct restrictions at compile time: use when you have multiple storage areas.
- We do not implement `AsRef<Path>` on `StrictPath`/`VirtualPath`. When an API expects `AsRef<Path>`, pass `.interop_path()`.
	(`PathBoundary` and `VirtualRoot` do implement `AsRef<Path>` for convenience at the root level.)
- Interop doesn't require `.unstrict()`: prefer `.interop_path()`; call `.unstrict()` only when an owned `PathBuf` is strictly required.
- Avoid std `Path::join`/`Path::parent` on leaked paths — they do not apply virtual-root
	clamping or restriction checks. Use `strict_join` / `virtualpath_parent` instead.
- Do not convert `StrictPath` -> `VirtualPath` just to print; for UI flows start with `VirtualPath::with_root(..).virtual_join(..)` and keep a `VirtualPath`.

### Feature semantics (when enabled)
- `app-path`: Environment override resolves to the final root path. When the env var is set, no subdirectory append occurs — the env value becomes the root.

### Anti‑Patterns (do NOT)
- Wrap secure types in `Path::new(..)` / `PathBuf::from(..)`.
- Use std `Path::join`/`parent` on leaked `StrictPath`/`VirtualPath` — use `strict_join`/`virtualpath_parent`.
- Construct `PathBoundary`/`VirtualRoot` inside helpers — treat them as policy and pass them in.
- Convert `StrictPath` → `VirtualPath` just to print; use `strictpath_display()` or start with `VirtualPath` for UI.
- Rely on implicit conversions: there is no `AsRef<Path>` on secure types; use `.interop_path()` explicitly.

## Common Usage Patterns

### Pattern 1: User File Uploads (VirtualPath)
```rust
struct UserFiles;
let user_root: VirtualRoot<UserFiles> = VirtualRoot::try_new_create("./users/alice")?;
let user_file = user_root.virtual_join(untrusted_filename)?; // Always safe
user_file.write(uploaded_data)?;
println!("Saved: {}", user_file.virtualpath_display()); // Shows: "/document.pdf"
```

### Pattern 2: Config File Access (StrictPath) 
```rust
let config_boundary = PathBoundary::try_new_create("./config")?;
let config_file = config_boundary.strict_join("app.toml")?;
let content = config_file.read_to_string()?;
println!("Config: {}", config_file.strictpath_display()); // Shows: "./config/app.toml"
```

### Pattern 3: Type Safety with Markers
```rust
struct UserFiles;
struct ConfigFiles;
fn process_user_file(f: &StrictPath<UserFiles>) -> Result<Vec<u8>> { f.read() }
fn process_config_file(f: &StrictPath<ConfigFiles>) -> Result<String> { f.read_to_string() }

let user_file = user_boundary.strict_join("data.json")?;
let config_file = config_boundary.strict_join("settings.toml")?;
// process_user_file(&config_file); // ❌ Compile error - wrong marker type
```

### Pattern 4: External API Interop
```rust
let safe_path = boundary.strict_join("file.txt")?;
// For APIs expecting AsRef<Path>
std::fs::copy(safe_path.interop_path(), "backup.txt")?;
tokio::fs::read(safe_path.interop_path()).await?;
// ❌ Don't do: safe_path.unstrict() - use interop_path() instead
```

## Error Handling

**Common Error Types**:
- `PathEscapesBoundary` - User attempted directory traversal (e.g., "../../../etc/passwd")
- `InvalidRestriction` - Cannot create/access the boundary directory  
- `PathResolutionError` - Invalid path format or I/O error during canonicalization
- `WindowsShortName` - Path contains DOS 8.3 short names (Windows only)

**Error Pattern**:
```rust
match boundary.strict_join(user_input) {
		Ok(safe_path) => { /* use safely */ },
		Err(StrictPathError::PathEscapesBoundary { .. }) => { /* log security attempt */ },
		Err(e) => { /* handle other errors */ }
}
```

## Detailed API Reference

### StrictPath API

- with_boundary<P: AsRef<Path>>(dir_path: P) -> Result<Self>  // sugar; directory must exist
- with_boundary_create<P: AsRef<Path>>(dir_path: P) -> Result<Self>  // sugar; creates directory if missing
- unstrict(self) -> PathBuf  // consumes — escape hatch (avoid)
- virtualize(self) -> VirtualPath<Marker>  // upgrade to virtual view (UI ops)
- strictpath_to_string_lossy(&self) -> Cow<'_, str>
- strictpath_to_str(&self) -> Option<&str>
- interop_path(&self) -> &OsStr
- strictpath_display(&self) -> std::path::Display<'_>  // explicit display method
- strict_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<Self>
- strictpath_parent(&self) -> Result<Option<Self>
- strictpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- strictpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- strict_rename<P: AsRef<Path>>(&self, dest: P) -> io::Result<()>
- strict_copy<P: AsRef<Path>>(&self, dest: P) -> io::Result<u64>
- strict_symlink(&self, link_path: &Self) -> io::Result<()>
- strict_hard_link(&self, link_path: &Self) -> io::Result<()>

All operations prevent traversal and symlink/junction escapes. Do not use `std::path::Path::join` on untrusted input; use the explicit `strict_*/virtual_*` operations documented below.

## Which Type Should I Use?

Quick Decision Matrix:
- **User Sandboxes** → `VirtualPath` (per-user isolated spaces)
- **Shared Boundaries** → `StrictPath` (common protected areas)  
- **Type Safety** → Both `StrictPath<T>` and `VirtualPath<T>` vs `Path/PathBuf`
- **Unrestricted** → `std::path::Path` (no safety guarantees)

Minimal decision checklist (LLM prompts)
- Input: untrusted user path segment; expected UX: rooted "/" display → Use `VirtualRoot` + `.virtual_join(...)` → `VirtualPath<T>`.
- Input: untrusted file/dir name for a known system directory → Use `PathBoundary` + `.strict_join(...)` → `StrictPath<T>`.
- Need one helper usable from both → Write `fn f<M>(p: &StrictPath<M>) { ... }`; call with `StrictPath` or `VirtualPath::as_unvirtual()`.
- Display: user-facing → `vpath.virtualpath_display()`; system logs → `spath.strictpath_display()`.
- Interop: when API expects `AsRef<Path>` → call `.interop_path()` on the secure type; do not use `.unstrict()` unless an owned `PathBuf` is required.

**Common Use Cases:**
```rust
// ✅ Per-user storage - each user gets their own "/"
let user_space: VirtualRoot<UserFiles> = VirtualRoot::try_new(format!("./users/{user_id}"))?;
let doc = user_space.virtual_join("docs/report.pdf")?; // User sees "/docs/report.pdf"

// ✅ Shared config area - all users access same protected space
let config_restriction: PathBoundary<ConfigFiles> = PathBoundary::try_new("./shared/config")?;
let cfg = config_restriction.strict_join(user_requested_config)?; // Validates within shared boundary

// ✅ Both can process user input safely
let user_input = "../../../etc/passwd";
let vp = user_space.virtual_join(user_input)?; // Clamped to user's space
let sp = config_restriction.strict_join(user_input)?; // Rejected if escapes shared boundary

// ❌ Don't use std::path for user input
let bad = PathBuf::from(user_input).join("file.txt"); // 🚨 Vulnerable to traversal
```

**Conceptual Models:**
- `StrictPath` = **Proven-safe, system-facing path**: validated path for system-facing I/O and interop
- `VirtualPath` = **User-friendly wrapper**: user-facing virtual "/" view with virtual path operations; also supports I/O and interop

**Unified Signatures (When Appropriate):**
```rust
// Generic across storage contexts — use only when required to have a function that works for multiple restrictions and contexts
fn process_file<M>(path: &StrictPath<M>) -> std::io::Result<Vec<u8>> {
	path.read()
}

// Callers pass either a borrowed StrictPath directly, or a borrowed StrictPath from VirtualPath::as_unvirtual()
process_file(&strict_path);
process_file(virtual_path.as_unvirtual());
```
```rust

struct UserFiles;
struct Logs;

let bytes = read_user_file(vpath.as_unvirtual())?;

// Compile-time separation of restrictions
let logs: PathBoundary<Logs> = PathBoundary::try_new("./logs")?;
let log_path = logs.strict_join("app.log")?;
// read_user_file(&log_path)?; // ❌ compile error: expected `StrictPath<UserFiles>`
```

## API Design Philosophy: Explicit Security

**No Display Trait**: Both types require explicit display methods to prevent accidental path leakage:

```rust
// ❌ No automatic Display trait
println!("{}", vpath);  // Compile error

// ✅ Explicit display methods
impl StrictPath {
		pub fn strictpath_display(&self) -> impl Display { ... }
}
impl VirtualPath {
	pub fn virtualpath_display(&self) -> impl Display { ... }   // Virtual view (rooted)
	// System-facing strings are explicit:
	// - Borrow the strict view and use Display: `self.as_unvirtual().strictpath_display()`
}

println!("User: {}", vpath.virtualpath_display());        // "/docs/file.txt"  
println!("Log: {}", vpath.as_unvirtual().strictpath_display());   // "/srv/users/alice/docs/file.txt"
```

`VirtualPath` provides `virtualpath_display()` for user-facing display. System-facing strings are available but must be called explicitly:

- Prefer virtual semantics in UI: `vpath.virtualpath_display()` or `vpath.virtualpath_display().to_string()`
- When you need the real, system path string, either:
	- Borrow the strict view and format it: `format!("{}", vpath.as_unvirtual().strictpath_display())`

This keeps potentially sensitive operations visible in code review while offering ergonomic access when required.



**Rationale:** Security-sensitive APIs should make potentially dangerous operations visible in code review. Automatic trait implementations like `Display` can hide semantic differences that could lead to unintentional information disclosure in user-facing contexts.

Start here: [Quick Recipes](#quick-recipes) · [Pitfalls](#pitfalls-and-how-to-avoid)

Top-level exports

| Symbol                        |   Kind | Purpose                                                                                                      |
| ----------------------------- | -----: | ------------------------------------------------------------------------------------------------------------ |
| `StrictPathError`             |   enum | Validation and resolution errors.                                                                            |
| `Result<T>`                   |  alias | `Result<T, StrictPathError>`                                                                                 |
| `StrictPath<Marker>`          | struct | System-facing, restriction‑validated path that proves containment; supports I/O.                             |
| `VirtualPath<Marker>`         | struct | User-facing path that extends `StrictPath` with a virtual‑root view and restriction‑aware ops; supports I/O. |
| `PathBoundary<Marker>`        | struct | Boundary policy that validates external input and produces `StrictPath`.                                     |
| `VirtualRoot<Marker>`         | struct | Virtual policy root that produces `VirtualPath` values.                                                      |
| `serde_ext` (feature `serde`) | module | Context-aware deserialization helpers (`WithBoundary`, `WithVirtualRoot`).                                   |

## Quick Recipes
- Create restriction (create dir if missing) and validate: `let restriction = PathBoundary::try_new_create("./safe")?; let sp = restriction.strict_join("a/b.txt")?;`
- Virtual user path: `let vroot = VirtualRoot::try_new("./safe")?; let vp = vroot.virtual_join("a/b.txt")?;`
- Convert between types: `vpath.unvirtual()` → `StrictPath`, `spath.virtualize()` → `VirtualPath`
- Unified functions: take `&StrictPath<_>` and call with `vpath.as_unvirtual()`

Example — unified helper (copy/paste):
```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

fn process_common<M>(p: &StrictPath<M>) -> std::io::Result<Vec<u8>> { p.read() }

let spath: StrictPath = PathBoundary::try_new("./assets")?
	.strict_join("style.css")?;

let vroot: VirtualRoot = VirtualRoot::try_new("./uploads/alice")?;
let vpath: VirtualPath = vroot.virtual_join("avatar.jpg")?;

let _ = process_common(&spath)?;                 // StrictPath
let _ = process_common(vpath.as_unvirtual())?;   // Borrow strict view from VirtualPath
```
- Display paths: `spath.strictpath_display()`, `vpath.virtualpath_display()` (no automatic Display trait)
- Type-safe function signatures: `fn serve_file<M>(p: &StrictPath<M>) -> io::Result<Vec<u8>> { p.read() }`
- Type-safe virtual signatures: `fn serve_user_file(p: &VirtualPath) -> io::Result<Vec<u8>> { p.read() }`
- Interop: when an API expects `AsRef<Path>`, pass `.interop_path()` (returns `&OsStr`, which implements `AsRef<Path>`). Example: `std::fs::copy(src.interop_path(), dst.interop_path())?;`
- Create parent dirs: `vp.create_parent_dir_all()?; vp.write("content")?;`

Markers and type inference
- All core types are generic over a `Marker` with a default of `()`.
- In many cases, binding the value is enough for inference: `let vroot: VirtualRoot = VirtualRoot::try_new("root")?; let vp = vroot.virtual_join("f.txt")?;`.
- When inference needs help, add an explicit type or an empty turbofish:
	- `let vroot: VirtualRoot<()> = VirtualRoot::try_new("root")?;`
	- `let vroot = VirtualRoot::<()>::try_new("root")?;`
- With a custom marker: `struct Docs; let vroot: VirtualRoot<Docs> = VirtualRoot::try_new("docs")?;`
- Prefer annotating the `let` binding or function signature for readability; use turbofish only when it clarifies intent or is required.

StrictPathError (variants)
- `InvalidRestriction { restriction: PathBuf, source: io::Error }`
- `PathEscapesBoundary { attempted_path: PathBuf, restriction_boundary: PathBuf }`
- `PathResolutionError { path: PathBuf, source: io::Error }`
- `WindowsShortName { component, original, checked_at }` (windows)

PathBoundary<Marker>
- try_new<P: AsRef<Path>>(restriction_path: P) -> Result<Self>
- try_new_create<P: AsRef<Path>>(root: P) -> Result<Self>
- strict_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<StrictPath<Marker>>
- interop_path(&self) -> &OsStr
- exists(&self) -> bool
- strictpath_display(&self) -> std::path::Display<'_>
- virtualize(self) -> VirtualRoot<Marker>
- strict_symlink(&self, link_path: &StrictPath<Marker>) -> io::Result<()>
- strict_hard_link(&self, link_path: &StrictPath<Marker>) -> io::Result<()>
 - read_dir(&self) -> io::Result<std::fs::ReadDir>
 - remove_dir(&self) -> io::Result<()>
 - remove_dir_all(&self) -> io::Result<()>

StrictPath<Marker>
Note: `.unstrict()` is an explicit escape hatch. Interop doesn’t require it — prefer `.interop_path()`; use `.unstrict()` only when an owned `PathBuf` is strictly required.
- with_boundary<P: AsRef<Path>>(dir_path: P) -> Result<Self>  // sugar; directory must exist
- with_boundary_create<P: AsRef<Path>>(dir_path: P) -> Result<Self>  // sugar; creates directory if missing
- unstrict(self) -> PathBuf  // consumes — escape hatch (avoid)
- virtualize(self) -> VirtualPath<Marker>  // upgrade to virtual view (UI ops)
- try_into_boundary(self) -> PathBoundary<Marker>
- try_into_boundary_create(self) -> PathBoundary<Marker>
- strictpath_to_string_lossy(&self) -> Cow<'_, str>
- strictpath_to_str(&self) -> Option<&str>
- interop_path(&self) -> &OsStr
- strictpath_display(&self) -> std::path::Display<'_>
- strict_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<Self>
- strictpath_parent(&self) -> Result<Option<Self>>
- strictpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- strictpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- strict_rename<P: AsRef<Path>>(&self, dest: P) -> io::Result<()>
- strict_copy<P: AsRef<Path>>(&self, dest: P) -> io::Result<u64>
- strict_symlink(&self, link_path: &Self) -> io::Result<()>
- strict_hard_link(&self, link_path: &Self) -> io::Result<()>
- strictpath_file_name(&self) -> Option<&OsStr>
- strictpath_file_stem(&self) -> Option<&OsStr>
- strictpath_extension(&self) -> Option<&OsStr>
- strictpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool
- strictpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool
- exists(&self) -> bool
- is_file(&self) -> bool
- is_dir(&self) -> bool
- metadata(&self) -> io::Result<std::fs::Metadata>
- read_dir(&self) -> io::Result<std::fs::ReadDir>
- read_to_string(&self) -> io::Result<String>
- read(&self) -> io::Result<Vec<u8>>
- write<C: AsRef<[u8]>>(&self, data: C) -> io::Result<()>
- create_dir(&self) -> io::Result<()>
- create_dir_all(&self) -> io::Result<()>
- create_parent_dir(&self) -> io::Result<()>
- create_parent_dir_all(&self) -> io::Result<()>
- remove_file(&self) -> io::Result<()>
- remove_dir(&self) -> io::Result<()>
- remove_dir_all(&self) -> io::Result<()>

VirtualRoot<Marker>
- try_new<P: AsRef<Path>>(root_path: P) -> Result<Self>
- try_new_create<P: AsRef<Path>>(root_path: P) -> Result<Self>
- virtual_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<VirtualPath<Marker>>
- interop_path(&self) -> &OsStr
- exists(&self) -> bool
- as_unvirtual(&self) -> &PathBoundary<Marker>
- unvirtual(self) -> PathBoundary<Marker>
 - read_dir(&self) -> io::Result<std::fs::ReadDir>
 - remove_dir(&self) -> io::Result<()>
 - remove_dir_all(&self) -> io::Result<()>

VirtualPath<Marker>
- with_root<P: AsRef<Path>>(root: P) -> Result<Self>  // sugar; root must exist
- with_root_create<P: AsRef<Path>>(root: P) -> Result<Self>  // sugar; creates root if missing
- unvirtual(self) -> StrictPath<Marker>  // downgrade to system-facing view when ownership is needed
- as_unvirtual(&self) -> &StrictPath<Marker> // borrow the underlying strict path for system-facing related operations
- interop_path(&self) -> &OsStr // for APIs that accept AsRef<Path>
- virtual_join<P: AsRef<Path>>(&self, path: P) -> Result<Self>
- virtualpath_parent(&self) -> Result<Option<Self>>
- virtualpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- virtualpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- virtual_rename<P: AsRef<Path>>(&self, dest: P) -> io::Result<()>
- virtual_copy<P: AsRef<Path>>(&self, dest: P) -> io::Result<u64>
- virtual_symlink(&self, link_path: &Self) -> io::Result<()>
- virtual_hard_link(&self, link_path: &Self) -> io::Result<()>
- virtualpath_file_name(&self) -> Option<&OsStr>
- virtualpath_file_stem(&self) -> Option<&OsStr>
- virtualpath_extension(&self) -> Option<&OsStr>
- virtualpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool
- virtualpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool
- virtualpath_display(&self) -> VirtualPathDisplay<'_, Marker>  // explicit display method
 - try_into_root(self) -> VirtualRoot<Marker>
- try_into_root_create(self) -> VirtualRoot<Marker>
- read_dir(&self) -> io::Result<std::fs::ReadDir>
- exists / is_file / is_dir / metadata / read_to_string / read / write / create_dir / create_dir_all / create_parent_dir / create_parent_dir_all / remove_file / remove_dir / remove_dir_all (delegates to `StrictPath`; parents derived via virtual semantics)
- virtual_symlink(&self, link_path: &VirtualPath<Marker>) -> io::Result<()>
- virtual_hard_link(&self, link_path: &VirtualPath<Marker>) -> io::Result<()>

### Feature-gated APIs (complete list)
These are available only when the corresponding Cargo features are enabled:

- Feature `dirs` (OS standard directories)
	- PathBoundary
		- `try_new_os_config(app_name: &str) -> Result<PathBoundary>`
		- `try_new_os_data(app_name: &str) -> Result<PathBoundary>`
		- `try_new_os_cache(app_name: &str) -> Result<PathBoundary>`
		- `try_new_os_config_local(app_name: &str) -> Result<PathBoundary>`
		- `try_new_os_data_local(app_name: &str) -> Result<PathBoundary>`
		- `try_new_os_home() -> Result<PathBoundary>`
		- `try_new_os_desktop() -> Result<PathBoundary>`
		- `try_new_os_documents() -> Result<PathBoundary>`
		- `try_new_os_downloads() -> Result<PathBoundary>`
		- `try_new_os_pictures() -> Result<PathBoundary>`
		- `try_new_os_audio() -> Result<PathBoundary>`
		- `try_new_os_videos() -> Result<PathBoundary>`
		- `try_new_os_executables() -> Result<PathBoundary>`
		- `try_new_os_runtime() -> Result<PathBoundary>`
		- `try_new_os_state(app_name: &str) -> Result<PathBoundary>`
	- VirtualRoot (one‑to‑one with `PathBoundary`)
		- `try_new_os_config(app_name: &str) -> Result<VirtualRoot>`
		- `try_new_os_data(app_name: &str) -> Result<VirtualRoot>`
		- `try_new_os_cache(app_name: &str) -> Result<VirtualRoot>`
		- `try_new_os_config_local(app_name: &str) -> Result<VirtualRoot>`
		- `try_new_os_data_local(app_name: &str) -> Result<VirtualRoot>`
		- `try_new_os_home() -> Result<VirtualRoot>`
		- `try_new_os_desktop() -> Result<VirtualRoot>`
		- `try_new_os_documents() -> Result<VirtualRoot>`
		- `try_new_os_downloads() -> Result<VirtualRoot>`
		- `try_new_os_pictures() -> Result<VirtualRoot>`
		- `try_new_os_audio() -> Result<VirtualRoot>`
		- `try_new_os_videos() -> Result<VirtualRoot>`
		- `try_new_os_executables() -> Result<VirtualRoot>`
		- `try_new_os_runtime() -> Result<VirtualRoot>`
		- `try_new_os_state(app_name: &str) -> Result<VirtualRoot>`

- Feature `tempfile` (RAII temporary directories)
	- `PathBoundary::try_new_temp() -> Result<PathBoundary>`
	- `PathBoundary::try_new_temp_with_prefix(prefix: &str) -> Result<PathBoundary>`
	- `VirtualRoot::try_new_temp() -> Result<VirtualRoot>`
	- `VirtualRoot::try_new_temp_with_prefix(prefix: &str) -> Result<VirtualRoot>`
	- VirtualRoot holds RAII of temp dirs when constructed from a temp PathBoundary

- Feature `app-path` (portable app‑relative dirs with optional env overrides)
	- `PathBoundary::try_new_app_path<P: AsRef<Path>>(subdir: P, env_override: Option<&str>) -> Result<PathBoundary>`
	- `PathBoundary::try_new_app_path_with_env<P: AsRef<Path>>(subdir: P, env_var_name: &str) -> Result<PathBoundary>`
	- `VirtualRoot::try_new_app_path<P: AsRef<Path>>(subdir: P, env_override: Option<&str>) -> Result<VirtualRoot>`
	- `VirtualRoot::try_new_app_path_with_env<P: AsRef<Path>>(subdir: P, env_var_name: &str) -> Result<VirtualRoot>`

	Note: `env_override` is the NAME of an environment variable. When set, its VALUE is used as the final root directory; the provided `subdir` is not appended in that case.

- Feature `serde`
	- `impl Serialize for StrictPath` → system path string
	- `impl Serialize for VirtualPath` → rooted virtual string (e.g., "/a/b.txt")
	- `serde_ext::WithBoundary<'_, Marker>`: `DeserializeSeed` to deserialize a `StrictPath<Marker>` with a provided `&PathBoundary<Marker>`
	- `serde_ext::WithVirtualRoot<'_, Marker>`: `DeserializeSeed` to deserialize a `VirtualPath<Marker>` with a provided `&VirtualRoot<Marker>`

Short usage rules (1-line each)
- For user input: use `VirtualPath::virtual_join(...)` (construct a root via `VirtualPath::with_root(..)`) -> `VirtualPath`.
- For I/O: use either `VirtualPath` or `StrictPath` (both support I/O). Call `.unvirtual()` only when you need a `StrictPath` explicitly.
- Do not bypass: never call std fs ops on raw `Path`/`PathBuf` built from untrusted input.
- Marker types prevent mixing distinct path boundaries at compile time: use when you have multiple storage areas.
- We do not implement `AsRef<Path>` on `StrictPath`/`VirtualPath`. When an API expects `AsRef<Path>`, pass `.interop_path()`.
	(`PathBoundary` and `VirtualRoot` do implement `AsRef<Path>` for convenience at the root level.)
- Interop doesn’t require `.unstrict()`: prefer `.interop_path()`; call `.unstrict()` only when an owned `PathBuf` is strictly required.
- Avoid std `Path::join`/`Path::parent` on leaked paths — they do not apply virtual-root
	clamping or path boundary checks. Use `strict_join` / `virtualpath_parent` instead.
 - Do not convert `StrictPath` -> `VirtualPath` just to print; for UI flows start with `VirtualPath::with_root(..).virtual_join(..)` and keep a `VirtualPath`.
 - `*_to_string_lossy()` returns `Cow<'_, str>`; call `.into_owned()` only when an owned `String` is required.
 - **ANTI-PATTERN**: Never use `.interop_path().to_string_lossy()` for display purposes. Use proper display methods instead:
	 - `PathBoundary`/`StrictPath`: use `strictpath_display()`
	 - `VirtualPath`: use `virtualpath_display()`
	 - `VirtualRoot`: use `vroot.as_unvirtual().strictpath_display()`
	 - Reserve `interop_path()` only for external API interop that requires `AsRef<Path>`.

Parent directory helpers (semantics)
- create_parent_dir: non-recursive; creates only the immediate parent; errors if grandparents are missing; Ok(()) at restriction/virtual root.
- create_parent_dir_all: recursive; creates the full chain up to the immediate parent; Ok(()) at restriction/virtual root.
- VirtualPath parent helpers act in the virtual dimension (use `virtualpath_parent()`), then perform I/O on the underlying strict system path.
 
Naming rationale (quick scan aid)
- We name methods by their dimension so intent is obvious at a glance.
- std `Path::join(..)` or `p.join(..)`: unsafe join (can escape); avoid on untrusted inputs.
- `PathBoundary::strict_join(..)` / `StrictPath::strict_join(..)`: safe, validated strict path join.
- `VirtualPath::virtual_join(..)`: safe, clamped virtual-path join (create a root via `VirtualPath::with_root(..)`).
- This applies to other operations too: `*_parent`, `*_with_file_name`, `*_with_extension`, `*_starts_with`, `*_ends_with`, etc. Shortened names apply only to `*_join`.
The explicit names make intent obvious even when types aren’t visible.
 - For directory creation, `create_` = non-recursive, `*_all` = recursive (matches std `std::fs` semantics). Parent helpers mirror this.
 - Switching views: typically stay within one dimension (virtual or system). For edge cases, upgrade with `.virtualize()` or downgrade with `.unvirtual()` to access the other dimension’s operations.

**Critical: Absolute Path Join Behavior**
- `std::path::Path::join("/absolute")`: DANGEROUS — replaces the base path entirely, enabling traversal.
- `StrictPath::strict_join("/absolute")`: SECURE — validates the result stays within the restriction boundary; errors if it would escape.
- `VirtualPath::virtual_join("/absolute")`: SECURE — interprets the path as absolute in the VIRTUAL namespace and replaces the current virtual path with that virtual-absolute. The resulting strict path is resolved under the same `VirtualRoot` (e.g., joining `/etc/passwd` yields a virtual `/etc/passwd` backed by `<virtual_root>/etc/passwd`). Any `..` that would go above the virtual root is clamped at the virtual root.

This difference makes `std::path::Path::join` the #1 source of path traversal vulnerabilities, while our types make such attacks impossible.

Display
- Use `vpath.virtualpath_display()` for user-facing virtual paths (e.g., "/a/b.txt").
- For system-facing logs and diagnostics, use `spath.strictpath_display()` or `vpath.as_unvirtual().strictpath_display()`.

Separator normalization (platform specifics)
- Windows: `virtualpath_display()` normalizes `\` to `/` and ensures a leading `/`.
- Unix: backslashes are not path separators; they are preserved as literal characters. A leading `/` is ensured.

Equality/Ordering/Hashing
- `PathBoundary<Marker>` and `VirtualRoot<Marker>` compare/hash by canonicalized restriction root path and marker.
- `VirtualPath` compares, orders, and hashes by its inner strict path, identical to `StrictPath`, including the marker type.
- Cross-type equality is supported: `VirtualPath<Marker> == StrictPath<Marker>` compares underlying strict paths. Borrow via `.as_unvirtual()` when needed.

## Traits at a glance
- PathBoundary<Marker>
	- Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash
	- AsRef<Path>
	- FromStr (when `Marker: Default`) → creates directory if missing
	- Cross-type equality: PartialEq<VirtualRoot<Marker>>, PartialEq<Path>, PartialEq<PathBuf>, PartialEq<&Path>

- VirtualRoot<Marker>
	- Clone, Debug, Display, Eq, PartialEq, Ord, PartialOrd, Hash
	- AsRef<Path>
	- FromStr (when `Marker: Default`) → creates directory if missing
	- Cross-type equality: PartialEq<PathBoundary<Marker>>, PartialEq<Path>, PartialEq<PathBuf>, PartialEq<&Path>

- StrictPath<Marker>
	- Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash
	- Cross-type equality: PartialEq<VirtualPath<Marker>>, PartialEq<T: AsRef<Path>>
	- No AsRef<Path>; use `interop_path()` when needed
	- [feature serde] Serialize → system path string

- VirtualPath<Marker>
	- Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash
	- Cross-type equality: PartialEq<StrictPath<Marker>>, PartialEq<T: AsRef<Path>> (compares virtual representation)
	- No Display (use `virtualpath_display()` wrapper); No AsRef<Path>
	- [feature serde] Serialize → rooted virtual string (e.g., "/a/b.txt")

## Pitfalls (And How To Avoid)
- Do not expose raw `Path`/`PathBuf` from `StrictPath`/`VirtualPath`. We do not implement `AsRef<Path>`. Prefer crate I/O or `.interop_path()` where `AsRef<Path>` is accepted, or explicit escape hatches when unavoidable.
- Use restriction-aware joins/parents; never call std `Path::join` on a leaked path.
- Virtual strings are rooted. Use `virtualpath_display()` for UI/logging.
- Use `PathBoundary::try_new_create(..)` when the restriction directory might not exist.
- Symlinks/junctions to outside: paths that traverse a symlink or junction inside the restriction to a location outside the restriction are rejected at validation time with `StrictPathError::PathEscapesBoundary`.

Common anti-patterns (LLM quick check)
- Passing strings to `AsRef<Path>`-only APIs: avoid. Use crate I/O helpers or explicit escape hatches; for `AsRef<Path>`-accepting APIs, use `.interop_path()`.
- Converting `StrictPath` -> `VirtualPath` only for display: **ANTI-PATTERN** `strict_path.clone().virtualize()` for virtual display - if you need virtual semantics, start with `VirtualRoot`/`VirtualPath` from the beginning.
- Using `Path::join`/`Path::parent` on leaked paths: use `strictpath_*` / `virtualpath_*` ops.
- Forcing ownership: avoid `.into_owned()` on `Cow` unless an owned `String` is required.
- Bare `{}` in format strings: prefer captured identifiers like `"{path}"` (bind a short local if needed).

