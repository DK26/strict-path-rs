# strict-path — LLM API Reference 

**Strictly enforce path boundaries to prevent directory traversal attacks.**

- `PathBoundary` — defines the containment boundary
- `StrictPath` — paths strictly validated to stay within the boundary
- Every operation is STRICTLY validated. No exceptions, no escapes.

Audience and usage: This page is a minimal-context, copy/paste guide for tool-calling LLMs. Prefer the bullets and short recipes here; link to README and mdBook for longer explanations.

**🚨 CRITICAL for LLM code generation:**
- NEVER validate hardcoded string literals like `boundary.strict_join("file.txt")` — this is security theater
- ALWAYS use variable names that show untrusted input: `user_input`, `requested_file`, `attack_input`, `uploaded_data`
- AVOID generic names: `filename`, `path`, `name`, `config_name` — they hide that you're validating untrusted input
- Include source comments: `// User input from HTTP request, CLI args, form data, etc.`

## Essential Flow (Start Here)
1. **Create boundary**: `PathBoundary::try_new_create(dir)` → secure foundation
2. **Validate input**: `boundary.strict_join(user_input)` → `StrictPath<T>` 
3. **Use safely**: All I/O methods available - `read()`, `write()`, `create_dir_all()`

**Core Security Promise**: If you have `StrictPath<T>` or `VirtualPath<T>`, path traversal is impossible.

## Features

- Feature `virtual-path` (opt-in): Enables `VirtualRoot`/`VirtualPath` and all virtual-only APIs.

  - Enable in Cargo.toml:
    ```toml
    [dependencies]
    strict-path = { version = "...", features = ["virtual-path"] }
    ```
  - When not enabled: Only `PathBoundary` + `StrictPath` are available (all I/O included). All `VirtualRoot`/`VirtualPath` APIs are removed.

- Feature `junctions` (Windows-only, opt-in): Enables built-in NTFS junction helpers

	- What you get when enabled (Windows):
		- `StrictPath::strict_junction<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>`
		- `PathBoundary::strict_junction<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>`
		- `VirtualPath::virtual_junction<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>`
		- `VirtualRoot::virtual_junction<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>`
	- Notes: Junctions are directory-only. Parents are not created automatically. Same-boundary rules apply.
	- Enable in Cargo.toml (Windows):
		```toml
		[dependencies]
		strict-path = { version = "...", features = ["junctions"] }
		```

## Core Security Foundation: `StrictPath`

- `StrictPath<Marker>` is the core safe path type used for system-facing I/O.
- If a function receives `&StrictPath<_>`, the path is already validated — no extra checks needed.
- Create `StrictPath` via `PathBoundary::strict_join(..)` or borrow from `VirtualPath` via `.as_unvirtual()`.

## When to Use Which Type? (Critical Decision)

**The fundamental distinction is whether escapes are attacks or expected behavior:**

### StrictPath — Detect & Reject (Default, 90% of use cases)

**Philosophy**: "If something tries to escape, I want to know about it"

Use `PathBoundary` → `StrictPath` when path escapes indicate **malicious intent**:

- **Archive extraction** — Detect malicious paths; reject compromised archives
- **File uploads** — Reject user-provided paths with traversal attempts  
- **Config loading** — Fail on untrusted config paths that try to escape
- **Log files, cache, assets** — Shared system resources with strict boundaries
- **Development tools** — Build systems, CLI utilities, single-user apps
- **Any security boundary** — Where escapes are attacks that must be detected

**Key behavior**: Returns `Err(PathEscapesBoundary)` when escape is attempted.

**No feature required** — `PathBoundary` and `StrictPath` are always available.

### VirtualPath — Contain & Redirect (Opt-in, 10% of use cases)

**Philosophy**: "Let things try to escape, but silently contain them"

Use `VirtualRoot` → `VirtualPath` when path escapes are **expected but must be controlled**:

- **Malware analysis sandboxes** — Observe malicious behavior while containing it
- **Multi-tenant systems** — Each user sees isolated `/` root without real paths
- **Container-like plugins** — Modules get their own filesystem view
- **Security research** — Simulate contained environments for testing
- **User content isolation** — When users shouldn't see real system paths

**Key behavior**: Silently clamps/redirects escape attempts within the virtual boundary.

**Requires feature** — Enable in `Cargo.toml`:
```toml
[dependencies]
strict-path = { version = "...", features = ["virtual-path"] }
```

### Decision Matrix

| Scenario           | Type          | Reason                      |
| ------------------ | ------------- | --------------------------- |
| Archive extraction | `StrictPath`  | Detect malicious paths      |
| File uploads       | `StrictPath`  | Reject traversal attacks    |
| Config loading     | `StrictPath`  | Fail on escape attempts     |
| Malware sandbox    | `VirtualPath` | Contain behavior safely     |
| Multi-tenant SaaS  | `VirtualPath` | Per-user isolation          |
| Single-user app    | `StrictPath`  | Simple boundary enforcement |

### VirtualRoot Quick Checklist (LLMs should follow)
- Construct per-user/tenant roots using an identifier segment: `let vroot = VirtualRoot::try_new_create(format!("users/{user_id}"))?;`.
- Do not use a shared `VirtualRoot` for multiple users; create one per user/tenant.
- Do not construct roots inside helpers; accept `&VirtualRoot`/`&VirtualPath` (or a root + raw segment) in function signatures.
- Always validate raw segments with `virtual_join(untrusted)` before any I/O.
- Use `virtualpath_display()` for UI and `.interop_path()` only for third‑party APIs that require `AsRef<Path>`.
- If `user_id` comes from outside, treat it as an identifier (not a path). Sanitize to a slug; avoid path separators.

### Marker playbook (LLM must follow)

- **Domain markers**: Define markers that describe what lives under the boundary (e.g., `struct PublicAssets;`, `struct UserUploads;`). Create boundaries with those markers so helpers can accept `&StrictPath<PublicAssets>` vs `&StrictPath<UserUploads>` and the compiler blocks cross-domain mix-ups.
- **Authorization markers**: Wrap a proof type in your marker when you need auth guarantees for shared system directories. Example: `struct UserHome { _proof: () }` with `fn authenticate_user_home(...) -> Result<UserHome, AuthError>`. After authentication, create a `PathBoundary<UserHome>` and call `.strict_join(...)` so every `StrictPath<UserHome>` proves both the boundary and the authorization.
- **Permission tuples (convention)**: Combine resource + capability in a tuple marker with a FLAT tuple: `StrictPath<(SystemFiles, ReadOnly)>` and for multiple caps `StrictPath<(SystemFiles, ReadOnly, WriteOnly)>`. Avoid nesting tuples like `(SystemFiles, (ReadOnly, WriteOnly))` — keep it flat and always put the resource first.
- **Naming rule (must follow)**: Use domain nouns that describe what lives under the boundary (`struct PublicAssets;`, `struct BrandEditorWorkspace;`). The marker must always communicate the filesystem contents protected by that restriction—any label that points at people, roles, or other metadata instead of the stored files is incorrect. Avoid meaningless suffixes like `Marker`, `Type`, or `Root`. Markers should never use human-centric labels unless the directory literally stores those artifacts; authorization state belongs in the capability witness. When combining with capabilities, keep the first tuple element as the storage domain and the remaining elements as capability proofs: `StrictPath<(BrandDirectorArchive, ReadOnly, WriteOnly)>`.
- **Function signatures**: Accept either the validated path (`&StrictPath<Marker>`) or accept the policy root plus raw segment (`&PathBoundary<Marker>`, `&VirtualRoot<Marker>`). Never take raw `Path`/`String` parameters for untrusted input.
- **Naming rule**: Use domain-based names (`public_assets_dir`, `user_uploads_dir`, `system_logs_dir`) for `PathBoundary`/`VirtualRoot` variables so the intent survives into code review.

Marker transformation guidance
- `.change_marker::<NewMarker>()` consumes the value and swaps only the marker. Use it right after you have proved a new authorization or capability (for example, after login or policy elevation).
- Do not call `.change_marker::<()>()` for a no-op update. Prefer annotating the binding or function signature instead: `let boundary: PathBoundary<()> = PathBoundary::try_new_create(dir)?;`.

## Quick Specs (LLM-friendly)

- PathBoundary<T>
	- Purpose: Policy root for safe strict paths (create → validate → use)
	- `PathBoundary::try_new_create<P: AsRef<Path>>(path: P) -> Result<PathBoundary<T>>`
		- Errors: `InvalidRestriction`
		- Example: `let boundary = PathBoundary::try_new_create("./config")?;`
	- `PathBoundary::strict_join<P: AsRef<Path>>(&self, candidate: P) -> Result<StrictPath<T>>`
		- Errors: `PathEscapesBoundary`, `PathResolutionError`
		- Security: Validates against boundary; prevents traversal/symlink escapes
		- Example: `let file = boundary.strict_join(user_input)?; file.read()?;`

- StrictPath<T>
	- Purpose: Proven-safe system path (within its boundary)
	- `StrictPath::strict_join<P: AsRef<Path>>(&self, path: P) -> Result<StrictPath<T>>`
		- Errors: `PathEscapesBoundary`, `PathResolutionError`
	- `StrictPath::interop_path(&self) -> &OsStr` (for unavoidable third-party `AsRef<Path>` APIs)
	- `StrictPath::strictpath_display(&self) -> Display`
		- `StrictPath::try_into_boundary(self) -> Result<PathBoundary<T>>` — promote the validated path to a boundary (directory must exist); call `.change_marker::<NewMarker>()` to propagate authorization markers
		- `StrictPath::try_into_boundary_create(self) -> Result<PathBoundary<T>>` — same as above but ensures the directory exists first
	- `StrictPath::create_file(&self) -> io::Result<File>` — open writable handle; call `.open_file()` for read-only access

- VirtualRoot<T>
	- Purpose: Policy root for user-facing sandbox with rooted virtual "/" semantics
	- `VirtualRoot::try_new_create<P: AsRef<Path>>(dir: P) -> Result<VirtualRoot<T>>`
		- Errors: `InvalidRestriction`
	- `VirtualRoot::virtual_join<P: AsRef<Path>>(&self, candidate: P) -> Result<VirtualPath<T>>`
		- Errors: `PathEscapesBoundary`, `PathResolutionError`

- VirtualPath<T>
	- Purpose: Virtual path with rooted "/" view; safe virtual operations mapped to a strict path
	- `VirtualPath::with_root<P: AsRef<Path>>(root: P) -> Result<VirtualPath<T>>`
	- `VirtualPath::with_root_create<P: AsRef<Path>>(root: P) -> Result<VirtualPath<T>>`
	- `VirtualPath::virtual_join<P: AsRef<Path>>(&self, path: P) -> Result<VirtualPath<T>>`
	- `VirtualPath::interop_path(&self) -> &OsStr` (for unavoidable third-party `AsRef<Path>` APIs)
	- `VirtualPath::virtualpath_display(&self) -> Display` (e.g., "/file.txt")
	- `VirtualPath::as_unvirtual(&self) -> &StrictPath<T>` (borrow strict/system view)
	- `VirtualPath::create_file(&self) -> io::Result<File>` / `.open_file()` — safe I/O streaming within the virtual root

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
- `.interop_path()` → `&OsStr` for third-party `AsRef<Path>` APIs you cannot adapt
- `.exists()` → Check if path exists (built-in, no need to use `Path::new().exists()`)
- `.read()/.write(data)` → I/O operations
- `.create_file()` → Writable handle (pass to tar builders, etc.)
- `.open_file()` → Read-only handle when you only need to stream bytes out
- `.strictpath_display()` → Display for logging

**VirtualRoot<T>**: User-friendly sandbox policy root
Use when: creating a per-user sandbox root that produces `VirtualPath` with rooted "/" UX.
- `VirtualRoot::try_new_create(dir)` → Create user sandbox root
- `.virtual_join(input)` → Validate/clamp user input → `VirtualPath<T>`
- `.interop_path()` → `&OsStr` for third-party `AsRef<Path>` APIs at the root
- `.read_dir()` / `.remove_dir()` / `.remove_dir_all()` → Root-level discovery and cleanup

**VirtualPath<T>**: User-facing clamped path
Use when: handling user-facing paths; clamp via `.virtual_join()`; borrow strict view with `.as_unvirtual()` for shared helpers.
- `.virtual_join(input)` → Chain additional safe virtual joins
- `.virtualpath_display()` → Virtual display (e.g., "/file.txt")
- `.as_unvirtual()` → Borrow underlying `StrictPath<T>` for shared helpers
- `.interop_path()` → Pass into third-party APIs expecting `AsRef<Path>`
- `.exists()` → Check if path exists (built-in)
- I/O helpers available: `.read()`, `.write(..)`, `.create_file()`, `.open_file()`, `.create_parent_dir_all()`
 - `.symlink_metadata()` → Get metadata without following symlinks

## Built-in I/O Methods (Always Use These!)

**CRITICAL**: `StrictPath` and `VirtualPath` provide built-in helpers for common filesystem operations. **Never** use `.interop_path()` to call `std::fs` methods directly — that's what these helpers are for!

**File Operations**:
- `.exists()` → Check if path exists (bool)
- `.read()` → Read file to Vec<u8>
- `.read_to_string()` → Read file to String
- `.write(contents)` → Write to file (creates or truncates)
- `.create_file()` → Get writable File handle
- `.open_file()` → Get read-only File handle
- `.remove_file()` → Delete file

**Directory Operations**:
- `.create_dir()` → Create directory (must not exist)
- `.create_dir_all()` → Create directory and all parents
- `.create_parent_dir_all()` → Create all parent directories for a file path
- `.read_dir()` → Iterate directory entries
- `.remove_dir()` → Delete empty directory
- `.remove_dir_all()` → Delete directory and all contents
 - `.symlink_metadata()` → Get metadata without following symlinks

**Path Manipulation**:
- `.strict_join(path)` / `.virtual_join(path)` → Safely append segment
- `.strictpath_parent()` / `.virtualpath_parent()` → Get parent directory
- `.strictpath_with_file_name()` / `.virtualpath_with_file_name()` → Replace filename
- `.strictpath_with_extension()` / `.virtualpath_with_extension()` → Replace extension

**File System Operations**:
- `.strict_copy(dest)` → Copy file to destination (accepts `AsRef<Path>`)
- `.strict_rename(dest)` → Move/rename file (accepts `AsRef<Path>`)
- `.strict_symlink(link_path)` → Create symbolic link (accepts `AsRef<Path>`)
- `.strict_hard_link(link_path)` → Create hard link (accepts `AsRef<Path>`)
- `.strict_junction(link_path)` → Create NTFS directory junction (Windows, feature = "junctions", accepts `AsRef<Path>`)

**Why This Matters:**
```rust
// ❌ WRONG - Using interop_path with std::fs
if Path::new(safe_path.interop_path()).exists() {  // DON'T DO THIS!
    let content = std::fs::read_to_string(safe_path.interop_path())?;  // DON'T DO THIS!
}

// ✅ CORRECT - Using built-in methods
if safe_path.exists() {  // ✅ Use the built-in method
    let content = safe_path.read_to_string()?;  // ✅ Use the built-in method
}
```



- ❌ **Never**: `std::path::Path::join(user_input)` - vulnerable to traversal  
- ✅ **Always**: `boundary.strict_join(user_input)` or `vroot.virtual_join(user_input)`
- ✅ **Only for third-party `AsRef<Path>` APIs**: use `.interop_path()` (never `.unstrict()`)
- Do not bypass: never call std fs ops on raw `Path`/`PathBuf` built from untrusted input.
- Marker types prevent mixing distinct restrictions at compile time: use when you have multiple storage areas.
- We do not implement `AsRef<Path>` on secure path values (`StrictPath`/`VirtualPath`). When an unavoidable third-party API expects `AsRef<Path>`, pass `.interop_path()`.
	Note: `.interop_path()` returns `&OsStr`, which already satisfies `AsRef<Path>` — you do not need to wrap it in `Path::new(..)` or `PathBuf::from(..)`.
	For roots/policy types, use `PathBoundary::interop_path()` and `VirtualRoot::interop_path()` similarly. Note: in this crate, `PathBoundary` and `VirtualRoot` also implement `AsRef<Path>` for ergonomics; this does not exist on `StrictPath`/`VirtualPath` by design.
- Interop doesn't require `.unstrict()`: prefer `.interop_path()` for those third-party adapters; call `.unstrict()` only when an owned `PathBuf` is strictly required.
- `.interop_path()` returns `&OsStr` (which is `AsRef<Path>`), not `&Path` — use it directly for external APIs.
- Never wrap `.interop_path()` in `Path::new()` to use `Path::join`/`parent` — they bypass security checks. Use `strict_join` / `virtualpath_parent` instead.
- After `.unstrict()` (explicit escape hatch), you own a `PathBuf` and can do whatever you need.
- Do not convert `StrictPath` -> `VirtualPath` just to print; for UI flows start with `VirtualPath::with_root(..).virtual_join(..)` and keep a `VirtualPath`.

### Feature semantics (when enabled)
- `app-path`: Environment override resolves to the final root path. When the env var is set, no subdirectory append occurs — the env value becomes the root.

### Anti‑Patterns (Tell‑offs — do NOT do these!)

**⚠️ SECURITY THEATER (THE ABSOLUTE WORST!) ⚠️**

If you're only validating constants or immediately converting back to unsafe paths, **you're writing security theater, not security code.**

- ❌ **Only validating constants**: `boundary.strict_join("hardcoded.txt")?` — no untrusted input ever flows through validation. This is completely pointless.
- ❌ **Generic variable names that hide intent**: Use `user_input`, `requested_file`, `uploaded_data` not `filename`, `path`, `name`. Variables must clearly show they represent untrusted external input.
- ❌ **Validating then converting back to unsafe types**: `let safe = boundary.strict_join(input)?; let path = PathBuf::from(safe.interop_path()); std::fs::read(&path)?` — you validated it, then threw away the safety!
- ❌ **Accepting unsafe types in functions**: `fn process(path: &str) { boundary.strict_join(path)?; }` — validate at call site, accept `&StrictPath<_>` in signature.

**Critical**: When writing code that uses this crate, always use variable names that make it obvious you're validating untrusted input:
- ✅ Good: `user_input`, `requested_file`, `attack_input`, `uploaded_avatar`, `config_input`
- ❌ Bad: `filename`, `path`, `name`, `config_name`, `user_doc_path`
- Include comments showing source: `// User input from HTTP request, CLI args, form data, etc.`

---

**Path Construction & Interop** (most common mistakes):
- ❌ `Path::new(path.interop_path()).join(untrusted)` — wrapping `.interop_path()` to use std path operations bypasses all security
- ❌ `PathBuf::from(path.interop_path()).join(untrusted)` — same problem; defeats the entire purpose of validation
- ❌ `Path::new(path.interop_path()).to_path_buf()` — `.interop_path()` is already `AsRef<Path>`; no wrapping needed
- ❌ Performing filesystem I/O via `std::fs` on `.interop_path()` paths — use built-in helpers (`StrictPath::create_file`, `StrictPath::read_to_string`, etc.)

**Key insight**: `.interop_path()` returns `&OsStr` which is `AsRef<Path>` — pass it directly to external APIs. Never wrap it in `Path::new()` or `PathBuf::from()` to perform path operations; that defeats all security. After `.unstrict()` (explicit escape hatch), you own a `PathBuf` and can do whatever you need.

**Validation & Policy**:
- ❌ Validating only constants (no untrusted segment ever flows through validation)
- ❌ Construct `PathBoundary`/`VirtualRoot` inside helpers — treat them as policy and pass them in
- ❌ Raw path parameters in safe helpers — use types/signatures that encode guarantees

**Display & Interop**:
- ❌ Convert `StrictPath` → `VirtualPath` just to print; use `strictpath_display()` or start with `VirtualPath` for UI
- ❌ `interop_path().as_ref()` or `as_unvirtual().interop_path()` — when adapting third-party crates, call `.interop_path()` directly; no extra `.as_ref()` dance
- ❌ Mixing interop and display (use `*_display()` for display)

**Markers & Conversions**:
- ❌ Using `change_marker()` without authorization checks or when converting between path types — conversions preserve markers automatically; only use `change_marker()` when you need a *different* marker after verification
- ❌ Calling `strict_join("")` or `virtual_join("")` to grab the root — use dedicated conversions (`PathBoundary::into_strictpath()`, `VirtualRoot::into_virtualpath()`)

**Multi-user Services**:
- ❌ Single‑user demo flows for multi‑user services — use per‑user `VirtualRoot`

**Remember**: `interop_path()` returns `&OsStr` which is already `AsRef<Path>`. You don't need to wrap it in anything!

### Quick Reference: Anti-Pattern → Fix

| ❌ Bad Pattern (DO NOT DO THIS!)                         | ✅ Correct Pattern                               | Why                                               |
| ------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------- |
| `Path::new(path.interop_path()).to_path_buf()`          | `path.interop_path()` directly                  | Already `AsRef<Path>`; wrapping adds nothing      |
| `PathBuf::from(path.interop_path())`                    | `path.interop_path()` or `.unvirtual()`         | Unnecessary conversion; use direct access         |
| `Path::new(path.interop_path()).exists()`               | `path.exists()`                                 | Built-in method; no leaking needed                |
| `println!("{}", path.interop_path().to_string_lossy())` | `println!("{}", path.strictpath_display())`     | Use display methods for user output               |
| `fn process(path: &str)` + validate inside              | `fn process(path: &StrictPath<_>)`              | Encode safety in signature; validate once at edge |
| `let boundary = PathBoundary::try_new(...)?`            | `let uploads_dir = PathBoundary::try_new(...)?` | Name by purpose, not type                         |
| `Path::new(path.interop_path()).join("child")`          | `path.strict_join("child")?`                    | Wrapping `.interop_path()` bypasses all security  |
| `vroot.as_unvirtual().interop_path()`                   | `vroot.interop_path()`                          | VirtualRoot has `interop_path()` directly         |
| `path.interop_path().as_ref()`                          | `path.interop_path()`                           | Already `AsRef<Path>`; redundant `.as_ref()`      |
| `std::fs::copy(path.interop_path(), ...)`               | `path.strict_copy(...)`                         | Use built-in I/O helpers, not raw `std::fs`       |
| `std::os::windows::fs::symlink_dir(..)` in app code     | `path.strict_symlink(&link_path)`               | Built-in link helpers apply boundary checks       |
| Manual junction creation in app code                    | `path.strict_junction(&link_path)`              | Windows-only helper when feature is enabled       |

### The Golden Rules (Memorize These!)

1. **`.interop_path()` returns `&OsStr` (already `AsRef<Path>`)** — pass directly to external APIs, never wrap in `Path::new()`
2. **Never wrap `.interop_path()` to use std path operations** — that defeats all security; use `strict_join`, `virtualpath_parent`, etc.
3. **`.unstrict()` is the escape hatch** — after calling it, you own a `PathBuf` and leave the safety guarantees
4. **Make functions accept safe types** - `&StrictPath<_>` in signatures, not `&str` with validation inside
3. **Name variables by purpose, not type** - `uploads_dir`, `config_dir`, not `boundary`, `jail`
4. **Use the right method for the job**:
   - Display to users → `strictpath_display()` / `virtualpath_display()`
   - Pass to third-party APIs → `interop_path()` (already `AsRef<Path>`)
   - I/O operations → Use built-in helpers (`.read()`, `.write()`, `.create_file()`, etc.)
5. **Let callers control security policy** - accept `&PathBoundary<_>` parameter, don't create inside helpers
6. **Actually validate untrusted input** - don't just validate constants (security theater!)

## Common Usage Patterns

### Pattern 1: User File Uploads (VirtualPath)
```rust
struct UserFiles;
let user_id = "alice";
let user_root: VirtualRoot<UserFiles> =
    VirtualRoot::try_new_create(format!("./users/{user_id}"))?;
let user_file = user_root.virtual_join(untrusted_filename)?; // Always safe
user_file.write(uploaded_data)?;
println!("Saved: {}", user_file.virtualpath_display()); // Shows: "/document.pdf"
```

### Pattern 2: Config File Access (StrictPath) 
```rust
let config_boundary = PathBoundary::try_new_create("./config")?;
// User input from CLI args, environment, or config loader
let user_input = "app.toml";
let config_file = config_boundary.strict_join(user_input)?;
let content = config_file.read_to_string()?;
println!("Config: {}", config_file.strictpath_display()); // Shows: "./config/app.toml"
```

### Pattern 3: Type Safety with Markers
```rust
struct UserFiles;
struct ConfigFiles;
fn process_user_file(f: &StrictPath<UserFiles>) -> Result<Vec<u8>> { f.read() }
fn process_config_file(f: &StrictPath<ConfigFiles>) -> Result<String> { f.read_to_string() }

// User input from request parameters, database, form data, etc.
let user_input = "data.json";
let config_input = "settings.toml";

let user_file = user_boundary.strict_join(user_input)?;
let config_file = config_boundary.strict_join(config_input)?;
// process_user_file(&config_file); // ❌ Compile error - wrong marker type
```

### Pattern 4: External API Interop
```rust
use walkdir::WalkDir;

// User input from request, form data, CLI args, etc.
let user_input = "uploads";
let safe_path = boundary.strict_join(user_input)?;
// Only for third-party crates that insist on `AsRef<Path>`
for entry in WalkDir::new(safe_path.interop_path()) {
	let entry = entry?;
	println!("{}", entry.path().display());
}
// ❌ Don't do: safe_path.unstrict() - prefer crate helpers; reach for `.interop_path()` only when adapting third-party APIs
```

## Error Handling

**Common Error Types**:
- `PathEscapesBoundary` - User attempted directory traversal (e.g., "../../../etc/passwd")
- `InvalidRestriction` - Cannot create/access the boundary directory  
- `PathResolutionError` - Invalid path format or I/O error during canonicalization

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
- change_marker<NewMarker>(self) -> StrictPath<NewMarker>  // transform marker after authorization
- unstrict(self) -> PathBuf  // consumes — escape hatch (avoid)
- virtualize(self) -> VirtualPath<Marker>  // upgrade to virtual view (UI ops) [feature: virtual-path]
- strictpath_to_string_lossy(&self) -> Cow<'_, str>
- strictpath_to_str(&self) -> Option<&str>
- interop_path(&self) -> &OsStr  // for unavoidable third-party `AsRef<Path>` adapters only
- strictpath_display(&self) -> std::path::Display<'_>  // explicit display method
- strict_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<Self>
- strictpath_parent(&self) -> Result<Option<Self>
- strictpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- strictpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- strict_rename<P: AsRef<Path>>(&self, dest: P) -> io::Result<()>
- strict_copy<P: AsRef<Path>>(&self, dest: P) -> io::Result<u64>
- strict_symlink<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>
- strict_hard_link<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>
- strict_junction<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>  // Windows-only, feature: junctions
- symlink_metadata(&self) -> io::Result<std::fs::Metadata>  // metadata without following symlinks

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
- Interop: when an unavoidable third-party API expects `AsRef<Path>` → call `.interop_path()` on the secure type; do not use `.unstrict()` unless an owned `PathBuf` is required.

**Common Use Cases:**
```rust
// ✅ Per-user storage - each user gets their own "/"
let user_space: VirtualRoot<UserFiles> = VirtualRoot::try_new(format!("./users/{user_id}"))?;
// User input from request path, form data, API payload, etc.
let user_input = "docs/report.pdf";
let doc = user_space.virtual_join(user_input)?; // User sees "/docs/report.pdf"

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
// User input from monitoring system, request parameter, log viewer, etc.
let user_input = "app.log";
let log_path = logs.strict_join(user_input)?;
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
let user_id = "alice";
println!("Log: {}", vpath.as_unvirtual().strictpath_display());   // "/srv/users/{user_id}/docs/file.txt"
```

`VirtualPath` provides `virtualpath_display()` for user-facing display. System-facing strings are available but must be called explicitly:

- Prefer virtual semantics in UI: `vpath.virtualpath_display()` or `vpath.virtualpath_display().to_string()`
- When you need the real, system path string, either:
	- Borrow the strict view and format it: `format!("{}", vpath.as_unvirtual().strictpath_display())`

This keeps potentially sensitive operations visible in code review while offering ergonomic access when required.



**Rationale:** Security-sensitive APIs should make potentially dangerous operations visible in code review. Automatic trait implementations like `Display` can hide semantic differences that could lead to unintentional information disclosure in user-facing contexts.

Start here: [Quick Recipes](#quick-recipes) · [Pitfalls](#pitfalls-and-how-to-avoid)

Top-level exports

| Symbol                 |   Kind | Purpose                                                                                                      |
| ---------------------- | -----: | ------------------------------------------------------------------------------------------------------------ |
| `StrictPathError`      |   enum | Validation and resolution errors.                                                                            |
| `Result<T>`            |  alias | `Result<T, StrictPathError>`                                                                                 |
| `StrictPath<Marker>`   | struct | System-facing, restriction‑validated path that proves containment; supports I/O.                             |
| `VirtualPath<Marker>`  | struct | User-facing path that extends `StrictPath` with a virtual‑root view and restriction‑aware ops; supports I/O. |
| `PathBoundary<Marker>` | struct | Boundary policy that validates external input and produces `StrictPath`.                                     |
| `VirtualRoot<Marker>`  | struct | Virtual policy root that produces `VirtualPath` values.                                                      |

## Quick Recipes
- **Sugar constructors (simple flows)**: `let sp = StrictPath::with_boundary_create("./safe")?.strict_join("a/b.txt")?;` or `let vp = VirtualPath::with_root_create("./safe")?.virtual_join("a/b.txt")?;`
- **Policy types (reusable roots)**: `let restriction = PathBoundary::try_new_create("./safe")?; let sp = restriction.strict_join("a/b.txt")?;` or `let vroot = VirtualRoot::try_new("./safe")?; let vp = vroot.virtual_join("a/b.txt")?;`
- Convert between types: `vpath.unvirtual()` → `StrictPath`, `spath.virtualize()` → `VirtualPath`
- Unified functions: take `&StrictPath<_>` and call with `vpath.as_unvirtual()`

Example — unified helper (copy/paste):
```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

fn process_common<M>(p: &StrictPath<M>) -> std::io::Result<Vec<u8>> { p.read() }

let spath: StrictPath = PathBoundary::try_new("./assets")?
	.strict_join("style.css")?;

let user_id = "alice";
let vroot: VirtualRoot = VirtualRoot::try_new(format!("./uploads/{user_id}"))?;
let vpath: VirtualPath = vroot.virtual_join("avatar.jpg")?;

let _ = process_common(&spath)?;                 // StrictPath
let _ = process_common(vpath.as_unvirtual())?;   // Borrow strict view from VirtualPath
```
- Display paths: `spath.strictpath_display()`, `vpath.virtualpath_display()` (no automatic Display trait)
- Type-safe function signatures: `fn serve_file<M>(p: &StrictPath<M>) -> io::Result<Vec<u8>> { p.read() }`
- Type-safe virtual signatures: `fn serve_user_file(p: &VirtualPath) -> io::Result<Vec<u8>> { p.read() }`
- Interop: when an unavoidable third-party API expects `AsRef<Path>`, pass `.interop_path()` (returns `&OsStr`, which implements `AsRef<Path>`). Example: `walkdir::WalkDir::new(src.interop_path())`.
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

PathBoundary<Marker>
- change_marker<NewMarker>(self) -> PathBoundary<NewMarker>
- try_new<P: AsRef<Path>>(restriction_path: P) -> Result<Self>
- try_new_create<P: AsRef<Path>>(root: P) -> Result<Self>
- strict_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<StrictPath<Marker>>
- into_strictpath(self) -> Result<StrictPath<Marker>>  // convert root into path (directory must exist)
- exists(&self) -> bool
- metadata(&self) -> io::Result<std::fs::Metadata>
- interop_path(&self) -> &OsStr  // for unavoidable third-party `AsRef<Path>` adapters only
- strictpath_display(&self) -> std::path::Display<'_>
- virtualize(self) -> VirtualRoot<Marker>
- strict_symlink<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>
- strict_hard_link<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>
- read_dir(&self) -> io::Result<std::fs::ReadDir>
- remove_dir(&self) -> io::Result<()>
- remove_dir_all(&self) -> io::Result<()>

StrictPath<Marker>
Note: `.unstrict()` is an explicit escape hatch. Interop doesn’t require it — prefer `.interop_path()`; use `.unstrict()` only when an owned `PathBuf` is strictly required.
- with_boundary<P: AsRef<Path>>(dir_path: P) -> Result<Self>  // sugar; directory must exist
- with_boundary_create<P: AsRef<Path>>(dir_path: P) -> Result<Self>  // sugar; creates directory if missing
- unstrict(self) -> PathBuf  // consumes — escape hatch (avoid)
- virtualize(self) -> VirtualPath<Marker>  // upgrade to virtual view (UI ops)
- try_into_boundary(self) -> Result<PathBoundary<Marker>>
- try_into_boundary_create(self) -> Result<PathBoundary<Marker>>
- strictpath_to_string_lossy(&self) -> Cow<'_, str>
- strictpath_to_str(&self) -> Option<&str>
- interop_path(&self) -> &OsStr  // third-party `AsRef<Path>` adapters only
- strictpath_display(&self) -> std::path::Display<'_>
- strict_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<Self>
- strictpath_parent(&self) -> Result<Option<Self>>
- strictpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- strictpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- strict_rename<P: AsRef<Path>>(&self, dest: P) -> io::Result<()>
- strict_copy<P: AsRef<Path>>(&self, dest: P) -> io::Result<u64>
- strict_symlink<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>
- strict_hard_link<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>
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
- create_file(&self) -> io::Result<std::fs::File>
- open_file(&self) -> io::Result<std::fs::File>
- create_dir(&self) -> io::Result<()>
- create_dir_all(&self) -> io::Result<()>
- create_parent_dir(&self) -> io::Result<()>
- create_parent_dir_all(&self) -> io::Result<()>
- remove_file(&self) -> io::Result<()>
- remove_dir(&self) -> io::Result<()>
- remove_dir_all(&self) -> io::Result<()>

VirtualRoot<Marker>
- change_marker<NewMarker>(self) -> VirtualRoot<NewMarker>
- try_new<P: AsRef<Path>>(root_path: P) -> Result<Self>
- try_new_create<P: AsRef<Path>>(root_path: P) -> Result<Self>
- virtual_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<VirtualPath<Marker>>
- into_virtualpath(self) -> Result<VirtualPath<Marker>>  // convert root into virtual path (directory must exist)
- metadata(&self) -> io::Result<std::fs::Metadata>
- virtual_symlink<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>
- virtual_hard_link<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>
- interop_path(&self) -> &OsStr  // third-party `AsRef<Path>` adapters only
- exists(&self) -> bool
- as_unvirtual(&self) -> &PathBoundary<Marker>
- unvirtual(self) -> PathBoundary<Marker>
- read_dir(&self) -> io::Result<std::fs::ReadDir>
- remove_dir(&self) -> io::Result<()>
- remove_dir_all(&self) -> io::Result<()>

VirtualPath<Marker>
- with_root<P: AsRef<Path>>(root: P) -> Result<Self>  // sugar; root must exist
- with_root_create<P: AsRef<Path>>(root: P) -> Result<Self>  // sugar; creates root if missing
- change_marker<NewMarker>(self) -> VirtualPath<NewMarker>  // transform marker after authorization
- unvirtual(self) -> StrictPath<Marker>  // downgrade to system-facing view when ownership is needed
- as_unvirtual(&self) -> &StrictPath<Marker> // borrow the underlying strict path for system-facing related operations
- interop_path(&self) -> &OsStr // for APIs that accept AsRef<Path>
- virtual_join<P: AsRef<Path>>(&self, path: P) -> Result<Self>
- virtualpath_parent(&self) -> Result<Option<Self>>
- virtualpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- virtualpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- virtual_rename<P: AsRef<Path>>(&self, dest: P) -> io::Result<()>
- virtual_copy<P: AsRef<Path>>(&self, dest: P) -> io::Result<u64>
- create_file(&self) -> io::Result<std::fs::File>
- open_file(&self) -> io::Result<std::fs::File>
- virtual_symlink<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>
- virtual_hard_link<P: AsRef<Path>>(&self, link_path: P) -> io::Result<()>
- symlink_metadata(&self) -> io::Result<std::fs::Metadata>  // metadata without following symlinks
- virtualpath_file_name(&self) -> Option<&OsStr>
- virtualpath_file_stem(&self) -> Option<&OsStr>
- virtualpath_extension(&self) -> Option<&OsStr>
- virtualpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool
- virtualpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool
- virtualpath_display(&self) -> VirtualPathDisplay<'_, Marker>  // explicit display method
- try_into_root(self) -> Result<VirtualRoot<Marker>>
- try_into_root_create(self) -> Result<VirtualRoot<Marker>>
- read_dir(&self) -> io::Result<std::fs::ReadDir>
- exists / is_file / is_dir / metadata / read_to_string / read / write / create_file / open_file / create_dir / create_dir_all / create_parent_dir / create_parent_dir_all / remove_file / remove_dir / remove_dir_all (delegates to `StrictPath`; parents derived via virtual semantics)

### Feature-gated APIs

- Feature `virtual-path`
	- Types: `VirtualRoot`, `VirtualPath`
	- Methods: All `virtual_*` and `virtualpath_*` operations, conversions to/from `VirtualRoot`/`VirtualPath`, and `StrictPath::virtualize()`
	- When not enabled: Only `PathBoundary`/`StrictPath` are available; all I/O remains available on `StrictPath`.

### Ecosystem Integration (Composition Pattern)

**Philosophy**: strict-path provides security primitives. You compose them with ecosystem tools.

Instead of feature-gated wrappers, use ecosystem crates directly with `PathBoundary`:

**Temporary Directories** (`tempfile` crate):
```rust
let temp = tempfile::tempdir()?;
let boundary = PathBoundary::try_new(temp.path())?;
// RAII cleanup from tempfile, security from strict-path
```

**OS Standard Directories** (`dirs` crate):
```rust
let config_base = dirs::config_dir().ok_or("No config")?;
let boundary = PathBoundary::try_new_create(config_base.join("myapp"))?;
```

**Portable App Paths** (`app-path` crate):
```rust
use app_path::AppPath;
let app_path = AppPath::with("config");  // Relative to executable directory
let boundary = PathBoundary::try_new_create(&app_path)?;
```

**Serialization** (`serde`):
- `PathBoundary` and `VirtualRoot` implement `FromStr`, enabling automatic deserialization
- Serialize paths as display strings: `boundary.strictpath_display().to_string()`
- For untrusted path fields, deserialize as `String` and validate manually via `boundary.strict_join()`

See the mdBook [Ecosystem Integration Guide](https://dk26.github.io/strict-path-rs/ecosystem_integration.html) for comprehensive patterns.

Short usage rules (1-line each)
- For user input: use `VirtualPath::virtual_join(...)` (construct a root via `VirtualPath::with_root(..)`) -> `VirtualPath`.
- For I/O: use either `VirtualPath` or `StrictPath` (both support I/O). Call `.unvirtual()` only when you need a `StrictPath` explicitly.
- Do not bypass: never call std fs ops on raw `Path`/`PathBuf` built from untrusted input.
- Marker types prevent mixing distinct path boundaries at compile time: use when you have multiple storage areas.
- We do not implement `AsRef<Path>` on `StrictPath`/`VirtualPath`. When an unavoidable third-party API expects `AsRef<Path>`, pass `.interop_path()`.
	(`PathBoundary` and `VirtualRoot` do implement `AsRef<Path>` for convenience at the root level.)
- Interop doesn't require `.unstrict()`: prefer `.interop_path()` for those third-party adapters; call `.unstrict()` only when an owned `PathBuf` is strictly required.
- `.interop_path()` returns `&OsStr` — never wrap it in `Path::new()` to use `Path::join`/`parent`; that bypasses all security. Use `strict_*` / `virtual_*` operations instead.
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
- Use restriction-aware joins/parents; never wrap `.interop_path()` in `Path::new()` to use std path operations.
- Virtual strings are rooted. Use `virtualpath_display()` for UI/logging.
- Use `PathBoundary::try_new_create(..)` when the restriction directory might not exist.
- Symlinks/junctions to outside: paths that traverse a symlink or junction inside the restriction to a location outside the restriction are rejected at validation time with `StrictPathError::PathEscapesBoundary`.

Common anti-patterns (LLM quick check)
- Passing strings to `AsRef<Path>`-only APIs: avoid. Use crate I/O helpers or explicit escape hatches; for `AsRef<Path>`-accepting APIs, use `.interop_path()`.
- Converting `StrictPath` -> `VirtualPath` only for display: **ANTI-PATTERN** `strict_path.clone().virtualize()` for virtual display - if you need virtual semantics, start with `VirtualRoot`/`VirtualPath` from the beginning.
- Wrapping `.interop_path()` in `Path::new()` to use `Path::join`/`Path::parent`: use `strict_*` / `virtual_*` operations instead.
- Forcing ownership: avoid `.into_owned()` on `Cow` unless an owned `String` is required.
- Bare `{}` in format strings: prefer captured identifiers like `"{path}"` (bind a short local if needed).

