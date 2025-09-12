# strict-path — API Reference (concise)

Provides safe, validated filesystem paths inside a confined directory (restriction).

## Core Security Foundation: `StrictPath`

**`StrictPath` is the fundamental security primitive** - every `StrictPath` instance is mathematical proof that a path is within its designated boundary. This guarantee is enforced through:

- Cryptographic-grade path canonicalization via [`soft-canonicalize`](https://crates.io/crates/soft-canonicalize)
- Type-level security contracts that make path traversal impossible
- Boundary validation that cannot be bypassed

**The security model:** If your code has a `StrictPath<Marker>`, it is guaranteed safe - no runtime validation needed within functions that accept it.

## Architecture Overview

All security flows through `StrictPath`:
- `PathBoundary` → validates external input → produces `StrictPath`  
- `VirtualPath` → extends `StrictPath` with user-friendly semantics
- `VirtualRoot` → provides root context for creating `VirtualPath` instances

Uses canonicalization + boundary checks to prevent directory traversal attacks.

### PathBoundary Design Philosophy

`PathBoundary` represents the secure foundation or starting point from which all path operations begin. Think of it as establishing a safe boundary (like `/home/users/alice`) and then performing validated operations from that foundation.

When you call `path_boundary.strict_join("documents/file.txt")`, you're building outward from the secure boundary with validated path construction. The boundary is the **trusted starting point**, and operations like `strict_join()` are the **validated tools** that work from that boundary to ensure you stay within the allowed area.

This design makes the API read naturally:
- `user_dir.strict_join("documents/report.pdf")` - "From the user directory boundary, strictly join documents/report.pdf"  
- `cache_boundary.strict_join("build/output.json")` - "From the cache boundary, strictly join build/output.json"

### Core Security Rules

- Do not bypass: never call std fs ops on raw `Path`/`PathBuf` built from untrusted input.
- Marker types prevent mixing distinct restrictions at compile time: use when you have multiple storage areas.
- We do not implement `AsRef<Path>` on `StrictPath`/`VirtualPath`. When an API expects `AsRef<Path>`, pass `.interop_path()`.
  (`PathBoundary` and `VirtualRoot` do implement `AsRef<Path>` for convenience at the root level.)
- Interop doesn't require `.unstrict()`: prefer `.interop_path()`; call `.unstrict()` only when an owned `PathBuf` is strictly required.
- Avoid std `Path::join`/`Path::parent` on leaked paths — they do not apply virtual-root
  clamping or restriction checks. Use `strict_join` / `virtualpath_parent` instead.
- Do not convert `StrictPath` -> `VirtualPath` just to print; for UI flows start with `VirtualRoot::virtual_join(..)` and keep a `VirtualPath`.

## StrictPath API

- unstrict(self) -> PathBuf  // consumes — escape hatch (avoid)
- virtualize(self) -> VirtualPath<Marker>  // upgrade to virtual view (UI ops)
- strictpath_to_string_lossy(&self) -> Cow<'_, str>
- strictpath_to_str(&self) -> Option<&str>
- interop_path(&self) -> &OsStr
- strictpath_display(&self) -> std::path::Display<'_>  // explicit display method
- strict_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<StrictPath<Marker>>
- strictpath_parent(&self) -> Result<Option<Self>>
- strictpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- strictpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>

All operations prevent traversal and symlink/junction escapes. Do not use `std::path::Path::join` on untrusted input; use the explicit `strict_*/virtual_*` operations documented below.

## Which Type Should I Use?

Ask yourself these questions to determine the right path type:

**🤔 Do we want to allow work with any form of path, but make sure it is always contained within a specified directory?**  
→ **Use `VirtualPath`** - Users can specify any path they want, and it gets automatically clamped to stay safe within your sandbox.

**🤔 Do we want to allow only paths that are within a specific other path (restriction), and reject all other paths?**  
→ **Use `StrictPath`** - Validates that the exact path is safe and within boundaries, rejecting anything that would escape.

**🤔 Do we want to allow complete freedom of paths but still make sure that freedom is safe and isolated within a sandbox?**  
→ **Use `VirtualPath`** - Creates a complete sandbox where users have apparent freedom but are mathematically constrained to safety.

**🤔 Do we want a raw path that could point anywhere in our system, as defined by system-admin, and should be overrideable if sysadmin so desires?**  
→ **Use `std::path::Path` or `PathBuf`** - This crate is for constraining paths, not for system-level administrative control.

**🤔 Do we want to give users their own isolated sandbox/workspace where they feel they have complete control?**  
→ **Use `VirtualPath`** - Each user gets their own apparent "/" root, perfect for per-user storage, isolated workspaces.

**🤔 Do we want to use a common shared space for all users, pointing somewhere in our system files, but ensure it cannot escape boundaries?**  
→ **Use `StrictPath`** - Validates that paths stay within a shared boundary, good for shared resources, config files, templates.

**🤔 Do we need compile-time guarantees that different storage contexts can't be accidentally mixed?**  
→ **Use `StrictPath<Marker>` or `VirtualPath<Marker>`** - Both support type markers to prevent mixing different contexts at compile time.

**Quick Decision Matrix:**
- **User Sandboxes** → `VirtualPath` (per-user isolated spaces)
- **Shared Boundaries** → `StrictPath` (common protected areas)  
- **Type Safety** → Both `StrictPath<T>` and `VirtualPath<T>` vs `Path/PathBuf`
- **Unrestricted** → `std::path::Path` (no safety guarantees)

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
  path.read_bytes()
}

// Callers pass either a borrowed StrictPath directly, or a borrowed StrictPath from VirtualPath::as_unvirtual()
process_file(&strict_path);
process_file(virtual_path.as_unvirtual());
```
Prefer marker-specific signatures for stronger guarantees. Use a generic `M` only when the function is intentionally shared across contexts.

**Marker-Specific Signatures (Stronger Guarantees):**
```rust
use std::io;
use strict_path::{PathBoundary, VirtualRoot, StrictPath, VirtualPath};

// Define distinct storage contexts
struct UserFiles;
struct Logs;

// Only accepts paths proven inside the UserFiles restriction
fn read_user_file(path: &StrictPath<UserFiles>) -> io::Result<Vec<u8>> {
    path.read_bytes()
}

// Example setup
let vroot: VirtualRoot<UserFiles> = VirtualRoot::try_new("./users/alice")?;
let vpath: VirtualPath<UserFiles> = vroot.virtual_join("docs/report.pdf")?;

// Works: borrow the strict view from a VirtualPath in the same marker
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

**Rationale:** Prevents accidental system path disclosure in user-facing contexts.

**Design Decision: VirtualPath Display Methods**

`VirtualPath` provides `virtualpath_display()` for user-facing display. System-facing strings are available but must be called explicitly:

- Prefer virtual semantics in UI: `vpath.virtualpath_display()` or `vpath.virtualpath_to_string_lossy()`
- When you need the real, system path string, either:
  - Borrow the strict view and format it: `format!("{}", vpath.as_unvirtual().strictpath_display())`

This keeps potentially sensitive operations visible in code review while offering ergonomic access when required.



**Rationale:** Security-sensitive APIs should make potentially dangerous operations visible in code review. Automatic trait implementations like `Display` can hide semantic differences that could lead to unintentional information disclosure in user-facing contexts.

Start here: [Quick Recipes](#quick-recipes) · [Pitfalls](#pitfalls-and-how-to-avoid)

Top-level exports

| Symbol                        |   Kind | Purpose                                                                                                      |
| ----------------------------- | -----: | ------------------------------------------------------------------------------------------------------------ |
| `StrictPathError`             |   enum | Validation and resolution errors.                                                                            |
| `PathBoundary<Marker>`        | struct | Validator that produces `StrictPath`.                                                                        |
| `StrictPath<Marker>`          | struct | Validated path proven inside the restriction; supports I/O.                                                  |
| `VirtualRoot<Marker>`         | struct | User-facing entry that clamps user paths to a restriction.                                                   |
| `VirtualPath<Marker>`         | struct | User-facing path that extends `StrictPath` with a virtual-root view and restriction-aware ops; supports I/O. |
| `Result<T>`                   |  alias | `Result<T, StrictPathError>`                                                                                 |
| `serde_ext` (feature `serde`) | module | Context-aware deserialization helpers (`WithBoundary`, `WithVirtualRoot`).                                   |

## Quick Recipes
- Create restriction (create dir if missing) and validate: `let restriction = PathBoundary::try_new_create("./safe")?; let sp = restriction.strict_join("a/b.txt")?;`
- Virtual user path: `let vroot = VirtualRoot::try_new("./safe")?; let vp = vroot.virtual_join("a/b.txt")?;`
- Convert between types: `vpath.unvirtual()` → `StrictPath`, `spath.virtualize()` → `VirtualPath`
- Unified functions: take `&StrictPath<_>` and call with `vpath.as_unvirtual()`
- Display paths: `spath.strictpath_display()`, `vpath.virtualpath_display()` (no automatic Display trait)
- Type-safe function signatures: `fn serve_file<M>(p: &StrictPath<M>) -> io::Result<Vec<u8>> { p.read_bytes() }`
- Type-safe virtual signatures: `fn serve_user_file(p: &VirtualPath) -> io::Result<Vec<u8>> { p.read_bytes() }`
- Interop: when an API expects `AsRef<Path>`, pass `.interop_path()` (returns `&OsStr`, which implements `AsRef<Path>`). Example: `std::fs::copy(src.interop_path(), dst.interop_path())?;`
- Create parent dirs: `vp.create_parent_dir_all()?; vp.write_string("content")?;`

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

StrictPath<Marker>
Note: `.unstrict()` is an explicit escape hatch. Interop doesn’t require it — prefer `.interop_path()`; use `.unstrict()` only when an owned `PathBuf` is strictly required.
- unstrict(self) -> PathBuf  // consumes — escape hatch (avoid)
- virtualize(self) -> VirtualPath<Marker>  // upgrade to virtual view (UI ops)
- strictpath_to_string_lossy(&self) -> Cow<'_, str>
- strictpath_to_str(&self) -> Option<&str>
- interop_path(&self) -> &OsStr
- strictpath_display(&self) -> std::path::Display<'_>
- strict_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<Self>
- strictpath_parent(&self) -> Result<Option<Self>>
- strictpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- strictpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- strictpath_file_name(&self) -> Option<&OsStr>
- strictpath_file_stem(&self) -> Option<&OsStr>
- strictpath_extension(&self) -> Option<&OsStr>
- strictpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool
- strictpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool
- exists(&self) -> bool
- is_file(&self) -> bool
- is_dir(&self) -> bool
- metadata(&self) -> io::Result<std::fs::Metadata>
- read_to_string(&self) -> io::Result<String>
- read_bytes(&self) -> io::Result<Vec<u8>>
- write_bytes(&self, data: &[u8]) -> io::Result<()>
- write_string(&self, data: &str) -> io::Result<()>
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

VirtualPath<Marker>
- unvirtual(self) -> StrictPath<Marker>  // downgrade to system-facing view when ownership is needed
- as_unvirtual(&self) -> &StrictPath<Marker> // borrow the underlying strict path for system-facing related operations
- interop_path(&self) -> &OsStr // for APIs that accept AsRef<Path>
- virtual_join<P: AsRef<Path>>(&self, path: P) -> Result<Self>
- virtualpath_parent(&self) -> Result<Option<Self>>
- virtualpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- virtualpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- virtualpath_file_name(&self) -> Option<&OsStr>
- virtualpath_file_stem(&self) -> Option<&OsStr>
- virtualpath_extension(&self) -> Option<&OsStr>
- virtualpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool
- virtualpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool
- virtualpath_display(&self) -> VirtualPathDisplay<'_, Marker>  // explicit display method
- exists / is_file / is_dir / metadata / read_to_string / read_bytes / write_bytes / write_string / create_dir / create_dir_all / create_parent_dir / create_parent_dir_all / remove_file / remove_dir / remove_dir_all (delegates to `StrictPath`; parents derived via virtual semantics)

### Feature-gated APIs (complete list)
These are available only when the corresponding Cargo features are enabled:

- Feature `dirs` (user directories)
  - `PathBoundary::try_new_config(app_name: &str) -> Result<PathBoundary>`
  - `PathBoundary::try_new_data(app_name: &str) -> Result<PathBoundary>`
  - `PathBoundary::try_new_cache(app_name: &str) -> Result<PathBoundary>`
  - `VirtualRoot::try_new_config(app_name: &str) -> Result<VirtualRoot>`
  - `VirtualRoot::try_new_data(app_name: &str) -> Result<VirtualRoot>`
  - `VirtualRoot::try_new_cache(app_name: &str) -> Result<VirtualRoot>`

- Feature `tempfile` (RAII temporary directories)
  - `PathBoundary::try_new_temp() -> Result<PathBoundary>`
  - `PathBoundary::try_new_temp_with_prefix(prefix: &str) -> Result<PathBoundary>`
  - `VirtualRoot` holds RAII of temp dirs internally when constructed from feature-enabled contexts

- Feature `app-path` (portable app-relative dirs with optional env overrides)
  - `PathBoundary::try_new_app_path(subdir: &str, env_override: Option<&str>) -> Result<PathBoundary>`
  - `VirtualRoot::try_new_app_path(subdir: &str, env_override: Option<&str>) -> Result<VirtualRoot>`

- Feature `serde`
  - `impl Serialize for StrictPath` → system path string
  - `impl Serialize for VirtualPath` → rooted virtual string (e.g., "/a/b.txt")
  - `serde_ext::WithBoundary<'_, Marker>`: `DeserializeSeed` to deserialize a `StrictPath<Marker>` with a provided `&PathBoundary<Marker>`
  - `serde_ext::WithVirtualRoot<'_, Marker>`: `DeserializeSeed` to deserialize a `VirtualPath<Marker>` with a provided `&VirtualRoot<Marker>`

Short usage rules (1-line each)
- For user input: use `VirtualRoot::virtual_join(...)` -> `VirtualPath`.
- For I/O: use either `VirtualPath` or `StrictPath` (both support I/O). Call `.unvirtual()` only when you need a `StrictPath` explicitly.
- Do not bypass: never call std fs ops on raw `Path`/`PathBuf` built from untrusted input.
- Marker types prevent mixing distinct path boundaries at compile time: use when you have multiple storage areas.
- We do not implement `AsRef<Path>` on `StrictPath`/`VirtualPath`. When an API expects `AsRef<Path>`, pass `.interop_path()`.
  (`PathBoundary` and `VirtualRoot` do implement `AsRef<Path>` for convenience at the root level.)
- Interop doesn’t require `.unstrict()`: prefer `.interop_path()`; call `.unstrict()` only when an owned `PathBuf` is strictly required.
- Avoid std `Path::join`/`Path::parent` on leaked paths — they do not apply virtual-root
  clamping or path boundary checks. Use `strict_join` / `virtualpath_parent` instead.
 - Do not convert `StrictPath` -> `VirtualPath` just to print; for UI flows start with `VirtualRoot::virtual_join(..)` and keep a `VirtualPath`.
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
- `VirtualRoot::virtual_join(..)` / `VirtualPath::virtual_join(..)`: safe, clamped virtual-path join.
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
- Windows: `virtualpath_display()` and `virtualpath_to_string_lossy()` normalize `\` to `/` and ensure a leading `/`.
- Unix: backslashes are not path separators; they are preserved as literal characters. A leading `/` is ensured.

Equality/Ordering/Hashing
- `PathBoundary<Marker>` and `VirtualRoot<Marker>` compare/hash by canonicalized restriction root path and marker.
- `VirtualPath` compares, orders, and hashes by its inner strict path, identical to `StrictPath`, including the marker type.
- Cross-type equality is supported: `VirtualPath<Marker> == StrictPath<Marker>` compares underlying strict paths. Borrow via `.as_unvirtual()` when needed.

## Traits at a glance
- PathBoundary<Marker>
  - Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash
  - AsRef<Path>
  - Cross-type equality: PartialEq<VirtualRoot<Marker>>, PartialEq<Path>, PartialEq<PathBuf>, PartialEq<&Path>

- VirtualRoot<Marker>
  - Clone, Debug, Display, Eq, PartialEq, Ord, PartialOrd, Hash
  - AsRef<Path>
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
- Virtual strings are rooted. Use `Display` or `virtualpath_to_string_lossy()` for UI/logging.
- Use `PathBoundary::try_new_create(..)` when the restriction directory might not exist.
- Symlinks/junctions to outside: paths that traverse a symlink or junction inside the restriction to a location outside the restriction are rejected at validation time with `StrictPathError::PathEscapesBoundary`.

Common anti-patterns (LLM quick check)
- Passing strings to `AsRef<Path>`-only APIs: avoid. Use crate I/O helpers or explicit escape hatches; for `AsRef<Path>`-accepting APIs, use `.interop_path()`.
- Converting `StrictPath` -> `VirtualPath` only for display: **ANTI-PATTERN** `strict_path.clone().virtualize()` for virtual display - if you need virtual semantics, start with `VirtualRoot`/`VirtualPath` from the beginning.
- Using `Path::join`/`Path::parent` on leaked paths: use `strictpath_*` / `virtualpath_*` ops.
- Forcing ownership: avoid `.into_owned()` on `Cow` unless an owned `String` is required.
- Bare `{}` in format strings: prefer captured identifiers like `"{path}"` (bind a short local if needed).

 

## Integrations (At a Glance)
- Serde (feature `serde`): `StrictPath`/`VirtualPath` implement `Serialize`. For deserialization, read `String` and validate via `PathBoundary::strict_join(..)` or `VirtualRoot::virtual_join(..)`. For single values with context, use `serde_ext::WithBoundary(&boundary)` / `serde_ext::WithVirtualRoot(&vroot)` on a serde Deserializer. See `serde_ext` docs.
- Axum: Put `VirtualRoot<Marker>` in state; validate `Path<String>` to `VirtualPath` per request (custom extractor optional). Handlers take `&VirtualPath<_>`/`&StrictPath<_>` for I/O. See `examples/web/axum_static_server.rs`.
- app-path: Use `app_path::app_path!("config", env = "APP_CONFIG_DIR")` to discover a config directory; path boundary it and operate through `StrictPath`. See `examples/config/app_path_config.rs`.
