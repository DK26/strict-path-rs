# jailed-path — API Reference (concise)

Provides safe, validated filesystem paths inside a confined directory (jail).

## Security Foundation

Uses canonicalization + boundary checking to prevent traversal and symlink/junction escapes. Do not use `std::path::Path::join` on untrusted input; use the explicit `jailed_*/virtual_*` operations documented below.

## Which Type Should I Use?

Ask yourself these questions to determine the right path type:

**🤔 Do we want to allow work with any form of path, but make sure it is always contained within a specified directory?**  
→ **Use `VirtualPath`** - Users can specify any path they want, and it gets automatically clamped to stay safe within your sandbox.

**🤔 Do we want to allow only paths that are within a specific other path (jail), and reject all other paths?**  
→ **Use `JailedPath`** - Validates that the exact path is safe and within boundaries, rejecting anything that would escape.

**🤔 Do we want to allow complete freedom of paths but still make sure that freedom is safe and isolated within a sandbox?**  
→ **Use `VirtualPath`** - Creates a complete sandbox where users have apparent freedom but are mathematically constrained to safety.

**🤔 Do we want a raw path that could point anywhere in our system, as defined by system-admin, and should be overrideable if sysadmin so desires?**  
→ **Use `std::path::Path` or `PathBuf`** - This crate is for constraining paths, not for system-level administrative control.

**🤔 Do we want to give users their own isolated sandbox/workspace where they feel they have complete control?**  
→ **Use `VirtualPath`** - Each user gets their own apparent "/" root, perfect for per-user storage, isolated workspaces.

**🤔 Do we want to use a common shared space for all users, pointing somewhere in our system files, but ensure it cannot escape boundaries?**  
→ **Use `JailedPath`** - Validates that paths stay within a shared boundary, good for shared resources, config files, templates.

**🤔 Do we need compile-time guarantees that different storage contexts can't be accidentally mixed?**  
→ **Use `JailedPath<Marker>` or `VirtualPath<Marker>`** - Both support type markers to prevent mixing different contexts at compile time.

**Quick Decision Matrix:**
- **User Sandboxes** → `VirtualPath` (per-user isolated spaces)
- **Shared Boundaries** → `JailedPath` (common protected areas)  
- **Type Safety** → Both `JailedPath<T>` and `VirtualPath<T>` vs `Path/PathBuf`
- **Unrestricted** → `std::path::Path` (no safety guarantees)

**Common Use Cases:**
```rust
// ✅ Per-user storage - each user gets their own "/"
let user_space: VirtualRoot<UserFiles> = VirtualRoot::try_new(format!("./users/{user_id}"))?;
let doc = user_space.virtual_join("docs/report.pdf")?; // User sees "/docs/report.pdf"

// ✅ Shared config area - all users access same protected space
let config_jail: Jail<ConfigFiles> = Jail::try_new("./shared/config")?;
let cfg = config_jail.jailed_join(user_requested_config)?; // Validates within shared boundary

// ✅ Both can process user input safely
let user_input = "../../../etc/passwd";
let vp = user_space.virtual_join(user_input)?; // Clamped to user's space
let jp = config_jail.jailed_join(user_input)?; // Rejected if escapes shared boundary

// ❌ Don't use std::path for user input
let bad = PathBuf::from(user_input).join("file.txt"); // 🚨 Vulnerable to traversal
```

**Conceptual Models:**
- `JailedPath` = **Proven-safe, system-facing path**: validated path for system-facing I/O and interop
- `VirtualPath` = **User-friendly wrapper**: user-facing virtual "/" view with virtual path operations; also supports I/O and interop

**Unified Signatures (When Appropriate):**
```rust
// Generic across storage contexts — use only when required to have a function that works for multiple jails and contexts
fn process_file<M>(path: &JailedPath<M>) -> std::io::Result<Vec<u8>> {
  path.read_bytes()
}

// Callers pass either a borrowed JailedPath directly, or a borrowed JailedPath from VirtualPath::as_unvirtual()
process_file(&jailed_path);
process_file(virtual_path.as_unvirtual());
```
Prefer marker-specific signatures for stronger guarantees. Use a generic `M` only when the function is intentionally shared across contexts.

**Marker-Specific Signatures (Stronger Guarantees):**
```rust
use std::io;
use jailed_path::{Jail, VirtualRoot, JailedPath, VirtualPath};

// Define distinct storage contexts
struct UserFiles;
struct Logs;

// Only accepts paths proven inside the UserFiles jail
fn read_user_file(path: &JailedPath<UserFiles>) -> io::Result<Vec<u8>> {
    path.read_bytes()
}

// Example setup
let vroot: VirtualRoot<UserFiles> = VirtualRoot::try_new("./users/alice")?;
let vpath: VirtualPath<UserFiles> = vroot.virtual_join("docs/report.pdf")?;

// Works: borrow the jailed view from a VirtualPath in the same marker
let bytes = read_user_file(vpath.as_unvirtual())?;

// Compile-time separation of jails
let logs: Jail<Logs> = Jail::try_new("./logs")?;
let log_path = logs.jailed_join("app.log")?;
// read_user_file(&log_path)?; // ❌ compile error: expected `JailedPath<UserFiles>`
```

## API Design Philosophy: Explicit Security

**No Display Trait**: Both types require explicit display methods to prevent accidental path leakage:

```rust
// ❌ No automatic Display trait
println!("{}", vpath);  // Compile error

// ✅ Explicit display methods
impl JailedPath {
    pub fn jailedpath_display(&self) -> impl Display { ... }
}
impl VirtualPath {
  pub fn virtualpath_display(&self) -> impl Display { ... }   // Virtual view (rooted)
  // System-facing strings are explicit:
  // - Borrow the jailed view and use Display: `self.as_unvirtual().jailedpath_display()`
}

println!("User: {}", vpath.virtualpath_display());        // "/docs/file.txt"  
println!("Log: {}", vpath.as_unvirtual().jailedpath_display());   // "/srv/users/alice/docs/file.txt"
```

**Rationale:** Prevents accidental system path disclosure in user-facing contexts.

**Design Decision: VirtualPath Display Methods**

`VirtualPath` provides `virtualpath_display()` for user-facing display. System-facing strings are available but must be called explicitly:

- Prefer virtual semantics in UI: `vpath.virtualpath_display()` or `vpath.virtualpath_to_string_lossy()`
- When you need the real, system path string, either:
  - Borrow the jailed view and format it: `format!("{}", vpath.as_unvirtual().jailedpath_display())`

This keeps potentially sensitive operations visible in code review while offering ergonomic access when required.



**Rationale:** Security-sensitive APIs should make potentially dangerous operations visible in code review. Automatic trait implementations like `Display` can hide semantic differences that could lead to unintentional information disclosure in user-facing contexts.

Start here: [Quick Recipes](#quick-recipes) · [Pitfalls](#pitfalls-and-how-to-avoid)

Top-level exports

| Symbol                        |   Kind | Purpose                                                                                               |
| ----------------------------- | -----: | ----------------------------------------------------------------------------------------------------- |
| `JailedPathError`             |   enum | Validation and resolution errors.                                                                     |
| `Jail<Marker>`                | struct | Validator that produces `JailedPath`.                                                                 |
| `JailedPath<Marker>`          | struct | Validated path proven inside the jail; supports I/O.                                                  |
| `VirtualRoot<Marker>`         | struct | User-facing entry that clamps user paths to a jail.                                                   |
| `VirtualPath<Marker>`         | struct | User-facing path that extends `JailedPath` with a virtual-root view and jail-aware ops; supports I/O. |
| `Result<T>`                   |  alias | `Result<T, JailedPathError>`                                                                          |
| `serde_ext` (feature `serde`) | module | Context-aware deserialization helpers (`WithJail`, `WithVirtualRoot`).                                |

## Quick Recipes
- Create jail (create dir if missing) and validate: `let jail = Jail::try_new_create("./safe")?; let jp = jail.jailed_join("a/b.txt")?;`
- Virtual user path: `let vroot = VirtualRoot::try_new("./safe")?; let vp = vroot.virtual_join("a/b.txt")?;`
- Convert between types: `vpath.unvirtual()` → `JailedPath`, `jpath.virtualize()` → `VirtualPath`
- Unified functions: take `&JailedPath<_>` and call with `vpath.as_unvirtual()`
- Display paths: `jpath.jailedpath_display()`, `vpath.virtualpath_display()` (no automatic Display trait)
- Type-safe function signatures: `fn serve_file<M>(p: &JailedPath<M>) -> io::Result<Vec<u8>> { p.read_bytes() }`
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

JailedPathError (variants)
- `InvalidJail { jail: PathBuf, source: io::Error }`
- `PathEscapesBoundary { attempted_path: PathBuf, jail_boundary: PathBuf }`
- `PathResolutionError { path: PathBuf, source: io::Error }`
- `WindowsShortName { component, original, checked_at }` (windows)

Jail<Marker>
- try_new<P: AsRef<Path>>(jail_path: P) -> Result<Self>
- try_new_create<P: AsRef<Path>>(root: P) -> Result<Self>
- jailed_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>>
- interop_path(&self) -> &OsStr
- exists(&self) -> bool
- jailedpath_display(&self) -> std::path::Display<'_>
- virtualize(self) -> VirtualRoot<Marker>

JailedPath<Marker>
Note: `.unjail()` is an explicit escape hatch. Interop doesn’t require it — prefer `.interop_path()`; use `.unjail()` only when an owned `PathBuf` is strictly required.
- unjail(self) -> PathBuf  // consumes — escape hatch (avoid)
- virtualize(self) -> VirtualPath<Marker>  // upgrade to virtual view (UI ops)
- jailedpath_to_string_lossy(&self) -> Cow<'_, str>
- jailedpath_to_str(&self) -> Option<&str>
- interop_path(&self) -> &OsStr
- jailedpath_display(&self) -> std::path::Display<'_>  // explicit display method
- jailed_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>>
- jailedpath_parent(&self) -> Result<Option<Self>>
- jailedpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- jailedpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- jailedpath_file_name(&self) -> Option<&OsStr>
- jailedpath_file_stem(&self) -> Option<&OsStr>
- jailedpath_extension(&self) -> Option<&OsStr>
- jailedpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool
- jailedpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool
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
- as_unvirtual(&self) -> &Jail<Marker>
- unvirtual(self) -> Jail<Marker>

VirtualPath<Marker>
- unvirtual(self) -> JailedPath<Marker>  // downgrade to system-facing view when ownership is needed
- as_unvirtual(&self) -> &JailedPath<Marker> // borrow the underlying jailed path for system-facing related operations
- interop_path(&self) -> &OsStr // for APIs that accept AsRef<Path>
- virtualpath_to_string_lossy(&self) -> Cow<'_, str>
- jailedpath_to_string_lossy(&self) -> Cow<'_, str>  // delegated system-path string accessor
- jailedpath_to_str(&self) -> Option<&str>           // delegated system-path string accessor
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
- exists / is_file / is_dir / metadata / read_to_string / read_bytes / write_bytes / write_string / create_dir / create_dir_all / create_parent_dir / create_parent_dir_all / remove_file / remove_dir / remove_dir_all (delegates to `JailedPath`; parents derived via virtual semantics)

### Feature-gated APIs (complete list)
These are available only when the corresponding Cargo features are enabled:

- Feature `dirs` (user directories)
  - `Jail::try_new_config(app_name: &str) -> Result<Jail>`
  - `Jail::try_new_data(app_name: &str) -> Result<Jail>`
  - `Jail::try_new_cache(app_name: &str) -> Result<Jail>`
  - `VirtualRoot::try_new_config(app_name: &str) -> Result<VirtualRoot>`
  - `VirtualRoot::try_new_data(app_name: &str) -> Result<VirtualRoot>`
  - `VirtualRoot::try_new_cache(app_name: &str) -> Result<VirtualRoot>`

- Feature `tempdir` (RAII temporary directories)
  - `Jail::try_new_temp() -> Result<Jail>`
  - `Jail::try_new_temp_with_prefix(prefix: &str) -> Result<Jail>`
  - `VirtualRoot` holds RAII of temp dirs internally when constructed from feature-enabled contexts

- Feature `app-path` (portable app-relative dirs with optional env overrides)
  - `Jail::try_new_app_path(subdir: &str, env_override: Option<&str>) -> Result<Jail>`
  - `VirtualRoot::try_new_app_path(subdir: &str, env_override: Option<&str>) -> Result<VirtualRoot>`

- Feature `serde`
  - `impl Serialize for JailedPath` → system path string
  - `impl Serialize for VirtualPath` → rooted virtual string (e.g., "/a/b.txt")
  - `serde_ext::WithJail<'_, Marker>`: `DeserializeSeed` to deserialize a `JailedPath<Marker>` with a provided `&Jail<Marker>`
  - `serde_ext::WithVirtualRoot<'_, Marker>`: `DeserializeSeed` to deserialize a `VirtualPath<Marker>` with a provided `&VirtualRoot<Marker>`

Short usage rules (1-line each)
- For user input: use `VirtualRoot::virtual_join(...)` -> `VirtualPath`.
- For I/O: use either `VirtualPath` or `JailedPath` (both support I/O). Call `.unvirtual()` only when you need a `JailedPath` explicitly.
- Do not bypass: never call std fs ops on raw `Path`/`PathBuf` built from untrusted input.
- Marker types prevent mixing distinct jails at compile time: use when you have multiple storage areas.
- We do not implement `AsRef<Path>` on `JailedPath`/`VirtualPath`. When an API expects `AsRef<Path>`, pass `.interop_path()`.
  (`Jail` and `VirtualRoot` do implement `AsRef<Path>` for convenience at the root level.)
- Interop doesn’t require `.unjail()`: prefer `.interop_path()`; call `.unjail()` only when an owned `PathBuf` is strictly required.
- Avoid std `Path::join`/`Path::parent` on leaked paths — they do not apply virtual-root
  clamping or jail checks. Use `jailed_join` / `virtualpath_parent` instead.
 - Do not convert `JailedPath` -> `VirtualPath` just to print; for UI flows start with `VirtualRoot::virtual_join(..)` and keep a `VirtualPath`.
 - `*_to_string_lossy()` returns `Cow<'_, str>`; call `.into_owned()` only when an owned `String` is required.

Parent directory helpers (semantics)
- create_parent_dir: non-recursive; creates only the immediate parent; errors if grandparents are missing; Ok(()) at jail/virtual root.
- create_parent_dir_all: recursive; creates the full chain up to the immediate parent; Ok(()) at jail/virtual root.
- VirtualPath parent helpers act in the virtual dimension (use `virtualpath_parent()`), then perform I/O on the underlying jailed system path.
 
Naming rationale (quick scan aid)
- We name methods by their dimension so intent is obvious at a glance.
- std `Path::join(..)` or `p.join(..)`: unsafe join (can escape); avoid on untrusted inputs.
- `Jail::jailed_join(..)` / `JailedPath::jailed_join(..)`: safe, validated jailed path join.
- `VirtualRoot::virtual_join(..)` / `VirtualPath::virtual_join(..)`: safe, clamped virtual-path join.
- This applies to other operations too: `*_parent`, `*_with_file_name`, `*_with_extension`, `*_starts_with`, `*_ends_with`, etc. Shortened names apply only to `*_join`.
The explicit names make intent obvious even when types aren’t visible.
 - For directory creation, `create_` = non-recursive, `*_all` = recursive (matches std `std::fs` semantics). Parent helpers mirror this.
 - Switching views: typically stay within one dimension (virtual or system). For edge cases, upgrade with `.virtualize()` or downgrade with `.unvirtual()` to access the other dimension’s operations.

**Critical: Absolute Path Join Behavior**
- `std::path::Path::join("/absolute")`: DANGEROUS — replaces the base path entirely, enabling traversal.
- `JailedPath::jailed_join("/absolute")`: SECURE — validates the result stays within the jail boundary; errors if it would escape.
- `VirtualPath::virtual_join("/absolute")`: SECURE — interprets the path as absolute in the VIRTUAL namespace and replaces the current virtual path with that virtual-absolute. The resulting jailed path is resolved under the same `VirtualRoot` (e.g., joining `/etc/passwd` yields a virtual `/etc/passwd` backed by `<virtual_root>/etc/passwd`). Any `..` that would go above the virtual root is clamped at the virtual root.

This difference makes `std::path::Path::join` the #1 source of path traversal vulnerabilities, while our types make such attacks impossible.

Display
- Use `vpath.virtualpath_display()` for user-facing virtual paths (e.g., "/a/b.txt").
- For system-facing logs and diagnostics, use `jpath.jailedpath_display()` or `vpath.as_unvirtual().jailedpath_display()`.

Separator normalization (platform specifics)
- Windows: `virtualpath_display()` and `virtualpath_to_string_lossy()` normalize `\` to `/` and ensure a leading `/`.
- Unix: backslashes are not path separators; they are preserved as literal characters. A leading `/` is ensured.

Equality/Ordering/Hashing
- `Jail<Marker>` and `VirtualRoot<Marker>` compare/hash by canonicalized jail root path and marker.
- `VirtualPath` compares, orders, and hashes by its inner jailed path, identical to `JailedPath`, including the marker type.
- Cross-type equality is supported: `VirtualPath<Marker> == JailedPath<Marker>` compares underlying jailed paths. Borrow via `.as_unvirtual()` when needed.

## Traits at a glance
- Jail<Marker>
  - Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash
  - AsRef<Path>
  - Cross-type equality: PartialEq<VirtualRoot<Marker>>, PartialEq<Path>, PartialEq<PathBuf>, PartialEq<&Path>

- VirtualRoot<Marker>
  - Clone, Debug, Display, Eq, PartialEq, Ord, PartialOrd, Hash
  - AsRef<Path>
  - Cross-type equality: PartialEq<Jail<Marker>>, PartialEq<Path>, PartialEq<PathBuf>, PartialEq<&Path>

- JailedPath<Marker>
  - Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash
  - Cross-type equality: PartialEq<VirtualPath<Marker>>, PartialEq<T: AsRef<Path>>
  - No AsRef<Path>; use `interop_path()` when needed
  - [feature serde] Serialize → system path string

- VirtualPath<Marker>
  - Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash
  - Cross-type equality: PartialEq<JailedPath<Marker>>, PartialEq<T: AsRef<Path>> (compares virtual representation)
  - No Display (use `virtualpath_display()` wrapper); No AsRef<Path>
  - [feature serde] Serialize → rooted virtual string (e.g., "/a/b.txt")

## Pitfalls (And How To Avoid)
- Do not expose raw `Path`/`PathBuf` from `JailedPath`/`VirtualPath`. We do not implement `AsRef<Path>`. Prefer crate I/O or `.interop_path()` where `AsRef<Path>` is accepted, or explicit escape hatches when unavoidable.
- Use jail-aware joins/parents; never call std `Path::join` on a leaked path.
- Virtual strings are rooted. Use `Display` or `virtualpath_to_string_lossy()` for UI/logging.
- Use `Jail::try_new_create(..)` when the jail directory might not exist.
- Symlinks/junctions to outside: paths that traverse a symlink or junction inside the jail to a location outside the jail are rejected at validation time with `JailedPathError::PathEscapesBoundary`.

Common anti-patterns (LLM quick check)
- Passing strings to `AsRef<Path>`-only APIs: avoid. Use crate I/O helpers or explicit escape hatches; for `AsRef<Path>`-accepting APIs, use `.interop_path()`.
- Converting `JailedPath` -> `VirtualPath` only for display: **ANTI-PATTERN** `jailed_path.clone().virtualize()` for virtual display - if you need virtual semantics, start with `VirtualRoot`/`VirtualPath` from the beginning.
- Using `Path::join`/`Path::parent` on leaked paths: use `jailedpath_*` / `virtualpath_*` ops.
- Forcing ownership: avoid `.into_owned()` on `Cow` unless an owned `String` is required.
- Bare `{}` in format strings: prefer captured identifiers like `"{path}"` (bind a short local if needed).

 

## Integrations (At a Glance)
- Serde (feature `serde`): `JailedPath`/`VirtualPath` implement `Serialize`. For deserialization, read `String` and validate via `Jail::jailed_join(..)` or `VirtualRoot::virtual_join(..)`. For single values with context, use `serde_ext::WithJail(&jail)` / `serde_ext::WithVirtualRoot(&vroot)` on a serde Deserializer. See `serde_ext` docs.
- Axum: Put `VirtualRoot<Marker>` in state; validate `Path<String>` to `VirtualPath` per request (custom extractor optional). Handlers take `&VirtualPath<_>`/`&JailedPath<_>` for I/O. See `examples/web/axum_static_server.rs`.
- app-path: Use `app_path::app_path!("config", env = "APP_CONFIG_DIR")` to discover a config directory; jail it and operate through `JailedPath`. See `examples/config/app_path_config.rs`.
