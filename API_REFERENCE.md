# jailed-path — API Reference (concise)

Provides safe, validated filesystem paths inside a confined directory (jail).

## Security Foundation

Built on `soft-canonicalize` with protection against documented CVEs (CVE-2025-8088, CVE-2022-21658, Windows 8.3 vulnerabilities, etc.). Provides mathematical guarantees via canonicalization and boundary checking—not simple string comparison.

**Conceptual Models:**
- `JailedPath` = **Proven-safe system path**: a validated path that's guaranteed safe for I/O operations
- `VirtualPath` = **User-friendly wrapper**: same safety as `JailedPath` but with virtual "/" root display and virtual path operations

Start here: [Quick Recipes](#quick-recipes) · [Pitfalls](#pitfalls-and-how-to-avoid)

Top-level exports

| Symbol                |   Kind | Purpose                                                                                               |
| --------------------- | -----: | ----------------------------------------------------------------------------------------------------- |
| `JailedPathError`     |   enum | Validation and resolution errors.                                                                     |
| `Jail<Marker>`        | struct | Validator that produces `JailedPath`.                                                                 |
| `JailedPath<Marker>`  | struct | Validated path proven inside the jail; supports I/O.                                                  |
| `VirtualRoot<Marker>` | struct | User-facing entry that clamps user paths to a jail.                                                   |
| `VirtualPath<Marker>` | struct | User-facing path that extends `JailedPath` with a virtual-root view and jail-aware ops; supports I/O. |
| `Result<T>`           |  alias | `Result<T, JailedPathError>`                                                                          |

## Quick Recipes
- Create jail (create dir if missing) and validate: `let jail = Jail::try_new_create("./safe")?; let jp = jail.systempath_join("a/b.txt")?;`
- Prefer signatures that require `JailedPath`: `fn serve(p: &JailedPath) -> io::Result<Vec<u8>> { p.read_bytes() }`
- Virtual user path: `let vroot = VirtualRoot::try_new("./safe")?; let vp = vroot.virtualpath_join("a/b.txt")?; println!("{vp}"); // "/a/b.txt"`
- Prefer signatures that require `VirtualPath`: `fn serve(p: &VirtualPath) -> io::Result<Vec<u8>> { p.read_bytes() }`
- AsRef<Path> interop (no allocation): `std::fs::copy(src.systempath_as_os_str(), dst.systempath_as_os_str())?; // src/dst: &JailedPath or &VirtualPath`
- Create the full parent chain (virtual semantics): `let vp = vroot.virtualpath_join("reports/2025/q3/summary.txt")?; vp.create_parent_dir_all()?; vp.write_string("contents")?;`

Markers and type inference
- All core types are generic over a `Marker` with a default of `()`.
- In many cases, binding the value is enough for inference: `let vroot: VirtualRoot = VirtualRoot::try_new("root")?; let vp = vroot.virtualpath_join("f.txt")?;`.
- When inference needs help, add an explicit type or an empty turbofish:
  - `let vroot: VirtualRoot<()> = VirtualRoot::try_new("root")?;`
  - `let vroot = VirtualRoot::<()>::try_new("root")?;`
- With a custom marker: `struct Docs; let vroot: VirtualRoot<Docs> = VirtualRoot::try_new("docs")?;`
- Prefer annotating the `let` binding or function signature for readability; use turbofish only when it clarifies intent or is required.
- AsRef<Path> interop (no allocation): `external_api(jp.systempath_as_os_str());`

JailedPathError (variants)
- `InvalidJail { jail: PathBuf, source: io::Error }`
- `PathEscapesBoundary { attempted_path: PathBuf, jail_boundary: PathBuf }`
- `PathResolutionError { path: PathBuf, source: io::Error }`
- `WindowsShortName { component, original, checked_at }` (windows)

Jail<Marker>
- try_new<P: AsRef<Path>>(jail_path: P) -> Result<Self>
- try_new_create<P: AsRef<Path>>(root: P) -> Result<Self>
- systempath_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>>
- path(&self) -> &Path

JailedPath<Marker>
- unjail(self) -> PathBuf  // consumes — escape hatch (avoid)
- virtualize(self) -> VirtualPath<Marker>  // upgrade to virtual view (UI ops)
- systempath_to_string_lossy(&self) -> Cow<'_, str>
- systempath_to_str(&self) -> Option<&str>
- systempath_as_os_str(&self) -> &OsStr
- display(&self) -> std::path::Display<'_>
- systempath_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>>
- systempath_parent(&self) -> Result<Option<Self>>
- systempath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- systempath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- systempath_file_name(&self) -> Option<&OsStr>
- systempath_file_stem(&self) -> Option<&OsStr>
- systempath_extension(&self) -> Option<&OsStr>
- systempath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool
- systempath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool
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
- virtualpath_join<P: AsRef<Path>>(&self, candidate_path: P) -> Result<VirtualPath<Marker>>
- path(&self) -> &Path

VirtualPath<Marker>
- unvirtual(self) -> JailedPath<Marker>  // downgrade to system view (access systempath_* operations)
- virtualpath_to_string_lossy(&self) -> Cow<'_, str>
- systempath_to_string_lossy(&self) -> Cow<'_, str>
- systempath_to_str(&self) -> Option<&str>
- systempath_as_os_str(&self) -> &OsStr
- virtualpath_join<P: AsRef<Path>>(&self, path: P) -> Result<Self>
- virtualpath_parent(&self) -> Result<Option<Self>>
- virtualpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- virtualpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- virtualpath_file_name(&self) -> Option<&OsStr>
- virtualpath_file_stem(&self) -> Option<&OsStr>
- virtualpath_extension(&self) -> Option<&OsStr>
- virtualpath_starts_with<P: AsRef<Path>>(&self, p: P) -> bool
- virtualpath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool
- display(&self) -> VirtualPathDisplay<'_, Marker>
- exists / is_file / is_dir / metadata / read_to_string / read_bytes / write_bytes / write_string / create_dir / create_dir_all / create_parent_dir / create_parent_dir_all / remove_file / remove_dir / remove_dir_all (delegates to `JailedPath`; parents derived via virtual semantics)

Short usage rules (1-line each)
- For user input: use `VirtualRoot::virtualpath_join(...)` -> `VirtualPath`.
- For I/O: use either `VirtualPath` or `JailedPath` (both support I/O). Call `.unvirtual()` only when you need a `JailedPath` explicitly.
- Do not bypass: never call std fs ops on raw `Path`/`PathBuf` built from untrusted input.
- Marker types prevent mixing distinct jails at compile time: use when you have multiple storage areas.
- Prefer interop by borrowing: for `AsRef<Path>` params in external APIs, pass
  `jailed_path.systempath_as_os_str()` rather than leaking a `Path`/`PathBuf`.
- Avoid std `Path::join`/`Path::parent` on leaked paths — they do not apply virtual-root
  clamping or jail checks. Use `systempath_join` / `virtualpath_parent` instead.
 - Do not convert `JailedPath` -> `VirtualPath` just to print; for UI flows start with `VirtualRoot::virtualpath_join(..)` and keep a `VirtualPath`.
 - `*_to_string_lossy()` returns `Cow<'_, str>`; call `.into_owned()` only when an owned `String` is required.

Parent directory helpers (semantics)
- create_parent_dir: non-recursive; creates only the immediate parent; errors if grandparents are missing; Ok(()) at jail/virtual root.
- create_parent_dir_all: recursive; creates the full chain up to the immediate parent; Ok(()) at jail/virtual root.
- VirtualPath parent helpers act in the virtual dimension (use `virtualpath_parent()`), then perform I/O on the underlying jailed system path.
 
Naming rationale (quick scan aid)
- We name methods by their dimension so intent is obvious at a glance.
- std `Path::join(..)` or `p.join(..)`: unsafe join (can escape); avoid on untrusted inputs.
- `JailedPath::systempath_join(..)`: safe, validated system-path join.
- `VirtualPath::virtualpath_join(..)`: safe, clamped virtual-path join.
- This applies to other operations too: `*_parent`, `*_with_file_name`, `*_with_extension`, `*_starts_with`, `*_ends_with`, etc.
The explicit names make intent obvious even when types aren’t visible.
 - For directory creation, `create_` = non-recursive, `*_all` = recursive (matches std `std::fs` semantics). Parent helpers mirror this.
 - Switching views: typically stay within one dimension (virtual or system). For edge cases, upgrade with `.virtualize()` or downgrade with `.unvirtual()` to access the other dimension’s operations.

**Critical: Absolute Path Join Behavior**
- `std::path::Path::join("/absolute")`: **DANGEROUS** — always completely replaces the base path with the absolute path, enabling directory traversal attacks.
- `JailedPath::systempath_join("/absolute")`: **SECURE** — validates that the result (if absolute) stays within the jail boundary. Returns error if it would escape.
- `VirtualPath::virtualpath_join("/absolute")`: **SECURE** — treats absolute paths as relative to the virtual root, effectively clamping them. `"/etc/passwd"` becomes `"/"`.

This difference makes `std::path::Path::join` the #1 source of path traversal vulnerabilities, while our types make such attacks impossible.

Display/Debug
- `Display` for `VirtualPath` shows a rooted virtual path (e.g., "/a/b.txt").
- `Debug` for `VirtualPath` is developer-facing and verbose: shows system path, virtual view, jail root, and marker type (no trait bounds required).
- `Debug` for `Jail` shows the jail root and marker type; `Display` is the real system path via `.path().display()`.
- `Debug` for `VirtualRoot` shows the root (jail) and marker type; `Display` shows the real root path.

## Pitfalls (And How To Avoid)
- Do not expose raw `Path`/`PathBuf` from `JailedPath`/`VirtualPath`; prefer `systempath_as_os_str()`.
- Use jail-aware joins/parents; never call std `Path::join` on a leaked path.
- Virtual strings are rooted. Use `Display` or `virtualpath_to_string_lossy()` for UI/logging.
- Use `Jail::try_new_create(..)` when the jail directory might not exist.
- Symlinks/junctions to outside: paths that traverse a symlink or junction inside the jail to a location outside the jail are rejected at validation time with `JailedPathError::PathEscapesBoundary`.

Common anti-patterns (LLM quick check)
- Passing strings to `AsRef<Path>` APIs (e.g., `*_to_string_lossy().as_ref()`): use `systempath_as_os_str()`.
- Converting `JailedPath` -> `VirtualPath` only to print: start with a `VirtualPath` for UI or print the `JailedPath` directly for system logs.
- Using `Path::join`/`Path::parent` on leaked paths: use `systempath_*` / `virtualpath_*` ops.
- Forcing ownership: avoid `.into_owned()` on `Cow` unless an owned `String` is required.
- Bare `{}` in format strings: prefer captured identifiers like `"{path}"` (bind a short local if needed).

Where to read the code
- `src/lib.rs`, `src/validator/jail.rs`, `src/validator/virtual_root.rs`, `src/path/jailed_path.rs`, `src/path/virtual_path.rs`, `src/error/mod.rs`

## Integrations (At a Glance)
- Serde (feature `serde`): `JailedPath`/`VirtualPath` implement `Serialize`. For deserialization, read `String` and validate via `Jail::systempath_join(..)` or `VirtualRoot::virtualpath_join(..)`. For single values with context, use `serde_ext::WithJail(&jail)` / `serde_ext::WithVirtualRoot(&vroot)` on a serde Deserializer. See `serde_ext` docs.
- Axum: Put `VirtualRoot<Marker>` in state; validate `Path<String>` to `VirtualPath` per request (custom extractor optional). Handlers take `&VirtualPath<_>`/`&JailedPath<_>` for I/O. See `examples/web/axum_static_server.rs`.
- app-path: Use `app_path::app_path!("config", env = "APP_CONFIG_DIR")` to discover a config directory; jail it and operate through `JailedPath`. See `examples/config/app_path_config.rs`.


