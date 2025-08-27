# jailed-path — API Reference (concise)

Provides safe, validated filesystem paths inside a confined directory (jail).

Start here: [Quick Recipes](#quick-recipes) · [Pitfalls](#pitfalls-and-how-to-avoid)

Top-level exports

| Symbol                |   Kind | Purpose                                                |
| --------------------- | -----: | ------------------------------------------------------ |
| `JailedPathError`     |   enum | Validation and resolution errors.                      |
| `Jail<Marker>`        | struct | Validator that produces `JailedPath`.                  |
| `JailedPath<Marker>`  | struct | System-facing validated path for I/O.                  |
| `VirtualRoot<Marker>` | struct | User-facing entry point that clamps/trusts user paths. |
| `VirtualPath<Marker>` | struct | User-facing path (display/manipulation).               |
| `Result<T>`           |  alias | `Result<T, JailedPathError>`                           |

## Quick Recipes
- Create jail (create dir if missing) and validate: `let jail = Jail::try_new_create("./safe")?; let jp = jail.try_path("a/b.txt")?;`
- Read/write file (system-facing): `let bytes = jp.read_bytes()?; jp.write_string("ok")?;`
- Virtual user path: `let vroot = VirtualRoot::try_new("./safe")?; let vp = vroot.try_path_virtual("a/b.txt")?; println!("{}", vp); // "/a/b.txt"`
- Convert Virtual -> System for I/O: `let jp = vp.unvirtual();`
- AsRef<Path> interop (no allocation): `external_api(jp.systempath_as_os_str());`

JailedPathError (variants)
- `InvalidJail { jail: PathBuf, source: io::Error }`
- `PathEscapesBoundary { attempted_path: PathBuf, jail_boundary: PathBuf }`
- `PathResolutionError { path: PathBuf, source: io::Error }`
- `WindowsShortName { component, original, checked_at }` (windows)

Jail<Marker>
- try_new<P: AsRef<Path>>(jail_path: P) -> Result<Self>
- try_new_create<P: AsRef<Path>>(root: P) -> Result<Self>
- try_path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>>
- path(&self) -> &Path

JailedPath<Marker>
- unjail(self) -> PathBuf  // consumes — escape hatch (avoid)
- virtualize(self) -> VirtualPath<Marker>
- systempath_to_string(&self) -> String
- systempath_to_str(&self) -> Option<&str>
- systempath_as_os_str(&self) -> &OsStr
- display(&self) -> std::path::Display<'_>
- join_systempath<P: AsRef<Path>>(&self, path: P) -> Result<Self>
- systempath_parent(&self) -> Result<Option<Self>>
- systempath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- systempath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- systempath_file_name(&self) -> Option<&OsStr>
- systempath_file_stem(&self) -> Option<&OsStr>
- systempath_extension(&self) -> Option<&OsStr>
- starts_with_systempath<P: AsRef<Path>>(&self, p: P) -> bool
- systempath_ends_with<P: AsRef<Path>>(&self, p: P) -> bool
- exists(&self) -> bool
- is_file(&self) -> bool
- is_dir(&self) -> bool
- metadata(&self) -> io::Result<std::fs::Metadata>
- read_to_string(&self) -> io::Result<String>
- read_bytes(&self) -> io::Result<Vec<u8>>
- write_bytes(&self, data: &[u8]) -> io::Result<()>
- write_string(&self, data: &str) -> io::Result<()>
- create_dir_all(&self) -> io::Result<()>
- remove_file(&self) -> io::Result<()>
- remove_dir(&self) -> io::Result<()>
- remove_dir_all(&self) -> io::Result<()>

VirtualRoot<Marker>
- try_new<P: AsRef<Path>>(root_path: P) -> Result<Self>
- try_new_create<P: AsRef<Path>>(root_path: P) -> Result<Self>
- try_path_virtual<P: AsRef<Path>>(&self, candidate_path: P) -> Result<VirtualPath<Marker>>
- path(&self) -> &Path

VirtualPath<Marker>
- unvirtual(self) -> JailedPath<Marker>
- virtualpath_to_string(&self) -> String
- systempath_to_string(&self) -> String
- systempath_to_str(&self) -> Option<&str>
- systempath_as_os_str(&self) -> &OsStr
- join_virtualpath<P: AsRef<Path>>(&self, path: P) -> Result<Self>
- virtualpath_parent(&self) -> Result<Option<Self>>
- virtualpath_with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- virtualpath_with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- virtualpath_file_name(&self) -> Option<&OsStr>
- virtualpath_file_stem(&self) -> Option<&OsStr>
- virtualpath_extension(&self) -> Option<&OsStr>
- starts_with_virtualpath<P: AsRef<Path>>(&self, p: P) -> bool
- ends_with_virtualpath<P: AsRef<Path>>(&self, p: P) -> bool
- display(&self) -> VirtualPathDisplay<'_, Marker>
- exists / is_file / is_dir / metadata / read_to_string / read_bytes / write_bytes / write_string / create_dir_all / remove_file / remove_dir / remove_dir_all (delegates to `JailedPath`)

Short usage rules (1-line each)
- For user input: use `VirtualRoot::try_path_virtual(...)` -> `VirtualPath`.
- For I/O: call `.unvirtual()` -> `JailedPath` and use I/O methods.
- Do not bypass: never call std fs ops on raw `Path`/`PathBuf` built from untrusted input.
- Marker types prevent mixing distinct jails at compile time: use when you have multiple storage areas.
- Prefer interop by borrowing: for `AsRef<Path>` params in external APIs, pass
  `jailed_path.systempath_as_os_str()` rather than leaking a `Path`/`PathBuf`.
- Avoid std `Path::join`/`Path::parent` on leaked paths — they do not apply virtual-root
  clamping or jail checks. Use `join_systempath` / `virtualpath_parent` instead.

## Pitfalls (And How To Avoid)
- Do not expose raw `Path`/`PathBuf` from `JailedPath`/`VirtualPath`; prefer `systempath_as_os_str()`.
- Use jail-aware joins/parents; never call std `Path::join` on a leaked path.
- Virtual strings are rooted. Use `Display` or `virtualpath_to_string()` for UI/logging.
- Use `Jail::try_new_create(..)` when the jail directory might not exist.

Where to read the code
- `src/lib.rs`, `src/validator/jail.rs`, `src/validator/virtual_root.rs`, `src/path/jailed_path.rs`, `src/path/virtual_path.rs`, `src/error/mod.rs`

