# jailed-path — API Reference (concise)

Provides safe, validated filesystem paths inside a confined directory (jail).

Top-level exports

| Symbol                |   Kind | Purpose                                                |
| --------------------- | -----: | ------------------------------------------------------ |
| `JailedPathError`     |   enum | Validation and resolution errors.                      |
| `Jail<Marker>`        | struct | Validator that produces `JailedPath`.                  |
| `JailedPath<Marker>`  | struct | System-facing validated path for I/O.                  |
| `VirtualRoot<Marker>` | struct | User-facing entry point that clamps/trusts user paths. |
| `VirtualPath<Marker>` | struct | User-facing path (display/manipulation).               |
| `Result<T>`           |  alias | `Result<T, JailedPathError>`                           |

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
- realpath_to_string(&self) -> String
- realpath_to_str(&self) -> Option<&str>
- display(&self) -> std::path::Display<'_>
- join_real<P: AsRef<Path>>(&self, path: P) -> Result<Self>
- parent_real(&self) -> Result<Option<Self>>
- with_file_name_real<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- with_extension_real<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- file_name_real(&self) -> Option<&OsStr>
- file_stem_real(&self) -> Option<&OsStr>
- extension_real(&self) -> Option<&OsStr>
- starts_with_real<P: AsRef<Path>>(&self, p: P) -> bool
- ends_with_real<P: AsRef<Path>>(&self, p: P) -> bool
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
- virtualpath_to_str(&self) -> Option<&str>
- virtualpath_as_os_str(&self) -> &OsStr
- realpath_to_string(&self) -> String
- realpath_to_str(&self) -> Option<&str>
- realpath_as_os_str(&self) -> &OsStr
- join_virtual<P: AsRef<Path>>(&self, path: P) -> Result<Self>
- parent_virtual(&self) -> Result<Option<Self>>
- with_file_name_virtual<S: AsRef<OsStr>>(&self, file_name: S) -> Result<Self>
- with_extension_virtual<S: AsRef<OsStr>>(&self, extension: S) -> Result<Self>
- file_name_virtual(&self) -> Option<&OsStr>
- file_stem_virtual(&self) -> Option<&OsStr>
- extension_virtual(&self) -> Option<&OsStr>
- starts_with_virtual<P: AsRef<Path>>(&self, p: P) -> bool
- ends_with_virtual<P: AsRef<Path>>(&self, p: P) -> bool
- display(&self) -> VirtualPathDisplay<'_, Marker>
- exists / is_file / is_dir / metadata / read_to_string / read_bytes / write_bytes / write_string / create_dir_all / remove_file / remove_dir / remove_dir_all (delegates to `JailedPath`)

Short usage rules (1-line each)
- For user input: use `VirtualRoot::try_path_virtual(...)` -> `VirtualPath`.
- For I/O: call `.unvirtual()` -> `JailedPath` and use I/O methods.
- Do not bypass: never call std fs ops on raw `Path`/`PathBuf` built from untrusted input.
- Marker types prevent mixing distinct jails at compile time: use when you have multiple storage areas.

Where to read the code
- `src/lib.rs`, `src/validator/jail.rs`, `src/validator/virtual_root.rs`, `src/path/jailed_path.rs`, `src/path/virtual_path.rs`, `src/error/mod.rs`

