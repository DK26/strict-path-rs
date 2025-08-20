# Jailed Path Roadmap (Compressed)

> **Security-first path validation with type-safe jails and safe symlinks**

## 🎯 Real-World Use Cases

**Cloud Storage**: User file uploads within storage quotas
**Web Hosting**: Website assets within site boundaries  
**Archive Extraction**: Safe ZIP/TAR extraction (blocks `../../../etc/passwd`)
**Enterprise Files**: Department-specific access with type safety
**Game Mods**: User content within mod directories
**Container Apps**: File access within container boundaries
**Backup Tools**: Multiple backup destinations with type isolation
**Development IDEs**: Project files within workspace boundaries
**Mobile Apps**: App-specific document sandboxing
**Healthcare**: HIPAA-compliant patient data handling

**Universal Benefits**: Compile-time safety, zero directory traversal, audit-friendly virtual paths, cross-platform, future-proof API.

---

## ️ Core Security Model

### **CRITICAL: Types and Responsibilities**

#### `Jail<Marker>` — System-facing validator
- Purpose: Owns the real filesystem root; validates full/absolute paths
- API: `try_new`, `try_new_create`, `try_path` (system paths), `path()` access to real root
- Display: N/A
- Security: Safe to expose `path()`; the boundary is enforced in `try_path`

#### `JailedPath<Marker>` — System path within jail
- Purpose: Represents a path that’s guaranteed to be inside the jail
- API: Real-only operations and I/O; no virtual manipulation
- Display: Shows REAL, system-facing path (for logs/interop)
- Security: ❌ No `AsRef<Path>`/`Deref<Target=Path>`; explicit methods only

#### `VirtualRoot<Marker>` — User-facing virtual root
- Purpose: Entry for user/virtual paths; composes virtual paths safely
- API: `try_new`, `try_new_create`, `try_path_virtual`
- Produces: `VirtualPath<Marker>`

#### `VirtualPath<Marker>` — User-facing path within virtual namespace
 - Purpose: Virtual presentation of a jailed path
 - API: Virtual string/joins/parents, plus `unvirtual()` to get a `JailedPath`
 - Display: Shows VIRTUAL, jail-relative path (forward-slash style)

## 🎯 Design Principles

1. No `&Path` leaks from `JailedPath`
2. `Jail` ergonomics: safe `path()` exposure
3. Virtual display lives on `VirtualPath`; `JailedPath` is system-facing
4. Explicit suffixes (Option A):
   - `VirtualPath`: methods end with `_virtual`
   - `JailedPath`: methods end with `_real`
5. One obvious way; no hidden conversions; use `unvirtual()` explicitly
6. Keep virtual manipulation off `JailedPath`

Note: Public APIs avoid returning `&Path` or `PathBuf` directly from `JailedPath`. Instead use `realpath_` prefixed accessors (e.g., `realpath_to_string()`, `realpath_as_os_str()`) and explicit `unjail()` when ownership is required. `VirtualPath` exposes `virtualpath_` prefixed accessors for its string/OS conversions — historical `*_virtual` names were removed to keep the API surface consistent.

Important: `StatedPath` is an internal type-state implementation detail. It must never be exposed in public APIs, docs, or examples. Keep `StatedPath` usage strictly inside the validator module.

### Type evolution and conversion names (explicit)

We document the canonical type flow and the exact function names to use for conversions. These rules are enforced by design: no `From`/`Into` between `JailedPath` and `VirtualPath` are provided.

Paths -> (jailed) -> JailedPath -> (virtualize()) -> VirtualPath

- `Jail::try_path(...) -> JailedPath` — validate a raw/system path into a jailed system-facing path.
- `JailedPath::virtualize() -> VirtualPath` — explicit conversion from system-facing to user-facing.
- `VirtualPath::unvirtual() -> JailedPath` — explicit conversion from user-facing back to system-facing.
- `JailedPath::unjail() -> PathBuf` — explicit escape hatch that yields ownership of the underlying PathBuf (unsafe to use without care).

Why: Making these conversion points explicit prevents accidental downgrades or upgrades and makes audit trails in security reviews trivial to follow.

## 🏷️ Method Naming Rules

### For `JailedPath<Marker>` (system-facing)

Rule A: Methods that surface the path must use the `realpath_` prefix for real/system-facing accessors
- Examples: `realpath_to_string()`, `realpath_to_str()`, `realpath_as_os_str()`, `starts_with_real()`

Rule B: No virtual manipulation lives here; omit any `_virtual` API on `JailedPath`

### For `VirtualPath<Marker>` (user-facing)

Rule C: Methods that present or manipulate virtual paths are documented with the `virtualpath_` prefix in user docs. Examples of the preferred aliases: `virtualpath_to_string()`, `virtualpath_to_str()`, `join_virtual()`, `parent_virtual()`, `with_extension_virtual()` (historical `*_virtual` method names remain available as aliases in the implementation).

Rule D: `VirtualPath` provides `unvirtual()` to transition to system operations

## 📋 API Surface (Final)

### `Jail<Marker>` (system-facing)
```rust
impl<Marker> Jail<Marker> {
    pub fn try_new<P: AsRef<Path>>(root: P) -> Result<Self>
    pub fn try_new_create<P: AsRef<Path>>(root: P) -> Result<Self>
  pub fn try_path<P: AsRef<Path>>(&self, path: P) -> Result<JailedPath<Marker>>
    
    // Path access (simple and readable)
    pub fn path(&self) -> &Path
}
```

### Path Validation Methods

Two distinct entry points for different use cases:

#### `Jail::try_path()` — Boundary-checked full paths (system)
- Purpose: Validate absolute/full filesystem paths against jail boundary
- Use Cases: Config files with absolute paths, database-stored paths, system integration
- Behavior: Accepts full paths if within jail boundary, rejects if outside
```rust
let jail = Jail::try_new("/app/uploads")?;
let config_path = jail.try_path("/app/uploads/config/settings.ini")?;  // ✅ Within boundary
let system_path = jail.try_path("/etc/passwd")?;                       // ❌ Outside boundary
```

#### `VirtualRoot::try_path_virtual()` — Clamped virtual paths (user input)
- Purpose: Treat all input as jail-relative/virtual paths
- Use Cases: User input, relative navigation, untrusted path strings
- Behavior: Always clamps `..` components to jail root, never escapes
```rust
let vroot = VirtualRoot::try_new("/app/uploads")?;
let user_file = vroot.try_path_virtual("documents/report.pdf")?;  // Relative to jail
let attack = vroot.try_path_virtual("../../../etc/passwd")?;      // Clamped to jail root
```

### `VirtualRoot<Marker>` (user-facing)
```rust
impl<Marker> VirtualRoot<Marker> {
  pub fn try_new<P: AsRef<Path>>(root: P) -> Result<Self>
  pub fn try_new_create<P: AsRef<Path>>(root: P) -> Result<Self>
  pub fn try_path_virtual<P: AsRef<Path>>(&self, path: P) -> Result<VirtualPath<Marker>>
}

Note: `VirtualRoot` can produce `VirtualPath` values directly from user input; you do not need to construct a `JailedPath` first. This keeps user-facing flows simple and focused on virtual semantics.

Example:
```rust
let vroot = VirtualRoot::<M>::try_new("/app/storage")?;
let vp = vroot.try_path_virtual("users/alice/report.pdf")?; // direct
```
```

### `VirtualPath<Marker>` (user-facing)
```rust
impl<Marker> VirtualPath<Marker> {
  // String conversion methods - virtual only
  // Preferred documented aliases: `virtualpath_to_string()` / `virtualpath_to_str()`
  pub fn virtualpath_to_string(&self) -> String      // "/user/file.txt" (virtual)
  pub fn virtualpath_to_str(&self) -> Option<&str>   // Virtual path as &str if valid UTF-8

  // Path manipulation (virtual)
  pub fn join_virtual<P: AsRef<Path>>(&self, path: P) -> Option<Self>
  pub fn parent_virtual(&self) -> Option<Self>
  pub fn with_file_name_virtual<S: AsRef<OsStr>>(&self, file_name: S) -> Option<Self>
  pub fn with_extension_virtual<S: AsRef<OsStr>>(&self, extension: S) -> Option<Self>

  // Transition to system-facing for I/O
  pub fn unvirtual(self) -> Result<JailedPath<Marker>>
}
```

### `JailedPath<Marker>` (system-facing) 
```rust
impl<Marker> JailedPath<Marker> {
  // String conversion methods - real only
  pub fn realpath_to_string(&self) -> String         // "/app/storage/user/file.txt" (real path)
  pub fn realpath_to_str(&self) -> Option<&str>      // Real path as &str if valid UTF-8
  pub fn realpath_as_os_str(&self) -> &OsStr         // Real OsStr
  pub fn unjail(self) -> PathBuf                 // Explicit escape hatch
    
    // File operations (built-in)
    pub fn exists(&self) -> bool
    pub fn is_file(&self) -> bool
    pub fn is_dir(&self) -> bool
    pub fn metadata(&self) -> io::Result<Metadata>
    pub fn read_to_string(&self) -> Result<String>
    pub fn read_bytes(&self) -> Result<Vec<u8>>
    pub fn write_string(&self, content: &str) -> Result<()>
    pub fn write_bytes(&self, content: &[u8]) -> Result<()>
    pub fn create_dir_all(&self) -> Result<()>
    pub fn remove_file(&self) -> Result<()>
    pub fn remove_dir(&self) -> Result<()>
    pub fn remove_dir_all(&self) -> Result<()>
    
  // Real boundary helpers
  pub fn starts_with_real<P: AsRef<Path>>(&self, base: P) -> bool
  pub fn ends_with_real<P: AsRef<Path>>(&self, tail: P) -> bool
}

// ✅ TRAIT IMPLEMENTATIONS
impl<Marker> Display for VirtualPath<Marker> { /* shows virtual path */ }
impl<Marker> Display for JailedPath<Marker> { /* shows real path */ }
impl<Marker> Debug for JailedPath<Marker> { /* real path for debugging */ }

// ❌ NOT IMPLEMENTED for security:
// - ~~AsRef<Path> / Borrow<Path>~~ - Removed in favor of explicit path() method
// - Deref<Target = Path> 
```

## 🚨 Security Features

### Jail Directory Requirements
- **MUST EXIST**: `try_new()` requires jail directory to exist (prevents typos)
- **EXPLICIT CREATION**: Use `try_new_create()` for directory creation when needed
- **CONTAINER SAFETY**: Prevents accidental directory creation in containers/production

### Windows 8.3 Short Names
- **Risk**: `PROGRA~1` ambiguity can resolve to different directories
- **Protection**: Reject potential 8.3 patterns to prevent path confusion
- **Implementation**: Precise pattern matching from `soft-canonicalize`

### Symlink Safety
- **Protection**: `soft_canonicalize` resolves symlinks safely
- **Validation**: All paths resolved before jail boundary checking
- **Cross-platform**: Handles Windows junctions, Unix symlinks

## 🎯 Immediate Priorities (Pre-v0.1.0)

### CRITICAL (Blocking v0.1.0):

Status (Aug 20, 2025): Initial implementation landed in commit 51d46c9. The core Virtual API is present; remaining work items are noted below.

1. ✅ IMPLEMENTED: `VirtualRoot` and `VirtualPath` — user-facing types with `_virtual` APIs (commit 51d46c9)
2. ✅ MIGRATED: Display rules — `VirtualPath` displays virtual; `JailedPath` displays real
3. ✅ API CLEANUP (in-progress): `JailedPath` virtual methods removed from the public surface; internal `StatedPath` state types and helpers were simplified/commented out to centralize the validation flow
4. ✅ VALIDATION SPLIT: `Jail::try_path` delegates to the central validator; `VirtualRoot::try_path_virtual` implemented as the user-facing entrypoint
5. � REFINE: Windows 8.3 detection — precise UTF-16 state machine documented in `ROADMAP.md`; needs verification and test coverage
6. ✅ REMOVED: `try_path_normalized()` — removed from public API

Remaining / follow-ups:
- Add tests for Windows 8.3 short-name detection and edge cases
- Clean up commented-out `StatedPath` code after stabilization
- Run a full test suite and CI verification for the refactor

### HIGH PRIORITY:
7. **🟡 UPDATE: Documentation** — Document the split (Virtual vs System), migration notes
8. **🟡 WINDOWS: Platform-specific documentation** — Document 8.3 behavior and Windows security considerations

## 📚 Usage Patterns

### Basic Usage (Virtual → System)
```rust
use jailed_path::{Jail, VirtualRoot};

let jail = Jail::try_new("/app/uploads")?;
let vroot = VirtualRoot::try_new("/app/uploads")?;

// Virtual/relative paths (user input, relative navigation)
let vpath = vroot.try_path_virtual("user/image.jpg")?;  // Always relative to jail
let attack = vroot.try_path_virtual("../../../etc/passwd")?;  // Clamped to jail root

// Full/absolute paths (config files, database entries)  
let config_file = jail.try_path("/app/uploads/config.json")?;  // OK - within boundary
// let system_file = jail.try_path("/etc/passwd")?;  // Error - outside boundary

// Transition to system-facing for I/O
let jailed = vpath.unvirtual()?;

// Display behavior
println!("Virtual (user): {}", vroot.try_path_virtual("user/image.jpg")?);  // "/user/image.jpg"
println!("System (real): {}", jailed);                                      // "/app/uploads/user/image.jpg"
```

### Testing with Ergonomic Path Access
```rust
let jail = Jail::try_new("/app/uploads")?;
let vroot = VirtualRoot::try_new("/app/uploads")?;
let vfile = vroot.try_path_virtual("user/image.jpg")?;
let file = vfile.unvirtual()?;

  // ✅ Clean test assertions
  assert!(file.starts_with_real(jail.path()));  // Explicit path access
  // Preferred form uses the `virtualpath_` alias; documentation now prefers `virtualpath_to_string()`.
  assert_eq!(vroot.try_path_virtual("user").unwrap().virtualpath_to_string(), "/user");
```

### Type Safety with Markers
```rust
struct PublicAsset;
struct UploadedFile;

let public_jail: Jail<PublicAsset> = Jail::try_new("/app/public")?;
let upload_jail: Jail<UploadedFile> = Jail::try_new("/app/uploads")?;

// Create matching VirtualRoots for user-facing operations and convert when needed
let public_vroot: VirtualRoot<PublicAsset> = VirtualRoot::try_new("/app/public")?;
let upload_vroot: VirtualRoot<UploadedFile> = VirtualRoot::try_new("/app/uploads")?;

let public_vpath = public_vroot.try_path_virtual("index.html")?;
let upload_vpath = upload_vroot.try_path_virtual("image.jpg")?;

// Transition to system-facing JailedPath when performing I/O or integration
let public_file: JailedPath<PublicAsset> = public_vpath.unvirtual()?;
let upload_file: JailedPath<UploadedFile> = upload_vpath.unvirtual()?;

// Compile-time type safety prevents mixing contexts
```

## 🔮 Future Roadmap

### v0.2.0 - Ecosystem Integration
- **Serde support**: Serialize as virtual paths for JSON APIs
- **Web framework examples**: Axum, Actix Web integration patterns
- **Error refinement**: More specific error types for different failure modes

---

## 🎯 Key Takeaways for LLMs

1. **Security Boundary**: Creating `JailedPath` via validation, not accessing jail root
2. **Safe Methods**: `Jail` can have `path()` method, `JailedPath` cannot expose `&Path`
3. **Virtual/System Split**: `Jail::try_path()` for full paths; `VirtualRoot::try_path_virtual()` for user input
4. **Display Rules**: `VirtualPath` displays virtual; `JailedPath` displays real
5. **Built-in I/O**: Direct file operations without trait conversion needed
6. **Type Safety**: Marker types prevent cross-context path mixing
7. **Explicit Escape**: Use `unjail()` when raw path access truly needed

**Remember**: `Virtual*` is user-facing (virtual), `Jail*` is system-facing (real).