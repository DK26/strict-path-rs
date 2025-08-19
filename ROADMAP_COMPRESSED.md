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
- API: Virtual string/joins/parents, plus `into_jailed(&Jail)` to get a `JailedPath`
- Display: Shows VIRTUAL, jail-relative path (forward-slash style)

## 🎯 Design Principles

1. No `&Path` leaks from `JailedPath`
2. `Jail` ergonomics: safe `path()` exposure
3. Virtual display lives on `VirtualPath`; `JailedPath` is system-facing
4. Explicit suffixes (Option A):
   - `VirtualPath`: methods end with `_virtual`
   - `JailedPath`: methods end with `_real`
5. One obvious way; no hidden conversions; use `into_jailed(&Jail)` explicitly
6. Keep virtual manipulation off `JailedPath`

## 🏷️ Method Naming Rules

### For `JailedPath<Marker>` (system-facing)

Rule A: Methods that surface the path must end with `_real()`
- Examples: `to_string_real()`, `to_str_real()`, `as_os_str_real()`, `starts_with_real()`

Rule B: No virtual manipulation lives here; omit any `_virtual` API on `JailedPath`

### For `VirtualPath<Marker>` (user-facing)

Rule C: Methods that present or manipulate virtual paths end with `_virtual()`
- Examples: `to_string_virtual()`, `to_str_virtual()`, `join_virtual()`, `parent_virtual()`, `with_extension_virtual()`

Rule D: `VirtualPath` provides `into_jailed(&Jail)` to transition to system operations

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
```

### `VirtualPath<Marker>` (user-facing)
```rust
impl<Marker> VirtualPath<Marker> {
  // String conversion methods - virtual only
  pub fn to_string_virtual(&self) -> String      // "/user/file.txt" (virtual)
  pub fn to_str_virtual(&self) -> Option<&str>   // Virtual path as &str if valid UTF-8

  // Path manipulation (virtual)
  pub fn join_virtual<P: AsRef<Path>>(&self, path: P) -> Option<Self>
  pub fn parent_virtual(&self) -> Option<Self>
  pub fn with_file_name_virtual<S: AsRef<OsStr>>(&self, file_name: S) -> Option<Self>
  pub fn with_extension_virtual<S: AsRef<OsStr>>(&self, extension: S) -> Option<Self>

  // Transition to system-facing for I/O
  pub fn into_jailed(self, jail: &Jail<Marker>) -> Result<JailedPath<Marker>>
}
```

### `JailedPath<Marker>` (system-facing) 
```rust
impl<Marker> JailedPath<Marker> {
  // String conversion methods - real only
  pub fn to_string_real(&self) -> String         // "/app/storage/user/file.txt" (real path)
  pub fn to_str_real(&self) -> Option<&str>      // Real path as &str if valid UTF-8
  pub fn as_os_str_real(&self) -> &OsStr         // Real OsStr
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
1. **🔴 IMPLEMENT: `VirtualRoot` and `VirtualPath`** — user-facing types with `_virtual` APIs
2. **🔴 MIGRATE: Display rules** — `VirtualPath` displays virtual; `JailedPath` displays real
3. **🔴 API CLEANUP: `JailedPath`** — remove/deprecate `_virtual` methods and virtual manipulation
4. **🔴 VALIDATION SPLIT** — keep `Jail::try_path`; move virtual validation to `VirtualRoot::try_path_virtual`
5. **🔴 REFINE: Windows 8.3 detection** — precise UTF-16 state machine (see ROADMAP.md)
6. **🔴 REMOVE: `try_path_normalized()`** — BREAKING CHANGE, confusing API surface

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
let jailed = vpath.into_jailed(&jail)?;

// Display behavior
println!("Virtual (user): {}", vroot.try_path_virtual("user/image.jpg")?);  // "/user/image.jpg"
println!("System (real): {}", jailed);                                      // "/app/uploads/user/image.jpg"
```

### Testing with Ergonomic Path Access
```rust
let jail = Jail::try_new("/app/uploads")?;
let vroot = VirtualRoot::try_new("/app/uploads")?;
let vfile = vroot.try_path_virtual("user/image.jpg")?;
let file = vfile.into_jailed(&jail)?;

// ✅ Clean test assertions
assert!(file.starts_with_real(jail.path()));  // Explicit path access
assert_eq!(vroot.try_path_virtual("user").unwrap().to_string_virtual(), "/user");
```

### Type Safety with Markers
```rust
struct PublicAsset;
struct UploadedFile;

let public_jail: Jail<PublicAsset> = Jail::try_new("/app/public")?;
let upload_jail: Jail<UploadedFile> = Jail::try_new("/app/uploads")?;

let public_file: JailedPath<PublicAsset> = public_jail.try_path_virtual("index.html")?;
let upload_file: JailedPath<UploadedFile> = upload_jail.try_path_virtual("image.jpg")?;

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