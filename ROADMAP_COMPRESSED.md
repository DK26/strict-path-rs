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

### **CRITICAL: `Jail` vs `JailedPath` Distinction**

#### `Jail<Marker>` - The Validator
- **Purpose**: Factory for creating `JailedPath` instances
- **Security**: ✅ **SAFE** to provide `path()` method
- **Rationale**: 
  - Jail root is not secret information
  - `jail.path().join("/escape")` just gives regular `Path` - no bypass
  - Simple and readable: `jail.path().display()`
  - Security boundary is in `jail.try_path()`, not accessing root

#### `JailedPath<Marker>` - The Security Promise  
- **Purpose**: Path guaranteed within jail boundaries
- **Security**: ❌ **FORBIDDEN** `AsRef<Path>` or `Deref<Target = Path>`
- **Rationale**:
  - Would allow `jailed_path.join("../../../etc/passwd")` attacks
  - Breaks compile-time safety guarantees
  - String-only access preserves security model

## 🎯 Design Principles

1. **NO PATH LEAKS FROM JAILEDPATH**: `JailedPath` never exposes `&Path`
2. **JAIL ERGONOMICS**: `Jail` provides `path()` method safely
3. **VIRTUAL BY DEFAULT**: Display shows jail-relative paths
4. **EXPLICIT SUFFIXES**: Use `_real`/`_virtual` suffixes when both variants exist
5. **CLEAN PATH MANIPULATION**: Standard names (`join()`, `parent()`) when only safe variants exist (do not leak real path)
6. **ONE OBVIOUS WAY**: Single method for each operation
7. **EXPLICIT OVER IMPLICIT**: No hidden conversions

## 🏷️ JailedPath Method Naming Rules

**Critical naming conventions for `JailedPath<Marker>` methods:**

**Rule A**: If a method exposes a real path in any way, it **MUST** end with the suffix `_real()`
- Examples: `to_string_real()`, `to_str_real()`, `as_os_str_real()`

**Rule B**: If a method could represent either a virtual variant or a real variant under the same name, it **MUST** end with a proper suffix: either `_real()` or `_virtual()`
- Examples: `to_string_virtual()` / `to_string_real()`, `to_str_virtual()` / `to_str_real()`

**Rule C**: If a method represents a virtual presentation, but has no (or should never have in the future) a `_real()` version, it is considered "safe" and should **NOT** use any suffix
- Examples: `join()`, `parent()`, `with_extension()` (these only have safe variants)

## 📋 API Surface (Final)

### `Jail<Marker>`
```rust
impl<Marker> Jail<Marker> {
    pub fn try_new<P: AsRef<Path>>(root: P) -> Result<Self>
    pub fn try_new_create<P: AsRef<Path>>(root: P) -> Result<Self>
    pub fn try_path<P: AsRef<Path>>(&self, path: P) -> Result<JailedPath<Marker>>
    
    // Path access (simple and readable)
    pub fn path(&self) -> &Path
}
```

### `JailedPath<Marker>`  
```rust
impl<Marker> JailedPath<Marker> {
    // String conversion methods - explicit suffixes when both variants exist
    pub fn to_string_virtual(&self) -> String      // "/user/file.txt" (virtual)
    pub fn to_string_real(&self) -> String         // "/app/storage/user/file.txt" (real path)
    pub fn to_str_virtual(&self) -> Option<&str>   // Virtual path as &str if valid UTF-8
    pub fn to_str_real(&self) -> Option<&str>      // Real path as &str if valid UTF-8
    pub fn as_os_str_real(&self) -> &OsStr         // Real OsStr
    pub fn as_os_str_virtual(&self) -> OsString    // Virtual OsStr (computed)
    pub fn unjail(self) -> PathBuf                 // Explicit escape hatch
    
    // Safe path manipulation (standard names since only safe variants exist)
    pub fn join<P: AsRef<Path>>(&self, path: P) -> Option<Self>
    pub fn parent(&self) -> Option<Self>
    pub fn with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Option<Self>
    pub fn with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Option<Self>
    
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
    
    // Path components (safe)
    pub fn file_name(&self) -> Option<&OsStr>
    pub fn extension(&self) -> Option<&OsStr>
    pub fn file_stem(&self) -> Option<&OsStr>
}

// ✅ TRAIT IMPLEMENTATIONS
impl<Marker> Display for JailedPath<Marker> {
    // Shows virtual path: "/user/file.txt" (jail-relative)
}

impl<Marker> Debug for JailedPath<Marker> {
    // Shows real path: "/app/storage/user/file.txt" (full filesystem path)
    // ⚠️ Exposes real paths - use only for debugging
}

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
1. **🔴 IMPLEMENT: `path()` method for `Jail`** - Enable explicit path access
2. **🔴 REFINE: Windows 8.3 detection** - Use precise UTF-16 state machine for short name detection (see ROADMAP.md for full implementation)
3. **🔴 REMOVE: `jail() -> &Path` method** - BREAKING CHANGE, replace with explicit `path()` method
4. **🔴 REMOVE: `try_path_normalized()` method** - BREAKING CHANGE, confusing API surface

### HIGH PRIORITY:
5. **🟡 UPDATE: Documentation** - Remove all references to removed methods, add `path()` method examples
6. **🟡 WINDOWS: Platform-specific documentation** - Document 8.3 behavior and Windows security considerations

## 📚 Usage Patterns

### Basic Usage
```rust
use jailed_path::Jail;

let jail = Jail::try_new("/app/uploads")?;
let file = jail.try_path("user/image.jpg")?;

// Display vs Debug behavior
println!("User sees: {}", file);        // Display: "/user/image.jpg" (virtual)
println!("Debug info: {:?}", file);     // Debug: "/app/uploads/user/image.jpg" (real)

// File operations
if file.exists() {
    let content = file.read_to_string()?;
}

// Safe path manipulation  
let backup = file.with_extension("bak").unwrap();
```

### Testing with Ergonomic Path Access
```rust
let jail = Jail::try_new("/app/uploads")?;
let file = jail.try_path("user/image.jpg")?;

// ✅ Clean test assertions
assert!(file.starts_with(jail.path()));  // Explicit path access
assert_eq!(file.parent().unwrap().to_string_virtual(), "/user");  // Explicit suffix
```

### Type Safety with Markers
```rust
struct PublicAsset;
struct UploadedFile;

let public_jail: Jail<PublicAsset> = Jail::try_new("/app/public")?;
let upload_jail: Jail<UploadedFile> = Jail::try_new("/app/uploads")?;

let public_file: JailedPath<PublicAsset> = public_jail.try_path("index.html")?;
let upload_file: JailedPath<UploadedFile> = upload_jail.try_path("image.jpg")?;

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
3. **Virtual Display**: Default display shows user-friendly relative paths
4. **Built-in I/O**: Direct file operations without trait conversion needed
5. **Type Safety**: Marker types prevent cross-context path mixing
6. **Explicit Escape**: Use `unjail()` when raw path access truly needed

**Remember**: `Jail` is a validator (safe to expose), `JailedPath` is a security promise (never expose as `Path`).
