# Jailed Path Roadmap

> **Advanced path validation: symlink-safe, multi-jail, compile-time guaranteed**  
> *Type-State Police™ - Keeping your paths in line since 2025*

This roadmap outlines the planned evolution of the `jailed-path` crate based on ecosystem research, user needs analysis, and security-first principles.

## 🎯 Real-World Use Cases

The `jailed-path` crate addresses critical security needs across multiple domains where path validation is essential:

### 🌐 **Cloud Storage Services**
**Challenge:** Users upload files that must stay within their allocated storage boundaries
```rust
// Each user gets their own secure storage jail
let user_jail = Jail::<UserStorage>::try_new(format!("/cloud/users/{}", user_id))?;
let uploaded_file = user_jail.try_path(&upload_request.filename)?;

// Safe file operations - guaranteed within user's storage
uploaded_file.write_bytes(&file_data)?;
log::info!("Saved file: {}", uploaded_file); // Shows: "/documents/photo.jpg" (virtual)
```

### 🌍 **Web Hosting Platforms**
**Challenge:** Website files must remain within designated site directories
```rust
// Each website gets isolated file access
let site_jail = Jail::<WebsiteAssets>::try_new(format!("/sites/{}/public", site_id))?;
let asset_path = site_jail.try_path(&request_path)?;

// Serve files safely - no directory traversal possible
if asset_path.is_file() {
    return serve_file(asset_path.read_bytes()?);
}
```

### 📦 **Archive Extraction Tools**
**Challenge:** ZIP/TAR files can contain malicious paths like `../../../etc/passwd`
```rust
// Extract to safe directory only
let extract_jail = Jail::<ExtractedFiles>::try_new("/tmp/safe_extract")?;

for entry in archive.entries() {
    // Automatically rejects directory traversal attempts
    if let Ok(safe_path) = extract_jail.try_path(&entry.path()) {
        safe_path.write_bytes(&entry.data())?;
        println!("Extracted: {}", safe_path); // Virtual path for user
    } else {
        warn!("Rejected malicious path: {}", entry.path());
    }
}
```

### 🏢 **Enterprise File Management**
**Challenge:** Users need access to department files but not sensitive areas
```rust
// Department-specific file access
let hr_jail = Jail::<HRDepartment>::try_new("/company/departments/hr")?;
let finance_jail = Jail::<FinanceDepartment>::try_new("/company/departments/finance")?;

// Type safety prevents cross-department access
let hr_document: JailedPath<HRDepartment> = hr_jail.try_path("employee_handbook.pdf")?;
// finance_jail.try_path() returns JailedPath<FinanceDepartment> - incompatible types!
```

### 🎮 **Game Mod/Plugin Systems**
**Challenge:** User-created content must not access system files
```rust
// Mods can only access their designated directories
let mod_jail = Jail::<ModAssets>::try_new(format!("/game/mods/{}", mod_name))?;
let texture_path = mod_jail.try_path(&mod_request.asset_path)?;

// Safe asset loading - guaranteed within mod boundaries
let texture_data = texture_path.read_bytes()?;
```

### 🐳 **Container/Sandbox Environments**
**Challenge:** Applications need file access within container boundaries
```rust
// Container-aware file operations
let container_jail = Jail::<ContainerFS>::try_new("/app/workspace")?;
let config_file = container_jail.try_path("config/app.toml")?;

// Works with container orchestration
config_file.write_string(&updated_config)?;
```

### 💾 **Backup and Sync Tools**
**Challenge:** Backup paths must stay within designated backup locations
```rust
// Multiple backup destinations with type safety
let local_backup = Jail::<LocalBackup>::try_new("/backups/local")?;
let cloud_backup = Jail::<CloudBackup>::try_new("/backups/cloud")?;

// Type system prevents mixing backup contexts
let file_backup: JailedPath<LocalBackup> = local_backup.try_path(&relative_path)?;
```

### 🔧 **Development Tools & IDEs**
**Challenge:** Project files must stay within project boundaries
```rust
// Project-scoped file operations
let project_jail = Jail::<ProjectFiles>::try_new(&workspace_root)?;
let source_file = project_jail.try_path(&relative_file_path)?;

// Safe code generation and file manipulation
source_file.write_string(&generated_code)?;
```

### 📱 **Mobile App Sandboxing**
**Challenge:** Apps need secure access to their document directories
```rust
// App-specific document access
let app_docs = Jail::<AppDocuments>::try_new(app_documents_dir())?;
let user_file = app_docs.try_path(&user_selected_filename)?;

// Guaranteed within app sandbox
user_file.write_bytes(&document_data)?;
```

### 🏥 **Healthcare Data Processing**
**Challenge:** Patient data must remain within compliant storage boundaries
```rust
// HIPAA-compliant file handling
let patient_jail = Jail::<PatientData>::try_new(format!("/medical/patients/{}", patient_id))?;
let medical_record = patient_jail.try_path("records/latest.json")?;

// Audit-safe operations with virtual path logging
audit_log!("Accessed file: {}", medical_record); // Virtual path only
```

**Key Benefits Across All Use Cases:**
- ✅ **Compile-time Safety**: Type system prevents mixing contexts
- ✅ **Zero Directory Traversal**: Automatic protection against `../` attacks  
- ✅ **Audit-Friendly**: Virtual paths in logs don't expose filesystem structure
- ✅ **Performance**: No runtime overhead for path validation after creation
- ✅ **Cross-Platform**: Handles Windows, Unix, and containerized environments
- ✅ **Future-Proof**: Easy to add new security features without breaking changes

---


## ✅ COMPLETED: Jail-Safe File Operations Trait

**Goal:** Provide ergonomic, jail-safe file operations directly on `JailedPath` without exposing the inner `Path` or relying on `Deref`/`AsRef<Path>`.

**Status:** ✅ **COMPLETED** - Available since version 0.0.4

**What was implemented:**
- Built-in file I/O operations directly on `JailedPath`
- No additional imports needed
- All operations work directly on `JailedPath` instances
- Includes: `exists()`, `is_file()`, `is_dir()`, `metadata()`, `read_to_string()`, `read_bytes()`, `write_string()`, `write_bytes()`, `create_dir_all()`, `remove_file()`, `remove_dir()`, `remove_dir_all()`

**Example Usage:**
```rust
use jailed_path::Jail;

let jail = Jail::<()>::try_new("./uploads")?;
let file = jail.try_path("document.txt")?;

// Direct file operations!
if file.exists() {
    let content = file.read_to_string()?;
    println!("Content: {}", content);
}
file.write_string("Hello, secure world!")?;
```

**Benefits Achieved:**
- All file operations are jail-safe by construction
- No trait-based leaks or accidental bypasses  
- API is as convenient as using `Path`/`PathBuf` with standard library, but always secure
- Optional trait import keeps the core API focused

---

## 🎯 IMMEDIATE: API Surface Design Refinement (Pre-v0.1.0)

**Goal:** Finalize the public API surface to be minimal, secure, and misuse-resistant based on comprehensive design review.

**Status:** 🔴 **REQUIRED** - Critical decisions made, implementation needed

### Key Design Decisions Made

**Security-First Principles:**
- ✅ **NO PATH LEAKS FROM JAILEDPATH**: `JailedPath` never exposes `&Path` or `AsRef<Path>` to prevent security bypasses
- ✅ **JAIL ERGONOMICS**: `Jail` provides `path()` method for explicit access (safe - jail root is not secret)
- ✅ **STRING-ONLY ACCESS**: JailedPath real paths only accessible via string methods
- ✅ **VIRTUAL BY DEFAULT**: All display/UI methods show virtual paths unless explicitly requesting real

**Naming Conventions:**
- ✅ **SUFFIX PATTERN**: Use `_real`/`_virtual` as suffixes for discoverability (e.g., `to_str_real()`)
- ✅ **JAIL NOT ROOT**: Methods access "jail" path, not "root" (jail is the security boundary)
- ✅ **NO VIRTUAL JAIL**: Jail root is always real filesystem path - no `_real` suffix needed

**Removed Confusing Methods:**
- ❌ `try_path_normalized()` - Confusing name, use `try_path()` 
- ❌ `jail() -> &Path` - Violates no-leak principle
- ❌ Virtual jail concepts - Jail root is always real

**Context:** After extensive API design review (August 2025), we identified several issues with the current API that allow misuse and confusion. The library's core principle is "make the secure path the only path, with one obvious way to do each operation."

### 🏛️ Critical Security Distinction: `Jail` vs `JailedPath`

**The security model has two distinct types with different safety requirements:**

#### `Jail<Marker>` - The Validator (Safe to expose as `Path`)
- **Purpose**: Factory for creating `JailedPath` instances
- **Security Role**: Validates user input, but is NOT itself a security promise
- **Path Exposure**: ✅ **SAFE** to provide `path()` method 
- **Rationale**: 
  - Jail root path is not secret information
  - Cannot be used to escape jail boundaries (`jail.path().join("/escape")` just gives you a regular `Path`)
  - Simple and readable: `jail.path().display()`
  - No security bypass possible - validation happens in `jail.try_path()`

#### `JailedPath<Marker>` - The Security Promise (NEVER expose as `Path`)
- **Purpose**: Represents a path guaranteed to be within jail boundaries
- **Security Role**: IS the security promise to users and compiler
- **Path Exposure**: ❌ **FORBIDDEN** to implement `AsRef<Path>` or `Deref<Target = Path>`
- **Rationale**:
  - Would allow `jailed_path.join("../../../etc/passwd")` attacks
  - Breaks compile-time safety guarantees
  - Users receiving `JailedPath` must not be able to escape jail
  - String-only access preserves security model

**Key Insight**: The security boundary is **creating** `JailedPath` instances, not accessing the jail root directory. This is why `Jail` can safely expose its path while `JailedPath` cannot.

### Core Design Principles Established:
1. **Minimalism Reduces Misuse:** Fewer methods = fewer ways to make mistakes
2. **Explicit Over Implicit:** No hidden conversions or automatic behaviors  
3. **One Obvious Way:** Avoid synonyms and alternative methods for the same operation
4. **No Raw Path Leakage:** Prevent access to `std::path::Path` that bypasses security
5. **Immutable Jails:** Once created, jail roots cannot change (prevents invalidating existing JailedPaths)

### 🚨 Critical API Issues Identified:

#### Issue 1: Multiple Path Validation Methods
**Problem:** `Jail` currently has both `try_path()` and `try_path_normalized()`, creating confusion about which to use.
- Users don't know when to use which method
- `try_path_normalized()` adds complexity without clear benefit
- All normalization should be internal

**Decision:** Remove `try_path_normalized()` entirely.

#### Issue 2: Raw Path Leakage via `jail() -> &Path`
**Problem:** The `jail()` method exposes raw `std::path::Path`, enabling dangerous misuse:
```rust
let root = jail.jail();  // Gets raw Path
let escaped = root.join("../../etc/passwd");  // Bypasses all security!
```
**Decision:** Remove `jail()` method entirely.

#### Issue 3: Windows 8.3 Short Name Security Gap
**Problem:** Current 8.3 detection has false positives (rejects legitimate paths like `backup~1`) but is necessary for security.

**Security Risk Explained:**
Windows 8.3 short names create an **ambiguous path resolution vulnerability**:

1. **The Core Problem - Ambiguous Resolution:**
   - Windows filesystem has both `C:\jail\uploads\Program Files\` and `C:\jail\uploads\PROGRA~1\`
   - Question: Does `PROGRA~1` refer to a literal directory named `PROGRA~1` or the short name for `Program Files`?
   - **Path resolution is non-deterministic** - depends on filesystem state and Windows behavior

2. **The Attack Scenario:**
   - Attacker creates literal directory: `C:\jail\uploads\PROGRA~1\malicious.exe`
   - Path validation passes: `C:\jail\uploads\PROGRA~1\malicious.exe` exists within jail
   - Later, administrator creates: `C:\jail\uploads\Program Files\` (normal operation)
   - **Now `PROGRA~1` could resolve to either location** depending on Windows filesystem behavior
   - If resolution changes, same path string accesses different files

3. **Why This Bypasses Security:**
   - **Path string ambiguity**: Same string `PROGRA~1` can resolve to different locations
   - **Not a TOCTOU issue**: Both paths can exist simultaneously
   - **Validation becomes meaningless**: We can't know which directory the path will actually access
   - **Breaks jail guarantees**: Same validated path can access different files over time

3. **Current False Positive Issue:**
   - Pattern `~[0-9]` matches legitimate files like `backup~1.txt`, `config~2.old`
   - Causes user frustration and limits legitimate use cases

**Decision:** Refine the detection using the precise algorithm from our `soft-canonicalize` crate.

### 📋 Required Implementation Actions:

#### 1. Simplify Jail API (CRITICAL - BREAKING CHANGE)
**Target:** Minimal, focused API surface
```rust
impl<Marker> Jail<Marker> {
    ✅ KEEP: pub fn try_new<P: AsRef<Path>>(root: P) -> Result<Self>
    ✅ KEEP: pub fn try_path<P: AsRef<Path>>(&self, user_path: P) -> Result<JailedPath<Marker>>
    🔴 REMOVE: pub fn try_path_normalized(&self, &str) -> Result<JailedPath<Marker>>
    🔴 REMOVE: pub fn jail(&self) -> &Path  // Raw Path leakage - replaced with path() method
    ⏳ CONSIDER: pub fn root(&self) -> JailedPath<Marker>  // Virtual "/" root, add only if needed

    // Path access (simple and readable)
    pub fn path(&self) -> &Path
}
```

**Rationale:**
- One obvious way to validate paths: `jail.try_path()`
- `path()` method for `Jail` improves ergonomics without security risk
- Removed `jail() -> &Path` method - replaced with explicit `path()` method
- Smaller surface = harder to misuse

#### 2. Refine Windows 8.3 Detection (CRITICAL - SECURITY)
**Target:** Use precise pattern matching from `soft-canonicalize` crate

**Current Problem:** False positives reject legitimate paths like `backup~1.txt`
**Solution:** Implement the refined detection using proper 8.3 format validation:

```rust
#[cfg(windows)]
fn is_potential_83_short_name(os: &OsStr) -> bool {
    // Use streaming UTF-16 state machine from soft-canonicalize
    // Matches ONLY actual 8.3 patterns: FILENAME~N where:
    // - FILENAME is 1-8 valid DOS characters (A-Z, 0-9, specific symbols)
    // - ~N where N is 1-6 digits
    // - Total length ≤ 12 characters (8 + ~ + 3 digits max)
    // 
    // ✅ Matches: PROGRA~1, MYDOCU~1, LONGFI~10
    // ❌ Rejects: backup~1.txt, config~2.old, file~backup
}
```

**Reference Implementation (Full Code):**
```rust
#[cfg(windows)]
#[inline]
fn has_windows_short_component(p: &Path) -> bool {
    use std::path::Component;
    for comp in p.components() {
        if let Component::Normal(name) = comp {
            // Fast path: check for '~' in UTF-16 code units without allocating a String
            use std::os::windows::ffi::OsStrExt;
            let mut saw_tilde = false;
            for u in name.encode_wide() {
                if u == b'~' as u16 {
                    saw_tilde = true;
                    break;
                }
            }
            if !saw_tilde {
                continue;
            }
            if is_likely_8_3_short_name_wide(name) {
                return true;
            }
        }
    }
    false
}

#[cfg(windows)]
fn is_likely_8_3_short_name_wide(name: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    // Stream over UTF-16 code units without heap allocation using a small state machine.
    // States:
    //   0 = before '~' (must see at least one ASCII char)
    //   1 = reading one-or-more digits after '~'
    let mut it = name.encode_wide();
    let mut seen_pre_char = false; // at least one ASCII char before '~'
    let mut state = 0u8;
    let mut saw_digit = false;

    // Iterate through all code units once.
    while let Some(u) = it.next() {
        // Enforce ASCII-only for 8.3 short names
        if u > 0x7F {
            return false;
        }
        let b = u as u8;
        match state {
            0 => {
                if b == b'~' {
                    // Require at least one char before '~'
                    if !seen_pre_char {
                        return false;
                    }
                    state = 1;
                } else {
                    // Any ASCII char counts as pre-tilde content
                    seen_pre_char = true;
                }
            }
            1 => {
                if b.is_ascii_digit() {
                    saw_digit = true;
                } else {
                    // Digit run ended; accept only "." followed by at least one more char
                    if !saw_digit {
                        return false;
                    }
                    if b == b'.' {
                        // Must have at least one ASCII unit after '.'
                        match it.next() {
                            Some(u2) if u2 <= 0x7F => return true,
                            _ => return false,
                        }
                    } else {
                        return false;
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    // End of stream: valid only if we were parsing digits and saw at least one.
    state == 1 && saw_digit
}
```

**Enhanced Security Justification:** 
- **Primary Risk**: Path string ambiguity - `PROGRA~1` can refer to different directories simultaneously
- **Attack Scenario**: Attacker creates literal `PROGRA~1` directory, later legitimate `Program Files` appears
- **Resolution Ambiguity**: Windows may resolve `PROGRA~1` to either the literal directory or as short name for `Program Files`
- **Breaks Security Model**: Same path string can access different files, making validation meaningless
- **Not TOCTOU**: Both directories can exist simultaneously - this is about ambiguous path resolution, not timing
- **Solution**: Reject ambiguous 8.3 patterns entirely to prevent path resolution confusion

#### 3. Windows Platform Documentation (HIGH PRIORITY)
**Target:** Platform-specific security documentation for Windows applications processing external paths

**Requirements:**
- Document 8.3 short name rejection behavior specifically for Windows compilations that handle untrusted paths
- Provide comprehensive security explanation for Windows-specific path ambiguity risks  
- Include deployment considerations for Windows applications (servers, desktop apps, CLI tools, etc.)
- Document configuration options for Windows-specific security features

**False Positive Refinement Goals:**
- Minimize legitimate path rejections while maintaining security posture
- Implement more precise 8.3 pattern detection using `soft-canonicalize` algorithms
- Provide clear documentation on what patterns are rejected and why
- Consider configurable strictness levels for different deployment scenarios

#### 4. Documentation Updates (HIGH PRIORITY)
**Target:** Clear, consistent API documentation

**Actions:**
- Remove all examples using `try_path_normalized()` 
- Remove all examples using `jail()` method
- Emphasize "one way to do things" principle
- Add security warnings on any methods exposing real paths
- Update all code examples to use simplified API

#### 5. Naming Convention Enforcement (MEDIUM PRIORITY)
**Target:** Consistent method naming across the crate

**Established Conventions:**
- `try_*` - Fallible security-critical operations
- `*_real` - Methods exposing real filesystem paths (dangerous, explicit)
- `*_virtual` - Methods exposing virtual display paths (safe, user-friendly)
- Path manipulation methods use standard names (`join()`, `parent()`, etc.) since only safe variants exist

---

## 🎯 Immediate Priorities (Pre-v0.1.0)

### CRITICAL (Blocking v0.1.0):
1. **🔴 IMPLEMENT: `path()` method for `Jail`** - Enable explicit path access (already specified in API above)
2. **🔴 REFINE: Windows 8.3 detection** - Use precise UTF-16 state machine for short name detection (full implementation included above)
3. **🔴 REMOVE: `jail() -> &Path` method** - BREAKING CHANGE, replace with explicit `path()` method
4. **🔴 REMOVE: `try_path_normalized()` method** - BREAKING CHANGE, confusing API surface

### HIGH PRIORITY:
5. **🟡 UPDATE: Documentation** - Remove all references to removed methods, add `path()` method examples
6. **🟡 WINDOWS: Platform-specific documentation** - Document 8.3 behavior and Windows security considerations

---

## 📋 Additional API Refinements (Post-Discussion):

#### Display Methods Clarification:
```rust
impl<Marker> JailedPath<Marker> {
    // DEFAULT: Virtual display via Display trait (jail-relative, user-friendly)
    // format!("{}", jailed_path) -> "/alice/documents/file.txt" (relative to jail)
    
    // String conversion - explicit suffixes when both variants exist
    pub fn to_string_virtual(&self) -> String      // Virtual path 
    pub fn to_string_real(&self) -> String         // Full filesystem path
    
    // String slice access - explicit suffixes when both variants exist  
    pub fn to_str_virtual(&self) -> Option<&str>   // Virtual path as &str
    pub fn to_str_real(&self) -> Option<&str>      // Full filesystem path as &str
    
    // OsStr access - explicit suffixes when both variants exist
    pub fn as_os_str_real(&self) -> &OsStr         // Real OsStr
    pub fn as_os_str_virtual(&self) -> OsString    // Virtual OsStr (computed)
}
```

#### Methods to Remove/Modify:
- **Remove or make private: `virtual_path()`** - Prevents confusion; users should work directly on JailedPath
- **Default Display = Virtual** - `format!("{}", jailed_path)` shows jail-relative path via Display trait
- **Explicit Real Access** - Methods like `real_path_to_str()` when full path needed for filesystem operations

#### Rationale:
- **Less confusion**: No `virtual_path()` method that returns a separate Path object
- **Clear intent**: `_real` vs `_virtual` suffixes make purpose obvious  
- **Sensible defaults**: Display shows user-friendly virtual paths by default
- **Explicit escape hatches**: Real path access requires explicit method calls

## 🏷️ JailedPath Method Naming Rules

**Critical naming conventions for `JailedPath<Marker>` methods:**

**Rule A**: If a method exposes a real path in any way, it **MUST** end with the suffix `_real()`
- Examples: `to_string_real()`, `to_str_real()`, `as_os_str_real()`
- Rationale: Makes real path exposure explicit and obvious in code review

**Rule B**: If a method could represent either a virtual variant or a real variant under the same name, it **MUST** end with a proper suffix: either `_real()` or `_virtual()`
- Examples: `to_string_virtual()` / `to_string_real()`, `to_str_virtual()` / `to_str_real()`
- Rationale: Eliminates ambiguity about which representation is returned

**Rule C**: If a method represents a virtual presentation, but has no (or should never have in the future) a `_real()` version, it is considered "safe" and should **NOT** use any suffix
- Examples: `join()`, `parent()`, `with_extension()` (these only have safe variants)
- Rationale: Clean API for common operations that don't leak real paths

## 📚 Final API Design Specification

Based on our comprehensive design review, here are the complete final type signatures and methods:

### 🏛️ `Jail<Marker>` - The Path Validator

```rust
/// Immutable jail that validates paths within a secure boundary.
/// The ONLY way to create JailedPath instances.
#[derive(Debug, Clone)]
pub struct Jail<Marker = ()> {
    jail: Arc<PathBuf>,           // Canonicalized jail root
    _marker: PhantomData<Marker>, // Type safety marker
}

impl<Marker> Jail<Marker> {
    /// Create a new jail rooted at the specified directory.
    /// SECURITY: The jail directory MUST exist and be a directory.
    /// This prevents typos and ensures explicit directory creation.
    /// Use try_new_create() if you want to create the jail directory.
    pub fn try_new<P: AsRef<Path>>(root: P) -> Result<Self, JailedPathError>
    
    /// Create a new jail, creating the directory if it doesn't exist.
    /// Uses create_dir_all() to create parent directories as needed.
    /// SECURITY: Still validates the final path is within expected bounds.
    pub fn try_new_create<P: AsRef<Path>>(root: P) -> Result<Self, JailedPathError>
    
    /// Validate a path and create a JailedPath confined to this jail.
    /// This is the ONLY way to create JailedPath instances.
    /// Automatically handles:
    /// - Directory traversal attacks (../)
    /// - Absolute path attempts
    /// - Symlink resolution
    /// - Windows 8.3 short name validation
    pub fn try_path<P: AsRef<Path>>(&self, user_path: P) -> Result<JailedPath<Marker>, JailedPathError>
    
    // ========================================
    // PATH ACCESS (Simple and Readable)
    // ========================================
    
    /// Get the jail root as a Path reference.
    /// ✅ SAFE: Jail root exposure doesn't compromise security.
    /// Simple and readable: jail.path().display()
    pub fn path(&self) -> &Path
    
    // ========================================
    // REMOVED METHODS (breaking changes)
    // ========================================
    // - try_path_normalized() - Removed to eliminate confusion
    // - jail() -> &Path - Removed in favor of path() method
    // - display() -> String - Use jail.path().display().to_string()
    // - to_str() -> Option<&str> - Use jail.path().to_str()
    // - to_string_lossy() -> Cow<str> - Use jail.path().to_string_lossy()
    // - as_os_str() -> &OsStr - Use jail.path().as_os_str()
    // - to_bytes() -> Vec<u8> - Use jail.path().as_os_str().as_bytes()
    // - as_path() -> &Path - Renamed to path() for simplicity
    // - AsRef<Path> implementation - Removed in favor of explicit path() method
    
    // FUTURE CONSIDERATION (only if real use case emerges):
    // pub fn root(&self) -> JailedPath<Marker>  // Returns virtual "/" root
}

// Standard traits
impl<Marker> PartialEq for Jail<Marker>  // Compare jail roots
impl<Marker> Eq for Jail<Marker>
impl<Marker> Hash for Jail<Marker>
impl<Marker> Clone for Jail<Marker>      // Cheap clone (Arc internally)

### 🛡️ `JailedPath<Marker>` - The Secure Path

```rust
/// A path that is guaranteed to be within a specific jail boundary.
/// Can only be created through Jail::try_path().
/// All operations are jail-safe by construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JailedPath<Marker = ()> {
    path: PathBuf,                // The real, validated filesystem path
    jail_root: Arc<PathBuf>,      // Shared jail root for virtual display
    _marker: PhantomData<Marker>, // Type safety marker
}

impl<Marker> JailedPath<Marker> {
    // ========================================
    // DISPLAY & STRING CONVERSION (Virtual by Default)
    // ========================================
    
    /// Virtual path as string (jail-relative, user-friendly).
    /// Same as format!("{}", self) but returns String directly.
    pub fn to_string_virtual(&self) -> String
    
    /// Real path as owned string.
    /// ⚠️ Use only for filesystem operations, not user display.
    pub fn to_string_real(&self) -> String
    
    /// Virtual path as UTF-8 string if possible.
    pub fn to_str_virtual(&self) -> Option<&str>
    
    /// Real path as UTF-8 string if possible, None if contains invalid UTF-8.
    /// ⚠️ Use only for filesystem operations, not user display.
    pub fn to_str_real(&self) -> Option<&str>
    
    /// Virtual path as string with lossy UTF-8 conversion.
    pub fn to_string_lossy_virtual(&self) -> String
    
    /// Real path as string with lossy UTF-8 conversion.
    /// ⚠️ Use only for filesystem operations, not user display.
    pub fn to_string_lossy_real(&self) -> Cow<str>
    
    // ========================================
    // OS STRING CONVERSION
    // ========================================
    
    /// Real path as OsStr (full filesystem path).
    pub fn as_os_str_real(&self) -> &OsStr
    
    /// Virtual path as OsString (jail-relative).
    pub fn as_os_str_virtual(&self) -> OsString
    
    // ========================================
    // SAFE PATH MANIPULATION (Virtual Methods)
    // ========================================
    
    /// Join a relative path segment safely. Returns None if result would escape jail.
    /// Example: jailed.join("subfolder/file.txt")
    pub fn join<P: AsRef<Path>>(&self, path: P) -> Option<Self>
    
    /// Get parent directory safely. Returns None if already at jail root.
    pub fn parent(&self) -> Option<Self>
    
    /// Replace file name safely. Returns None if result would escape jail.
    pub fn with_file_name<S: AsRef<OsStr>>(&self, file_name: S) -> Option<Self>
    
    /// Replace file extension safely. Returns None if result would escape jail.
    pub fn with_extension<S: AsRef<OsStr>>(&self, extension: S) -> Option<Self>
    
    // ========================================
    // PATH COMPONENT ACCESS (Always Safe)
    // ========================================
    
    /// File name component (same as Path::file_name).
    pub fn file_name(&self) -> Option<&OsStr>
    
    /// File extension (same as Path::extension).
    pub fn extension(&self) -> Option<&OsStr>
    
    /// File stem - file name without extension.
    pub fn file_stem(&self) -> Option<&OsStr>
    
    /// Whether this is an absolute path (always true for JailedPath).
    pub fn is_absolute(&self) -> bool  // Always returns true
    
    /// Whether this is a relative path (always false for JailedPath).
    pub fn is_relative(&self) -> bool  // Always returns false
    
    // ========================================
    // BUILT-IN FILE OPERATIONS (Jail-Safe)
    // ========================================
    
    /// Check if path exists on filesystem.
    pub fn exists(&self) -> bool
    
    /// Check if path is a file.
    pub fn is_file(&self) -> bool
    
    /// Check if path is a directory.
    pub fn is_dir(&self) -> bool
    
    /// Get file metadata.
    pub fn metadata(&self) -> io::Result<Metadata>
    
    /// Read file contents as bytes.
    pub fn read_bytes(&self) -> io::Result<Vec<u8>>
    
    /// Read file contents as UTF-8 string.
    pub fn read_to_string(&self) -> io::Result<String>
    
    /// Write bytes to file.
    pub fn write_bytes(&self, contents: &[u8]) -> io::Result<()>
    
    /// Write string to file.
    pub fn write_string(&self, contents: &str) -> io::Result<()>
    
    /// Create directory and all parent directories.
    pub fn create_dir_all(&self) -> io::Result<()>
    
    /// Remove file.
    pub fn remove_file(&self) -> io::Result<()>
    
    /// Remove empty directory.
    pub fn remove_dir(&self) -> io::Result<()>
    
    /// Remove directory and all contents recursively.
    pub fn remove_dir_all(&self) -> io::Result<()>
    
    // ========================================
    // ESCAPE HATCH (Explicit and Consuming)
    // ========================================
    
    /// Extract the inner PathBuf, consuming the JailedPath.
    /// ⚠️  SECURITY WARNING: This removes all safety guarantees!
    /// Use only when you need to pass to external APIs that require PathBuf.
    pub fn unjail(self) -> PathBuf
    
    // ========================================
    // ECOSYSTEM INTEGRATION
    // ========================================
    
    /// Convert to bytes for integration with path crates like `typed-path`.
    /// Example: `WindowsPath::new(jailed.to_bytes_real())`
    pub fn to_bytes_real(&self) -> Vec<u8>
    
    /// Convert to bytes consuming self for zero-copy integration.
    pub fn into_bytes_real(self) -> Vec<u8>
    
    /// Virtual path as bytes (jail-relative).
    pub fn to_bytes_virtual(&self) -> Vec<u8>
}

// ========================================
// TRAIT IMPLEMENTATIONS
// ========================================

impl<Marker> fmt::Display for JailedPath<Marker> {
    /// Display shows virtual path (jail-relative, user-friendly).
    /// Example: "/alice/documents/file.txt" instead of "/app/storage/users/alice/documents/file.txt"
    /// Used by: format!("{}", jailed), println!("{}", jailed), etc.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_virtual())
    }
}

impl<Marker> fmt::Debug for JailedPath<Marker> {
    /// Debug shows real path (full filesystem path) for debugging/logging.
    /// Example: "/app/storage/users/alice/documents/file.txt"
    /// ⚠️ This exposes real paths - use only for debugging, not user-facing output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_real())
    }
}

impl<Marker> JailedPath<Marker> {
    // ========================================
    // JAIL ACCESS (String Methods Only)
    // ========================================
    
    // ========================================
    // JAIL ACCESS - REMOVED (Use jail.path() instead)
    // ========================================
    // - jail_display() -> String - Use jail.path().display().to_string()
    // - jail_to_str() -> Option<&str> - Use jail.path().to_str()  
    // - jail_to_string_lossy() -> Cow<str> - Use jail.path().to_string_lossy()
    //
    // Rationale: Keep reference to original Jail for jail information
    // Pattern: let (jail, jailed) = (jail, jail.try_path("file")?);
    
    // ========================================
    // REMOVED METHODS (Breaking Changes)
    // ========================================
    
    // REMOVED: virtual_path() -> PathBuf
    //   Reason: Creates confusion - users should work directly on JailedPath
    
    // REMOVED: real_path() -> &Path  
    //   Reason: Too easy to misuse - use unjail() for explicit intent
    
    // REMOVED: as_path() -> &Path
    //   Reason: Ambiguous whether real or virtual - use unjail() instead
    
    // NOT IMPLEMENTED: Deref<Target = Path>
    //   Reason: Would allow jailed.join("../escape") bypassing security
    
    // NOT IMPLEMENTED: AsRef<Path> / Borrow<Path>
    //   Reason: Same security concern as Deref
}

// Standard traits for collections and comparisons
impl<Marker> PartialEq for JailedPath<Marker>  // Compare real paths
impl<Marker> Eq for JailedPath<Marker>
impl<Marker> Hash for JailedPath<Marker>        // Hash real paths
impl<Marker> PartialOrd for JailedPath<Marker>  // Order by real paths
impl<Marker> Ord for JailedPath<Marker>
impl<Marker> Clone for JailedPath<Marker>       // Cheap clone (Arc internally)
impl<Marker> Display for JailedPath<Marker>     // Virtual display by default

// Optional serde support (behind feature flag)
#[cfg(feature = "serde")]
impl<Marker> Serialize for JailedPath<Marker>   // Serialize as virtual path
#[cfg(feature = "serde")]
impl<Marker> Deserialize for JailedPath<Marker> // Custom deserializer needed
```

### 🎯 Key Design Principles Applied:

1. **Minimal API Surface**: Only essential methods, no synonyms
2. **Virtual by Default**: Display and string conversion show jail-relative paths
3. **Explicit Real Access**: Methods with `_real` suffix when full path needed
4. **No Raw Path Leakage**: No Deref/AsRef to prevent bypassing security
5. **Consuming Escape Hatch**: `unjail()` makes intent explicit and removes safety
6. **Built-in File Operations**: Common operations are jail-safe by construction
7. **Type Safety**: Markers prevent mixing paths from different jails

### 🚀 Usage Examples:

```rust
use jailed_path::Jail;

// Create jail
let jail = Jail::<UserFiles>::try_new("/app/storage/users")?;

// Validate path
let file = jail.try_path("alice/documents/report.pdf")?;

// Display (virtual by default)
println!("File: {}", file);  // "/alice/documents/report.pdf"
tracing::info!("Serving: {}", file);  // Clean logs

// Debug (real path for debugging)
println!("Debug: {:?}", file);  // "/app/storage/users/alice/documents/report.pdf"

// Real path when needed for filesystem operations
println!("Debug: {}", file.to_string_real());  // "/app/storage/users/alice/documents/report.pdf"

// Safe path manipulation
let backup = file.with_extension("backup")?;
let parent = file.parent()?;

// Built-in file operations
if file.exists() {
    let content = file.read_to_string()?;
    let backup_file = file.with_extension("bak")?;
    backup_file.write_string(&content)?;
}

// External API integration (explicit)
let path_buf = file.unjail();  // Loses safety guarantees
some_external_function(&path_buf);
```

This design achieves our goals: **secure by default, minimal surface, explicit intent, hard to misuse**.

### 🔗 Ecosystem Integration

Based on patterns from [`app-path`](https://github.com/DK26/app-path-rs), `jailed-path` integrates seamlessly with popular Rust path crates:

#### **Popular Path Crate Compatibility**

| Crate                                                           | Use Case                           | Integration Pattern                                  |
| --------------------------------------------------------------- | ---------------------------------- | ---------------------------------------------------- |
| **[`camino`](https://crates.io/crates/camino)**                 | UTF-8 path guarantees for web apps | `Utf8PathBuf::try_from(jailed.to_string_virtual())?` |
| **[`typed-path`](https://crates.io/crates/typed-path)**         | Cross-platform type-safe paths     | `WindowsPath::new(jailed.to_string_virtual())`       |
| **[`dunce`](https://crates.io/crates/dunce)**                   | Windows UNC path canonicalization  | `dunce::canonicalize(jailed.unjail())?`              |
| **[`path-clean`](https://crates.io/crates/path-clean)**         | Lexical path cleaning              | Not needed - jailed-path handles this internally     |
| **[`normalize-path`](https://crates.io/crates/normalize-path)** | Path normalization                 | Not needed - jailed-path handles this internally     |

#### **Integration Examples**

```rust
use jailed_path::Jail;
use camino::Utf8PathBuf;
use typed_path::WindowsPath;

// UTF-8 web development with camino
let jail = Jail::try_new("/app/storage")?;
let jailed = jail.try_path("users/alice/config.json")?;

// Convert to UTF-8 path for web APIs (VIRTUAL ONLY for security)
let utf8_path = Utf8PathBuf::try_from(jailed.to_string_virtual())
    .map_err(|_| "Non-UTF-8 path not supported")?;

// Cross-platform paths with typed-path (VIRTUAL ONLY for security)
let windows_path = WindowsPath::new(jailed.to_string_virtual());
let unix_path = typed_path::UnixPath::new(jailed.to_string_virtual());

// Database storage (virtual paths for user-facing data)
let storage_path = jailed.to_string_virtual(); // "/users/alice/config.json"
database.store("file_path", &storage_path)?;

// For REAL paths - use explicit unjail() escape hatch
let real_pathbuf = jailed.unjail();  // Explicit escape
let utf8_real = Utf8PathBuf::from_path_buf(real_pathbuf)?;

// Debugging and logging (jail root information)
log::debug!("File {} in jail {}", jailed, jail.path().display());
```

#### **Security Considerations for Integration**

```rust
// ✅ SAFE: Using virtual display for user-facing data
let user_friendly = jailed.to_string_virtual(); // "/alice/documents/file.txt"
response.json(json!({ "path": user_friendly }));

// ✅ SAFE: Using virtual strings for ecosystem integration (no path leakage)
let windows_path = WindowsPath::new(jailed.to_string_virtual());

// ⚠️  CAREFUL: Jail root exposure (only for debugging/logging)
log::debug!("Jail root: {}", jail.path().display()); // "/app/storage/users"

// ⚠️  CAREFUL: Full path exposure (only for external APIs)
let raw_path = jailed.unjail(); // Loses all safety guarantees
external_lib::process_file(&raw_path);
```

### 🎯 Implementation Priority:

1. **IMMEDIATE (Blocking v0.1.0):**
   - Remove `try_path_normalized()` method
   - Remove `jail()` method  
   - Refine Windows 8.3 detection
   - Update all documentation and examples

2. **BEFORE v0.1.0:**
   - Comprehensive testing of simplified API
   - Security audit of remaining surface
   - Performance validation

### 📝 Breaking Change Notes:
This is a **major breaking change** but justified because:
- Library is pre-v0.1.0 (breaking changes expected)
- Security-first approach requires getting API right
- Simpler API will be more maintainable long-term
- Better to break now than after v1.0

### 🔗 Related Context:
- Discussion thread: August 13, 2025 - API Surface Design Review
- Security analysis: Windows 8.3 short name vulnerability assessment  
- Ergonomics review: Comparison with std::path API surface
- Integration with `soft-canonicalize` crate patterns

### 🚨 CRITICAL SECURITY DECISIONS (August 13, 2025):

**Note:** Some legacy examples throughout this document may still reference `PathValidator` - these should be read as `Jail` for current API design.

1. **Jail Directory Must Exist**: Changed from soft canonicalization approach to requiring jail existence
   - **Rationale**: "Remember we are a security crate, so we must keep the most secure options"
   - **Implementation**: `try_new()` requires existence, `try_new_create()` for explicit creation
   - **Benefits**: Prevents typos, ensures explicit intent, container safety

2. **Naming Convention Finalized**: `_real` and `_virtual` suffixes for all path access
   - **Virtual by default**: Display shows jail-relative paths (`/alice/file.txt`)
   - **Explicit real access**: Methods with `_real` suffix when full path needed
   - **No jail/root confusion**: `Jail` uses `display()`, `JailedPath` uses `jail_display()` for clarity

3. **No Path Leakage**: Removed all `&Path` returning methods for security
   - **Removed**: `jail() -> &Path`, `try_path_normalized()`, `virtual_path() -> &Path`
   - **Added**: String-only jail access, explicit `unjail()` for escape hatch
   - **Rationale**: Prevent accidental bypass via raw Path operations

4. **Windows 8.3 Short Name Security**: Enhanced detection to prevent ambiguous path resolution
   - **Risk**: `PROGRA~1` paths can refer to different directories simultaneously
   - **Solution**: Reject 8.3 patterns to prevent path resolution ambiguity  
   - **Benefit**: Eliminates path string ambiguity while reducing false positives on legitimate files

---

## Planned: Enhanced Security Features
## Current Status (v0.0.4)

✅ **Implemented**
- Core path validation with soft canonicalization
- Type-state design with jail markers
- Cross-platform compatibility (Windows, macOS, Linux)
- Comprehensive test suite
- Zero false positives/negatives security guarantee
- Clamping for traversal and absolute paths: All `..` and absolute paths are clamped to jail root, not blocked
- Virtual root display: Paths shown as jail-relative, never leaking absolute paths
**Type-safe clamped path API: `ValidatedPath` type-state API with `.clamp()` enforces security at compile time** (COMPLETED)
- Integration tests for clamping and virtual root
- Documentation and examples for new clamping behavior

## 📋 Task Tracking Matrix

| Phase                                           | Feature                                    | Status      | Priority     | Notes                                                                                                                                                                                                               |
| ----------------------------------------------- | ------------------------------------------ | ----------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Phase 1: Core UX & Web Integration (v0.1.0)** |
| 1.1                                             | Virtual Root Display                       | ✅           | 1 - CRITICAL | Implemented via `Display` trait. Virtual paths show jail-relative display by default without separate method.                                                                                                       |
| 1.1.0                                           | **Security-hardened jail creation**        | ✅           | 1 - CRITICAL | SECURITY: Requires jail directories to exist. Added `try_new_create()` for explicit creation. Prioritizes secure defaults over convenience.                                                                         |
| 1.1.1                                           | Store jail root as `Arc<ValidatedPath>`    | ✅           | 1 - CRITICAL | Implemented for memory-efficient jail root sharing.                                                                                                                                                                 |
| 1.1.3                                           | Implement `Display` trait                  | ✅           | 1 - CRITICAL | Implemented for clean, virtual root display.                                                                                                                                                                        |
| 1.1.4                                           | Add debug formatting                       | ✅           | 2 - HIGH     | Implemented custom `Debug` to show full path and jail root.                                                                                                                                                         |
| 1.2                                             | Web Framework Integration                  | ⏳           | 2 - HIGH     | Examples and patterns for Axum and other frameworks.                                                                                                                                                                |
| 1.2.1                                           | `examples/axum_file_server.rs`             | 🎯           | 2 - HIGH     | **NEXT:** Create a complete, working Axum example.                                                                                                                                                                  |
| 1.2.2                                           | `examples/actix_web_integration.rs`        | ⏳           | 3 - MEDIUM   | Actix Web integration example.                                                                                                                                                                                      |
| 1.2.3                                           | Documentation: web framework patterns      | ⏳           | 2 - HIGH     | Guide on using `JailedPath` in web app state.                                                                                                                                                                       |
| 1.3                                             | Serde Support                              | ⏳           | 1 - CRITICAL | Essential for web API integration.                                                                                                                                                                                  |
| 1.3.1                                           | Add `serde` feature flag                   | ⏳           | 1 - CRITICAL | Make `serde` an optional dependency.                                                                                                                                                                                |
| 1.3.2                                           | Implement `Serialize` for `JailedPath`     | ⏳           | 1 - CRITICAL | Serialize as a secure, virtual path string.                                                                                                                                                                         |
| 1.3.3                                           | Custom deserializer helpers                | ⏳           | 2 - HIGH     | Provide helpers for validating paths during deserialization.                                                                                                                                                        |
| 1.4                                             | Core Validation Functions                  | ⏳           | 1 - CRITICAL | Simple public API for one-off path validation.                                                                                                                                                                      |
| 1.4.1                                           | `try_jail<Marker=()>(jail, path)` function | ✅ (removed) | 1 - CRITICAL | Was a simple, top-level function for easy validation; replaced by explicit `Jail::try_new().try_path()`.                                                                                                            |
| **Phase 2: Secure API & Ergonomics (v0.2.0)**   |
| 2.1                                             | Secure Path Manipulation API               | ✅           | 1 - CRITICAL | All path manipulation is done via secure `virtual_*` methods.                                                                                                                                                       |
| 2.1.1                                           | `join()` method                            | ✅           | 1 - CRITICAL | Implemented for secure path joining.                                                                                                                                                                                |
| 2.1.2                                           | `parent()` method                          | ✅           | 1 - CRITICAL | Implemented for secure parent navigation.                                                                                                                                                                           |
| 2.1.3                                           | `with_file_name()` method                  | ✅           | 2 - HIGH     | Implemented for secure file name replacement.                                                                                                                                                                       |
| 2.1.4                                           | `with_extension()` method                  | ✅           | 2 - HIGH     | Implemented for secure extension replacement.                                                                                                                                                                       |
| 2.2                                             | Explicit Path Access API                   | ✅           | 1 - CRITICAL | API requires explicit calls to access the inner path, preventing misuse.                                                                                                                                            |
| 2.2.1                                           | ~~`real_path()` method~~                   | ❌           | ~~CRITICAL~~ | **Removed:** Discourages raw `&Path` use. Philosophy is to add specialized methods to `JailedPath` as needed. Forcing an escape hatch requires `to_string()` or `unjail()`, making the developer's intent explicit. |
| 2.2.2                                           | `unjail()` method                          | ✅           | 1 - CRITICAL | Explicitly consumes `JailedPath` to return the inner `PathBuf`, removing safety guarantees.                                                                                                                         |
| 2.2.3                                           | `to_bytes()` / `into_bytes()` methods      | ✅           | 2 - HIGH     | Implemented for ecosystem compatibility.                                                                                                                                                                            |
| 2.3                                             | Ergonomic Trait Implementations            | ✅           | 1 - CRITICAL | `PartialEq`, `Eq`, `Hash`, `Ord`, `PartialOrd` are implemented for seamless use in collections.                                                                                                                     |

| 2.5                                              | Built-in File I/O Operations                      | ✅      | 2 - HIGH     | Added built-in file I/O methods directly on `JailedPath` for direct, safe operations.                         |
| 2.6                                              | ~~`Deref` to `Path`~~                             | ❌      | ~~CRITICAL~~ | **Removed:** Intentionally omitted to prevent insecure `Path::join` usage.                                     |
| 2.7                                              | ~~`AsRef<Path>` / `Borrow<Path>`~~                | ❌      | ~~CRITICAL~~ | **Removed:** Intentionally omitted for the same security reasons as `Deref`.                                   |
| **Phase 3: Ecosystem & Performance (v0.3.0)**    |
| 3.1                                              | Advanced Testing                                  | ⏳      | 2 - HIGH     | Enhance security and compatibility testing.                                                                    |
| 3.1.1                                            | Security vulnerability test suite                 | ⏳      | 2 - HIGH     | Add dedicated tests for path traversal and symlink attacks.                                                    |
| 3.1.2                                            | Cross-platform edge cases                         | ⏳      | 3 - MEDIUM   | Test UNC paths, special files, and case-insensitive filesystems.                                               |
| 3.2                                              | Performance Optimization                          | ⏳      | 4 - LOW      | Benchmark and optimize path validation logic.                                                                  |
| 3.2.1                                            | Benchmark suite vs alternatives                   | ⏳      | 4 - LOW      | Compare performance against other path validation crates.                                                      |
| 3.3                                              | Additional Framework Support                      | ⏳      | 3 - MEDIUM   | Expand ecosystem support with more examples.                                                                   |
| 3.3.1                                            | `examples/warp_integration.rs`                    | ⏳      | 3 - MEDIUM   | Add a Warp integration example.                                                                                |
| 3.3.2                                            | `examples/rocket_integration.rs`                  | ⏳      | 3 - MEDIUM   | Add a Rocket integration example.                                                                              |
| 3.3.3                                            | `examples/cli_tool.rs`                            | ⏳      | 3 - MEDIUM   | Add an example for command-line application patterns.                                                          |

**Legend:**
- ✅ **Completed** - Feature implemented and tested
- 🚧 **In Progress** - Currently being worked on
- 🎯 **Next** - Next item to be worked on (highest priority todo)
- ⏳ **Planned** - Scheduled for implementation
- 🔬 **Research** - Experimental/research phase
- ❌ **Blocked/Removed** - Waiting on dependencies, decisions, or removed from scope

**Priority Levels:**
- **1 - CRITICAL** - Blocking adoption, core functionality must have
- **2 - HIGH** - Important for usability and differentiation  
- **3 - MEDIUM** - Nice to have, improves experience
- **4 - LOW** - Polish features, not essential
- **5 - RESEARCH** - Experimental, may not be implemented

## 📊 Priority Assignment Rationale

### **CRITICAL (1) - Blocking Adoption**
*Core API features that absolutely must exist for the crate to be usable*

**Core Infrastructure:**
- **Virtual Root Display (1.1)**: Without `Display` trait and jail root storage, users see confusing full paths instead of intuitive relative paths
- **Fix jail creation canonicalization (1.1.0)**: Current inconsistency breaks container deployments and testing
- **Store jail root as Arc<PathBuf> in JailedPath (1.1.1)**: Memory-efficient shared jail root enables Display trait and efficient cloning
- **Implement Display trait (1.1.3)**: Essential UX - users need clean path display
- **Serde Support (1.3)**: Essential for web APIs and JSON serialization - most web apps require this

**Path-Complete API (2.3):**
- **Built-in file operations (2.5)**: Direct I/O operations on JailedPath without Path exposure
- **~~Essential traits (2.3.7)~~**: ~~`AsRef`, `Borrow`, `PartialEq` needed for collections and ecosystem integration~~ (❌ Cancelled for security)
- **Core path methods (2.3.1, 2.3.2)**: `join()` and `parent()` implemented for safe path manipulation
- **Explicit conversion methods (2.3.5, 2.3.5a)**: `unjail()` and string methods for ecosystem compatibility

### **HIGH (2) - Important for Usability**
*Features that significantly improve the developer experience and enable real-world usage*

**Development Experience:**
- **Debug formatting (1.1.4)**: Developers need to see full paths when debugging
- **UTF-8 helpers (1.3.3, 1.3.4)**: Important for web development and JSON APIs
- **Security testing (3.2)**: High-quality security library requires comprehensive testing
- **Web Framework Integration (1.2)**: Examples and documentation once API is stable

**Advanced Features:**
- **Web Framework Integration**: Axum examples with JailedPath extractors for security-first patterns
- **Ecosystem methods (2.3.5b, 2.3.5c)**: `to_bytes()` and `into_bytes()` enable specialized library integration
- **Path manipulation (2.3.3, 2.3.4)**: `with_file_name()` and `with_extension()` complete the PathBuf API

### **MEDIUM (3) - Nice to Have**
*Features that improve experience but aren't essential*

**Developer Convenience:**
- **UTF-8 helpers (1.4)**: Convenient for web development but not essential
- **Additional framework examples (1.2.2, 3.3)**: More framework support once core API is proven
- **Custom documentation (1.2.4, 2.1.4)**: Best practices guides and comprehensive examples

**Production Features:**
- **Observability (2.2)**: Useful for production monitoring but optional
- **Cross-platform testing (3.2.3, 3.2.4)**: Important for robustness but not blocking adoption

### **LOW (4) - Polish Features**
*Features that are nice but not essential for core functionality*

**Optional Security:**
- **TOCTOU Protection (1.1.0b)**: Theoretical attack with limited real-world impact
- **Attack pattern detection (2.2.3)**: Advanced monitoring for paranoid deployments

**Performance:**
- **Performance optimization (3.1)**: Nice to have but security and correctness come first
- **Benchmarks (3.1.1)**: Good for marketing but not blocking adoption

### **RESEARCH (5) - Experimental**
*Features that may never be implemented*

**Future Possibilities:**
- **Formal verification (4.1.3)**: Academic research, may not be practical
- **Plugin systems (4.2.1)**: Would break security guarantees
- **SIMD optimization (3.1.4)**: May not provide meaningful benefit

## Phase 1: Core UX & Web Integration (v0.1.0)
*Priority: HIGH - Foundation for adoption*

### 🎯 Virtual Root Display
**Goal**: Improve user experience with intuitive path display

```rust
// Instead of: /home/user/app/storage/users/alice/documents/file.txt
// Display as: /alice/documents/file.txt (relative to jail)
impl<Marker> Display for JailedPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Simple and efficient: just strip the jail root prefix
        if let Ok(relative) = self.path.strip_prefix(&self.jail_root) {
            write!(f, "/{}", relative.display())
        } else {
            write!(f, "{}", self.path.display()) // Fallback
        }
    }
}

// No separate relative_path() method needed!
// Users get relative display automatically via print/Display
```

**Implementation**:
- Store jail root as `Arc<PathBuf>` in `JailedPath` structure for memory efficiency
- Implement `Display` trait for virtual root display (relative path)
- Add debug formatting that shows full path
- No separate `relative_path()` method needed

**Usage Example**:
```rust
use jailed_path::{Jail, JailedPath};

// Create jail for user files
struct UserFiles;
let jail: Jail<UserFiles> = Jail::try_new("/app/storage/users")?;

// Validate and create jailed path
let jailed: JailedPath<UserFiles> = jail.try_path("alice/documents/report.pdf")?;

// Display automatically shows virtual root (user-friendly)
println!("File: {}", jailed);  // Output: "/alice/documents/report.pdf"

// Display automatically shows virtual root (user-friendly)
println!("File: {}", jailed);  // Output: "/alice/documents/report.pdf"
println!("Processing {}", jailed);  // Clean, intuitive display

// Debug shows full path (for debugging)
println!("Debug: {:?}", jailed);  // Output: "/app/storage/users/alice/documents/report.pdf"

// For the rare case you need the relative Path object:
// Use Deref and strip_prefix manually (if really needed)
let relative: &Path = jailed.strip_prefix("/app/storage/users").unwrap();
```

### 🌐 Web Framework Integration
**Goal**: Make jailed-path the go-to choice for secure file serving

**Axum Integration**:
```rust
#[derive(Clone)]
struct AppState {
    user_files: Jail<UserFiles>,    // No Arc needed - already efficient
    public_assets: Jail<PublicAssets>, // Arc<PathBuf> internally
}

async fn serve_user_file(
    State(state): State<AppState>,
    Path((user_id, file_path)): Path<(String, String)>,
) -> Result<Response, StatusCode> {
    // This automatically blocks ../../../etc/passwd attempts
    let safe_path: JailedPath<UserFiles> = state.user_files
        .try_path(&format!("{}/{}", user_id, file_path))
        .map_err(|_| StatusCode::FORBIDDEN)?;  // Silent security failure
}
```

**Deliverables**:
- `examples/axum_file_server.rs` - Complete working example
- `examples/actix_web_integration.rs` - Actix Web integration
- Documentation section on web framework patterns
- AppState patterns and best practices guide

**Real-World Usage Example**:
```rust
use axum::{extract::{Path, State}, response::Response, http::StatusCode};
use jailed_path::{Jail, JailedPath};
use std::sync::Arc;

struct UserFiles;
struct PublicAssets;

#[derive(Clone)]
struct AppState {
    user_files: Jail<UserFiles>,    // Jail is cheap to clone
    assets: Jail<PublicAssets>,     // Arc<PathBuf> shared internally
}

// Serve user files with automatic security
async fn serve_user_file(
    State(state): State<AppState>,
    Path((user_id, file_path)): Path<(String, String)>,
) -> Result<Response, StatusCode> {
    // This automatically blocks ../../../etc/passwd attempts
    let safe_path: JailedPath<UserFiles> = state.user_files
        .try_path(&format!("{}/{}", user_id, file_path))
        .map_err(|_| StatusCode::FORBIDDEN)?;  // Silent security failure
    
    // safe_path is guaranteed to be within /app/storage/users/
    let content = tokio::fs::read(&safe_path).await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    
    // Log shows clean virtual path via Display
    tracing::info!("Serving file: {}", safe_path);  // "/alice/documents/file.txt"
    
    Ok(content.into_response())
}

// Usage in main
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_state = AppState {
        user_files: Jail::try_new("/app/storage/users")?,    // No Arc wrapping
        assets: Jail::try_new("/app/public")?,               // Jail handles efficiency
    };
    
    let app = Router::new()
        .route("/users/:user_id/files/*file_path", get(serve_user_file))
        .with_state(app_state);
    
    // Requests like GET /users/alice/files/../../../etc/passwd 
    // are automatically blocked and return 403
    axum::serve(listener, app).await?;
    Ok(())
}
```

### 📦 Serde Support
**Goal**: Enable seamless integration with web APIs

```rust
#[cfg(feature = "serde")]
impl<Marker> Serialize for JailedPath<Marker> {
    // Serialize as relative path for security
}

// Usage in request types:
#[derive(Deserialize)]
struct FileRequest {
    #[serde(deserialize_with = "validate_path")]
    path: String, // Validated by custom deserializer
}
```

**Implementation**:
- Add `serde` feature flag
- Serialize as relative paths (security best practice)
- Handle non-UTF-8 paths gracefully with lossy conversion
- Custom deserializer helpers for common patterns

**API Usage Example**:
```rust
use serde::{Serialize, Deserialize};
use jailed_path::{Jail, JailedPath};

struct UserFiles;

#[derive(Serialize, Deserialize)]
struct FileInfo {
    // Serializes using Display trait (virtual root)
    path: JailedPath<UserFiles>,  // Will serialize as "/users/alice/document.pdf"
    size: u64,
    modified: SystemTime,
}

// Serialization example
let jail = Jail::try_new("/app/storage")?;
let jailed = jail.try_path("users/alice/document.pdf")?;

let file_info = FileInfo {
    path: jailed,
    size: 1024,
    modified: SystemTime::now(),
};

// Serializes as: {"path": "/users/alice/document.pdf", "size": 1024, ...}
// Uses Display trait automatically - no relative_path() needed!
let json = serde_json::to_string(&file_info)?;

// API request/response types
#[derive(Deserialize)]
struct FileRequest {
    #[serde(deserialize_with = "validate_user_path")]
    path: JailedPath<UserFiles>,  // Automatically validated during deserialization
}

// Custom deserializer helper (to be implemented)
fn validate_user_path<'de, D>(deserializer: D) -> Result<JailedPath<UserFiles>, D::Error>
where D: Deserializer<'de> {
    let path_str = String::deserialize(deserializer)?;
    // Get validator from context (implementation detail)
    USER_jail.try_path(&path_str).map_err(serde::de::Error::custom)
}

// Usage in web handler
async fn upload_file(Json(req): Json<FileRequest>) -> Result<StatusCode, StatusCode> {
    // req.path is guaranteed to be safe - no validation needed!
    tokio::fs::write(&req.path, data).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    println!("Uploaded to: {}", req.path);  // Clean display via Display trait
    Ok(StatusCode::CREATED)
}
```

### 🛠️ UTF-8 Helper Methods
**Goal**: Support web developers without forcing UTF-8 constraints

```rust
impl<Marker> JailedPath<Marker> {
    pub fn to_str(&self) -> Option<&str> { /* UTF-8 string if possible */ }
    pub fn to_string_lossy(&self) -> Cow<str> { /* Never fails, may be lossy */ }
    pub fn relative_str(&self) -> Option<&str> { /* Relative path as UTF-8 */ }
}
```

**Benefits**:
- Easy JSON serialization for web APIs
- Database storage compatibility
- Maintains OS-native path support

**API Usage Example**:
```rust
use jailed_path::{Jail, JailedPath};

struct UserFiles;
let jail = Jail::try_new("/app/storage")?;
let jailed: JailedPath<UserFiles> = jail.try_path("users/alice/файл.txt")?;  // Non-UTF-8 filename

// UTF-8 methods for web development
match jailed.to_str_real() {
    Some(utf8_path) => {
        // ⚠️ This gives FULL path - use only for filesystem operations
        // For clean API responses, use virtual display:
        let clean_display = jailed.to_string_virtual();  // "/users/alice/файл.txt" (virtual)
        let response = json!({ "path": clean_display });
    }
    None => {
        // Fallback for non-UTF-8 filenames
        let lossy_display = format!("{}", jailed);  // Uses Display trait with lossy conversion
        log::warn!("Non-UTF-8 filename displayed as: {}", lossy_display);
    }
}

// For the rare case you need real path string:
let full_path_str = jailed.to_str_real().unwrap();  // "/app/storage/users/alice/file.txt"

// ✅ PREFERRED: Use virtual strings for user-facing operations
let virtual_str = jailed.to_string_virtual();  // "/users/alice/file.txt"

// But usually just use Display trait:
println!("User sees: {}", jailed);  // Automatic virtual display

// Access path components safely (direct methods on JailedPath)
let extension = jailed.extension();  // Option<&OsStr>
let file_name = jailed.file_name();  // Option<&OsStr>
let is_absolute = jailed.is_absolute();  // bool - always true for JailedPath

// Use with file I/O via built-in methods (no trait conversion needed)
jailed.metadata()?;  // Built-in metadata access
jailed.read_to_string()?;  // Built-in file reading
// For external crates, use unjail() explicitly when needed
```

### 🔧 Core Validation Functions
**Goal**: Simple, one-line validation for quick use cases and public API

**Core Function**:
```rust
/// Create a JailedPath - validates that path is safely within jail boundary
/// Returns JailedPath for secure file operations
/// 
/// # Type Parameters
/// - `Marker`: Optional type marker for compile-time type safety (defaults to `()`)
/// 
/// # Examples
/// ```rust
/// // Simple usage (no marker)
/// let file = Jail::try_new("/user/files")?.try_path("documents/report.pdf")?;
/// 
/// // With type marker for compile-time safety
/// struct UserFiles;
/// let file: JailedPath<UserFiles> = Jail::try_new("/user/files")?.try_path("documents/report.pdf")?;
/// ```
// try_jail removed; use: Jail::<Marker>::try_new(jail).and_then(|j| j.try_path(path))
where 
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    Jail::<Marker>::try_new(jail)?.try_path(path)
}
```

**Usage Examples**:
```rust
use jailed_path::Jail;

// Simple usage - defaults to JailedPath<()>
let file = Jail::try_new("/user/files")?.try_path("documents/report.pdf")?;
println!("File: {}", file); // "/documents/report.pdf"

// Direct use with file operations
let config = Jail::try_new("/app/config")?.try_path("app.toml")?;
let settings: AppSettings = toml::from_str(&std::fs::read_to_string(&config)?)?;

// Type-safe validation with explicit marker type
struct UserFiles;
let file: JailedPath<UserFiles> = Jail::try_new("/user/files")?.try_path("documents/report.pdf")?;

// Or use turbofish syntax for explicit typing
let file = Jail::<UserFiles>::try_new("/user/files")?.try_path("documents/report.pdf")?;

// Attack prevention examples - these will return Err()
assert!(Jail::try_new("/jail").and_then(|j| j.try_path("../../../etc/passwd")).is_ok()); // clamped
assert!(Jail::try_new("/jail").and_then(|j| j.try_path("/etc/passwd")).is_ok());          // clamped
assert!(Jail::try_new("/jail").and_then(|j| j.try_path("safe/file.txt")).is_ok());        // allowed

// Error handling for security
match Jail::try_new("/app/public").and_then(|j| j.try_path(&user_input)) {
    Ok(safe_path) => {
        // Safe to proceed with file operations
        let content = tokio::fs::read(&safe_path).await?;
        Ok(content)
    }
    Err(_) => Err(ApiError::Forbidden), // Path outside jail
}

// One-line file operations
let config = Jail::try_new("/app/config")?.try_path("app.toml")?;
let settings: AppSettings = toml::from_str(&std::fs::read_to_string(&config)?)?;

// Database path validation
fn store_user_file(user_id: &str, filename: &str) -> Result<(), DbError> {
    let file_path = Jail::try_new("/app/uploads")?.try_path(&format!("{}/{}", user_id, filename))?;
    
    // file_path is guaranteed safe - store in database
    database.insert("user_files", &format!("{}", file_path))?; // Uses Display trait
    Ok(())
}
```

**Benefits**:
- **Simple**: One function call for validation
- **Public API**: Useful for external validation checks  
- **Familiar**: Similar to `std::fs::read(path)` pattern
- **Flexible**: Both Result and boolean variants
- **Efficient**: No intermediate objects for simple checks
- **Security-focused**: Blocks directory traversal attacks automatically

**When to use each approach**:
```rust
// One-off operations - create a jail inline
let temp_file = Jail::try_new("/tmp")?.try_path("upload_123.txt")?;

// Multiple validations - use Jail (more efficient)
let jail = Jail::try_new("/user/files")?;
let doc1 = jail.try_path("document1.pdf")?;
let doc2 = jail.try_path("document2.pdf")?;
let doc3 = jail.try_path("document3.pdf")?;

// Type safety needed - use explicit type annotation or turbofish
struct UserFiles;
let file: JailedPath<UserFiles> = Jail::try_new("/user/files")?.try_path("doc.pdf")?;
// or
let file = Jail::<UserFiles>::try_new("/user/files")?.try_path("doc.pdf")?;
```

## Phase 2: Advanced Security Features (v0.2.0)
*Priority: MEDIUM - Differentiating capabilities*

### 🔧 Path-Complete API: Secure by Default
**Goal**: Make `JailedPath` an ergonomic and secure alternative to `PathBuf` for all path-related operations.

#### Design: Explicit Path Access, No `Deref`
A core design principle of `jailed-path` is **explicitness**. The `JailedPath` struct intentionally does **not** implement `Deref`, `AsRef<Path>`, or `Borrow<Path>`.

**Rationale:**
Automatic dereferencing to `&Path` is dangerous because it makes it easy to accidentally use insecure methods like `Path::join()`. A user might write `jailed_path.join("../../../etc/passwd")`, thinking it's safe, but this would bypass the jail entirely. This would break the compile-time safety guarantees this crate aims to provide.

By omitting these traits, we force the developer to be explicit about their intent, which makes the code safer and easier to audit.

**The Secure API:**
- **Path Manipulation**: All path modifications (joining, getting parent, etc.) **must** be done using the provided safe methods (`join()`, `parent()`, etc.). These methods are guaranteed to be jail-safe.
- **Filesystem Access**: For I/O operations, you can use the convenient built-in methods (`.read()`, `.write()`) or explicitly get the real path as a string via `to_string_lossy()` and create a `Path` from it.
- **Leaving the Jail**: If you need to convert the `JailedPath` back into a regular `PathBuf` (and thus lose the safety guarantees), you must call the explicit `.unjail()` method.
- **Ergonomics**: Traits like `PartialEq`, `Eq`, `Ord`, and `Hash` are implemented to ensure `JailedPath` works seamlessly in collections and comparisons.

**API Usage Example - The Secure Way:**
```rust
use jailed_path::{PathValidator, JailedPath};
use std::collections::HashMap;

struct UserFiles;

fn process_file_secure(path: JailedPath<UserFiles>) -> Result<String, Box<dyn std::error::Error>> {
    // CORRECT: Use the built-in, safe read method.
    let content = path.read()?;
    
    // CORRECT: Path manipulation uses jail-safe virtual methods.
    let backup_path = path.with_extension("backup").ok_or("Backup path failed")?;
    
    // CORRECT: Use the explicit `to_string_lossy()` for functions expecting a &Path.
    std::fs::copy(path.to_string_lossy().as_ref(), backup_path.to_string_lossy().as_ref())?;
    
    Ok(String::from_utf8_lossy(&content).to_string())
}

// Collections work seamlessly due to Hash and PartialEq implementations.
let mut file_cache: HashMap<JailedPath<UserFiles>, Vec<u8>> = HashMap::new();

let jail = PathValidator::with_jail("/app/storage")?;
let jailed = jail.try_path("users/alice/config.toml")?;

file_cache.insert(jailed.clone(), b"cached content".to_vec());

// Path manipulation is explicit and safe.
let config_dir = jailed.parent().unwrap();
let log_file = config_dir.join("app.log").unwrap();
let backup_config = jailed.with_file_name("config.backup.toml").unwrap();

// You can still access path components safely.
println!("Config file: {}", jailed.file_name().unwrap().to_string_lossy());
println!("Extension: {:?}", jailed.extension());

// To use with external libraries, be explicit.
fn existing_file_function(path: &Path) -> std::io::Result<u64> {
    std::fs::metadata(path).map(|m| m.len())
}
// CORRECT: Pass the real path explicitly.
let file_size = existing_file_function(Path::new(&jailed.to_string_lossy()))?;

// To get the inner PathBuf, you must "unjail" it.
let raw_path: PathBuf = jailed.unjail(); // Safety guarantees are now gone.
```

#### Design: `Jail` Can Safely Provide `path()` Method

**Important Distinction**: While `JailedPath` intentionally avoids `AsRef<Path>` for security reasons, `Jail` can safely provide a `path()` method because it serves a different purpose:

**Why `Jail` + `path()` is Safe:**
- **No Security Promise**: `Jail` is just a validator factory, not a security guarantee itself
- **No Escape Possible**: `jail.path().join("/escape")` just gives you a regular `Path` - no jail bypass
- **Simple and Readable**: Simple `path()` method enables clean patterns like `jail.path().display()`
- **Boundary is Creation**: Security boundary is creating `JailedPath` instances via `jail.try_path()`, not accessing jail root

**Ergonomic Benefits:**
```rust
let jail = Jail::try_new("/app/uploads")?;
let file = jail.try_path("user/image.jpg")?;

// Clean, readable test assertions
assert!(file.starts_with(jail.path()));  // ✅ Explicit and readable

// Alternative string-based approach if needed
let jail_display = jail.path().display().to_string();
```

**The jail root path is not secret information** - it's just a validation boundary. The security model prevents path traversal during validation, not access to the jail directory itself.

### 🌐 Web Framework Integration (Axum)
**Goal**: Security-first web handler patterns with pre-validated paths.

The recommended pattern is to use `JailedPath` throughout your application, ensuring that paths are validated at the boundary and then used safely.

```rust
use axum::{extract::{Path, State}, http::StatusCode, response::Response, routing::get, Router};
use jailed_path::{PathValidator, JailedPath};
use std::sync::Arc;

struct UserFiles;

#[derive(Clone)]
struct AppState {
    user_files: PathValidator<UserFiles>,
}

// Security-first handler: receives user input, validates it, and then uses the
// secure JailedPath for all subsequent operations.
async fn serve_user_file(
    State(state): State<AppState>,
    Path((user_id, file_path)): Path<(String, String)>,
) -> Result<Vec<u8>, StatusCode> {
    // This automatically blocks ../../../etc/passwd attempts.
    let safe_path: JailedPath<UserFiles> = state.user_files
        .try_path(&format!("{}/{}", user_id, file_path))
        .map_err(|_| StatusCode::FORBIDDEN)?; // Path outside jail is forbidden.
    
    // CORRECT: Use built-in methods for I/O.
    let content = safe_path.read_bytes()
        .map_err(|_| StatusCode::NOT_FOUND)?;
    
    // The Display trait provides a clean, jail-relative path for logging.
    tracing::info!("Serving file: {}", safe_path); // e.g., "/alice/documents/file.txt"
    
    Ok(content)
}

// Application setup
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app_state = AppState {
        user_files: PathValidator::with_jail("/app/storage/users")?,
    };
    
    let app = Router::new()
        .route("/users/:user_id/files/*file_path", get(serve_user_file))
        .with_state(app_state);
    
    // ... server setup ...
    Ok(())
}
```



## Phase 3: Ecosystem & Performance (v0.3.0)
*Priority: LOW - Polish and optimization*

### ⚡ Performance Optimization
**Goal**: Make jailed-path the fastest secure path library

**Benchmarks vs Alternatives**:
- `path-clean` - basic dot removal
- `path-absolutize` - virtual root handling
- `dunce` - Windows canonicalization
- `std::fs::canonicalize` - standard library

**Optimization Areas**:
- Path component caching for repeated validations
- Lazy canonicalization for performance-critical paths
- SIMD path traversal detection (research phase)

### 🧪 Advanced Testing
**Goal**: Comprehensive security and compatibility testing

**Security Test Suite**:
```bash
# Add to CI
- name: Security vulnerability tests
  run: |
    cargo test --test security_suite --verbose
    cargo test --test path_traversal_attacks --verbose
    cargo test --test symlink_attacks --verbose
```

**Cross-Platform Edge Cases**:
- Windows UNC paths: `\\server\share\file`
- Unix domain sockets and special files
- Case-insensitive filesystems (macOS)
- Non-UTF-8 filenames on all platforms

### 🔌 Additional Framework Support
**Goal**: Broad ecosystem compatibility

**Framework Examples**:
- `examples/warp_integration.rs` - Warp web framework
- `examples/rocket_integration.rs` - Rocket framework  
- `examples/tide_integration.rs` - Tide async framework
- `examples/cli_tool.rs` - Command-line application patterns

## Phase 4: Research & Innovation (v0.4.0+)
*Priority: RESEARCH - Future possibilities*

### 🔬 Advanced Security Research

**Path Fuzzing Integration**:
- Property-based testing with `proptest`
- Automated attack pattern generation
- Filesystem state mutation testing

**Formal Verification**:
- Research mathematical proofs of security properties
- Integration with verification tools (CBMC, KLEE)
- Specification in TLA+ or similar

### 🏗️ Architecture Considerations

**Plugin System** (Research Phase):
```rust
// Hypothetical future API - NOT committed
trait CanonicalizeStrategy {
    fn canonicalize(&self, path: &Path) -> Result<PathBuf>;
}

struct PathValidator<Marker, Strategy = SoftCanonicalize> {
    // Allow custom canonicalization strategies
}
```

**Pros**: Flexibility for specialized use cases  
**Cons**: Breaks security guarantees, increases complexity  
**Decision**: Research only - unlikely to implement

## Non-Goals

❌ **Custom Canonicalization**: Would break security guarantees  
❌ **Async Filesystem Operations**: Out of scope, use with `tokio::fs`  
❌ **Path Watching/Monitoring**: Use `notify` crate instead  
❌ **Forced UTF-8**: Maintains OS-native path support  
❌ **Existing Path Only Requirement**: Would break file creation, uploads, and web applications

## Design Analysis: Why "Existing Path Only" Would Be Harmful

**Critical Use Cases That Would Break:**

1. **File Creation & Uploads**:
   ```rust
   // ❌ Would fail with "existing only" requirement
   let new_file = jail.try_path("uploads/user123/new_document.pdf")?;
   tokio::fs::write(&new_file, content).await?; // Can't create new files!
   ```

2. **Web Application File Serving**:
   ```rust
   // ❌ User uploads would be impossible
   async fn upload_handler(file_data: Vec<u8>) -> Result<()> {
       let upload_path = jail.try_path("temp/upload_123.tmp")?; // Fails!
       std::fs::write(&upload_path, file_data)?; // Never reached
   }
   ```

3. **Log File Creation**:
   ```rust
   // ❌ New log files couldn't be validated
   let log_file = jail.try_path("logs/app_2025_07_22.log")?; // Fails!
   let mut logger = File::create(&log_file)?; // Never works
   ```

4. **Backup & Export Operations**:
   ```rust
   // ❌ Can't create backup files
   let backup_path = jail.try_path("backups/db_backup_20250722.sql")?; // Fails!
   ```

5. **Session Management**:
   ```rust
   // ❌ Temporary session files couldn't be created
   let session_file = jail.try_path("sessions/sess_abc123.json")?; // Fails!
   ```

**Why Current Soft Canonicalization Design Is Correct:**

✅ **Security**: Still validates against jail boundary for non-existent paths  
✅ **Usability**: Supports file creation workflows  
✅ **Performance**: No filesystem modification during validation  
✅ **Real-world compatibility**: Works with web frameworks, CLI tools, etc.  

## Success Metrics

### Adoption Metrics
- **GitHub Stars**: Target 100+ (security-focused crates typically 50-500)
- **Crates.io Downloads**: Target 1000+ monthly
- **Reverse Dependencies**: Target 10+ published crates using jailed-path

### Quality Metrics  
- **Test Coverage**: Maintain >95%
- **Documentation Coverage**: 100% public API documented
- **Platform Support**: Windows, macOS, Linux all green in CI
- **MSRV Policy**: Support last 4 Rust releases (~6 months)

### Security Metrics
- **Zero CVEs**: Maintain clean security record
- **Penetration Testing**: Annual security audit
- **Fuzzing**: Continuous fuzzing with OSS-Fuzz integration

## Contributing

This roadmap is living document. Contributions welcome:

1. **Feature Requests**: Open GitHub issue with use case
2. **Security Research**: Responsible disclosure process
3. **Performance**: Benchmarks and optimization PRs
4. **Documentation**: Examples and integration guides

## Design Decisions & Conclusions

This section documents key design decisions and conclusions reached during development, with practical code examples for future reference.

### 🎯 **Conclusion 1: Non-Existent Paths Are Safe and Essential**

**Decision**: Support validation of non-existent paths using soft canonicalization.

**Rationale**: 
- Non-existent paths cannot be symlinks (fundamental security insight)
- Essential for real-world use cases: file creation, uploads, logging, backups
- Enables container/deployment scenarios where directories are created after validator setup

**Code Examples**:
```rust
// ✅ CORRECT: All these work with soft canonicalization
let jail = PathValidator::with_jail("/app/storage")?;

// File creation (path doesn't exist yet)
let new_file = jail.try_path("uploads/user123/document.pdf")?;
tokio::fs::write(&new_file, data).await?;

// Log file creation
let log_file = jail.try_path("logs/app_2025_07_22.log")?;
File::create(&log_file)?;

// Backup operations
let backup = jail.try_path("backups/db_backup.sql")?;

// Container scenario (jail doesn't exist yet)
let future_validator = PathValidator::with_jail("/app/future-storage")?; // ✅ Works!
```

**Security Analysis**:
```rust
// Attack attempt with non-existent path
let attack_path = "symlinked_ancestor/new_upload.txt";

// 1. Lexical validation: ✅ No ".." components
// 2. Soft canonicalization:
//    - Find existing ancestor: /jail/symlinked_ancestor/ (could be symlink)
//    - Canonicalize existing part: /jail/symlinked_ancestor/ → /evil/ (if symlinked)
//    - Append non-existing: /evil/new_upload.txt
// 3. Boundary check: ❌ /evil/new_upload.txt not within /jail/
// 4. Result: Attack blocked!
```

### 🏗️ **Conclusion 2: Security-First Jail Creation (UPDATED)**

**SECURITY DECISION**: Require jail directories to exist for maximum security.

**Rationale**: As a security crate, we prioritize the most secure options:
- **Prevents typos**: `/app/storage/uesrs` would fail immediately instead of creating wrong directory
- **Explicit directory creation**: Forces developers to think about directory structure
- **Container safety**: Ensures mounted volumes are actually mounted
- **No surprises**: Clear error messages when configuration is wrong

**Final Implementation**:
```rust
// ✅ SECURITY-FIRST: Jail must exist (secure default)
pub fn try_new<P: AsRef<Path>>(jail: P) -> Result<Self> {
    let canonical_jail = jail.as_ref().canonicalize()
        .map_err(|_| JailedPathError::jail_not_found(jail.as_ref()))?;
    
    if !canonical_jail.is_dir() {
        return Err(JailedPathError::jail_not_directory(canonical_jail));
    }
    
    Ok(Self { jail: Arc::new(canonical_jail), _marker: PhantomData })
}

// ✅ CONVENIENCE: Explicit creation when needed
pub fn try_new_create<P: AsRef<Path>>(jail: P) -> Result<Self> {
    std::fs::create_dir_all(&jail)?;
    Self::try_new(jail)  // Delegate to secure version
}

// ✅ PATH VALIDATION: Still uses soft canonicalization for non-existent files
pub fn try_path<P: AsRef<Path>>(&self, path: P) -> Result<JailedPath<Marker>> {
    let resolved = soft_canonicalize(&full_path)?;  // Files don't need to exist
    // ... boundary validation
}
```

**Benefits Demonstrated**:
```rust
// ✅ Container deployment with explicit creation
Jail::try_new_create("/app/storage")?; // Creates directory if needed
let jail = Jail::try_new("/app/storage")?; // Then requires it to exist

// ✅ Testing with setup
#[test]
fn test_validation() {
    std::fs::create_dir_all("/tmp/test-jail")?; // Explicit setup
    let jail = Jail::try_new("/tmp/test-jail")?; // Security-first: must exist
    // ... test validation logic
}
}

// ✅ Dynamic workspaces
let workspace = format!("/app/workspaces/{}", session_id);
let jail = PathValidator::with_jail(&workspace)?; // Works immediately
```

### 📁 **Conclusion 3: No Automatic Directory Creation**

**Decision**: `with_jail()` should NOT automatically create directories.

**Rationale**:
- **Separation of concerns**: Path validation vs filesystem operations
- **User control**: Explicit directory creation with proper permissions
- **No side effects**: `with_jail()` is purely about validation setup
- **Security**: Avoid accidental directory creation in wrong locations

**Recommended API Design (UPDATED - Security First)**:
```rust
impl<Marker> Jail<Marker> {
    /// Creates a jail for the given path.
    /// SECURITY: The jail directory MUST exist and be a directory.
    pub fn try_new<P: AsRef<Path>>(jail: P) -> Result<Self, JailedPathError> {
        let canonical_jail = jail.as_ref().canonicalize()
            .map_err(|_| JailedPathError::jail_not_found(jail.as_ref()))?;
        
        if !canonical_jail.is_dir() {
            return Err(JailedPathError::jail_not_directory(canonical_jail));
        }
        
        Ok(Self { jail: Arc::new(canonical_jail), _marker: PhantomData })
    }
    
    /// Creates a jail, creating the directory if needed.
    pub fn try_new_create<P: AsRef<Path>>(jail: P) -> Result<Self, JailedPathError> {
        std::fs::create_dir_all(&jail)?;
        Self::try_new(jail)
    }
    }
    
    /// Convenience method that creates the jail directory if it doesn't exist.
    pub fn with_jail_created<P: AsRef<Path>>(jail: P) -> Result<Self, JailedPathError> {
        let jail_path = jail.as_ref();
        std::fs::create_dir_all(jail_path)
            .map_err(|e| JailedPathError::jail_creation_failed(jail_path.to_path_buf(), e))?;
        
        Self::with_jail(jail_path)
    }
}
```

**Usage Patterns**:
```rust
// Pattern 1: Existing directory
let jail = PathValidator::with_jail("/app/storage")?;

// Pattern 2: Ensure directory exists (user control)
std::fs::create_dir_all("/app/storage")?;
let jail = PathValidator::with_jail("/app/storage")?;

// Pattern 3: Convenience method (optional)
let jail = PathValidator::with_jail_created("/app/storage")?;

// Pattern 4: Future directory (containers)
let jail = PathValidator::with_jail("/app/future-storage")?; // ✅ Works!
```

### 🔐 **Conclusion 4: Symlink Attack Reality Check**

**Decision**: Focus on realistic threats, not theoretical ones.

**Real Symlink Threats**:
```rust
// 1. Archive Extraction (Avoid entirely)
// ❌ NEVER allow users to extract arbitrary archives
tar -xf malicious.tar     // Creates: config.txt -> /etc/passwd (symlink)

// Detection approach:
use infer;

fn is_symlink_preserving_archive(data: &[u8]) -> bool {
    if let Some(kind) = infer::get(data) {
        match kind.mime_type() {
            "application/x-tar" => true,     // TAR preserves symlinks
            "application/gzip" => true,      // Likely .tar.gz
            "application/x-bzip2" => true,   // Likely .tar.bz2
            "application/x-xz" => true,      // Likely .tar.xz
            "application/zip" => false,      // ZIP typically doesn't
            _ => false,
        }
    } else {
        false
    }
}

// 2. Administrative Mistakes (Fix deployment)
// ln -s /etc/passwd /app/uploads/config.txt

// 3. Directory Symlinks (Fix deployment)
// ln -s /etc/ /app/uploads/config_dir
```

**Corrected Understanding**:
```rust
// ✅ Simple file uploads DON'T preserve symlinks
// When users upload a symlink file via HTTP, it becomes a regular file
multipart_upload.save("/app/uploads/user_file.txt")?; // Regular file, not symlink

// ❌ Archive extraction DOES preserve symlinks (dangerous)
tar -xf user_uploaded.tar -C /app/uploads/; // Creates actual symlinks!
```

### 🏛️ **Conclusion 5: JailedPath Structure Design**

**Decision**: Store jail root directly in `JailedPath` for virtual root display and sub-jail support.

**Recommended Structure**:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JailedPath<Marker = ()> {
    path: PathBuf,                // The validated path
    jail_root: Arc<PathBuf>,      // Shared jail root for memory efficiency
    _marker: PhantomData<Marker>,
}

impl<Marker> Display for JailedPath<Marker> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Virtual root display: strip jail prefix
        if let Ok(relative) = self.path.strip_prefix(&self.jail_root) {
            write!(f, "/{}", relative.display())
        } else {
            write!(f, "{}", self.path.display()) // Fallback
        }
    }
}
```

**Usage Examples**:
```rust
let jail = PathValidator::with_jail("/app/storage/users")?;
let jailed = jail.try_path("alice/documents/report.pdf")?;

// Virtual root display (user-friendly)
println!("File: {}", jailed);  // Output: "/alice/documents/report.pdf"

// Debug shows full path
println!("Debug: {:?}", jailed);  // Output: "/app/storage/users/alice/documents/report.pdf"

// Sub-jail creation (enabled by storing jail_root)
let user_validator = jailed.into_subjail_with::<UserSpace>()?;
```

### 🎭 **Conclusion 6: TOCTOU Threat Assessment**

**Decision**: TOCTOU attacks are theoretical concerns with limited real-world impact.

**Reality Check**:
If an attacker has filesystem write access to create directories in your jail's parent path, symlink attacks are not your primary concern. They likely have easier attack vectors.

**Practical Implementation**:
```rust
// Optional paranoid validation (feature flag)
#[cfg(feature = "paranoid-validation")]
fn validate_jail_integrity(&self) -> Result<(), JailedPathError> {
    let current_jail = soft_canonicalize(&self.jail)?;
    if current_jail != self.jail {
        return Err(JailedPathError::jail_compromised(
            self.jail.clone(), 
            current_jail, 
            "jail modified since creation"
        ));
    }
    Ok(())
}

// Primary security focus: directory traversal prevention
let safe_path = jail.try_path("../../../etc/passwd")?; // ❌ Blocked!
```

### 🚀 **Conclusion 7: Web Framework Integration Patterns**

**Decision**: Provide comprehensive web framework integration with security-first design.

**Axum Integration Pattern**:
```rust
#[derive(Clone)]
struct AppState {
    user_files: Arc<PathValidator<UserFiles>>,
    public_assets: Arc<PathValidator<PublicAssets>>,
}

async fn serve_user_file(
    State(state): State<AppState>,
    Path((user_id, file_path)): Path<(String, String)>,
) -> Result<Response, StatusCode> {
    // Automatic security - blocks ../../../etc/passwd attempts
    let safe_path: JailedPath<UserFiles> = state.user_files
        .try_path(&format!("{}/{}", user_id, file_path))
        .map_err(|_| StatusCode::FORBIDDEN)?;  // Silent security failure
    
    let content = tokio::fs::read(&safe_path).await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    
    // Clean logging via Display trait
    tracing::info!("Serving file: {}", safe_path);  // "/alice/documents/file.txt"
    
    Ok(content.into_response())
}
```

**Simple Dynamic Validator Pattern**:
```rust
// Authentication: create user-specific validator using simple path joining
async fn authenticate_user(user_id: &str) -> Result<PathValidator<UserSpace>, AuthError> {
    let app_validator = PathValidator::with_jail("/app/storage")?;
    
    // ✅ SECURITY: Simple path joining with validation
    let user_validator = PathValidator::with_jail(
        app_jail.jail().join(&format!("users/{}", user_id))
    )?;
    
    Ok(user_validator)
}

// Session management: create session validator from user validator
async fn create_session(
    user_jail: &PathValidator<UserSpace>,
    session_id: &str
) -> Result<PathValidator<SessionSpace>, SessionError> {
    
    // ✅ SECURITY: Dynamic validator creation with proper validation
    let session_validator = PathValidator::with_jail(
        user_jail.jail().join(&format!("sessions/{}", session_id))
    )?;
    
    Ok(session_validator)
}
```

### 📊 **Conclusion 8: Security Priorities**

**Primary Security Value**: Directory traversal protection (`../../../etc/passwd`)
- **Common threat**: Web applications, user input
- **Easy to exploit**: No special filesystem access required
- **High impact**: Access to sensitive system files

**Secondary Security Value**: Symlink protection
- **Administrative mistakes**: Deployment/configuration errors
- **Archive extraction**: TAR-based formats (avoid entirely)
- **Lower priority**: Requires filesystem write access or admin mistakes

**Code Example - Defense in Depth**:
```rust
impl<Marker> PathValidator<Marker> {
    pub fn try_path<P: AsRef<Path>>(&self, path: P) -> Result<JailedPath<Marker>> {
        let candidate = path.as_ref();
        
        // 1. Lexical validation (blocks .. components)
        self.validate_no_parent_traversal(candidate)?;
        
        // 2. Soft canonicalization (resolves symlinks in existing parts)
        let full_path = self.jail.join(candidate);
        let resolved = soft_canonicalize(&full_path)?;
        
        // 3. Boundary validation (mathematical verification)
        if !resolved.starts_with(&self.jail) {
            return Err(JailedPathError::path_escapes_boundary(resolved, self.jail.clone()));
        }
        
        // 4. Type-state isolation (compile-time safety)
        Ok(JailedPath::new(resolved, self.jail.clone()))
    }
}
```

These conclusions form the foundation of jailed-path's design philosophy: **secure by default, practical by design, honest about threat models**.

## Decision Log

### Why Soft Canonicalization?
- **Security**: Handles non-existent paths safely
- **Performance**: Faster than full filesystem canonicalization  
- **Cross-platform**: Consistent behavior across OS
- **Consistency**: Should be used for BOTH jail creation and path validation

### Critical Design Issue: Mixed Canonicalization Approaches

**Current Problem**: PathValidator uses inconsistent canonicalization:
```rust
// Jail creation - requires existing directory
pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self> {
    let canonical_jail = jail_path.canonicalize()?;  // ❌ std::fs::canonicalize
}

// Path validation - supports non-existent paths
pub fn try_path<P: AsRef<Path>>(&self, path: P) -> Result<JailedPath<Marker>> {
    let resolved = soft_canonicalize(&full_path)?;  // ✅ soft_canonicalize
}
```

**Problems This Causes**:
- Can't create validators for directories that will exist later
- Deployment/container issues where jail dirs are created after validator setup
- Inconsistent behavior between jail creation and path validation
- Testing complexity requiring jail directory creation

**Recommended Fix**: Use soft canonicalization consistently:
```rust
pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self> {
    let canonical_jail = soft_canonicalize(jail.as_ref())?;  // ✅ Consistent!
    
    // Additional validation: if jail exists, ensure it's a directory
    if canonical_jail.exists() && !canonical_jail.is_dir() {
        return Err(JailedPathError::invalid_jail_not_directory(canonical_jail));
    }
    
    Ok(Self { jail: canonical_jail, _marker: PhantomData })
}
```

**Benefits of Consistent Soft Canonicalization**:
- ✅ Can create validators for future directories
- ✅ Better deployment/container support  
- ✅ Consistent security model throughout
- ✅ Simpler testing (no pre-creation required)
- ✅ Maintains security - soft canonicalization is still secure
- ✅ **Separation of concerns**: Path validation vs filesystem operations
- ✅ **User control**: Explicit directory creation with proper permissions
- ✅ **No side effects**: `with_jail()` is purely about validation setup

### Why Type-State Design?
- **Compile-time Safety**: Prevents jail mixing at compile time
- **Zero Runtime Cost**: Type information erased after compilation
- **API Clarity**: Makes security boundaries explicit

### Why No Custom Canonicalization?
- **Security Guarantee**: Cannot verify custom functions are secure
- **Simplicity**: Opinionated approach reduces configuration complexity
- **Trust Model**: Users trust our security expertise, not their own

### Security Analysis: Non-Existent Paths and Symlink Safety

**Key Insight**: Non-existent paths cannot be symlinks, eliminating direct symlink traversal risk for target files.

**Core Security Logic**:
- **Non-existent path** → **Cannot be a symlink** → **No symlink traversal risk for target**
- **Symlinks must exist** to be followed by canonicalization
- **Direct symlink attack on target file is impossible** if the file doesn't exist

**Critical Edge Case: Ancestor Symlinks**

While the target path cannot be a symlink if non-existent, **existing ancestor directories** can contain symlinks that enable escape:

```rust
// Example attack scenario:
// 1. /jail/safe_dir/ exists and is a symlink to /outside/dangerous/
// 2. User requests: "safe_dir/new_file.txt" (new_file.txt doesn't exist)
// 3. Without proper handling: could escape to /outside/dangerous/new_file.txt
```

**How Soft Canonicalization Provides Complete Protection**:

1. **Finds deepest existing ancestor** (`/jail/safe_dir/` - exists, might be symlink)
2. **Canonicalizes existing part** (resolves symlink: `/jail/safe_dir/` → `/outside/dangerous/`)  
3. **Appends non-existing components** (`new_file.txt`)
4. **Validates final resolved path** (`/outside/dangerous/new_file.txt` fails jail boundary check)

**Security Flow Example**:
```rust
// Attack attempt using ancestor symlink
let attack_path = "symlinked_ancestor/new_upload.txt";

// 1. Lexical validation: ✅ No ".." components  
// 2. Soft canonicalization:
//    - Find existing ancestor: /jail/symlinked_ancestor/ (symlink to /evil/)
//    - Canonicalize existing part: /evil/ (symlink target resolved)
//    - Append non-existing: /evil/new_upload.txt  
// 3. Boundary check: ❌ /evil/new_upload.txt not within /jail/
// 4. Result: JailedPathError::PathEscapesBoundary - attack blocked!
```

**Why This Design Is Superior**:

✅ **Complete symlink protection**: Handles both target and ancestor symlinks  
✅ **Non-existent path support**: Enables file creation, uploads, logging  
✅ **No filesystem modification**: Pure mathematical path resolution  
✅ **Consistent security model**: Same protection for existing and non-existent paths  
✅ **Performance**: No temporary file creation during validation  
✅ **Real-world compatibility**: Works with container deployments, testing, web frameworks

**Defense-in-Depth Architecture**:

1. **Lexical validation**: Blocks `..` components before filesystem access
2. **Soft canonicalization**: Resolves all symlinks in existing path segments  
3. **Boundary validation**: Mathematical verification against jail root
4. **Type-state isolation**: Compile-time prevention of jail mixing

This multi-layer approach ensures that even complex attack patterns involving combinations of `..` traversal, symlink redirection, and non-existent path exploitation are mathematically impossible to bypass.

**Research Note**: The insight that "non-existent paths cannot be symlinks" is fundamental to understanding why soft canonicalization with non-existent path support is both secure and necessary. The real security challenge is ancestor symlink resolution, which soft canonicalization handles correctly.

### Security Analysis: TOCTOU Attack Threat Assessment

**Theoretical Vulnerability**: Time-of-Check-Time-of-Use (TOCTOU) attack when jail directory doesn't exist during validator creation.

**Attack Requirements**:
1. **Filesystem write access** to jail parent directory
2. **Precise timing** to win race condition
3. **Sustained access** to maintain symlink
4. **No monitoring** of filesystem changes

**Reality Check**: If an attacker has filesystem write access to create directories in your jail's parent path, symlink attacks are not your primary security concern. They likely have much easier attack vectors available.

**Practical Threat Level**: **MEDIUM** - Theoretical concern with limited real-world impact given the prerequisites.

**Simple Solution: Runtime Jail Validation**

For applications that need TOCTOU protection, implement optional runtime validation:

```rust
impl<Marker> PathValidator<Marker> {
    pub fn try_path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>> {
        let candidate_path = candidate_path.as_ref();
        
        // 1. Lexical validation (primary security value)
        self.validate_no_parent_traversal(candidate_path)?;
        
        // 2. Optional TOCTOU protection (feature flag: "paranoid-validation")
        #[cfg(feature = "paranoid-validation")]
        {
            let current_jail = soft_canonicalize(&self.jail)?;
            if current_jail != self.jail {
                return Err(JailedPathError::jail_compromised(
                    self.jail.clone(), current_jail, "jail modified since creation"
                ));
            }
        }
        
        // 3. Standard soft canonicalization
        let full_path = if candidate_path.is_absolute() {
            candidate_path.to_path_buf()
        } else {
            self.jail.join(candidate_path)
        };
        
        let resolved_path = soft_canonicalize(&full_path)?;
        
        if !resolved_path.starts_with(&self.jail) {
            return Err(JailedPathError::path_escapes_boundary(resolved_path, self.jail.clone()));
        }
        
        Ok(JailedPath::new(resolved_path))
    }
}
```

**Primary Security Value**: Protection against `../../../etc/passwd` style attacks in web applications, which are common and don't require filesystem write access.

**Secondary Security Value**: Protection against symlink-based attacks (where applicable):

1. **Archive Extraction Attacks** (Avoid entirely):
   ```bash
   # ❌ NEVER allow users to extract arbitrary archives
   # TAR formats preserve symlinks; ZIP typically doesn't
   tar -xf malicious.tar     # Creates: config.txt -> /etc/passwd (symlink)
   tar -xzf malicious.tar.gz # Creates symlinks from archive
   tar -xjf malicious.tar.bz2
   # ZIP files usually convert symlinks to regular files, but some tools can preserve them
   ```
   
   **Magic Number Detection** (if you must handle archives):
   ```rust
   // Use dedicated crates for reliable magic number detection:
   // - `infer` crate - Fast and accurate file type detection
   // - `tree_magic_mini` crate - Alternative with MIME type support
   
   use infer;
   
   fn is_symlink_preserving_archive(data: &[u8]) -> bool {
       if let Some(kind) = infer::get(data) {
           match kind.mime_type() {
               // TAR formats that preserve symlinks
               "application/x-tar" => true,
               "application/gzip" => {
                   // Gzip could be .tar.gz, check TAR signature inside
                   // This requires decompression or heuristics
                   true // Conservative: assume tar.gz
               },
               "application/x-bzip2" => true,  // Likely .tar.bz2
               "application/x-xz" => true,     // Likely .tar.xz
               
               // ZIP files typically don't preserve symlinks
               "application/zip" => false,
               
               _ => false,
           }
       } else {
           false
       }
   }
   
   // Manual approach for reference (TAR signature detection):
   // .tar     - Magic: "ustar\0" at offset 257
   // .tar.gz  - Magic: 1F 8B (gzip) + TAR headers
   // .tar.bz2 - Magic: 42 5A 68 (bzip2) + TAR headers
   // .tar.xz  - Magic: FD 37 7A 58 5A (xz) + TAR headers
   ```
   
   **Best Practice**: Don't extract user archives. If you must, use sandboxed extraction with strict validation and symlink filtering.

2. **Pre-existing Symlinks** (Administrative threat):
   ```bash
   # If admin/deployment creates symlinks in jail directories:
   ln -s /etc/passwd /app/uploads/config_file.txt
   ```
   Path validation passes, but reads return sensitive data. **Fix**: Secure deployment processes.

3. **Directory Symlinks** (Administrative threat):
   ```bash
   # If admin/deployment creates symlinked directories:
   ln -s /etc/ /app/uploads/config_dir
   ```
   Accessing "config_dir/passwd" escapes jail. **Fix**: Secure deployment processes.

**Key Insight**: Most symlink attacks require either:
- **Admin/deployment mistakes** (fix your deployment)
- **Allowing users to extract archives** (don't do this)
- **Filesystem write access** (bigger security problem)

**Unprompted Yet**: 
- Make `..` legal to use, but cannot escape Jail Root


**Conclusion**: Directory traversal (`../`) protection is the primary value. Symlink protection is a valuable safety net for administrative mistakes, but proper application design (no user archive extraction) is more important than trying to secure fundamentally unsafe operations.

---

*Last Updated: July 22, 2025*  
*Next Review: August 2025*
