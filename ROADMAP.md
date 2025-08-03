# Jailed Path Roadmap

> **Advanced path validation: symlink-safe, multi-jail, compile-time guaranteed**  
> *Type-State Police™ - Keeping your paths in line since 2025*

This roadmap outlines the planned evolution of the `jailed-path` crate based on ecosystem research, user needs analysis, and security-first principles.



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

| Phase                                            | Feature                                           | Status | Priority     | Notes                                                                                                          |
| ------------------------------------------------ | ------------------------------------------------- | ------ | ------------ | -------------------------------------------------------------------------------------------------------------- |
| **Phase 1: Core UX & Web Integration (v0.1.0)**  |
| 1.1                                              | Virtual Root Display                              | ✅      | 1 - CRITICAL | Implemented via `Display` trait and `virtual_path()` method.                                                   |
| 1.1.0                                            | **Fix jail creation canonicalization**            | ✅      | 1 - CRITICAL | Now uses `soft_canonicalize` in `PathValidator::with_jail`; supports non-existent jails.                       |
| 1.1.1                                            | Store jail root as `Arc<ValidatedPath>`           | ✅      | 1 - CRITICAL | Implemented for memory-efficient jail root sharing.                                                            |
| 1.1.3                                            | Implement `Display` trait                         | ✅      | 1 - CRITICAL | Implemented for clean, virtual root display.                                                                   |
| 1.1.4                                            | Add debug formatting                              | ✅      | 2 - HIGH     | Implemented custom `Debug` to show full path and jail root.                                                    |
| 1.2                                              | Web Framework Integration                         | ⏳      | 2 - HIGH     | Examples and patterns for Axum and other frameworks.                                                           |
| 1.2.1                                            | `examples/axum_file_server.rs`                    | 🎯      | 2 - HIGH     | **NEXT:** Create a complete, working Axum example.                                                             |
| 1.2.2                                            | `examples/actix_web_integration.rs`               | ⏳      | 3 - MEDIUM   | Actix Web integration example.                                                                                 |
| 1.2.3                                            | Documentation: web framework patterns             | ⏳      | 2 - HIGH     | Guide on using `JailedPath` in web app state.                                                                  |
| 1.3                                              | Serde Support                                     | ⏳      | 1 - CRITICAL | Essential for web API integration.                                                                             |
| 1.3.1                                            | Add `serde` feature flag                          | ⏳      | 1 - CRITICAL | Make `serde` an optional dependency.                                                                           |
| 1.3.2                                            | Implement `Serialize` for `JailedPath`            | ⏳      | 1 - CRITICAL | Serialize as a secure, virtual path string.                                                                    |
| 1.3.3                                            | Custom deserializer helpers                       | ⏳      | 2 - HIGH     | Provide helpers for validating paths during deserialization.                                                   |
| 1.4                                              | Core Validation Functions                         | ⏳      | 1 - CRITICAL | Simple public API for one-off path validation.                                                                 |
| 1.4.1                                            | `try_jail<Marker=()>(jail, path)` function        | ✅      | 1 - CRITICAL | Create a simple, top-level function for easy validation.                                                       |
| **Phase 2: Secure API & Ergonomics (v0.2.0)**    |
| 2.1                                              | Secure Path Manipulation API                      | ✅      | 1 - CRITICAL | All path manipulation is done via secure `virtual_*` methods.                                                  |
| 2.1.1                                            | `virtual_join()` method                           | ✅      | 1 - CRITICAL | Implemented for secure path joining.                                                                           |
| 2.1.2                                            | `virtual_parent()` method                         | ✅      | 1 - CRITICAL | Implemented for secure parent navigation.                                                                      |
| 2.1.3                                            | `virtual_with_file_name()` method                 | ✅      | 2 - HIGH     | Implemented for secure file name replacement.                                                                  |
| 2.1.4                                            | `virtual_with_extension()` method                 | ✅      | 2 - HIGH     | Implemented for secure extension replacement.                                                                  |
| 2.2                                              | Explicit Path Access API                          | ✅      | 1 - CRITICAL | API requires explicit calls to access the inner path, preventing misuse.                                       |
| 2.2.1                                            | ~~`real_path()` method~~                          | ❌      | ~~CRITICAL~~ | **Removed:** Discourages raw `&Path` use. Philosophy is to add specialized methods to `JailedPath` as needed. Forcing an escape hatch requires `to_string()` or `unjail()`, making the developer's intent explicit. |
| 2.2.2                                            | `unjail()` method                                 | ✅      | 1 - CRITICAL | Explicitly consumes `JailedPath` to return the inner `PathBuf`, removing safety guarantees.                    |
| 2.2.3                                            | `to_bytes()` / `into_bytes()` methods             | ✅      | 2 - HIGH     | Implemented for ecosystem compatibility.                                                                       |
| 2.3                                              | Ergonomic Trait Implementations                   | ✅      | 1 - CRITICAL | `PartialEq`, `Eq`, `Hash`, `Ord`, `PartialOrd` are implemented for seamless use in collections.                |

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
- **Deref to Path (2.3.6)**: Enables zero-cost access to all Path methods - fundamental compatibility
- **~~Essential traits (2.3.7)~~**: ~~`AsRef`, `Borrow`, `PartialEq` needed for collections and ecosystem integration~~ (❌ Cancelled, see below)
- **Core path methods (2.3.1, 2.3.2)**: `join()` and `parent()` are essential for path manipulation
- **Conversion methods (2.3.5, 2.3.5a)**: `into_path_buf()` and `into_inner()` needed for ecosystem compatibility

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
use jailed_path::{PathValidator, JailedPath};

// Create validator for user files
struct UserFiles;
let validator: PathValidator<UserFiles> = PathValidator::with_jail("/app/storage/users")?;

// Validate and create jailed path
let jailed: JailedPath<UserFiles> = validator.try_path("alice/documents/report.pdf")?;

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
    user_files: PathValidator<UserFiles>,    // No Arc needed - already efficient
    public_assets: PathValidator<PublicAssets>, // Arc<PathBuf> internally
}

async fn serve_user_file(
    State(state): State<AppState>,
    Path((user_id, file_path)): Path<(String, String)>,
) -> Result<Response, StatusCode> {
    let safe_path = state.user_files.try_path(&format!("{}/{}", user_id, file_path))?;
    // Escape attempts automatically blocked, return 403
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
use jailed_path::{PathValidator, JailedPath};
use std::sync::Arc;

struct UserFiles;
struct PublicAssets;

#[derive(Clone)]
struct AppState {
    user_files: PathValidator<UserFiles>,    // PathValidator is cheap to clone
    assets: PathValidator<PublicAssets>,     // Arc<PathBuf> shared internally
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
        user_files: PathValidator::with_jail("/app/storage/users")?,    // No Arc wrapping
        assets: PathValidator::with_jail("/app/public")?,               // PathValidator handles efficiency
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
use jailed_path::{PathValidator, JailedPath};

struct UserFiles;

#[derive(Serialize, Deserialize)]
struct FileInfo {
    // Serializes using Display trait (virtual root)
    path: JailedPath<UserFiles>,  // Will serialize as "/users/alice/document.pdf"
    size: u64,
    modified: SystemTime,
}

// Serialization example
let validator = PathValidator::with_jail("/app/storage")?;
let jailed = validator.try_path("users/alice/document.pdf")?;

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
    USER_VALIDATOR.try_path(&path_str).map_err(serde::de::Error::custom)
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
use jailed_path::{PathValidator, JailedPath};

struct UserFiles;
let validator = PathValidator::with_jail("/app/storage")?;
let jailed: JailedPath<UserFiles> = validator.try_path("users/alice/файл.txt")?;  // Non-UTF-8 filename

// UTF-8 methods for web development
match jailed.to_str() {
    Some(utf8_path) => {
        // Perfect for JSON APIs - but this gives FULL path
        // For clean API responses, use Display formatting:
        let clean_display = format!("{}", jailed);  // "/users/alice/файл.txt" (virtual root)
        let response = json!({ "path": clean_display });
    }
    None => {
        // Fallback for non-UTF-8 filenames
        let lossy_display = format!("{}", jailed);  // Uses Display trait with lossy conversion
        log::warn!("Non-UTF-8 filename displayed as: {}", lossy_display);
    }
}

// For the rare case you need relative UTF-8 string manually:
let full_path_str = jailed.to_str().unwrap();  // "/app/storage/users/alice/file.txt"
let relative_str = full_path_str.strip_prefix("/app/storage").unwrap();  // "/users/alice/file.txt"

// But usually just use Display trait:
println!("User sees: {}", jailed);  // Automatic virtual root display

// Still works with all standard Path methods via Deref
let extension = jailed.extension();  // Option<&OsStr>
let file_name = jailed.file_name();  // Option<&OsStr>
let is_absolute = jailed.is_absolute();  // bool

// Use with existing file I/O functions
std::fs::metadata(&jailed)?;  // Works seamlessly via AsRef<Path>
tokio::fs::read(&jailed).await?;  // Works with async file I/O
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
/// let file = try_jail("/user/files", "documents/report.pdf")?;
/// 
/// // With type marker for compile-time safety
/// struct UserFiles;
/// let file: JailedPath<UserFiles> = try_jail("/user/files", "documents/report.pdf")?;
/// ```
pub fn try_jail<Marker = (), P1, P2>(jail: P1, path: P2) -> Result<JailedPath<Marker>, JailedPathError>
where 
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    PathValidator::<Marker>::with_jail(jail)?.try_path(path)
}
```

**Usage Examples**:
```rust
use jailed_path::try_jail;

// Simple usage - defaults to JailedPath<()>
let file = try_jail("/user/files", "documents/report.pdf")?;
println!("File: {}", file); // "/documents/report.pdf"

// Direct use with file operations
let config = try_jail("/app/config", "app.toml")?;
let settings: AppSettings = toml::from_str(&std::fs::read_to_string(&config)?)?;

// Type-safe validation with explicit marker type
struct UserFiles;
let file: JailedPath<UserFiles> = try_jail("/user/files", "documents/report.pdf")?;

// Or use turbofish syntax for explicit typing
let file = try_jail::<UserFiles, _, _>("/user/files", "documents/report.pdf")?;

// Attack prevention examples - these will return Err()
assert!(try_jail("/jail", "../../../etc/passwd").is_err()); // blocked!
assert!(try_jail("/jail", "/etc/passwd").is_err());          // absolute path blocked
assert!(try_jail("/jail", "safe/file.txt").is_ok());         // allowed

// Error handling for security
match try_jail("/app/public", &user_input) {
    Ok(safe_path) => {
        // Safe to proceed with file operations
        let content = tokio::fs::read(&safe_path).await?;
        Ok(content)
    }
    Err(_) => Err(ApiError::Forbidden), // Path outside jail
}

// One-line file operations
let config = try_jail("/app/config", "app.toml")?;
let settings: AppSettings = toml::from_str(&std::fs::read_to_string(&config)?)?;

// Database path validation
fn store_user_file(user_id: &str, filename: &str) -> Result<(), DbError> {
    let file_path = try_jail("/app/uploads", &format!("{}/{}", user_id, filename))?;
    
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
// One-off operations - use try_jail with default marker
let temp_file = try_jail("/tmp", "upload_123.txt")?;

// Multiple validations - use PathValidator (more efficient)
let validator = PathValidator::with_jail("/user/files")?;
let doc1 = validator.try_path("document1.pdf")?;
let doc2 = validator.try_path("document2.pdf")?;
let doc3 = validator.try_path("document3.pdf")?;

// Type safety needed - use explicit type annotation or turbofish
struct UserFiles;
let file: JailedPath<UserFiles> = try_jail("/user/files", "doc.pdf")?;
// or
let file = try_jail::<UserFiles, _, _>("/user/files", "doc.pdf")?;
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
- **Path Manipulation**: All path modifications (joining, getting parent, etc.) **must** be done using the provided `virtual_*` methods (`virtual_join()`, `virtual_parent()`, etc.). These methods are guaranteed to be jail-safe.
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
    let backup_path = path.virtual_with_extension("backup").ok_or("Backup path failed")?;
    
    // CORRECT: Use the explicit `to_string_lossy()` for functions expecting a &Path.
    std::fs::copy(path.to_string_lossy().as_ref(), backup_path.to_string_lossy().as_ref())?;
    
    Ok(String::from_utf8_lossy(&content).to_string())
}

// Collections work seamlessly due to Hash and PartialEq implementations.
let mut file_cache: HashMap<JailedPath<UserFiles>, Vec<u8>> = HashMap::new();

let validator = PathValidator::with_jail("/app/storage")?;
let jailed = validator.try_path("users/alice/config.toml")?;

file_cache.insert(jailed.clone(), b"cached content".to_vec());

// Path manipulation is explicit and safe.
let config_dir = jailed.virtual_parent().unwrap();
let log_file = config_dir.virtual_join("app.log").unwrap();
let backup_config = jailed.virtual_with_file_name("config.backup.toml").unwrap();

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
   let new_file = validator.try_path("uploads/user123/new_document.pdf")?;
   tokio::fs::write(&new_file, content).await?; // Can't create new files!
   ```

2. **Web Application File Serving**:
   ```rust
   // ❌ User uploads would be impossible
   async fn upload_handler(file_data: Vec<u8>) -> Result<()> {
       let upload_path = validator.try_path("temp/upload_123.tmp")?; // Fails!
       std::fs::write(&upload_path, file_data)?; // Never reached
   }
   ```

3. **Log File Creation**:
   ```rust
   // ❌ New log files couldn't be validated
   let log_file = validator.try_path("logs/app_2025_07_22.log")?; // Fails!
   let mut logger = File::create(&log_file)?; // Never works
   ```

4. **Backup & Export Operations**:
   ```rust
   // ❌ Can't create backup files
   let backup_path = validator.try_path("backups/db_backup_20250722.sql")?; // Fails!
   ```

5. **Session Management**:
   ```rust
   // ❌ Temporary session files couldn't be created
   let session_file = validator.try_path("sessions/sess_abc123.json")?; // Fails!
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
let validator = PathValidator::with_jail("/app/storage")?;

// File creation (path doesn't exist yet)
let new_file = validator.try_path("uploads/user123/document.pdf")?;
tokio::fs::write(&new_file, data).await?;

// Log file creation
let log_file = validator.try_path("logs/app_2025_07_22.log")?;
File::create(&log_file)?;

// Backup operations
let backup = validator.try_path("backups/db_backup.sql")?;

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

### 🏗️ **Conclusion 2: Consistent Soft Canonicalization**

**Decision**: Use soft canonicalization for both jail creation and path validation.

**Problem with Mixed Approach**:
```rust
// ❌ CURRENT PROBLEM: Inconsistent canonicalization
pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self> {
    let canonical_jail = jail_path.canonicalize()?;  // Requires existing directory
}

pub fn try_path<P: AsRef<Path>>(&self, path: P) -> Result<JailedPath<Marker>> {
    let resolved = soft_canonicalize(&full_path)?;  // Supports non-existent paths
}
```

**Recommended Solution**:
```rust
// ✅ CORRECT: Consistent soft canonicalization
pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self> {
    let canonical_jail = soft_canonicalize(jail.as_ref())?;
    
    // Validate that if jail exists, it must be a directory
    if canonical_jail.exists() && !canonical_jail.is_dir() {
        return Err(JailedPathError::invalid_jail_not_directory(canonical_jail));
    }
    
    Ok(Self { jail: canonical_jail, _marker: PhantomData })
}
```

**Benefits Demonstrated**:
```rust
// ✅ Container deployment
let validator = PathValidator::with_jail("/app/storage")?; // Works before dir exists
std::fs::create_dir_all("/app/storage")?; // Create later

// ✅ Testing simplicity
#[test]
fn test_validation() {
    let validator = PathValidator::with_jail("/tmp/test-jail")?; // No pre-creation needed
    // ... test validation logic
}

// ✅ Dynamic workspaces
let workspace = format!("/app/workspaces/{}", session_id);
let validator = PathValidator::with_jail(&workspace)?; // Works immediately
```

### 📁 **Conclusion 3: No Automatic Directory Creation**

**Decision**: `with_jail()` should NOT automatically create directories.

**Rationale**:
- **Separation of concerns**: Path validation vs filesystem operations
- **User control**: Explicit directory creation with proper permissions
- **No side effects**: `with_jail()` is purely about validation setup
- **Security**: Avoid accidental directory creation in wrong locations

**Recommended API Design**:
```rust
impl<Marker> PathValidator<Marker> {
    /// Creates a validator for the given jail path.
    /// The jail directory does not need to exist.
    /// If the jail path exists, it must be a directory.
    pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self, JailedPathError> {
        let canonical_jail = soft_canonicalize(jail.as_ref())?;
        
        if canonical_jail.exists() && !canonical_jail.is_dir() {
            return Err(JailedPathError::invalid_jail_not_directory(canonical_jail));
        }
        
        Ok(Self { jail: canonical_jail, _marker: PhantomData })
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
let validator = PathValidator::with_jail("/app/storage")?;

// Pattern 2: Ensure directory exists (user control)
std::fs::create_dir_all("/app/storage")?;
let validator = PathValidator::with_jail("/app/storage")?;

// Pattern 3: Convenience method (optional)
let validator = PathValidator::with_jail_created("/app/storage")?;

// Pattern 4: Future directory (containers)
let validator = PathValidator::with_jail("/app/future-storage")?; // ✅ Works!
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
let validator = PathValidator::with_jail("/app/storage/users")?;
let jailed = validator.try_path("alice/documents/report.pdf")?;

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
let safe_path = validator.try_path("../../../etc/passwd")?; // ❌ Blocked!
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
        app_validator.jail().join(&format!("users/{}", user_id))
    )?;
    
    Ok(user_validator)
}

// Session management: create session validator from user validator
async fn create_session(
    user_validator: &PathValidator<UserSpace>,
    session_id: &str
) -> Result<PathValidator<SessionSpace>, SessionError> {
    
    // ✅ SECURITY: Dynamic validator creation with proper validation
    let session_validator = PathValidator::with_jail(
        user_validator.jail().join(&format!("sessions/{}", session_id))
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
