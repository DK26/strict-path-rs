# Ecosystem Integration

> *"Compose strict-path with ecosystem tools — no feature flags needed."*

`strict-path` provides security primitives for path operations. You compose these with popular ecosystem crates directly — no coupling, no feature flags, just clean integration.

**Philosophy**: We don't wrap ecosystem crates. We show you how to use them together effectively.

---

## Table of Contents

- [Temporary Directories (tempfile)](#temporary-directories-tempfile)
- [Portable Application Paths (app-path)](#portable-application-paths-app-path)
- [OS Standard Directories (dirs)](#os-standard-directories-dirs)
- [Serialization & Deserialization (serde)](#serialization--deserialization-serde)
- [Third-Party Crate Integration Patterns](#third-party-crate-integration-patterns)

---

## Temporary Directories (tempfile)

The [`tempfile`](https://crates.io/crates/tempfile) crate provides RAII temporary directories that auto-cleanup on drop. Perfect for extraction staging, upload processing, and test fixtures.

### Basic Integration

```rust
use strict_path::PathBoundary;
use tempfile::TempDir;

fn process_upload() -> Result<(), Box<dyn std::error::Error>> {
    // Create temporary directory with RAII cleanup
    let temp_dir = tempfile::tempdir()?;

    // Establish strict boundary
    let upload_boundary = PathBoundary::try_new(temp_dir.path())?;

    // Now all operations are bounded
    let user_file = upload_boundary.strict_join("user/data.txt")?;
    user_file.create_parent_dir_all()?;
    user_file.write(b"uploaded content")?;

    // Process files...
    let contents = user_file.read_to_string()?;
    println!("Processed: {}", contents);

    Ok(())
    // temp_dir automatically deleted here when dropped
}
```

### With Custom Prefix

```rust
use strict_path::PathBoundary;

fn extraction_staging() -> Result<(), Box<dyn std::error::Error>> {
    // Temp directory with identifiable prefix
    let temp_dir = tempfile::Builder::new()
        .prefix("archive-extract-")
        .tempdir()?;

    let extract_boundary = PathBoundary::try_new(temp_dir.path())?;

    // Extract archive entries safely
    for entry_name in &["file1.txt", "../../etc/passwd", "file2.txt"] {
        match extract_boundary.strict_join(entry_name) {
            Ok(safe_path) => {
                safe_path.create_parent_dir_all()?;
                safe_path.write(b"extracted")?;
                println!("✓ Extracted: {}", safe_path.strictpath_display());
            }
            Err(e) => {
                eprintln!("✗ Blocked malicious path '{}': {}", entry_name, e);
            }
        }
    }

    Ok(())
}
```

### Test Fixtures Pattern

```rust
use strict_path::PathBoundary;
use tempfile::TempDir;

#[test]
fn test_file_processing() {
    let temp = tempfile::tempdir().unwrap();
    let boundary = PathBoundary::try_new(temp.path()).unwrap();

    // Setup test files
    let input = boundary.strict_join("input.txt").unwrap();
    input.write(b"test data").unwrap();

    // Run your code
    process_file(&boundary, "input.txt").unwrap();

    // Verify results
    let output = boundary.strict_join("output.txt").unwrap();
    assert!(output.exists());

    // temp auto-cleans on drop
}

fn process_file(boundary: &PathBoundary, name: &str) -> std::io::Result<()> {
    let input = boundary.strict_join(name).unwrap();
    let output = boundary.strict_join("output.txt").unwrap();

    let data = input.read_to_string()?;
    output.write(data.to_uppercase().as_bytes())?;
    Ok(())
}
```

### VirtualRoot with Temporary Directories

```rust
use strict_path::VirtualRoot;

fn temp_sandbox() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = tempfile::tempdir()?;
    let sandbox = VirtualRoot::try_new(temp_dir.path())?;

    // Escape attempts are clamped
    let user_path = sandbox.virtual_join("../../../etc/passwd")?;

    // Stays within temp directory
    println!("Virtual: {}", user_path.virtualpath_display()); // "/etc/passwd"
    println!("Real: {}", user_path.realpath_display());       // "/<tempdir>/etc/passwd"

    user_path.create_parent_dir_all()?;
    user_path.write(b"safe content")?;

    Ok(())
}
```

---

## Portable Application Paths (app-path)

The [`app-path`](https://crates.io/crates/app-path) crate creates executable-relative paths for truly portable applications (USB drives, different install locations).

**Key API**:
- `AppPath::new()` - Returns executable directory
- `AppPath::with("subdir")` - Returns executable_dir/subdir
- Implements `Deref<Target=Path>` so it can be used directly as a path

### Basic Portable App

```rust
use strict_path::PathBoundary;
use app_path::AppPath;

fn setup_portable_app() -> Result<(), Box<dyn std::error::Error>> {
    // AppPath::with() returns executable_dir/MyPortableApp
    let app_dir = AppPath::with("MyPortableApp");

    // Establish boundary for the app directory
    let boundary = PathBoundary::try_new_create(app_dir)?;

    // Safe operations within app directory
    let config = boundary.strict_join("config/settings.ini")?;
    config.create_parent_dir_all()?;
    config.write(b"[settings]\nportable=true\n")?;

    let data = boundary.strict_join("data/userfiles")?;
    data.create_dir_all()?;

    println!("App directory: {}", boundary.strictpath_display());

    Ok(())
}
```

### Environment Variable Overrides (Testing/CI/CD)

Perfect for testing, CI/CD pipelines, and container deployments where you need to control the data location.

```rust
use strict_path::PathBoundary;
use app_path::AppPath;

fn setup_app_with_override() -> Result<(), Box<dyn std::error::Error>> {
    // Use AppPath's built-in override support
    let env_var = "MY_APP_DATA_DIR";
    let app_path = AppPath::with_override("MyApp", Some(env_var));

    let boundary = PathBoundary::try_new_create(app_path)?;

    println!("Using app directory: {}", boundary.strictpath_display());
    // In production: /path/to/exe/MyApp
    // In CI with MY_APP_DATA_DIR=/tmp/ci-test: /tmp/ci-test

    let log_file = boundary.strict_join("logs/app.log")?;
    log_file.create_parent_dir_all()?;
    log_file.write(b"Application started\n")?;

    Ok(())
}
```

### Multi-Directory Pattern

```rust
use strict_path::PathBoundary;
use app_path::AppPath;

struct AppPaths {
    config: PathBoundary<ConfigDir>,
    data: PathBoundary<DataDir>,
    cache: PathBoundary<CacheDir>,
}

struct ConfigDir;
struct DataDir;
struct CacheDir;

impl AppPaths {
    fn new(app_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // AppPath::with() returns executable_dir/app_name
        let base_dir = AppPath::with(app_name);

        Ok(Self {
            config: PathBoundary::try_new_create(base_dir.join("config"))?,
            data: PathBoundary::try_new_create(base_dir.join("data"))?,
            cache: PathBoundary::try_new_create(base_dir.join("cache"))?,
        })
    }
}

fn use_app_paths() -> Result<(), Box<dyn std::error::Error>> {
    let paths = AppPaths::new("MyApp")?;

    let settings = paths.config.strict_join("settings.toml")?;
    settings.write(b"theme = 'dark'\n")?;

    let user_db = paths.data.strict_join("users.db")?;
    user_db.write(b"database content")?;

    let temp_cache = paths.cache.strict_join("thumbnails/thumb1.png")?;
    temp_cache.create_parent_dir_all()?;
    temp_cache.write(b"cached data")?;

    Ok(())
}
```

---

## OS Standard Directories (dirs)

The [`dirs`](https://crates.io/crates/dirs) crate provides cross-platform access to standard user directories (config, data, cache, downloads, etc.).

### Configuration Directory

```rust
use strict_path::PathBoundary;

fn setup_config() -> Result<(), Box<dyn std::error::Error>> {
    // Get platform-specific config directory
    let config_base = dirs::config_dir()
        .ok_or("No config directory available")?;

    // Create app-specific subdirectory boundary
    let app_config = config_base.join("myapp");
    let boundary = PathBoundary::try_new_create(&app_config)?;

    // Platform-specific locations:
    // Linux:   ~/.config/myapp/
    // Windows: C:\Users\Alice\AppData\Roaming\myapp\
    // macOS:   ~/Library/Application Support/myapp/

    let settings = boundary.strict_join("settings.toml")?;
    settings.write(b"[app]\nversion = '1.0'\n")?;

    Ok(())
}
```

### Multi-Directory Application

```rust
use strict_path::PathBoundary;

struct AppDirectories {
    config: PathBoundary,
    data: PathBoundary,
    cache: PathBoundary,
}

impl AppDirectories {
    fn new(app_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config_base = dirs::config_dir()
            .ok_or("No config directory")?;
        let data_base = dirs::data_dir()
            .ok_or("No data directory")?;
        let cache_base = dirs::cache_dir()
            .ok_or("No cache directory")?;

        Ok(Self {
            config: PathBoundary::try_new_create(config_base.join(app_name))?,
            data: PathBoundary::try_new_create(data_base.join(app_name))?,
            cache: PathBoundary::try_new_create(cache_base.join(app_name))?,
        })
    }
}

fn use_standard_dirs() -> Result<(), Box<dyn std::error::Error>> {
    let dirs = AppDirectories::new("MyApp")?;

    // Config: user preferences
    let prefs = dirs.config.strict_join("preferences.json")?;
    prefs.write(br#"{"theme": "dark"}"#)?;

    // Data: persistent user data
    let database = dirs.data.strict_join("app.db")?;
    database.write(b"database data")?;

    // Cache: temporary/regenerable data
    let thumbnail = dirs.cache.strict_join("thumbs/image1.jpg")?;
    thumbnail.create_parent_dir_all()?;
    thumbnail.write(b"thumbnail data")?;

    Ok(())
}
```

### User Content Directories

```rust
use strict_path::PathBoundary;

fn access_user_content() -> Result<(), Box<dyn std::error::Error>> {
    // Downloads directory
    if let Some(downloads) = dirs::download_dir() {
        let boundary = PathBoundary::try_new(&downloads)?;

        // Safe access to user-selected file
        let user_input = "report.pdf"; // From file picker or CLI
        let file = boundary.strict_join(user_input)?;

        if file.exists() {
            let data = file.read()?;
            println!("Processing file: {} bytes", data.len());
        }
    }

    // Documents directory
    if let Some(documents) = dirs::document_dir() {
        let boundary = PathBoundary::try_new(&documents)?;

        let export = boundary.strict_join("exports/data.csv")?;
        export.create_parent_dir_all()?;
        export.write(b"col1,col2\nval1,val2\n")?;

        println!("Exported to: {}", export.strictpath_display());
    }

    Ok(())
}
```

---

## Serialization & Deserialization (serde)

For JSON, TOML, YAML, and other formats, use `FromStr` trait with manual validation — giving you explicit control over path validation.

### Deserializing Boundaries with FromStr

`PathBoundary` and `VirtualRoot` implement `FromStr`, so they deserialize automatically with serde:

```rust
use strict_path::PathBoundary;
use serde::Deserialize;

#[derive(Deserialize)]
struct AppConfig {
    // Deserializes via FromStr automatically
    upload_dir: PathBoundary,
    data_dir: PathBoundary,
}

fn load_config() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{
        "upload_dir": "./uploads",
        "data_dir": "./data"
    }"#;

    let config: AppConfig = serde_json::from_str(json)?;

    // Boundaries are ready to use
    let file = config.upload_dir.strict_join("user/file.txt")?;
    file.create_parent_dir_all()?;
    file.write(b"content")?;

    Ok(())
}
```

### Explicit Path Validation Pattern

For paths within boundaries, deserialize as `String` and validate explicitly:

```rust
use strict_path::PathBoundary;
use serde::Deserialize;

#[derive(Deserialize)]
struct UploadRequest {
    boundary: PathBoundary,
    user_paths: Vec<String>, // Validate these manually
}

fn handle_upload(json: &str) -> Result<(), Box<dyn std::error::Error>> {
    let request: UploadRequest = serde_json::from_str(json)?;

    // Explicit validation - security-conscious and visible
    for path_str in &request.user_paths {
        match request.boundary.strict_join(path_str) {
            Ok(safe_path) => {
                safe_path.create_parent_dir_all()?;
                safe_path.write(b"uploaded")?;
                println!("✓ Uploaded: {}", safe_path.strictpath_display());
            }
            Err(e) => {
                eprintln!("✗ Rejected '{}': {}", path_str, e);
            }
        }
    }

    Ok(())
}
```

### Web API Example (Axum)

```rust
use strict_path::PathBoundary;
use serde::{Deserialize, Serialize};
use axum::{Json, extract::State};

#[derive(Deserialize)]
struct FileUpload {
    filename: String, // User input - must validate!
    content: String,
}

#[derive(Serialize)]
struct UploadResponse {
    success: bool,
    path: String,
}

struct AppState {
    upload_boundary: PathBoundary,
}

async fn upload_file(
    State(state): State<AppState>,
    Json(upload): Json<FileUpload>,
) -> Json<UploadResponse> {
    // Explicit validation of user input
    match state.upload_boundary.strict_join(&upload.filename) {
        Ok(safe_path) => {
            safe_path.create_parent_dir_all().ok();
            safe_path.write(upload.content.as_bytes()).ok();

            Json(UploadResponse {
                success: true,
                path: safe_path.strictpath_display().to_string(),
            })
        }
        Err(e) => {
            Json(UploadResponse {
                success: false,
                path: format!("Error: {}", e),
            })
        }
    }
}
```

### Config File Pattern

```rust
use strict_path::PathBoundary;
use serde::Deserialize;

#[derive(Deserialize)]
struct ServerConfig {
    // Boundaries deserialize via FromStr
    public_assets: PathBoundary<PublicAssets>,
    user_uploads: PathBoundary<UserUploads>,

    // Other config
    port: u16,
    host: String,
}

struct PublicAssets;
struct UserUploads;

fn load_server_config() -> Result<(), Box<dyn std::error::Error>> {
    let toml_str = r#"
        public_assets = "./public"
        user_uploads = "./uploads"
        port = 8080
        host = "127.0.0.1"
    "#;

    let config: ServerConfig = toml::from_str(toml_str)?;

    // Use boundaries immediately
    let favicon = config.public_assets.strict_join("favicon.ico")?;
    println!("Favicon: {}", favicon.strictpath_display());

    let user_file = config.user_uploads.strict_join("user123/file.txt")?;
    user_file.create_parent_dir_all()?;

    Ok(())
}
```

### Serializing Paths

```rust
use strict_path::{PathBoundary, StrictPath};
use serde_json::json;

fn serialize_paths() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = PathBoundary::try_new_create("./data")?;
    let file = boundary.strict_join("config/settings.json")?;

    // Serialize to JSON using display methods
    let response = json!({
        "boundary": boundary.strictpath_display().to_string(),
        "file": file.strictpath_display().to_string(),
        "file_name": file.strictpath_file_name()
            .unwrap()
            .to_string_lossy(),
    });

    println!("{}", serde_json::to_string_pretty(&response)?);

    Ok(())
}
```

---

## Third-Party Crate Integration Patterns

When integrating with crates like `tar`, `zip`, `walkdir`, or other filesystem libraries, follow these patterns to maintain security.

### Archive Crates (tar, zip)

Archive crates often expect file handles or byte slices. Use strict-path's built-in I/O to read content, then pass bytes to the archive crate.

**Pattern: Read with strict-path, write with archive crate**

```rust
use strict_path::PathBoundary;
use tar::Builder;

fn create_archive(
    source_dir: &PathBoundary,
    files: &[&str],  // Untrusted file list from user/config
) -> std::io::Result<Vec<u8>> {
    let mut archive = Builder::new(Vec::new());

    for requested_file in files {
        // Validate each path through strict-path
        let safe_path = source_dir.strict_join(requested_file)?;

        // Read content using strict-path's I/O
        let content = safe_path.read()?;

        // Pass bytes to archive crate (no path escapes possible)
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();

        archive.append_data(&mut header, requested_file, content.as_slice())?;
    }

    archive.into_inner()
}
```

**Anti-pattern to avoid:**
```rust
// ❌ WRONG: Passing interop_path() to archive crate for reading
let file = std::fs::File::open(path.interop_path())?;
archive.append_file(path_str, &mut file)?;

// ✅ CORRECT: Read with strict-path, pass bytes
let content = path.read()?;
archive.append_data(&mut header, path_str, content.as_slice())?;
```

### When `interop_path()` Is Acceptable

> ⚠️ **Security Warning**: `interop_path()` returns the **real host filesystem path**. Never expose it to end-users (API responses, error messages, logs visible to clients). In multi-tenant or cloud scenarios, this leaks internal server structure. Use `virtualpath_display()` for user-facing output.

Use `interop_path()` when:
1. **The crate only needs to read from a validated path** and you've already validated it
2. **The crate provides no way to accept bytes** (rare, but some do)
3. **You're passing to strict-path's own methods** like `strict_copy()` or `strict_rename()` which re-validate
4. **The path will ONLY be used for internal I/O operations** — never returned to end-users

```rust
// ✅ OK: WalkDir only reads, doesn't write or follow user input
use walkdir::WalkDir;
let boundary = PathBoundary::try_new("./data")?;
for entry in WalkDir::new(boundary.interop_path()) {
    let entry = entry?;
    // Re-validate each discovered path before operations
    if let Ok(relative) = entry.path().strip_prefix(boundary.interop_path()) {
        let safe_path = boundary.strict_join(relative)?;
        // Now safe to use
    }
}

// ✅ OK: strict_copy re-validates the destination
let src = boundary.strict_join("file.txt")?;
src.strict_copy("backup/file.txt")?;  // Destination is re-validated internally
```

**When NOT to use `interop_path()`:**
- For any write operation to untrusted paths
- When the third-party crate would follow symlinks you haven't validated
- When you could use strict-path's built-in I/O instead

### Directory Traversal Crates (walkdir, globwalk)

When using directory traversal crates, re-validate discovered paths:

```rust
use strict_path::PathBoundary;
use walkdir::WalkDir;

fn process_all_files(
    boundary: &PathBoundary,
) -> std::io::Result<Vec<String>> {
    let mut results = Vec::new();

    for entry in WalkDir::new(boundary.interop_path()) {
        let entry = entry?;

        // Skip directories, only process files
        if !entry.file_type().is_file() {
            continue;
        }

        // Re-validate through strict-path before any I/O
        let relative = entry.path()
            .strip_prefix(boundary.interop_path())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let safe_path = boundary.strict_join(relative)?;

        // Now safe to read/process
        let content = safe_path.read_to_string()?;
        results.push(content);
    }

    Ok(results)
}
```

**Or use the built-in `strict_read_dir()` for simpler cases:**

```rust
use strict_path::PathBoundary;

fn list_files(boundary: &PathBoundary) -> std::io::Result<Vec<String>> {
    let mut results = Vec::new();

    for entry in boundary.into_strictpath()?.strict_read_dir()? {
        let path = entry?;
        if path.is_file() {
            results.push(path.read_to_string()?);
        }
    }

    Ok(results)
}
```

### Summary: The "Read Content, Pass Bytes" Pattern

For maximum security with third-party crates:

1. **Validate the path** with `strict_join()` or `virtual_join()`
2. **Read content** using strict-path's built-in I/O (`read()`, `read_to_string()`, `open_file()`)
3. **Pass bytes/handles** to the third-party crate

This ensures:
- Path validation happens through strict-path
- No symlink-following surprises from third-party crates
- Clear separation between validation and I/O

---

## Why No Feature Flags?

**Philosophy**: `strict-path` provides security primitives. You compose them with ecosystem tools.

**Benefits of direct integration:**

1. ✅ **Full control** - Access all options of external crates, not just what we expose
2. ✅ **No version coupling** - Use any version of `tempfile`, `dirs`, etc.
3. ✅ **Clear dependencies** - You explicitly add what you use
4. ✅ **Reduced bloat** - Pay only for what you import
5. ✅ **Explicit validation** - Security operations are visible in your code

**Trade-off**: Write one extra line of code for explicit, secure integration.

---

## Quick Reference

```rust
// Temporary directories
let temp = tempfile::tempdir()?;
let boundary = PathBoundary::try_new(temp.path())?;

// Portable app paths
use app_path::AppPath;
let app_path = AppPath::with("MyApp");  // Relative to executable directory
let boundary = PathBoundary::try_new_create(&app_path)?;

// OS directories
let config = dirs::config_dir().ok_or("No config dir")?;
let boundary = PathBoundary::try_new_create(config.join("myapp"))?;

// Deserialization (FromStr)
#[derive(Deserialize)]
struct Config {
    boundary: PathBoundary,  // Automatic via FromStr
    user_path: String,        // Manual validation
}
```

---

## See Also

- [Real-World Examples](./examples/overview.md)
- [Best Practices](./best_practices.md)
- [Axum Tutorial](./axum_tutorial/overview.md)
