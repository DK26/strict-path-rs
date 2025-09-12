# Features

The `strict-path` crate provides several optional features that extend functionality while maintaining the core security guarantees. All features are disabled by default to keep the core library lightweight.

## Available Features

### `dirs` - OS Standard Directories
Cross-platform access to operating system standard directories following platform conventions (XDG Base Directory on Linux, Known Folder API on Windows, Apple Standard Directories on macOS).

```toml
[dependencies]
strict-path = { version = "0.1.0-alpha.1", features = ["dirs"] }
```

Enables constructors like:
- `PathBoundary::try_new_os_config("MyApp")` - Application configuration
- `PathBoundary::try_new_os_data("MyApp")` - Application data storage  
- `PathBoundary::try_new_os_cache("MyApp")` - Application cache
- `PathBoundary::try_new_os_documents()` - User documents directory
- And many more...

**[→ Full OS Directories Documentation](./os_directories.md)**

### `serde` - Serialization Support
Adds `Serialize` implementations for `StrictPath` and `VirtualPath`, plus deserialization helpers for secure path handling in web APIs and configuration files.

```toml
[dependencies]
strict-path = { version = "0.1.0-alpha.1", features = ["serde"] }
```

Enables:
- Direct serialization: `serde_json::to_string(&strict_path)?`
- Context-aware deserialization helpers
- Integration with web frameworks and config parsers

### `tempfile` - Temporary Directories
RAII temporary directories that are automatically cleaned up when dropped, with each `PathBoundary` getting a unique temporary directory.

```toml
[dependencies]  
strict-path = { version = "0.1.0-alpha.1", features = ["tempfile"] }
```

Enables:
- `PathBoundary::try_new_temp()` - Unique temporary directory
- `PathBoundary::try_new_temp_with_prefix("my-prefix")` - Custom prefix
- Automatic cleanup when the boundary is dropped

### `app-path` - Portable Application Directories
Integration with the `app-path` crate for discovering application directories relative to the executable with environment variable overrides.

```toml
[dependencies]
strict-path = { version = "0.1.0-alpha.1", features = ["app-path"] }
```

Enables portable application directory discovery for:
- Configuration directories relative to executable
- Data directories with environment overrides
- Cross-platform deployment scenarios

## Feature Combinations

Features can be combined as needed:

```toml
[dependencies]
strict-path = { 
    version = "0.1.0-alpha.1", 
    features = ["dirs", "serde", "tempfile"] 
}
```

## Design Philosophy

All optional features:
- **Maintain security**: Never compromise path boundary enforcement
- **Zero-cost when unused**: Features add no overhead if not enabled  
- **Composable**: Features work together seamlessly
- **Platform-aware**: Handle platform differences gracefully
- **Standards-compliant**: Follow established conventions and specifications

## Migration and Compatibility

Features are additive and backward-compatible. Enabling new features won't break existing code, and the core API remains stable across all feature combinations.

When features are unavailable:
- Missing feature methods result in compile-time errors (not runtime failures)
- Documentation clearly indicates feature requirements
- Examples include feature guards for conditional compilation

## API Reference Summary

### Core Types Comparison

| Feature                   | `Path`/`PathBuf`                      | `StrictPath`                         | `VirtualPath`                                |
| ------------------------- | ------------------------------------- | ------------------------------------ | -------------------------------------------- |
| **Security**              | None 💥                                | Validates & rejects ✅                | Clamps any input ✅                           |
| **Join safety**           | Unsafe (can escape)                   | Boundary-checked                     | Boundary-clamped                             |
| **Boundary guarantee**    | None                                  | Jailed (cannot escape)               | Jailed (virtual view)                        |
| **Input permissiveness**  | Any path (no validation)              | Only safe paths                      | Any input (auto-clamped)                     |
| **Display format**        | OS path                               | OS path                              | Virtual root path                            |
| **Example: good input**   | `"file.txt"` → `"file.txt"`           | `"file.txt"` → `"boundary/file.txt"` | `"file.txt"` → `"/file.txt"`                 |
| **Example: attack input** | `"/etc/passwd"` → **System breach** 💥 | `"/etc/passwd"` → **Error** ❌        | `"/etc/passwd"` → **`/etc/passwd`** (safe) ✅ |
| **Best for**              | Known-safe paths                      | System boundaries                    | User interfaces                              |

### Integration Examples

#### Serde Integration

```rust
use strict_path::{PathBoundary, StrictPath};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct FileRequest {
    filename: String,  // Accept as string first
}

#[derive(Serialize)]  
struct FileResponse {
    path: StrictPath<UserFiles>,  // Serialize safe path
}

async fn handle_upload(req: FileRequest) -> Result<FileResponse, Error> {
    let uploads = PathBoundary::try_new("uploads")?;
    let safe_path = uploads.strict_join(&req.filename)?;  // Validate here
    
    // ... process file ...
    
    Ok(FileResponse { path: safe_path })
}
```

#### Axum Web Framework

```rust
use axum::{extract::Path, response::Result};
use strict_path::PathBoundary;

struct StaticFiles;

async fn serve_static(Path(filename): Path<String>) -> Result<Vec<u8>> {
    let static_dir = PathBoundary::<StaticFiles>::try_new("./static")?;
    let safe_path = static_dir.strict_join(&filename)?; // Attack = Error
    
    Ok(safe_path.read_bytes()?)
}
```

#### Configuration with app-path

```rust
use app_path::AppPath;
use strict_path::PathBoundary;

fn load_app_config() -> Result<Config, Box<dyn std::error::Error>> {
    let app_dir = AppPath::new("MyApp").get_app_dir();
    let config_boundary = PathBoundary::try_new_create(app_dir)?;
    let config_file = config_boundary.strict_join("config.toml")?;
    
    Ok(toml::from_str(&config_file.read_to_string()?)?)
}
```

## Next Steps

- **For OS directories**: See [OS Standard Directories](./os_directories.md)
- **For serialization**: Check the integrations section in [Getting Started](./chapter_1.md)  
- **For examples**: Browse [Real-World Examples](./examples.md) with feature-specific demos