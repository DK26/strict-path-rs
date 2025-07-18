# jailed-path

[![Crates.io](https://img.shields.io/crates/v/jailed-path.svg)](https://crates.io/crates/jailed-path)
[![Documentation](https://docs.rs/jailed-path/badge.svg)](https://docs.rs/jailed-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/jailed-path-rs#license)

**Type-safe path validation ensuring files stay within defined jail boundaries**

`jailed-path` prevents directory traversal attacks by validating that file paths remain within designated boundaries using Rust's type system.

## Quick Start

```rust
use jailed_path::PathValidator;

// Create validator with jail boundary
let temp_dir = std::env::temp_dir();
let validator: PathValidator = PathValidator::with_jail(&temp_dir)?;

// Validate user-provided paths  
let safe_path = validator.try_path("image.jpg")?;

// Use with any std::fs operation
std::fs::write(&safe_path, b"image data")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Key Features

- **Zero Dependencies**: Only depends on our own `soft-canonicalize` crate
- **Type Safety**: Compile-time guarantees that validated paths are within jail boundaries
- **Security First**: Prevents `../` path traversal attacks automatically  
- **Path Canonicalization**: Resolves symlinks and relative components safely
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Performance**: Minimal allocations, efficient validation

## API Design

- `PathValidator::with_jail()` - Create validator with jail boundary
- `PathValidator::try_path()` - Validate paths (returns `Result`)  
- `JailedPath` - Validated path type with full `Path` compatibility
- `JailedPathError` - Detailed error information for debugging

## Security Examples

```rust
use jailed_path::PathValidator;

let temp_dir = std::env::temp_dir();
let validator: PathValidator = PathValidator::with_jail(&temp_dir)?;

// ✅ Valid - within jail
let file = validator.try_path("uploads/photo.jpg")?;

// ❌ Blocked - directory traversal  
let evil = validator.try_path("../../../etc/passwd"); // Returns Err
assert!(evil.is_err());

// ❌ Blocked - absolute path escape
let bad = validator.try_path("/etc/shadow"); // Returns Err  
assert!(bad.is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Integration Examples

### Web Server File Serving

```rust
use jailed_path::PathValidator;

fn serve_static_file(validator: &PathValidator, request_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Safely validate user-provided path
    let safe_path = validator.try_path(request_path)?;
    
    // Read file - guaranteed to be within jail
    Ok(std::fs::read(&safe_path).unwrap_or_default())
}

let temp_dir = std::env::temp_dir();
let validator = PathValidator::with_jail(&temp_dir)?;
let _content = serve_static_file(&validator, "images/logo.png")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

### With app-path for Portable Applications

```rust
use app_path::app_path;
use jailed_path::PathValidator;

// Get application data directory using app-path macro  
let app_data = app_path!("data");
app_data.create_dir()?;

// Create validator jail around app data
let validator: PathValidator = PathValidator::with_jail(&app_data)?;

// Safely handle user file requests
let user_file = validator.try_path("document.pdf")?;
std::fs::write(&user_file, b"pdf data")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Path Compatibility

`JailedPath` is fully compatible with Rust's path ecosystem:

```rust
use jailed_path::PathValidator;

let temp_dir = std::env::temp_dir();
let validator = PathValidator::with_jail(&temp_dir)?;
let jailed_path = validator.try_path("file.txt")?;

// Works as &Path (via Deref)
let _exists = jailed_path.exists();
let _metadata = jailed_path.metadata();

// Works with any function expecting AsRef<Path>
let _content = std::fs::read_to_string(&jailed_path);

// Convert to owned types  
let path_buf = jailed_path.into_path_buf();
assert!(path_buf.ends_with("file.txt"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

- **Security First**: Prevents `../` path traversal attacks automatically
- **Type Safety**: Compile-time guarantees that validated paths are within jail boundaries
- **Path Canonicalization**: Resolves symlinks and relative components safely
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Single Dependency**: Only depends on our own `soft-canonicalize` crate

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
