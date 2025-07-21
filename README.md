# jailed-path

[![Crates.io](https://img.shields.io/crates/v/jailed-path.svg)](https://crates.io/crates/jailed-path)
[![Documentation](https://docs.rs/jailed-path/badge.svg)](https://docs.rs/jailed-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/jailed-path-rs#license)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/jailed-path-rs)

**Advanced path validation: symlink-safe, multi-jail, compile-time guaranteed**

*Brought to you by the Type-State Police™ - because apparently YOU can't be trusted with file paths!*

`jailed-path` transforms runtime path validation into mathematical compile-time guarantees using Rust's type system. Unlike other validation libraries, it safely resolves and follows symbolic links while maintaining strict boundary enforcement.

## Why Type Safety Beats Manual Validation

```rust
use jailed_path::{PathValidator, JailedPath};

// ✅ Type-safe: Only accepts validated paths
fn serve_file(safe_path: &JailedPath) -> std::io::Result<Vec<u8>> {
    std::fs::read(safe_path)
}

let validator = PathValidator::with_jail(std::env::temp_dir())?;
let safe_path: JailedPath = validator.try_path("document.pdf")?; // Only way to create JailedPath
```

## Adding Context with Markers (Optional)

```rust
use jailed_path::{PathValidator, JailedPath};

struct UserUploads;

fn process_upload(file: &JailedPath<UserUploads>) -> std::io::Result<()> {
    let content = std::fs::read(file)?;
    Ok(())
}

let upload_validator: PathValidator<UserUploads> = PathValidator::with_jail(std::env::temp_dir())?;
let upload_file: JailedPath<UserUploads> = upload_validator.try_path("photo.jpg")?;
```

## Multiple Jails with Compile-Time Safety

```rust
use jailed_path::{PathValidator, JailedPath};

struct ConfigFiles;
struct UserData;

fn load_config(config_path: &JailedPath<ConfigFiles>) -> Result<String, std::io::Error> {
    std::fs::read_to_string(config_path)
}

let config_validator: PathValidator<ConfigFiles> = PathValidator::with_jail(std::env::temp_dir())?;
let user_validator: PathValidator<UserData> = PathValidator::with_jail(std::env::temp_dir())?;

let config_file: JailedPath<ConfigFiles> = config_validator.try_path("app.toml")?;
let user_file: JailedPath<UserData> = user_validator.try_path("profile.json")?;

load_config(&config_file)?; // ✅ Correct type
// load_config(&user_file)?; // ❌ Compile error: wrong marker type!
```

## Key Features

- **Single Dependency**: Only depends on our own `soft-canonicalize` crate
- **Type Safety**: Compile-time guarantees that validated paths are within jail boundaries
- **Security First**: Prevents `../` path traversal attacks automatically  
- **Path Canonicalization**: Resolves symlinks and relative components safely
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Performance**: Minimal allocations, efficient validation
- **Zero-Cost Markers**: Generic markers add no runtime overhead

## API Design

- `PathValidator::with_jail()` - Create validator with jail boundary
- `validator.try_path()` - Validate paths (returns `Result`)  
- `JailedPath` - Validated path type with full `Path` compatibility
- `JailedPathError` - Detailed error information for debugging

## Security Guarantees

All `..` components are blocked before processing, symbolic links are resolved, and paths are
mathematically validated against the jail boundary. Path traversal attacks
are impossible to bypass.

```rust
use jailed_path::PathValidator;

let validator: PathValidator = PathValidator::with_jail(std::env::temp_dir())?;

// ✅ Valid paths
let safe = validator.try_path("file.txt")?;
let nested = validator.try_path("dir/file.txt")?;

// ❌ Any `..` component causes validation failure
assert!(validator.try_path("../escape.txt").is_err());
assert!(validator.try_path("dir/../file.txt").is_err());
assert!(validator.try_path("../../etc/passwd").is_err());
```

## Integration Examples

### With app-path for Portable Applications

```rust
use app_path::app_path;
use jailed_path::PathValidator;

let app_data = app_path!("data");
app_data.create_dir()?;
let validator: PathValidator = PathValidator::with_jail(&app_data)?;

let user_file = validator.try_path("document.pdf")?;
std::fs::write(&user_file, b"pdf data")?;
```

## Path Compatibility

```rust
use jailed_path::PathValidator;

let temp_dir = std::env::temp_dir();
let validator = PathValidator::with_jail(&temp_dir)?;
let jailed_path = validator.try_path("file.txt")?;

let _exists = jailed_path.exists();
let _metadata = jailed_path.metadata();
let _content = std::fs::read_to_string(&jailed_path);

let path_buf = jailed_path.into_path_buf();
assert!(path_buf.ends_with("file.txt"));
```

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
jailed-path = "0.0.2"
```

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
