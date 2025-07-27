# jailed-path

[![Crates.io](https://img.shields.io/crates/v/jailed-path.svg)](https://crates.io/crates/jailed-path)
[![Documentation](https://docs.rs/jailed-path/badge.svg)](https://docs.rs/jailed-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/jailed-path-rs#license)
[![CI](https://github.com/DK26/jailed-path-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DK26/jailed-path-rs/actions/workflows/ci.yml)
[![Type-State Police](https://img.shields.io/badge/protected%20by-Type--State%20Police-blue.svg)](https://github.com/DK26/jailed-path-rs)

**Advanced path validation: symlink-safe, multi-jail, compile-time guaranteed**

> *New from the Type-State Police Department! Putting your paths in jail!*

*because apparently YOU can't be trusted with file paths!*

`jailed-path` transforms runtime path validation into mathematical compile-time guarantees using Rust's type system. Unlike other validation libraries, it safely resolves and follows symbolic links while maintaining strict boundary enforcement.

## Why Type Safety Beats Manual Validation

```rust
use jailed_path::{PathValidator, JailedPath};

// ✅ Type-safe: Only accepts validated paths
fn serve_file(safe_path: &JailedPath) -> std::io::Result<Vec<u8>> {
    std::fs::read(safe_path)
}

let validator = PathValidator::with_jail("./public")?;
let safe_path: JailedPath = validator.try_path("index.html")?; // Only way to create JailedPath
```


## Key Features

- **Security First**: Prevents `../` path traversal attacks by clamping all traversal and absolute paths to the jail root
- **Path Canonicalization**: Resolves symlinks and relative components safely
- **Type Safety**: Compile-time guarantees that validated paths are within jail boundaries
- **Multi-Jail Support**: You can use your own marker types to prevent accidentally mixing up paths from different jails  
- **Single Dependency**: Only depends on our own `soft-canonicalize` crate  
- **Cross-Platform**: Works on Windows, macOS, and Linux  
- **Performance**: Minimal allocations, efficient validation  
- **Virtual Root Display**: Shows paths as if they start from the root of your jail, making user-facing output clean and intuitive. No leaking of internal or absolute paths—just what the user expects to see.

### Virtual Root Display Example

```rust
use jailed_path::{PathValidator, JailedPath};

let validator = PathValidator::with_jail("./public")?;
let doc_path: JailedPath = validator.try_path("users/alice/documents/report.pdf")?;
// Output is always shown as if from the jail root, never leaking internal paths
println!("Document: {}", doc_path); // Output: /users/alice/documents/report.pdf
```

## Preventing Mix-ups with Multiple Jails

When your application uses multiple jail directories, you can use your own marker types to mathematically distinguish between different jails at compile time:

```rust
use jailed_path::{PathValidator, JailedPath};

struct ConfigFiles;
struct UserData;

fn load_config(config_path: &JailedPath<ConfigFiles>) -> Result<String, std::io::Error> {
    std::fs::read_to_string(config_path)
}

let config_validator: PathValidator<ConfigFiles> = PathValidator::with_jail("./config")?;
let user_validator: PathValidator<UserData> = PathValidator::with_jail("./userdata")?;

let config_file: JailedPath<ConfigFiles> = config_validator.try_path("app.toml")?;
let user_file: JailedPath<UserData> = user_validator.try_path("profile.json")?;

load_config(&config_file)?; // ✅ Correct type
// load_config(&user_file)?; // ❌ Compile error: wrong marker type!
```

The type system prevents you from accidentally passing a user data path to a function expecting a config path.

## Optional: Using Marker Types with Single Jails

Even with just one jail, you may use marker types to add semantic context about what the path represents:

```rust
use jailed_path::{PathValidator, JailedPath};

struct UserUploads;

fn process_upload(file: &JailedPath<UserUploads>) -> std::io::Result<()> {
    let content = std::fs::read(file)?;
    println!("Processing {} bytes", content.len());
    Ok(())
}

let upload_validator: PathValidator<UserUploads> = PathValidator::with_jail("./uploads")?;
let upload_file: JailedPath<UserUploads> = upload_validator.try_path("photo.jpg")?;
```

Without markers, you can simply use `PathValidator` and `JailedPath` directly.

## API Design

- `PathValidator::with_jail()` - Create validator with jail boundary
- `validator.try_path()` - Validate a single path, returns `Result<JailedPath, JailedPathError>`
- `JailedPath` - Validated path type (can ONLY be created via `try_path()`)
- `JailedPathError` - Detailed error information for debugging

## Security Guarantees

All `..` components and absolute paths are now clamped to the jail root, rather than blocked. Symbolic links are resolved, and paths are mathematically validated against the jail boundary. Path traversal attacks are impossible to bypass, but attempts to escape the jail will be clamped to the jail root or its parent, never allowed to escape.

```rust
use jailed_path::PathValidator;

let validator: PathValidator = PathValidator::with_jail("./public")?;

// ✅ Valid paths,  Any `..` component or absolute path is clamped to jail root

validator.try_path("index.html")?;                  // full path: ./public/index.html
                                                    // prints:    /index.html

validator.try_path("css/style.css")?;               // full path: ./public/css/style.css
                                                    // prints:    /css/style.css

validator.try_path("/etc/shadow")?;                 // full path: ./public/etc/shadow
                                                    // prints:    /etc/shadow

validator.try_path("../config.toml")?;              // full path: ./public/
                                                    // prints:    /

validator.try_path("assets/../../../etc/passwd")?;  // full path: ./public/
                                                    // prints:    /

```

## Integration Examples

### With External Crates (app-path example)

```rust
// Example using app-path crate for portable executable-relative directories
use app_path::app_path;
use jailed_path::PathValidator;

struct ConfigFiles;
struct UserData;  
struct Uploads;

// Portable paths relative to your executable
let config_validator: PathValidator<ConfigFiles> = PathValidator::with_jail(app_path!("config"))?;
let user_validator: PathValidator<UserData> = PathValidator::with_jail(app_path!("user_data"))?;
let upload_validator: PathValidator<Uploads> = PathValidator::with_jail(app_path!("uploads"))?;

// Type-safe file access
let config_file: JailedPath<ConfigFiles> = config_validator.try_path("app.toml")?;
let profile: JailedPath<UserData> = user_validator.try_path("profile.json")?;
let upload: JailedPath<Uploads> = upload_validator.try_path("document.pdf")?;
```

### Path Compatibility

```rust
use jailed_path::PathValidator;

let validator = PathValidator::with_jail("./data")?;
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
jailed-path = "0.0.3"
```

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
