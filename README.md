# jailed-path

[![Crates.io](https://img.shields.io/crates/v/jailed-path.svg)](https://crates.io/crates/jailed-path)
[![Documentation](https://docs.rs/jailed-path/badge.svg)](https://docs.rs/jailed-path)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/DK26/jailed-path-rs#license)

**Type-safe path validation ensuring files stay within defined jail boundaries**

`jailed-path` provides a simple, zero-dependency solution for validating that file paths remain within designated jail boundaries. It prevents directory traversal and ensures paths stay within allowed areas using Rust's type system.

## Quick Start

```rust
use jailed_path::{PathValidator, JailedPath};

// Developer defines validation jail
let validator = PathValidator::with_jail("/safe/directory")?;

// Runtime validates user-provided paths
let jailed_path = validator.path("user/requested/file.txt")?;

// Type guarantees the path is validated
let path: &Path = jailed_path.as_path();
```

## Core Concepts

### PathValidator
Sets the jail boundary that paths must stay within:

```rust
let validator = PathValidator::with_jail("/app/data")?;
```

### JailedPath
A validated path guaranteed to be within the jail:

```rust
// ✅ Valid - within jail
let file = validator.path("uploads/photo.jpg")?;

// ❌ Blocked - directory traversal
let evil = validator.path("../../../etc/passwd"); // Returns Err
```

## Integration with app-path

Works seamlessly with `app-path` for validated, portable applications:

```rust
use app_path::AppPath;
use jailed_path::PathValidator;

// Get application directory (portable across platforms)
let app = AppPath::new("MyApp")?;
let data_dir = app.data_dir()?;

// Create validator jail around app data
let validator = PathValidator::with_jail(data_dir)?;

// Safely handle user file requests
let user_file = validator.path("user_uploads/document.pdf")?;

// JailedPath works with any std::fs operation
std::fs::write(&user_file, pdf_data)?;
let metadata = user_file.metadata()?;
```

## Complete Path Compatibility

`JailedPath` is fully compatible with Rust's path ecosystem:

```rust
use jailed_path::PathValidator;
use std::path::{Path, PathBuf};

let validator = PathValidator::with_jail("/safe")?;
let jailed_path = validator.path("file.txt")?;

// Works as &Path (via Deref)
let exists = jailed_path.exists();
let metadata = jailed_path.metadata()?;

// Works with any function expecting AsRef<Path>
std::fs::read_to_string(&jailed_path)?;

// Convert to owned types
let path_buf: PathBuf = jailed_path.into_path_buf();

// Compare with regular paths
assert_eq!(*jailed_path, *Path::new("/safe/file.txt"));
assert_eq!(*jailed_path, *PathBuf::from("/safe/file.txt"));
```

## Features

- **Zero Dependencies**: No external dependencies
- **Type Safety**: Compile-time guarantees that validated paths are within jail boundaries
- **Simple API**: Two main types - `PathValidator` and `JailedPath`
- **Directory Traversal Prevention**: Prevents `../` path traversal automatically
- **Path Canonicalization**: Resolves symlinks and relative components
- **Cross-Platform**: Works on Windows, macOS, and Linux

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
