# Builtin I/O Operations

`strict-path` provides safe I/O helpers that maintain boundary security while eliminating the need for raw `std::fs` calls on leaked paths.

## Why Use Builtin Methods?

**Security**: All operations stay within validated boundaries  
**Ergonomics**: No need to call `.interop_path()` for common operations  
**Correctness**: Type-checked paths guarantee safety at compile time

## File Operations

### Reading Files

```rust
use strict_path::PathBoundary;

let config_dir = PathBoundary::try_new("/etc/myapp")?;
let config_file = config_dir.strict_join("config.toml")?;

// Read entire file as string
let contents = config_file.read_to_string()?;

// Read as bytes
let bytes = config_file.read()?;
```

### Writing Files

```rust
use strict_path::VirtualRoot;

let user_docs = VirtualRoot::try_new("/home/user/documents")?;
let report = user_docs.virtual_join("reports/summary.txt")?;

// Ensure parent directories exist
report.create_parent_dir_all()?;

// Write string content
report.write("Monthly Summary\n\nTotal: 42")?;

// Write bytes
report.write_bytes(b"Binary data")?;
```

### File Handles

For streaming or more control, use file handles:

```rust
use std::io::{Read, Write};

// Create or truncate file, get writable handle
let mut file = report.create_file()?;
file.write_all(b"Line 1\n")?;
file.write_all(b"Line 2\n")?;

// Open for reading
let mut file = report.open_file()?;
let mut contents = String::new();
file.read_to_string(&mut contents)?;
```

## Directory Operations

### Creating Directories

```rust
// Create single directory (parent must exist)
let subdir = config_dir.strict_join("plugins")?;
subdir.create_dir()?;

// Create all parent directories if missing
let nested = config_dir.strict_join("data/cache/temp")?;
nested.create_dir_all()?;

// Non-recursive variant (VirtualPath)
let vdir = user_docs.virtual_join("archive")?;
vdir.create_dir_non_recursive()?; // Fails if parent missing
```

### Listing Directory Contents

```rust
// Discovery: enumerate entries
for entry in config_dir.read_dir()? {
    let entry = entry?;
    let name = entry.file_name();
    
    // Re-validate discovered path before use
    let validated = config_dir.strict_join(&name)?;
    println!("Found: {}", validated.strictpath_display());
}
```

### Removing Directories

```rust
// Remove empty directory
subdir.remove_dir()?;

// Remove directory and all contents (dangerous!)
nested.remove_dir_all()?;
```

## Metadata Operations

### Checking Existence and Type

```rust
// Check if path exists
if config_file.exists() {
    println!("Config file found");
}

// Check type
if config_file.is_file() {
    println!("It's a file");
}

if config_dir.is_dir() {
    println!("It's a directory");
}
```

### Getting Metadata

```rust
// Get full metadata
let metadata = config_file.metadata()?;

println!("Size: {} bytes", metadata.len());
println!("Read-only: {}", metadata.permissions().readonly());
println!("Modified: {:?}", metadata.modified()?);
```

### Symlink Metadata (Don't Follow Links)

```rust
// Get metadata without following symlinks
let link_meta = config_file.symlink_metadata()?;

if link_meta.is_symlink() {
    println!("This is a symbolic link");
}
```

## Copy, Rename, and Link Operations

### Copying Files

```rust
let source = config_dir.strict_join("template.conf")?;
let dest = config_dir.strict_join("active.conf")?;

// Copy file, returns bytes copied
let bytes = source.strict_copy(&dest)?;
println!("Copied {} bytes", bytes);
```

### Renaming/Moving

```rust
let old_name = config_dir.strict_join("draft.txt")?;
let new_name = config_dir.strict_join("final.txt")?;

// Move/rename within same boundary
old_name.strict_rename(&new_name)?;
```

### Creating Links

```rust
// Symbolic link
let target = config_dir.strict_join("current")?;
let link = config_dir.strict_join("link-to-current")?;
target.strict_symlink(&link)?;

// Hard link
target.strict_hard_link(&link)?;
```

## Builtin vs std::fs Comparison

| Operation  | `strict-path`          | `std::fs`                                           | Why Prefer Builtin?  |
| ---------- | ---------------------- | --------------------------------------------------- | -------------------- |
| Read file  | `.read_to_string()?`   | `fs::read_to_string(path.interop_path())?`          | Shorter, stays typed |
| Write file | `.write("content")?`   | `fs::write(path.interop_path(), "content")?`        | No interop needed    |
| Copy file  | `.strict_copy(&dest)?` | `fs::copy(src.interop_path(), dst.interop_path())?` | Both paths validated |
| Metadata   | `.metadata()?`         | `fs::metadata(path.interop_path())?`                | Cleaner, same result |
| Create dir | `.create_dir_all()?`   | `fs::create_dir_all(path.interop_path())?`          | Type-safe path       |

## When to Use interop_path()

**Only for unavoidable third-party crates** that demand `AsRef<Path>`:

```rust
// ✅ GOOD: Third-party crate requires AsRef<Path>
let image = config_dir.strict_join("logo.png")?;
let img = image::open(image.interop_path())?; // No choice

// ❌ BAD: Using interop when builtin exists
std::fs::read_to_string(image.interop_path())?; // Use .read_to_string() instead

// ✅ GOOD: Use builtin
let contents = image.read_to_string()?;
```

## VirtualPath I/O Operations

All methods work on `VirtualPath` too, maintaining virtual display semantics:

```rust
let user_root = VirtualRoot::try_new("/var/lib/app/users/alice")?;
let doc = user_root.virtual_join("documents/readme.txt")?;

// All I/O operations available
doc.create_parent_dir_all()?;
doc.write("Welcome to your virtual filesystem!")?;

// Display shows virtual path
println!("Wrote to: {}", doc.virtualpath_display()); // "/documents/readme.txt"

// But I/O happens at real system location
println!("System location: {}", doc.as_unvirtual().strictpath_display());
```

## Performance Notes

**No overhead**: Builtin methods call `std::fs` internally with zero abstraction cost.  
**Same syscalls**: Operations compile to identical machine code as direct `std::fs` usage.  
**Validation cost**: Only paid once during `strict_join`/`virtual_join`, not on every I/O operation.

## Summary

- **Use builtin methods for all common I/O operations**
- **Reserve `.interop_path()` for third-party crates**
- **Both `StrictPath` and `VirtualPath` support the full I/O API**
- **No performance penalty vs raw `std::fs`**
- **Type safety and boundary security maintained automatically**
