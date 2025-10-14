# Common Operations Guide

> *Complete reference for all path operations with strict-path.*

This chapter provides comprehensive examples for every operation you'll need when working with validated paths. Always use dimension-specific methods—never use `std::path` methods on leaked paths.

---

## Joins

**Purpose**: Combine a boundary/root with an untrusted segment to create a validated path.

### Basic Joins

```rust
use strict_path::{PathBoundary, StrictPath};

fn join_examples(boundary: &PathBoundary) -> std::io::Result<()> {
    // Single join
    let file = boundary.strict_join("docs/readme.md")?;
    
    // Join with slash or backslash - both work
    let file2 = boundary.strict_join("docs\\readme.md")?;
    
    // Multi-segment path
    let deep = boundary.strict_join("a/b/c/d/file.txt")?;
    
    Ok(())
}
```

### Chained Joins

```rust
use strict_path::{PathBoundary, StrictPath};

fn chained_joins(boundary: &PathBoundary) -> std::io::Result<()> {
    // Navigate through directories
    let level1 = boundary.strict_join("level1")?;
    let level2 = level1.strict_join("level2")?;
    let file = level2.strict_join("file.txt")?;
    
    // Or go up and down
    let sibling = level2
        .strictpath_parent().unwrap()
        .strict_join("sibling/file.txt")?;
    
    Ok(())
}
```

### Joining Discovered Names

```rust
use strict_path::{PathBoundary, StrictPath};

fn discover_and_join(boundary: &PathBoundary) -> std::io::Result<Vec<StrictPath>> {
    let mut files = Vec::new();
    
    // Walk directory
    for entry in boundary.read_dir()? {
        let entry = entry?;
        let name = entry.file_name();
        
        // IMPORTANT: Re-validate each discovered name
        let validated = boundary.strict_join(&name.to_string_lossy())?;
        files.push(validated);
    }
    
    Ok(files)
}
```

**Key rules:**
- Always validate untrusted segments with `strict_join()` or `virtual_join()`
- Re-validate discovered directory names before using them
- Never use `std::path::Path::join()` on untrusted input

---

## Parents and Ancestors

**Purpose**: Navigate up the directory tree safely.

### Getting Parent Directory

```rust
use strict_path::StrictPath;

fn parent_examples(file: &StrictPath) -> std::io::Result<()> {
    // Get parent directory
    if let Some(parent) = file.strictpath_parent() {
        println!("Parent: {}", parent.strictpath_display());
        
        // Create parent if needed
        parent.create_dir_all()?;
    } else {
        println!("At boundary root");
    }
    
    Ok(())
}
```

### Walking Up to Root

```rust
use strict_path::StrictPath;

fn walk_to_root(file: &StrictPath) {
    let mut current = Some(file.clone());
    let mut level = 0;
    
    while let Some(path) = current {
        println!("Level {}: {}", level, path.strictpath_display());
        current = path.strictpath_parent();
        level += 1;
    }
}
```

### Finding Ancestor with Specific Name

```rust
use strict_path::StrictPath;

fn find_ancestor(file: &StrictPath, target_name: &str) -> Option<StrictPath> {
    let mut current = Some(file.clone());
    
    while let Some(path) = current {
        if path.strictpath_display().to_string().ends_with(target_name) {
            return Some(path);
        }
        current = path.strictpath_parent();
    }
    
    None
}
```

**Key insight**: `strictpath_parent()` returns `None` at the boundary root—you can't escape upward.

---

## File Name and Extension Operations

**Purpose**: Modify path components while staying within the boundary.

### Changing File Names

```rust
use strict_path::StrictPath;

fn filename_operations(file: &StrictPath) -> std::io::Result<()> {
    // Change filename (keeps directory and extension)
    let renamed = file.strictpath_with_file_name("newname.txt")?;
    
    // Change just the stem (keeps extension)
    let new_stem = file.strictpath_with_file_name("report")?
        .strictpath_with_extension(
            file.strictpath_extension().unwrap_or("txt")
        )?;
    
    Ok(())
}
```

### Changing Extensions

```rust
use strict_path::StrictPath;

fn extension_operations(file: &StrictPath) -> std::io::Result<()> {
    // Change extension
    let markdown = file.strictpath_with_extension("md")?;
    let json = file.strictpath_with_extension("json")?;
    
    // Remove extension
    let no_ext = file.strictpath_with_extension("")?;
    
    // Add extension if missing
    let with_ext = if file.strictpath_extension().is_none() {
        file.strictpath_with_extension("txt")?
    } else {
        file.clone()
    };
    
    Ok(())
}
```

### Combining Operations

```rust
use strict_path::StrictPath;

fn combined_operations(file: &StrictPath) -> std::io::Result<()> {
    // Change both filename and extension
    let transformed = file
        .strictpath_with_file_name("report")?
        .strictpath_with_extension("pdf")?;
    
    // Add timestamp to filename
    let timestamp = "2025-10-14";
    let current_name = file.strictpath_file_stem().unwrap_or("file");
    let timestamped = file.strictpath_with_file_name(
        format!("{}_{}", current_name, timestamp)
    )?.strictpath_with_extension(
        file.strictpath_extension().unwrap_or("txt")
    )?;
    
    Ok(())
}
```

---

## Rename and Move Operations

**Purpose**: Move files/directories while staying within the boundary.

### Simple Rename (Same Directory)

```rust
use strict_path::{PathBoundary, StrictPath};

fn simple_rename(boundary: &PathBoundary) -> std::io::Result<()> {
    let current = boundary.strict_join("logs/app.log")?;
    current.write(b"log data")?;
    
    // Rename returns the new path
    let renamed = current.strict_rename("logs/app.old")?;
    
    assert!(renamed.exists());
    assert!(!current.exists()); // Original path no longer exists
    
    Ok(())
}
```

### Move to Different Directory

```rust
use strict_path::{PathBoundary, StrictPath};

fn move_file(boundary: &PathBoundary) -> std::io::Result<()> {
    let source = boundary.strict_join("temp/file.txt")?;
    source.write(b"data")?;
    
    // Create destination directory first
    let dest_dir = boundary.strict_join("archive")?;
    dest_dir.create_dir_all()?;
    
    // Move to new directory
    let moved = source.strict_rename("archive/file.txt")?;
    
    Ok(())
}
```

### Rename with Parent Directory Creation

```rust
use strict_path::PathBoundary;

fn rename_with_mkdir(boundary: &PathBoundary) -> std::io::Result<()> {
    let file = boundary.strict_join("data.txt")?;
    file.write(b"content")?;
    
    // Rename to path in subdirectory (create if needed)
    let new_path = boundary.strict_join("backups/2025/data.txt")?;
    if let Some(parent) = new_path.strictpath_parent() {
        parent.create_dir_all()?;
    }
    
    let renamed = file.strict_rename("backups/2025/data.txt")?;
    
    Ok(())
}
```

### Virtual Rename (Clean Paths)

```rust,no_run
#[cfg(feature = "virtual-path")]
use strict_path::VirtualRoot;

#[cfg(feature = "virtual-path")]
fn virtual_rename_example(vroot: &VirtualRoot) -> std::io::Result<()> {
    let file = vroot.virtual_join("uploads/photo.jpg")?;
    file.write(b"image data")?;
    
    // Virtual rename - user sees clean paths
    let renamed = file.virtual_rename("uploads/photo_2025.jpg")?;
    
    println!("User sees: {}", renamed.virtualpath_display());
    // Output: "/uploads/photo_2025.jpg"
    
    println!("System path: {}", renamed.as_unvirtual().strictpath_display());
    // Output: actual filesystem path
    
    Ok(())
}
```

---

## Deletion Operations

**Purpose**: Remove files and directories safely.

### Delete Single File

```rust
use strict_path::PathBoundary;

fn delete_file(boundary: &PathBoundary) -> std::io::Result<()> {
    let file = boundary.strict_join("temp/cache.tmp")?;
    
    // Check existence before deleting
    if file.exists() {
        file.remove_file()?;
    }
    
    Ok(())
}
```

### Delete Empty Directory

```rust
use strict_path::PathBoundary;

fn delete_empty_dir(boundary: &PathBoundary) -> std::io::Result<()> {
    let dir = boundary.strict_join("temp/empty")?;
    
    // Only works if directory is empty
    if dir.exists() && dir.metadata()?.is_dir() {
        dir.remove_dir()?;
    }
    
    Ok(())
}
```

### Recursive Directory Deletion

```rust
use strict_path::PathBoundary;

fn delete_directory_tree(boundary: &PathBoundary) -> std::io::Result<()> {
    let dir = boundary.strict_join("temp/data")?;
    
    // Removes directory and ALL contents recursively
    if dir.exists() {
        dir.remove_dir_all()?;
    }
    
    Ok(())
}
```

### Safe Cleanup with Validation

```rust
use strict_path::PathBoundary;

fn safe_cleanup(boundary: &PathBoundary, path: &str) -> std::io::Result<()> {
    // Validate path first
    match boundary.strict_join(path) {
        Ok(safe_path) => {
            if safe_path.exists() {
                if safe_path.metadata()?.is_dir() {
                    safe_path.remove_dir_all()?;
                } else {
                    safe_path.remove_file()?;
                }
                println!("Deleted: {}", safe_path.strictpath_display());
            }
            Ok(())
        },
        Err(e) => {
            eprintln!("🚨 Invalid path, refusing to delete: {e}");
            Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        }
    }
}
```

**Safety note**: Always validate paths before deletion. Never delete based on untrusted input without validation.

---

## Metadata Inspection

**Purpose**: Query file/directory properties without reading contents.

### Basic Metadata

```rust
use strict_path::StrictPath;
use std::time::SystemTime;

fn inspect_metadata(file: &StrictPath) -> std::io::Result<()> {
    let meta = file.metadata()?;
    
    // File type checks
    println!("Is file: {}", meta.is_file());
    println!("Is directory: {}", meta.is_dir());
    println!("Is symlink: {}", meta.file_type().is_symlink());
    
    // Size and permissions
    println!("Size: {} bytes", meta.len());
    println!("Read-only: {}", meta.permissions().readonly());
    
    // Timestamps
    if let Ok(modified) = meta.modified() {
        let duration = SystemTime::now().duration_since(modified).unwrap();
        println!("Modified {} seconds ago", duration.as_secs());
    }
    
    Ok(())
}
```

### Conditional Operations Based on Metadata

```rust
use strict_path::StrictPath;

fn cleanup_empty_files(file: &StrictPath) -> std::io::Result<()> {
    let meta = file.metadata()?;
    
    if meta.is_file() && meta.len() == 0 {
        println!("Empty file, removing: {}", file.strictpath_display());
        file.remove_file()?;
    }
    
    Ok(())
}
```

### Finding Files by Criteria

```rust
use strict_path::{PathBoundary, StrictPath};

fn find_large_files(boundary: &PathBoundary, min_size: u64) -> std::io::Result<Vec<StrictPath>> {
    let mut large_files = Vec::new();
    
    for entry in boundary.read_dir()? {
        let entry = entry?;
        let name = entry.file_name();
        let path = boundary.strict_join(&name.to_string_lossy())?;
        
        if let Ok(meta) = path.metadata() {
            if meta.is_file() && meta.len() > min_size {
                large_files.push(path);
            }
        }
    }
    
    Ok(large_files)
}
```

---

## Copy Operations

**Purpose**: Duplicate files while preserving validation.

### Simple Copy

```rust
use strict_path::PathBoundary;

fn simple_copy(boundary: &PathBoundary) -> std::io::Result<()> {
    let source = boundary.strict_join("docs/original.txt")?;
    let dest = boundary.strict_join("docs/copy.txt")?;
    
    // Returns number of bytes copied
    let bytes_copied = source.copy(&dest)?;
    println!("Copied {bytes_copied} bytes");
    
    Ok(())
}
```

### Copy with Overwrite Protection

```rust
use strict_path::PathBoundary;

fn copy_if_not_exists(boundary: &PathBoundary) -> std::io::Result<()> {
    let source = boundary.strict_join("docs/original.txt")?;
    let dest = boundary.strict_join("docs/backup.txt")?;
    
    if !dest.exists() {
        source.copy(&dest)?;
        println!("Copied to {}", dest.strictpath_display());
    } else {
        println!("Destination already exists, skipping");
    }
    
    Ok(())
}
```

### Copy to Different Directory

```rust
use strict_path::PathBoundary;

fn copy_to_archive(boundary: &PathBoundary) -> std::io::Result<()> {
    let source = boundary.strict_join("docs/report.pdf")?;
    
    // Create backup directory
    let backup_dir = boundary.strict_join("backups/2025")?;
    backup_dir.create_dir_all()?;
    
    // Copy to backup location
    let dest = boundary.strict_join("backups/2025/report.pdf")?;
    source.copy(&dest)?;
    
    Ok(())
}
```

---

## Comprehensive Example: File Management

Putting it all together—a complete file management function:

```rust,no_run
use strict_path::{PathBoundary, StrictPath};
use std::time::{SystemTime, Duration};

fn manage_user_file(
    uploads_dir: &PathBoundary,
    filename: &str
) -> Result<FileInfo, Box<dyn std::error::Error>> {
    // 1. Validate path
    let file = uploads_dir.strict_join(filename)?;
    
    // 2. Check existence
    if !file.exists() {
        return Err("File not found".into());
    }
    
    // 3. Get metadata
    let meta = file.metadata()?;
    
    // 4. Archive old files
    if should_archive(&meta)? {
        let archive_dir = uploads_dir.strict_join("archive")?;
        archive_dir.create_dir_all()?;
        
        let archived = file.strict_rename(&format!("archive/{filename}"))?;
        
        // 5. Compress large files
        if meta.len() > 10_000_000 {
            compress_file(&archived)?;
        }
        
        return Ok(FileInfo {
            path: archived.strictpath_display().to_string(),
            status: FileStatus::Archived,
            size: meta.len(),
        });
    }
    
    Ok(FileInfo {
        path: file.strictpath_display().to_string(),
        status: FileStatus::Active,
        size: meta.len(),
    })
}

fn should_archive(meta: &std::fs::Metadata) -> std::io::Result<bool> {
    let modified = meta.modified()?;
    let age = SystemTime::now().duration_since(modified)
        .unwrap_or(Duration::ZERO);
    
    Ok(age > Duration::from_secs(30 * 24 * 60 * 60)) // 30 days
}

fn compress_file(_file: &StrictPath) -> std::io::Result<()> {
    // Compression implementation
    Ok(())
}

#[derive(Debug)]
struct FileInfo {
    path: String,
    status: FileStatus,
    size: u64,
}

#[derive(Debug)]
enum FileStatus {
    Active,
    Archived,
}
```

---

## Key Principles

**Always use dimension-specific methods:**
- Use `strict_join()` / `virtual_join()` for joins
- Use `strictpath_parent()` / `virtualpath_parent()` for parents
- Use `strictpath_with_*()` / `virtualpath_with_*()` for modifications
- **Never** use `std::path` methods on leaked paths

**Handle errors explicitly:**
- Path operations can fail (permissions, disk full, invalid paths)
- Use `?` operator or explicit `match` for error handling
- Log security incidents when paths escape boundaries

**Check before destructive operations:**
- Use `.exists()` before deletion
- Use `.metadata()` to check file vs. directory
- Create parent directories with `.create_dir_all()` before moves

**Validate discovered paths:**
- Re-validate directory entries with `strict_join()` / `virtual_join()`
- Don't trust filesystem listings—validate before use

---

## Learn More

- **[Best Practices Overview →](../best_practices.md)** - Core guidelines and decision matrices
- **[Real-World Patterns →](./real_world_patterns.md)** - Production-ready examples
- **[Policy & Reuse →](./policy_and_reuse.md)** - When to use VirtualRoot/PathBoundary
- **[Authorization Patterns →](./authorization_architecture.md)** - Compile-time authorization

