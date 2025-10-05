# Daily Usage Patterns

Common workflows and patterns for everyday `strict-path` usage.

## Pattern 1: Validate User Input

**Problem**: User provides a filename, you need to ensure it stays in your directory.

```rust
use strict_path::PathBoundary;

fn handle_user_request(user_filename: &str) -> Result<String, Box<dyn std::error::Error>> {
    let uploads = PathBoundary::try_new("/var/uploads")?;
    
    // Validate the user input
    let safe_path = uploads.strict_join(user_filename)?;
    
    // Now safe to use
    let contents = safe_path.read_to_string()?;
    Ok(contents)
}

// ✅ Safe: "../etc/passwd" gets rejected
// ✅ Safe: "documents/report.pdf" gets validated
```

## Pattern 2: Configuration Loading

**Problem**: Load config files from multiple standard locations.

```rust
use strict_path::PathBoundary;
use std::path::PathBuf;

fn find_config() -> Result<String, Box<dyn std::error::Error>> {
    let config_locations = vec![
        PathBuf::from("/etc/myapp/config.toml"),
        PathBuf::from("/usr/local/etc/myapp/config.toml"),
        dirs::config_dir().unwrap().join("myapp/config.toml"),
    ];
    
    for location in config_locations {
        if let Some(parent) = location.parent() {
            if let Ok(boundary) = PathBoundary::try_new(parent) {
                if let Some(filename) = location.file_name() {
                    if let Ok(config_path) = boundary.strict_join(filename) {
                        if config_path.exists() {
                            return config_path.read_to_string();
                        }
                    }
                }
            }
        }
    }
    
    Err("No config file found".into())
}
```

## Pattern 3: Per-User Virtual Filesystem

**Problem**: Multiple users, each needs their own isolated filesystem view.

```rust
use strict_path::VirtualRoot;

struct UserSession {
    user_id: String,
    root: VirtualRoot<UserSpace>,
}

struct UserSpace;

impl UserSession {
    fn new(user_id: String) -> Result<Self, Box<dyn std::error::Error>> {
        let base_dir = format!("/var/lib/app/users/{}", user_id);
        let root = VirtualRoot::try_new_create(&base_dir)?;
        Ok(Self { user_id, root })
    }
    
    fn read_file(&self, virtual_path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let file = self.root.virtual_join(virtual_path)?;
        Ok(file.read_to_string()?)
    }
    
    fn write_file(&self, virtual_path: &str, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
        let file = self.root.virtual_join(virtual_path)?;
        file.create_parent_dir_all()?;
        file.write(contents)?;
        Ok(())
    }
    
    fn list_files(&self, virtual_dir: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let dir = self.root.virtual_join(virtual_dir)?;
        let mut files = Vec::new();
        
        for entry in dir.as_unvirtual().read_dir()? {
            let entry = entry?;
            // Re-validate discovered names
            let validated = self.root.virtual_join(format!("{}/{}", virtual_dir, entry.file_name().to_string_lossy()))?;
            files.push(validated.virtualpath_display().to_string());
        }
        
        Ok(files)
    }
}

// Usage
let alice = UserSession::new("alice".to_string())?;
alice.write_file("documents/report.txt", "Quarterly report")?;
let report = alice.read_file("documents/report.txt")?;
```

## Pattern 4: Safe Archive Extraction

**Problem**: Extract ZIP/TAR without directory traversal attacks.

```rust
use strict_path::PathBoundary;
use zip::ZipArchive;
use std::fs::File;

fn safe_extract_zip(
    zip_path: &std::path::Path,
    extract_to: &str
) -> Result<(), Box<dyn std::error::Error>> {
    let extract_dir = PathBoundary::try_new_create(extract_to)?;
    let mut archive = ZipArchive::new(File::open(zip_path)?)?;
    
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let filename = file.name();
        
        // Validate each file path before extraction
        let safe_path = match extract_dir.strict_join(filename) {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Skipping malicious path: {}", filename);
                continue; // Skip paths that escape
            }
        };
        
        // Create parent directories
        safe_path.create_parent_dir_all()?;
        
        // Extract to validated path
        let mut outfile = safe_path.create_file()?;
        std::io::copy(&mut file, &mut outfile)?;
    }
    
    Ok(())
}
```

## Pattern 5: Temporary File Processing

**Problem**: Create temp directory for processing, auto-cleanup.

```rust
use strict_path::PathBoundary;

fn process_upload(
    data: &[u8]
) -> Result<ProcessedData, Box<dyn std::error::Error>> {
    // Create temp directory with RAII cleanup
    let temp_dir = PathBoundary::<()>::try_new_temp()?;
    
    // Write input
    let input_file = temp_dir.strict_join("input.dat")?;
    input_file.write_bytes(data)?;
    
    // Process
    let output_file = temp_dir.strict_join("output.dat")?;
    process_data(&input_file, &output_file)?;
    
    // Read result
    let result = output_file.read()?;
    
    // temp_dir dropped here, automatically cleaned up
    Ok(ProcessedData::from_bytes(&result))
}
```

## Pattern 6: Chaining Operations

**Problem**: Multiple sequential operations on paths.

```rust
use strict_path::PathBoundary;

fn backup_and_update_config(
    new_config: &str
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = PathBoundary::try_new("/etc/myapp")?;
    
    let config = config_dir.strict_join("config.toml")?;
    let backup = config_dir.strict_join("config.toml.backup")?;
    
    // Chain operations
    config.strict_copy(&backup)?;           // Backup current
    config.write(new_config)?;               // Write new
    
    // Verify
    if config.read_to_string()? == new_config {
        println!("Config updated successfully");
    }
    
    Ok(())
}
```

## Pattern 7: Authorization with Markers

**Problem**: Different users need different access levels.

```rust
use strict_path::{PathBoundary, StrictPath};

struct ReadOnly;
struct ReadWrite;

fn authenticate_user(
    username: &str,
    password: &str
) -> Result<PathBoundary<ReadWrite>, AuthError> {
    // Check credentials
    if verify_credentials(username, password) {
        let user_dir = format!("/var/data/users/{}", username);
        let boundary: PathBoundary<ReadOnly> = PathBoundary::try_new(&user_dir)
            .map_err(|_| AuthError::NoAccess)?;
        
        // Escalate to write access after auth check
        Ok(boundary.change_marker())
    } else {
        Err(AuthError::InvalidCredentials)
    }
}

fn write_user_data(
    boundary: &PathBoundary<ReadWrite>, // Requires write marker
    filename: &str,
    data: &str
) -> Result<(), Box<dyn std::error::Error>> {
    let file = boundary.strict_join(filename)?;
    file.write(data)?;
    Ok(())
}

// ✅ Can only call write_user_data with ReadWrite marker
let rw_boundary = authenticate_user("alice", "secret123")?;
write_user_data(&rw_boundary, "notes.txt", "My notes")?;
```

## Pattern 8: Error Handling

**Problem**: Gracefully handle path validation failures.

```rust
use strict_path::{PathBoundary, StrictPathError};

fn safe_file_access(
    base: &str,
    user_path: &str
) -> Result<String, AppError> {
    let boundary = PathBoundary::try_new(base)
        .map_err(|e| AppError::InvalidBase(e))?;
    
    let file = boundary.strict_join(user_path)
        .map_err(|e| match e {
            StrictPathError::PathEscapesBoundary { attempted, boundary } => {
                AppError::PathEscape { 
                    path: attempted.display().to_string(),
                    reason: "Attempted directory traversal"
                }
            }
            _ => AppError::ValidationFailed(e)
        })?;
    
    file.read_to_string()
        .map_err(|e| AppError::IoError(e))
}

#[derive(Debug)]
enum AppError {
    InvalidBase(StrictPathError),
    PathEscape { path: String, reason: &'static str },
    InvalidPath { reason: String },
    ValidationFailed(StrictPathError),
    IoError(std::io::Error),
}
```

## Pattern 9: Database Path Storage

**Problem**: Store and retrieve validated paths from database.

```rust
use strict_path::{PathBoundary, StrictPath};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct FileRecord {
    id: u64,
    // Store as string in DB
    relative_path: String,
}

struct FileService {
    boundary: PathBoundary<DataDir>,
}

struct DataDir;

impl FileService {
    fn save_file(&self, name: &str, data: &[u8]) -> Result<FileRecord, Box<dyn std::error::Error>> {
        // Validate before using
        let file = self.boundary.strict_join(name)?;
        file.write_bytes(data)?;
        
        // Store relative path in DB
        Ok(FileRecord {
            id: generate_id(),
            relative_path: name.to_string(),
        })
    }
    
    fn load_file(&self, record: &FileRecord) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Re-validate on load
        let file = self.boundary.strict_join(&record.relative_path)?;
        Ok(file.read()?)
    }
}
```

## Pattern 10: Logging and Auditing

**Problem**: Log file access for compliance.

```rust
use strict_path::StrictPath;
use tracing::{info, warn};

fn audit_read<M>(
    path: &StrictPath<M>,
    user: &str
) -> std::io::Result<String> {
    info!(
        user = user,
        path = %path.strictpath_display(),
        action = "read",
        "File access"
    );
    
    match path.read_to_string() {
        Ok(contents) => {
            info!(
                user = user,
                path = %path.strictpath_display(),
                size = contents.len(),
                "Read successful"
            );
            Ok(contents)
        }
        Err(e) => {
            warn!(
                user = user,
                path = %path.strictpath_display(),
                error = %e,
                "Read failed"
            );
            Err(e)
        }
    }
}
```

## Performance Tips

### Reuse Boundaries

```rust
// ✅ Good: create boundary once
let boundary = PathBoundary::try_new("/var/data")?;

for filename in filenames {
    let file = boundary.strict_join(filename)?;
    process(file)?;
}

// ❌ Bad: recreating boundary every iteration
for filename in filenames {
    let boundary = PathBoundary::try_new("/var/data")?; // Wasteful!
    let file = boundary.strict_join(filename)?;
    process(file)?;
}
```

### Batch Validation

```rust
// Validate all paths upfront
let files: Result<Vec<_>, _> = filenames
    .iter()
    .map(|name| boundary.strict_join(name))
    .collect();

let files = files?; // Single error handling point

// Then process
for file in files {
    process(&file)?;
}
```

### Avoid Redundant Checks

```rust
// ❌ Bad: checking twice
if file.exists() {
    file.read_to_string()?;
}

// ✅ Good: let I/O operation handle it
match file.read_to_string() {
    Ok(contents) => { /* use contents */ }
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => { /* handle missing */ }
    Err(e) => return Err(e.into()),
}
```

## Summary

- **Always validate user input through `strict_join`/`virtual_join`**
- **Create boundaries once, reuse for multiple paths**
- **Use markers to encode authorization at type level**
- **Handle errors gracefully with specific error types**
- **Re-validate paths loaded from databases**
- **Log file operations for audit trails**
- **Prefer builtin I/O methods over `.interop_path()`**
- **Use temporary directories with RAII cleanup**
