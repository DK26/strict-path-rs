# Archive Extraction with Safety

Extract ZIP files and other archives safely without zip-slip vulnerabilities. This example shows how `PathBoundary` detects and rejects malicious archive entries.

## The Problem

Archive extractors are vulnerable to **zip-slip attacks** where malicious archives contain entries like:
- ❌ `../../../etc/passwd` - Escapes to system files
- ❌ `..\\..\\windows\\system32\\evil.exe` - Escapes on Windows
- ❌ Symlinks pointing outside the extraction directory

## The Solution: Choose Based on Your Use Case

### Production Archive Extraction: Use PathBoundary to Detect Attacks

**Use `PathBoundary` for production archive extraction.** This detects malicious paths and allows you to:
- Log the attack attempt
- Reject the entire archive as compromised
- Alert administrators
- Take appropriate security action

When extracting archives in production:
- Escape attempts indicate a **malicious archive**
- You want to **detect and reject** the archive, not silently hide the attack
- The archive should be quarantined or deleted
- Users/admins should be alerted to the attempted attack

`PathBoundary` returns `Err(PathEscapesBoundary)` so you can handle the security event appropriately.

### Research/Sandbox: Use VirtualRoot to Safely Analyze

**Use `VirtualRoot` when analyzing suspicious archives in a controlled environment:**
- Malware analysis and security research
- Safely studying attack techniques
- Observing malicious behavior while containing it
- Testing archive parsing without risk

In research scenarios, you **want** to see what the malicious archive tries to do, but safely contained within a virtual boundary.

## Recommended Patterns

- ✅ Use `create_parent_dir_all()` before writes to avoid race conditions
- ✅ Always join via `virtual_join()` or `strict_join()` - never concatenate paths manually
- ✅ Treat absolute, UNC, drive-relative, or namespace-prefixed paths as untrusted
- ✅ On Windows, NTFS Alternate Data Streams (ADS) like `"file.txt:stream"` are handled safely

## Anti-Patterns (Don't Do This)

- ❌ Building paths with `format!`/`push`/`join` on `std::path::Path` without validation
- ❌ Stripping `"../"` by string replacement
- ❌ Allowing absolute paths through to the OS
- ❌ Treating encoded/unicode tricks (URL-encoded, dot lookalikes) as pre-sanitized

## Complete Example with PathBoundary

```rust
use strict_path::{PathBoundary, StrictPath};
use std::fs;
use std::io::Write;

struct SafeArchiveExtractor {
    extraction_dir: PathBoundary,
}

impl SafeArchiveExtractor {
    fn new(extract_to: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let extraction_dir = PathBoundary::try_new_create(extract_to)?;
        Ok(Self { extraction_dir })
    }
    
    fn extract_entry(&self, entry_path: &str, content: &[u8]) -> Result<StrictPath, Box<dyn std::error::Error>> {
        // This automatically prevents zip-slip attacks
        let safe_path = self.extraction_dir.strict_join(entry_path)?;

        // Create parent directories and write the file
        safe_path.create_parent_dir_all()?;
        safe_path.write(content)?;

        println!("📦 Extracted: {entry_path} -> {}", safe_path.strictpath_display());
        Ok(safe_path)
    }
    
    fn extract_mock_zip(&self) -> Result<Vec<StrictPath>, Box<dyn std::error::Error>> {
        // Simulate extracting a ZIP file with various entries
        let entries = vec![
            ("readme.txt", b"Welcome to our software!" as &[u8]),
            ("src/main.rs", b"fn main() { println!(\"Hello!\"); }"),
            ("docs/api.md", b"# API Documentation"),
            ("config/settings.json", b"{ \"debug\": true }"),
            
            // These malicious entries would be automatically blocked:
            // ("../../../etc/passwd", b"hacked"),           // ❌ Blocked!
            // ("..\\windows\\system32\\evil.exe", b"malware"), // ❌ Blocked!
            // ("/absolute/path/hack.txt", b"bad"),          // ❌ Blocked!
        ];
        
        let mut extracted_files = Vec::new();
        
        for (entry_path, content) in entries {
            match self.extract_entry(entry_path, content) {
                Ok(safe_path) => extracted_files.push(safe_path),
                Err(e) => println!("⚠️  Blocked malicious entry '{}': {}", entry_path, e),
            }
        }
        
        Ok(extracted_files)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let extractor = SafeArchiveExtractor::new("extracted_files")?;
    
    println!("🗃️  Extracting archive safely...");
    let extracted = extractor.extract_mock_zip()?;
    
    println!("\n✅ Successfully extracted {} files:", extracted.len());
    for file in &extracted {
        println!("   📄 {}", file.strictpath_display());
    }
    
    // Verify we can read the extracted files
    for file in &extracted {
        if file.strictpath_extension().and_then(|s| s.to_str()) == Some("txt") {
            let content = file.read_to_string()?;
            println!("📖 {}: {}", file.strictpath_display(), content.trim());
        }
    }
    
    Ok(())
}
```

## Handling Malicious Archives

When a malicious path is detected, you should:

```rust
fn extract_entry_with_security(
    extraction_dir: &PathBoundary,
    entry_path: &str,
    content: &[u8],
) -> Result<StrictPath, Box<dyn std::error::Error>> {
    match extraction_dir.strict_join(entry_path) {
        Ok(safe_path) => {
            // Valid path - extract normally
            safe_path.create_parent_dir_all()?;
            safe_path.write(content)?;
            Ok(safe_path)
        }
        Err(e) => {
            // Malicious path detected!
            eprintln!("🚨 SECURITY ALERT: Malicious archive entry detected!");
            eprintln!("   Entry path: {}", entry_path);
            eprintln!("   Error: {}", e);
            eprintln!("   Action: Rejecting entire archive as compromised");
            
            // Return error to stop extraction
            Err(format!("Archive contains malicious path: {}", entry_path).into())
        }
    }
}

// Usage
let entries = vec![
    ("readme.txt", b"Safe content" as &[u8]),
    ("../../../etc/passwd", b"Malicious"), // Skipped with log
    ("docs/api.md", b"More safe content"),
];

let count = extract_all_resilient("extracted", entries)?;
println!("✅ Successfully extracted {} files", count);
```

## Key Security Features

### 1. Bounded Extraction Directory
```rust
let extraction_dir = PathBoundary::try_new_create(extract_to)?;
```
All extracted files must stay within this directory.

### 2. Automatic Malicious Path Detection
```rust
let safe_path = self.extraction_dir.strict_join(entry_path)?;
```
This line does all the heavy lifting:
- Normalizes `../` sequences
- Blocks absolute paths
- Prevents symlink escapes
- Returns an error for malicious paths

### 3. Parent Directory Creation
```rust
safe_path.create_parent_dir_all()?;
```
Automatically creates any necessary parent directories within the boundary.

### 4. Type-Safe Returns
```rust
fn extract_entry(&self, entry_path: &str, content: &[u8]) -> Result<StrictPath, ...>
```
Returning `StrictPath` ensures extracted paths are always validated.

## Attack Scenarios Prevented

| Malicious Entry                   | StrictPath Result                    | VirtualPath Result                              |
| --------------------------------- | ------------------------------------ | ----------------------------------------------- |
| `../../../etc/passwd`             | ❌ Error: path escapes boundary       | ✅ Clamped to vroot `/etc/passwd`                |
| `..\\windows\\system32\\evil.exe` | ❌ Error: path escapes boundary       | ✅ Clamped to vroot `/windows/system32/evil.exe` |
| `/var/www/html/shell.php`         | ❌ Error: absolute path rejected      | ✅ Clamped to vroot `/var/www/html/shell.php`    |
| `legitimate/../../etc/passwd`     | ❌ Normalized and blocked             | ✅ Normalized and clamped                        |
| Symlink to `/etc/passwd`          | ❌ Target validated, error if outside | ✅ Target clamped to vroot `/etc/passwd`         |

**Note:** For archive extraction, consider using `VirtualPath` instead of `StrictPath` to gracefully clamp malicious entries rather than rejecting them. This provides defense-in-depth: even hostile archives with absolute paths or symlinks are safely contained within the extraction directory.

## Real ZIP Integration

With the `zip` crate:

```rust
use strict_path::{PathBoundary, StrictPath};
use zip::ZipArchive;
use std::fs::File;
use std::io::Read;

struct RealArchiveExtractor {
    extraction_dir: PathBoundary,
}

impl RealArchiveExtractor {
    fn new(extract_to: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let extraction_dir = PathBoundary::try_new_create(extract_to)?;
        Ok(Self { extraction_dir })
    }
    
    fn extract_zip(&self, zip_path: &str) -> Result<Vec<StrictPath>, Box<dyn std::error::Error>> {
        let file = File::open(zip_path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut extracted_files = Vec::new();
        
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let entry_path = file.name();
            
            // Validate the entry path - blocks zip-slip automatically
            let safe_path = match self.extraction_dir.strict_join(entry_path) {
                Ok(path) => path,
                Err(e) => {
                    println!("⚠️  Skipping malicious entry '{}': {}", entry_path, e);
                    continue;
                }
            };
            
            if file.is_dir() {
                safe_path.create_dir_all()?;
            } else {
                safe_path.create_parent_dir_all()?;
                let mut content = Vec::new();
                file.read_to_end(&mut content)?;
                safe_path.write(&content)?;
                extracted_files.push(safe_path);
                println!("📦 Extracted: {}", entry_path);
            }
        }
        
        Ok(extracted_files)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let extractor = RealArchiveExtractor::new("extracted")?;
    
    // Extract a real ZIP file safely
    let files = extractor.extract_zip("archive.zip")?;
    println!("✅ Extracted {} files", files.len());
    
    Ok(())
}
```

## TAR Archives

With the `tar` crate:

```rust
use strict_path::{PathBoundary, StrictPath};
use tar::Archive;
use std::fs::File;

fn extract_tar(tar_path: &str, extract_to: &str) -> Result<Vec<StrictPath>, Box<dyn std::error::Error>> {
    let boundary = PathBoundary::try_new_create(extract_to)?;
    let mut extracted = Vec::new();
    
    let file = File::open(tar_path)?;
    let mut archive = Archive::new(file);
    
    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?;
        let entry_path_str = entry_path.to_string_lossy();
        
        // Validate each entry path
        let safe_path = match boundary.strict_join(&*entry_path_str) {
            Ok(path) => path,
            Err(e) => {
                println!("⚠️  Skipping malicious entry '{}': {}", entry_path_str, e);
                continue;
            }
        };
        
        // Extract using the validated path
        entry.unpack(safe_path.interop_path())?;
        extracted.push(safe_path);
        println!("📦 Extracted: {}", entry_path_str);
    }
    
    Ok(extracted)
}
```

## Advanced: Extraction with Filters

Skip certain files or enforce naming patterns:

```rust
impl SafeArchiveExtractor {
    fn extract_with_filter<F>(
        &self,
        entries: Vec<(&str, &[u8])>,
        filter: F,
    ) -> Result<Vec<StrictPath>, Box<dyn std::error::Error>>
    where
        F: Fn(&str) -> bool,
    {
        let mut extracted = Vec::new();
        
        for (entry_path, content) in entries {
            // Apply custom filter
            if !filter(entry_path) {
                println!("⏭️  Skipped by filter: {}", entry_path);
                continue;
            }
            
            // Validate and extract
            match self.extract_entry(entry_path, content) {
                Ok(path) => extracted.push(path),
                Err(e) => println!("⚠️  Failed to extract '{}': {}", entry_path, e),
            }
        }
        
        Ok(extracted)
    }
}

// Usage:
let extracted = extractor.extract_with_filter(entries, |path| {
    // Only allow certain file types
    path.ends_with(".txt") || path.ends_with(".md") || path.ends_with(".rs")
})?;
```

## Temporary Extraction

Extract to a temporary directory for processing:

```rust
use strict_path::PathBoundary;
use tempfile::TempDir;

fn extract_to_temp(archive_path: &str) -> Result<(TempDir, Vec<StrictPath>), Box<dyn std::error::Error>> {
    // Create temp directory
    let temp = TempDir::new()?;
    
    // Create boundary from temp path
    let boundary = PathBoundary::try_new(temp.path())?;
    
    // Extract archive
    let extracted = extract_archive_to_boundary(&boundary, archive_path)?;
    
    // Return both TempDir (to keep it alive) and extracted paths
    Ok((temp, extracted))
}

// Temp directory is automatically cleaned up when TempDir is dropped
```

## Testing Advice

Test your extraction code with a malicious archive corpus:

### Test Cases to Include

- **Directory traversal**: `"../"`, `"..\\"`, `"legitimate/../../etc/passwd"`
- **Absolute paths**: `"/var/www/evil"`, `"C:\\windows\\system32\\evil.exe"`
- **Windows-specific**:
  - UNC paths: `"\\\\?\\C:\\windows\\evil"`
  - Drive-relative: `"C:..\\foo"`
  - ADS streams: `"decoy.txt:..\\..\\evil.exe"`
  - Reserved names: `"CON"`, `"PRN"`, `"AUX"`
- **Unicode tricks**: Dot lookalikes, NFC vs NFD forms
- **Long paths**: Paths exceeding system limits

### Assertions

```rust
#[test]
fn test_archive_extraction_safety() {
    let boundary = PathBoundary::try_new_create("./test_extract").unwrap();
    
    // Should succeed
    assert!(boundary.strict_join("safe/path.txt").is_ok());
    
    // Should fail
    assert!(boundary.strict_join("../../../etc/passwd").is_err());
    assert!(boundary.strict_join("/absolute/path").is_err());
    
    // Cleanup
    std::fs::remove_dir_all("test_extract").ok();
}
```

## Behavior Notes

- **Virtual joins clamp traversal** lexically to the virtual root
- **System-facing escapes** (via symlinks/junctions) are rejected during resolution
- **Unicode is not normalized** - NFC and NFD forms are stored as-is, both safely contained
- **Hard links and privileged mount tricks** are outside path-level protections (see README limitations)

## Using VirtualPath for Extra Safety

For even safer archive extraction, consider using `VirtualPath` instead of `StrictPath`. This clamps malicious entries instead of rejecting them:

```rust
use strict_path::{VirtualRoot, VirtualPath};

struct VirtualArchiveExtractor {
    extraction_vroot: VirtualRoot,
}

impl VirtualArchiveExtractor {
    fn new(extract_to: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let extraction_vroot = VirtualRoot::try_new_create(extract_to)?;
        Ok(Self { extraction_vroot })
    }
    
    fn extract_entry(&self, entry_path: &str, content: &[u8]) 
        -> Result<VirtualPath, Box<dyn std::error::Error>> 
    {
        // Malicious paths are CLAMPED instead of rejected
        // "../../../etc/passwd" becomes safe "vroot/etc/passwd"
        // Absolute symlink targets are also clamped to vroot
        let safe_path = self.extraction_vroot.virtual_join(entry_path)?;

        safe_path.create_parent_dir_all()?;
        safe_path.write(content)?;

        println!("📦 Extracted: {} -> {}", 
                 entry_path, 
                 safe_path.virtualpath_display());
        Ok(safe_path)
    }
}
```

**Why VirtualPath for archives?**
- ✅ Hostile entries with `../../../` are clamped, not rejected
- ✅ Absolute symlink targets (e.g., `link -> /etc/passwd`) are clamped to vroot
- ✅ Archive extraction continues even with malicious entries
- ✅ Defense-in-depth: every entry is safely contained
- ✅ Perfect for untrusted archives from the internet

**When to use each:**
- **`StrictPath`:** Fail-fast validation — reject malicious archives immediately
- **`VirtualPath`:** Graceful containment — clamp every entry to stay safe, continue extraction

## Best Practices

1. **Always validate** - Never trust archive entry paths
2. **Log suspicious entries** - Track and alert on blocked paths
3. **Limit extraction size** - Check total extracted size to prevent zip bombs
4. **Filter file types** - Only extract expected file types
5. **Use temporary storage** - Extract to temp directory first, then move to final location
6. **Consider VirtualPath** - Use for untrusted archives to clamp rather than reject malicious entries

## Integration Tips

### With Web Uploads
```rust
async fn handle_upload(file: UploadedFile) -> Result<Vec<String>, AppError> {
    // Save uploaded file
    let temp_zip = save_upload(file).await?;
    
    // Extract safely
    let extractor = SafeArchiveExtractor::new("uploads/extracted")?;
    let files = extractor.extract_zip(&temp_zip)?;
    
    // Return list of extracted files
    Ok(files.iter()
        .map(|p| p.strictpath_display().to_string())
        .collect())
}
```

### With Background Jobs
```rust
async fn extract_job(job_id: String, archive_path: String) -> Result<(), JobError> {
    let extract_dir = format!("jobs/{}/extracted", job_id);
    let extractor = SafeArchiveExtractor::new(&extract_dir)?;
    
    let files = extractor.extract_zip(&archive_path)?;
    
    // Store results in database
    for file in files {
        db_store_file(&job_id, file.strictpath_display())?;
    }
    
    Ok(())
}
```

## Next Steps

- See [CLI Tool](./cli_tool.md) for handling user-provided file paths
- See [Web Upload Service](./web_upload_service.md) for combining uploads with safe storage
