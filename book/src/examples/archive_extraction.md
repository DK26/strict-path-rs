# Archive Extraction with Safety

Extract ZIP files and other archives safely without zip-slip vulnerabilities. This example shows how path validation automatically prevents malicious archive entries.

## The Problem

Archive extractors are vulnerable to **zip-slip attacks** where malicious archives contain entries like:
- ❌ `../../../etc/passwd` - Escapes to system files
- ❌ `..\\..\\windows\\system32\\evil.exe` - Escapes on Windows
- ❌ Symlinks pointing outside the extraction directory

## The Solution

Use `PathBoundary` to restrict extraction to a specific directory. Malicious paths are automatically blocked.

## Complete Example

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

| Malicious Entry                   | Result                                  |
| --------------------------------- | --------------------------------------- |
| `../../../etc/passwd`             | ❌ Error: path escapes boundary          |
| `..\\windows\\system32\\evil.exe` | ❌ Error: path escapes boundary          |
| `/var/www/html/shell.php`         | ❌ Treated as relative, may still escape |
| `legitimate/../../etc/passwd`     | ❌ Normalized and blocked                |
| Symlink to `/etc/passwd`          | ❌ Resolved and validated                |

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

## Best Practices

1. **Always validate** - Never trust archive entry paths
2. **Log suspicious entries** - Track and alert on blocked paths
3. **Limit extraction size** - Check total extracted size to prevent zip bombs
4. **Filter file types** - Only extract expected file types
5. **Use temporary storage** - Extract to temp directory first, then move to final location

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
