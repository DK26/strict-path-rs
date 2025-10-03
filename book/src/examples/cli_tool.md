# CLI Tool with Safe Path Handling

Build command-line tools that safely process user-provided file paths. This example shows how to handle untrusted path arguments securely.

## The Problem

CLI tools accept file paths from users, but must prevent:
- ❌ Users accessing files outside the working directory
- ❌ Path traversal attacks via command-line arguments
- ❌ Accidental exposure of sensitive files

## The Solution

Use `PathBoundary` to create a working directory jail. All file operations are restricted to this boundary.

## Complete Example

```rust
use strict_path::{PathBoundary, StrictPath};
use std::env;
use std::fs;

struct SafeFileProcessor {
    working_dir: PathBoundary,
}

impl SafeFileProcessor {
    fn new(working_directory: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Create or validate the working directory
        let working_dir = PathBoundary::try_new_create(working_directory)?;
        println!("🔒 Working directory jail: {}", working_dir.strictpath_display());
        Ok(Self { working_dir })
    }
    
    fn process_file(&self, relative_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Validate the user-provided path
        let safe_path = self.working_dir.strict_join(relative_path)?;
        
        if !safe_path.exists() {
            return Err(format!("File not found: {}", relative_path).into());
        }
        
        // Process the file (example: count lines)
        let content = safe_path.read_to_string()?;
        let line_count = content.lines().count();
        let word_count = content.split_whitespace().count();
        let char_count = content.chars().count();
        
        println!("📊 Statistics for {}:", relative_path);
        println!("   Lines: {}", line_count);
        println!("   Words: {}", word_count);
        println!("   Characters: {}", char_count);
        
        Ok(())
    }
    
    fn create_sample_files(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create some sample files for testing
        let samples = vec![
            ("sample1.txt", "Hello world!\nThis is a test file.\nWith multiple lines."),
            ("data/sample2.txt", "Another file\nwith some content\nfor processing."),
            ("docs/readme.md", "# Sample Project\n\nThis is a sample markdown file."),
        ];
        
        for (path, content) in samples {
            let safe_path = self.working_dir.strict_join(path)?;
            safe_path.create_parent_dir_all()?;
            safe_path.write(content)?;
            println!("📝 Created: {path}");
        }
        
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <file-path>", args[0]);
        println!("       {} --create-samples", args[0]);
        return Ok(());
    }
    
    // Set up our safe processor
    let processor = SafeFileProcessor::new("workspace")?;
    
    if args[1] == "--create-samples" {
        processor.create_sample_files()?;
        println!("✅ Sample files created in workspace/");
        return Ok(());
    }
    
    // Process the user-specified file
    let file_path = &args[1];
    
    match processor.process_file(file_path) {
        Ok(()) => println!("✅ File processed successfully!"),
        Err(e) => {
            println!("❌ Error processing file: {}", e);
            
            if file_path.contains("..") || file_path.starts_with('/') || file_path.contains('\\') {
                println!("💡 Tip: Use relative paths within the workspace directory only.");
                println!("   Trying to escape the workspace? That's not allowed! 🔒");
            }
        }
    }
    
    Ok(())
}

// Example usage:
// cargo run -- --create-samples
// cargo run -- sample1.txt                    # ✅ Works
// cargo run -- data/sample2.txt              # ✅ Works  
// cargo run -- ../../../etc/passwd           # ❌ Blocked!
// cargo run -- /absolute/path/hack.txt       # ❌ Blocked!
```

## Key Security Features

### 1. Working Directory Jail
```rust
let working_dir = PathBoundary::try_new_create(working_directory)?;
```
All file operations are restricted to this directory and its subdirectories.

### 2. User Input Validation
```rust
let safe_path = self.working_dir.strict_join(relative_path)?;
```
User-provided paths from command-line arguments are validated before any file access.

### 3. Helpful Error Messages
```rust
if file_path.contains("..") || file_path.starts_with('/') {
    println!("💡 Tip: Use relative paths within the workspace directory only.");
}
```
Guide users toward safe usage patterns.

### 4. Safe File Operations
All operations use the validated `StrictPath`, so security is guaranteed by the type system.

## Attack Scenarios Prevented

| User Input                  | Result                                 |
| --------------------------- | -------------------------------------- |
| `sample1.txt`               | ✅ Processes workspace/sample1.txt      |
| `data/sample2.txt`          | ✅ Processes workspace/data/sample2.txt |
| `../../../etc/passwd`       | ❌ Error: path escapes boundary         |
| `/var/log/system.log`       | ❌ Error: absolute paths not allowed    |
| `..\\..\\windows\\system32` | ❌ Error: path escapes boundary         |

## Advanced: Multiple Operations

Process multiple files from command-line arguments:

```rust
impl SafeFileProcessor {
    fn process_multiple(&self, paths: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        for path in paths {
            match self.process_file(path) {
                Ok(()) => println!("✅ Processed: {}", path),
                Err(e) => println!("❌ Failed to process '{}': {}", path, e),
            }
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <file1> [file2] [file3] ...", args[0]);
        return Ok(());
    }
    
    let processor = SafeFileProcessor::new("workspace")?;
    let file_paths = &args[1..];
    
    processor.process_multiple(file_paths)?;
    
    Ok(())
}
```

## Pattern Matching and Filtering

Process files matching a pattern:

```rust
impl SafeFileProcessor {
    fn process_pattern(&self, pattern: &str) -> Result<Vec<StrictPath>, Box<dyn std::error::Error>> {
        let mut processed = Vec::new();
        
        for entry in self.working_dir.read_dir()? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let filename = entry.file_name();
                let filename_str = filename.to_string_lossy();
                
                // Simple pattern matching (extend with regex if needed)
                if filename_str.ends_with(pattern) {
                    let file_path = self.working_dir.strict_join(&filename)?;
                    self.process_file(&filename_str)?;
                    processed.push(file_path);
                }
            }
        }
        
        Ok(processed)
    }
}

// Usage:
// cargo run -- "*.txt"  // Process all .txt files
// cargo run -- "*.md"   // Process all .md files
```

## Interactive Mode

Build an interactive CLI with safe path handling:

```rust
use std::io::{self, BufRead};

fn interactive_mode(processor: &SafeFileProcessor) -> Result<(), Box<dyn std::error::Error>> {
    println!("📂 Interactive mode - enter file paths to process (type 'quit' to exit)");
    println!("🔒 Working in: {}", processor.working_dir.strictpath_display());
    
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        let trimmed = line.trim();
        
        if trimmed == "quit" || trimmed == "exit" {
            break;
        }
        
        if trimmed == "list" {
            list_files(&processor.working_dir)?;
            continue;
        }
        
        if trimmed.is_empty() {
            continue;
        }
        
        match processor.process_file(trimmed) {
            Ok(()) => println!("✅ Done"),
            Err(e) => println!("❌ Error: {}", e),
        }
    }
    
    println!("👋 Goodbye!");
    Ok(())
}

fn list_files(boundary: &PathBoundary) -> Result<(), Box<dyn std::error::Error>> {
    println!("📁 Available files:");
    for entry in boundary.read_dir()? {
        let entry = entry?;
        println!("  - {}", entry.file_name().to_string_lossy());
    }
    Ok(())
}
```

## Output File Handling

Write results to output files safely:

```rust
impl SafeFileProcessor {
    fn process_to_output(
        &self,
        input_path: &str,
        output_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Validate both input and output paths
        let input = self.working_dir.strict_join(input_path)?;
        let output = self.working_dir.strict_join(output_path)?;
        
        // Process input
        let content = input.read_to_string()?;
        let processed = content.to_uppercase(); // Example transformation
        
        // Write to output
        output.create_parent_dir_all()?;
        output.write(&processed)?;
        
        println!("✅ Processed {} -> {}", input_path, output_path);
        
        Ok(())
    }
}

// Usage:
// cargo run -- input.txt output.txt
```

## Environment Variable Configuration

Allow configuration via environment variables:

```rust
fn get_working_directory() -> String {
    env::var("WORKSPACE_DIR")
        .unwrap_or_else(|_| "workspace".to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let work_dir = get_working_directory();
    let processor = SafeFileProcessor::new(&work_dir)?;
    
    // ... rest of implementation
    Ok(())
}

// Usage:
// WORKSPACE_DIR=/path/to/data cargo run -- file.txt
```

## Progress Tracking

For processing many files:

```rust
impl SafeFileProcessor {
    fn process_directory(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut total = 0;
        let mut processed = 0;
        let mut failed = 0;
        
        // Count total files
        for entry in self.working_dir.read_dir()? {
            if entry?.file_type()?.is_file() {
                total += 1;
            }
        }
        
        println!("📊 Processing {} files...", total);
        
        // Process each file
        for entry in self.working_dir.read_dir()? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let filename = entry.file_name();
                let path_str = filename.to_string_lossy();
                
                match self.process_file(&path_str) {
                    Ok(()) => {
                        processed += 1;
                        println!("[{}/{}] ✅ {}", processed + failed, total, path_str);
                    }
                    Err(e) => {
                        failed += 1;
                        println!("[{}/{}] ❌ {}: {}", processed + failed, total, path_str, e);
                    }
                }
            }
        }
        
        println!("\n📈 Summary:");
        println!("   Total: {}", total);
        println!("   Processed: {}", processed);
        println!("   Failed: {}", failed);
        
        Ok(())
    }
}
```

## Best Practices

1. **Clear boundaries** - Clearly communicate the working directory to users
2. **Helpful errors** - Explain why paths are rejected and suggest alternatives
3. **Relative paths only** - Guide users toward using relative paths
4. **Validate early** - Check paths before performing expensive operations
5. **Log rejections** - Track attempted path escapes for security monitoring

## Integration Tips

### With `clap` for Argument Parsing
```rust
use clap::Parser;

#[derive(Parser)]
struct Cli {
    /// File to process (relative to workspace)
    #[arg(value_name = "FILE")]
    file_path: String,
    
    /// Working directory
    #[arg(short, long, default_value = "workspace")]
    workspace: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let processor = SafeFileProcessor::new(&cli.workspace)?;
    processor.process_file(&cli.file_path)?;
    Ok(())
}
```

### With Glob Patterns
```rust
use glob::glob;

fn process_glob(processor: &SafeFileProcessor, pattern: &str) -> Result<(), Box<dyn std::error::Error>> {
    let workspace = processor.working_dir.strictpath_display().to_string();
    let full_pattern = format!("{}/{}", workspace, pattern);
    
    for entry in glob(&full_pattern)? {
        let path = entry?;
        if let Ok(relative) = path.strip_prefix(&workspace) {
            if let Some(relative_str) = relative.to_str() {
                processor.process_file(relative_str)?;
            }
        }
    }
    
    Ok(())
}
```

## Next Steps

- See [Configuration Manager](./config_manager.md) for handling config files safely
- See [Archive Extraction](./archive_extraction.md) for processing archives from CLI
