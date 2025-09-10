# Real-World Examples

This chapter shows practical, real-world scenarios where jailed-path helps secure your applications. Each example includes complete, runnable code that you can adapt to your own projects.

## Web File Upload Service

Let's build a simple file upload service that allows users to upload files safely:

```rust
use jailed_path::{Jail, JailedPath};
use std::fs;
use std::io::{self, Write};

struct FileUploadService {
    uploads_jail: Jail,
}

impl FileUploadService {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Create a jail for uploaded files
        let uploads_jail = Jail::try_new_create("user_uploads")?;
        Ok(Self { uploads_jail })
    }
    
    fn upload_file(&self, filename: &str, content: &[u8]) -> Result<JailedPath, Box<dyn std::error::Error>> {
        // Validate the filename is safe
        let safe_path = self.uploads_jail.jailed_join(filename)?;
        
        // Create parent directories if needed
        if let Some(parent) = safe_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Write the file safely
        fs::write(&safe_path, content)?;
        
        println!("✅ File uploaded safely to: {}", safe_path.as_path().display());
        Ok(safe_path)
    }
    
    fn list_files(&self) -> Result<Vec<JailedPath>, Box<dyn std::error::Error>> {
        let mut files = Vec::new();
        
        // Only iterate within the jail
        for entry in fs::read_dir(&self.uploads_jail)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                // Validate each path through the jail
                let safe_path = self.uploads_jail.jailed_join(entry.file_name())?;
                files.push(safe_path);
            }
        }
        
        Ok(files)
    }
    
    fn download_file(&self, filename: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Validate the requested filename
        let safe_path = self.uploads_jail.jailed_join(filename)?;
        
        // Read and return the file content
        let content = fs::read(&safe_path)?;
        Ok(content)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = FileUploadService::new()?;
    
    // Simulate user uploads - these are all SAFE
    service.upload_file("document.txt", b"Hello, world!")?;
    service.upload_file("reports/january.pdf", b"PDF content here")?;
    service.upload_file("images/photo.jpg", b"JPEG data")?;
    
    // These would FAIL with directory traversal protection:
    // service.upload_file("../../../etc/passwd", b"attack")?;  // ❌ Blocked!
    // service.upload_file("..\\windows\\system32\\evil.exe", b"malware")?;  // ❌ Blocked!
    
    // List uploaded files
    println!("📁 Uploaded files:");
    for file in service.list_files()? {
        println!("  - {}", file.as_path().display());
    }
    
    // Download a file
    let content = service.download_file("document.txt")?;
    println!("📄 Downloaded: {}", String::from_utf8_lossy(&content));
    
    Ok(())
}
```

## Configuration File Manager

Here's how to safely handle user configuration files:

```rust
use jailed_path::{Jail, JailedPath};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug)]
struct AppConfig {
    theme: String,
    language: String,
    auto_save: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            language: "en".to_string(),
            auto_save: true,
        }
    }
}

struct ConfigManager {
    config_jail: Jail,
}

impl ConfigManager {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Create a jail for configuration files
        let config_jail = Jail::try_new_create("app_config")?;
        Ok(Self { config_jail })
    }
    
    fn load_config(&self, config_name: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
        // Ensure the config file name is safe
        let config_path = self.config_jail.jailed_join(config_name)?;
        
        // Load config or create default
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: AppConfig = serde_json::from_str(&content)?;
            println!("📖 Loaded config from: {}", config_path.as_path().display());
            Ok(config)
        } else {
            println!("🆕 Creating default config at: {}", config_path.as_path().display());
            let default_config = AppConfig::default();
            self.save_config(config_name, &default_config)?;
            Ok(default_config)
        }
    }
    
    fn save_config(&self, config_name: &str, config: &AppConfig) -> Result<JailedPath, Box<dyn std::error::Error>> {
        // Validate the config file path
        let config_path = self.config_jail.jailed_join(config_name)?;
        
        // Serialize and save
        let content = serde_json::to_string_pretty(config)?;
        fs::write(&config_path, content)?;
        
        println!("💾 Saved config to: {}", config_path.as_path().display());
        Ok(config_path)
    }
    
    fn list_configs(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut configs = Vec::new();
        
        for entry in fs::read_dir(&self.config_jail)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".json") {
                        configs.push(name.to_string());
                    }
                }
            }
        }
        
        Ok(configs)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_manager = ConfigManager::new()?;
    
    // Load or create user config
    let mut user_config = config_manager.load_config("user.json")?;
    println!("Current config: {:#?}", user_config);
    
    // Modify and save
    user_config.theme = "light".to_string();
    user_config.auto_save = false;
    config_manager.save_config("user.json", &user_config)?;
    
    // Create a different profile
    let admin_config = AppConfig {
        theme: "admin".to_string(),
        language: "en".to_string(),
        auto_save: true,
    };
    config_manager.save_config("admin.json", &admin_config)?;
    
    // List all configs
    println!("📋 Available configs: {:?}", config_manager.list_configs()?);
    
    // These attempts would be blocked:
    // config_manager.load_config("../../../etc/passwd")?;  // ❌ Blocked!
    // config_manager.save_config("..\\windows\\evil.json", &user_config)?;  // ❌ Blocked!
    
    Ok(())
}
```

## Multi-User Document Storage with VirtualPath

For applications where each user should feel like they have their own filesystem:

```rust
use jailed_path::{VirtualRoot, VirtualPath};
use std::fs;
use std::collections::HashMap;

struct DocumentStore {
    user_roots: HashMap<String, VirtualRoot>,
}

impl DocumentStore {
    fn new() -> Self {
        Self {
            user_roots: HashMap::new(),
        }
    }
    
    fn get_user_root(&mut self, username: &str) -> Result<&VirtualRoot, Box<dyn std::error::Error>> {
        if !self.user_roots.contains_key(username) {
            // Each user gets their own isolated storage
            let user_dir = format!("user_data_{}", username);
            let vroot = VirtualRoot::try_new_create(&user_dir)?;
            self.user_roots.insert(username.to_string(), vroot);
            println!("🏠 Created virtual root for user: {}", username);
        }
        
        Ok(self.user_roots.get(username).unwrap())
    }
    
    fn save_document(&mut self, username: &str, virtual_path: &str, content: &str) -> Result<VirtualPath, Box<dyn std::error::Error>> {
        let user_root = self.get_user_root(username)?;
        
        // User thinks they're saving to their own filesystem starting from "/"
        let doc_path = user_root.virtual_join(virtual_path)?;
        
        // Create parent directories if needed
        if let Some(parent) = doc_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Save the document
        fs::write(&doc_path, content)?;
        
        println!("📝 User {} saved document to: {}", username, virtual_path);
        println!("    (Actually stored at: {})", doc_path.as_path().display());
        
        Ok(doc_path)
    }
    
    fn load_document(&mut self, username: &str, virtual_path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let user_root = self.get_user_root(username)?;
        let doc_path = user_root.virtual_join(virtual_path)?;
        
        let content = fs::read_to_string(&doc_path)?;
        println!("📖 User {} loaded document from: {}", username, virtual_path);
        
        Ok(content)
    }
    
    fn list_user_documents(&mut self, username: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let user_root = self.get_user_root(username)?;
        let mut docs = Vec::new();
        
        fn collect_files(dir: &std::path::Path, base: &std::path::Path, docs: &mut Vec<String>) -> std::io::Result<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_file() {
                    if let Ok(relative) = path.strip_prefix(base) {
                        if let Some(path_str) = relative.to_str() {
                            docs.push(format!("/{}", path_str.replace("\\", "/")));
                        }
                    }
                } else if path.is_dir() {
                    collect_files(&path, base, docs)?;
                }
            }
            Ok(())
        }
        
        collect_files(user_root.as_path(), user_root.as_path(), &mut docs)?;
        Ok(docs)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = DocumentStore::new();
    
    // Alice saves some documents
    store.save_document("alice", "/reports/quarterly.txt", "Q1 revenue was strong")?;
    store.save_document("alice", "/notes/meeting.md", "# Meeting Notes\n- Discuss new features")?;
    store.save_document("alice", "/drafts/proposal.doc", "Project proposal draft")?;
    
    // Bob saves his documents (completely separate from Alice)
    store.save_document("bob", "/code/main.rs", "fn main() { println!(\"Hello!\"); }")?;
    store.save_document("bob", "/docs/readme.txt", "My awesome project")?;
    
    // Charlie tries to access Alice's files - this is blocked at the path level
    // store.save_document("charlie", "/../alice/reports/quarterly.txt", "hacked")?;  // ❌ Blocked!
    
    // Each user can access their own files
    println!("📄 Alice's quarterly report: {}", store.load_document("alice", "/reports/quarterly.txt")?);
    println!("💻 Bob's code: {}", store.load_document("bob", "/code/main.rs")?);
    
    // List each user's documents
    println!("📁 Alice's documents: {:?}", store.list_user_documents("alice")?);
    println!("📁 Bob's documents: {:?}", store.list_user_documents("bob")?);
    
    Ok(())
}
```

## Archive Extraction with Safety

Safely extract ZIP files and other archives without zip-slip vulnerabilities:

```rust
use jailed_path::{Jail, JailedPath};
use std::fs;
use std::io::Write;

struct SafeArchiveExtractor {
    extraction_jail: Jail,
}

impl SafeArchiveExtractor {
    fn new(extract_to: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let extraction_jail = Jail::try_new_create(extract_to)?;
        Ok(Self { extraction_jail })
    }
    
    fn extract_entry(&self, entry_path: &str, content: &[u8]) -> Result<JailedPath, Box<dyn std::error::Error>> {
        // This automatically prevents zip-slip attacks
        let safe_path = self.extraction_jail.jailed_join(entry_path)?;
        
        // Create parent directories
        if let Some(parent) = safe_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Write the file
        fs::write(&safe_path, content)?;
        
        println!("📦 Extracted: {} -> {}", entry_path, safe_path.as_path().display());
        Ok(safe_path)
    }
    
    fn extract_mock_zip(&self) -> Result<Vec<JailedPath>, Box<dyn std::error::Error>> {
        // Simulate extracting a ZIP file with various entries
        let entries = vec![
            ("readme.txt", b"Welcome to our software!"),
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
        println!("   📄 {}", file.as_path().display());
    }
    
    // Verify we can read the extracted files
    for file in &extracted {
        if file.as_path().extension().and_then(|s| s.to_str()) == Some("txt") {
            let content = fs::read_to_string(file)?;
            println!("📖 {}: {}", file.as_path().display(), content.trim());
        }
    }
    
    Ok(())
}
```

## CLI Tool with Safe Path Handling

A command-line tool that processes user-provided file paths safely:

```rust
use jailed_path::{Jail, JailedPath};
use std::env;
use std::fs;

struct SafeFileProcessor {
    working_jail: Jail,
}

impl SafeFileProcessor {
    fn new(working_directory: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Create or validate the working directory
        let working_jail = Jail::try_new_create(working_directory)?;
        println!("🔒 Working directory jail: {}", working_jail.as_path().display());
        Ok(Self { working_jail })
    }
    
    fn process_file(&self, relative_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Validate the user-provided path
        let safe_path = self.working_jail.jailed_join(relative_path)?;
        
        if !safe_path.exists() {
            return Err(format!("File not found: {}", relative_path).into());
        }
        
        // Process the file (example: count lines)
        let content = fs::read_to_string(&safe_path)?;
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
            let safe_path = self.working_jail.jailed_join(path)?;
            if let Some(parent) = safe_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&safe_path, content)?;
            println!("📝 Created: {}", path);
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

## Key Takeaways

These examples show how jailed-path helps in real scenarios:

1. **Web uploads**: Users can't escape the upload directory
2. **Configuration**: Config files stay in their designated area
3. **Multi-user**: Each user gets isolated storage that feels like their own filesystem
4. **Archive extraction**: Automatic protection against zip-slip attacks
5. **CLI tools**: User-provided paths are validated safely

The common pattern is:
1. Create a `Jail` or `VirtualRoot` for your safe area
2. Always validate external paths through `jailed_join()` or `virtual_join()`
3. Use the resulting `JailedPath` or `VirtualPath` for file operations
4. Let the compiler enforce that only validated paths are used

This makes your code both secure and maintainable - security isn't something you have to remember to check, it's built into the type system!
