# Real-World Examples

This chapter shows practical, real-world scenarios where strict-path helps secure your applications. Each example includes complete, runnable code that you can adapt to your own projects.

## Web File Upload Service

Let's build a simple file upload service that allows users to upload files safely:

```rust
use strict_path::{StrictPath, VirtualPath, VirtualRoot};
use std::io;

struct FileUploadService;

impl FileUploadService {
    // Multi-user: each user operates under their own VirtualRoot
    fn upload_file(
        &self,
        user_root: &VirtualRoot,
        filename: &str,
        content: &[u8],
    ) -> Result<VirtualPath, Box<dyn std::error::Error>> {
        // Validate the untrusted filename at the user’s virtual root
        let dest = user_root.virtual_join(filename)?;
        // Reuse strict-typed helper when needed
        self.save_uploaded(dest.as_unvirtual(), content)?;
        println!("✅ File uploaded safely to: {}", dest.virtualpath_display());
        Ok(dest)
    }

    // Internal helper: signature encodes guarantee (accepts only &StrictPath)
    fn save_uploaded(&self, path: &StrictPath, content: &[u8]) -> io::Result<()> {
        path.create_parent_dir_all()?;
        path.write_bytes(content)
    }

    fn list_files(
        &self,
        user_root: &VirtualRoot,
    ) -> Result<Vec<VirtualPath>, Box<dyn std::error::Error>> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(user_root.interop_path())? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let vpath = user_root.virtual_join(entry.file_name())?;
                files.push(vpath);
            }
        }
        Ok(files)
    }

    fn download_file(&self, path: &VirtualPath) -> io::Result<Vec<u8>> {
        // Read and return the file content — type ensures safety
        path.read_bytes()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = FileUploadService;

    // Per-user virtual roots
    let alice_root: VirtualRoot = VirtualRoot::try_new_create("user_uploads/alice")?;
    let bob_root: VirtualRoot = VirtualRoot::try_new_create("user_uploads/bob")?;

    // Simulate user uploads - these are all SAFE and isolated
    service.upload_file(&alice_root, "document.txt", b"Hello, world!")?;
    service.upload_file(&alice_root, "reports/january.pdf", b"PDF content here")?;
    service.upload_file(&bob_root, "images/photo.jpg", b"JPEG data")?;

    // These would be clamped/blocked by validation:
    // service.upload_file(&alice_root, "../../../etc/passwd", b"attack")?;  // ❌ Blocked!
    // service.upload_file(&alice_root, "..\\windows\\system32\\evil.exe", b"malware")?;  // ❌ Blocked!

    // List Alice’s uploaded files (virtual paths)
    println!("📁 Alice's files:");
    for vpath in service.list_files(&alice_root)? {
        println!("  - {}", vpath.virtualpath_display());
    }

    // Download a file using VirtualPath
    let target = alice_root.virtual_join("document.txt")?;
    let content = service.download_file(&target)?;
    println!("📄 Downloaded: {}", String::from_utf8_lossy(&content));

    Ok(())
}
```

## Configuration File Manager

Here's how to safely handle user configuration files:

```rust
use strict_path::{PathBoundary, StrictPath};
use serde::{Deserialize, Serialize};

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
    config_dir: PathBoundary,
}

impl ConfigManager {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Create a jail for configuration files
        let config_dir = PathBoundary::try_new_create("app_config")?;
        Ok(Self { config_dir })
    }
    
    fn load_config(&self, config_name: &str) -> Result<AppConfig, Box<dyn std::error::Error>> {
        // Ensure the config file name is safe
        let config_path = self.config_dir.strict_join(config_name)?;
        
        // Load config or create default
        if config_path.exists() {
            let content = config_path.read_to_string()?;
            let config: AppConfig = serde_json::from_str(&content)?;
            println!("📖 Loaded config from: {}", config_path.strictpath_display());
            Ok(config)
        } else {
            println!("🆕 Creating default config at: {}", config_path.strictpath_display());
            let default_config = AppConfig::default();
            self.save_config(config_name, &default_config)?;
            Ok(default_config)
        }
    }
    
    fn save_config(&self, config_name: &str, config: &AppConfig) -> Result<StrictPath, Box<dyn std::error::Error>> {
        // Validate the config file path
        let config_path = self.config_dir.strict_join(config_name)?;
        
        // Serialize and save
        let content = serde_json::to_string_pretty(config)?;
        config_path.write_string(&content)?;

        println!("💾 Saved config to: {}", config_path.strictpath_display());
        Ok(config_path)
    }
    
    fn list_configs(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut configs = Vec::new();
        
        for entry in std::fs::read_dir(self.config_dir.interop_path())? {
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
use strict_path::{VirtualRoot, VirtualPath};
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
        
        // Create parent directories and save
        doc_path.create_parent_dir_all()?;
        doc_path.write_string(content)?;
        
        println!("📝 User {username} saved document to: {}", doc_path.virtualpath_display());
        println!("    (Actually stored at: {})", doc_path.as_unvirtual().strictpath_display());
        
        Ok(doc_path)
    }
    
    fn load_document(&mut self, username: &str, virtual_path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let user_root = self.get_user_root(username)?;
        let doc_path = user_root.virtual_join(virtual_path)?;
        
        let content = doc_path.read_to_string()?;
        println!("📖 User {} loaded document from: {}", username, virtual_path);
        
        Ok(content)
    }
    
    fn list_user_documents(&mut self, username: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let user_root = self.get_user_root(username)?;
        let mut docs = Vec::new();
        
        fn collect_files(dir: impl AsRef<std::path::Path>, base: impl AsRef<std::path::Path>, docs: &mut Vec<String>) -> std::io::Result<()> {
            let dir = dir.as_ref();
            let base = base.as_ref();
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
        
        collect_files(user_root.interop_path(), user_root.interop_path(), &mut docs)?;
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
        safe_path.write_bytes(content)?;

        println!("📦 Extracted: {entry_path} -> {}", safe_path.strictpath_display());
        Ok(safe_path)
    }
    
    fn extract_mock_zip(&self) -> Result<Vec<StrictPath>, Box<dyn std::error::Error>> {
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

## CLI Tool with Safe Path Handling

A command-line tool that processes user-provided file paths safely:

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
            safe_path.write_string(content)?;
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

## Advanced: Type-Safe Context Separation

One of the most powerful features is using marker types to prevent accidentally mixing different storage contexts at compile time:

```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

// Define marker types for different contexts
struct WebAssets;    // CSS, JS, images
struct UserFiles;    // Uploaded documents
struct ConfigData;   // Application configuration

// Functions enforce context via type system
fn serve_asset(path: &StrictPath<WebAssets>) -> Result<Vec<u8>, std::io::Error> {
    path.read_bytes()
}

fn process_upload(path: &StrictPath<UserFiles>) -> Result<(), std::io::Error> {
    // Process user-uploaded file
    let content = path.read_to_string()?;
    println!("Processing user file: {}", content.len());
    Ok(())
}

fn load_config(path: &StrictPath<ConfigData>) -> Result<String, std::io::Error> {
    path.read_to_string()
}

fn example_type_safety() -> Result<(), Box<dyn std::error::Error>> {
    // Create context-specific boundaries
    let assets_root: VirtualRoot<WebAssets> = VirtualRoot::try_new("public")?;
    let uploads_root: VirtualRoot<UserFiles> = VirtualRoot::try_new("uploads")?;
    let config_boundary: PathBoundary<ConfigData> = PathBoundary::try_new("config")?;

    // Create paths with proper contexts
    let css: VirtualPath<WebAssets> = assets_root.virtual_join("app.css")?;
    let doc: VirtualPath<UserFiles> = uploads_root.virtual_join("report.pdf")?;
    let cfg: StrictPath<ConfigData> = config_boundary.strict_join("app.toml")?;

    // Type system prevents context mixing
    serve_asset(&css.unvirtual())?;         // ✅ Correct context
    process_upload(&doc.unvirtual())?;      // ✅ Correct context  
    load_config(&cfg)?;                     // ✅ Correct context

    // These would be compile errors:
    // serve_asset(&doc.unvirtual())?;      // ❌ Compile error - wrong context!
    // process_upload(&css.unvirtual())?;   // ❌ Compile error - wrong context!
    // load_config(&css.unvirtual())?;      // ❌ Compile error - wrong context!

    Ok(())
}
```

**Benefits of this approach:**

1. **Compile-time safety**: Impossible to accidentally serve user uploads as web assets
2. **Clear interfaces**: Function signatures document what type of files they expect
3. **Refactoring safety**: If you change a function's context, the compiler finds all places that need updates
4. **Team collaboration**: New developers can't make context mixing mistakes

### Function Signatures That Enforce Security

Design your functions to make security bypass impossible:

```rust
// ✅ SECURE: Function signature guarantees safety
fn process_file<M>(path: &StrictPath<M>) -> std::io::Result<Vec<u8>> {
    path.read_bytes() // No validation needed - type system enforces it
}

// ✅ SECURE: Caller must validate before calling  
fn save_upload(file: &VirtualPath) -> std::io::Result<()> {
    file.write_bytes(&data) // Guaranteed within boundaries
}

// ❌ INSECURE: Function accepts dangerous inputs
fn dangerous_function(path: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(path) // 🚨 Could read anything on filesystem
}
```

**The Pattern**: Push validation to the boundary, then use safe types everywhere.

## Key Takeaways

These examples show how strict-path helps in real scenarios:

1. **Web uploads**: Users can't escape the upload directory
2. **Configuration**: Config files stay in their designated area
3. **Multi-user**: Each user gets isolated storage that feels like their own filesystem
4. **Archive extraction**: Automatic protection against zip-slip attacks
5. **CLI tools**: User-provided paths are validated safely
6. **Type safety**: Marker types prevent mixing different storage contexts

The common pattern is:
1. Create a `PathBoundary` or `VirtualRoot` for your safe area
2. Always validate external paths through `strict_join()` or `virtual_join()`
3. Use the resulting `StrictPath` or `VirtualPath` for file operations
4. Let the compiler enforce that only validated paths are used

This makes your code both secure and maintainable - security isn't something you have to remember to check, it's built into the type system!
