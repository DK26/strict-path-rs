# Stage 6: Feature Integration — Ecosystem Integration with Safe Boundaries

> *"Integrate with OS directories, temp files, and app-specific paths — safely."*

You've mastered the core concepts: boundaries, markers, authorization, and virtual paths. Now you'll learn how to integrate strict-path with your ecosystem using **feature-gated constructors** that work seamlessly with popular Rust crates.

## The Problem: External Directory APIs

Your app needs to work with standard directories:
- **User config:** `~/.config/myapp/` (Linux) or `C:\Users\Alice\AppData\Roaming\myapp\` (Windows)
- **Temp files:** System temp directory with automatic cleanup
- **Downloads:** User's Downloads folder
- **App directories:** Portable app-specific paths

But you still need **boundary enforcement**! Otherwise, untrusted input can escape these directories too.

## The Solution: Feature-Gated Constructors

Enable features in `Cargo.toml`:

```toml
[dependencies]
strict-path = { version = "0.1.0-beta.1", features = ["dirs", "tempfile", "app-path", "serde"] }
```

Now you get special constructors that combine external crate APIs with strict-path's boundary enforcement.

## Feature: `dirs` — OS Standard Directories

The `dirs` feature adds constructors for platform-specific user directories:

```rust
use strict_path::PathBoundary;

struct AppConfig;
struct UserDownloads;
struct UserDocuments;

fn use_os_directories() -> Result<(), Box<dyn std::error::Error>> {
    // Get user's config directory (platform-specific)
    let config_dir: PathBoundary<AppConfig> = PathBoundary::try_new_os_config("myapp")?;
    // Linux: ~/.config/myapp/
    // Windows: C:\Users\Alice\AppData\Roaming\myapp\
    // macOS: ~/Library/Application Support/myapp/

    let config_file = config_dir.strict_join("settings.toml")?;
    config_file.write(b"theme = dark\nlanguage = en")?;
    println!("Config: {}", config_file.strictpath_display());

    // Get user's downloads directory
    let downloads_dir: PathBoundary<UserDownloads> = PathBoundary::try_new_os_downloads()?;
    let export_file = downloads_dir.strict_join("export.csv")?;
    export_file.write(b"col1,col2\nval1,val2")?;
    println!("Export: {}", export_file.strictpath_display());

    // Get user's documents directory
    let docs_dir: PathBoundary<UserDocuments> = PathBoundary::try_new_os_documents()?;
    let report = docs_dir.strict_join("report.pdf")?;
    report.write(b"PDF content")?;
    println!("Report: {}", report.strictpath_display());

    Ok(())
}
```

### Available OS Directory Constructors

| Constructor                | Linux                 | Windows                             | macOS                                |
| -------------------------- | --------------------- | ----------------------------------- | ------------------------------------ |
| `try_new_os_config("app")` | `~/.config/app/`      | `C:\Users\...\AppData\Roaming\app\` | `~/Library/Application Support/app/` |
| `try_new_os_data("app")`   | `~/.local/share/app/` | `C:\Users\...\AppData\Roaming\app\` | `~/Library/Application Support/app/` |
| `try_new_os_cache("app")`  | `~/.cache/app/`       | `C:\Users\...\AppData\Local\app\`   | `~/Library/Caches/app/`              |
| `try_new_os_downloads()`   | `~/Downloads/`        | `C:\Users\...\Downloads\`           | `~/Downloads/`                       |
| `try_new_os_documents()`   | `~/Documents/`        | `C:\Users\...\Documents\`           | `~/Documents/`                       |
| `try_new_os_pictures()`    | `~/Pictures/`         | `C:\Users\...\Pictures\`            | `~/Pictures/`                        |
| `try_new_os_videos()`      | `~/Videos/`           | `C:\Users\...\Videos\`              | `~/Videos/`                          |
| `try_new_os_music()`       | `~/Music/`            | `C:\Users\...\Music\`               | `~/Music/`                           |

See the [OS Directories chapter](../os_directories.md) for the complete list and details.

### Try It: Cross-Platform Config Manager

```rust
use strict_path::PathBoundary;

struct AppSettings;

fn save_user_settings(theme: &str, language: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Works on Linux, Windows, and macOS automatically!
    let config_dir: PathBoundary<AppSettings> = 
        PathBoundary::try_new_os_config("myapp")?;

    let settings_file = config_dir.strict_join("settings.toml")?;
    let content = format!("theme = {}\nlanguage = {}\n", theme, language);
    settings_file.write(content.as_bytes())?;

    println!("Settings saved to: {}", settings_file.strictpath_display());
    Ok(())
}

fn load_user_settings() -> Result<String, Box<dyn std::error::Error>> {
    let config_dir: PathBoundary<AppSettings> = 
        PathBoundary::try_new_os_config("myapp")?;

    let settings_file = config_dir.strict_join("settings.toml")?;
    Ok(settings_file.read_to_string()?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    save_user_settings("dark", "en")?;
    let settings = load_user_settings()?;
    println!("Loaded settings:\n{}", settings);
    Ok(())
}
```

## Feature: `tempfile` — Automatic Cleanup with RAII

The `tempfile` feature works with the `tempfile` crate for automatic cleanup:

```rust
use strict_path::PathBoundary;
use tempfile::TempDir;

struct WorkDir;

fn process_with_temp() -> Result<(), Box<dyn std::error::Error>> {
    // Create temporary directory (cleaned up automatically when dropped)
    let temp = TempDir::new()?;
    
    println!("Created temp directory: {:?}", temp.path());

    // Wrap in PathBoundary for safe operations
    let work_dir: PathBoundary<WorkDir> = PathBoundary::try_new(temp.path())?;

    // Do work inside temp directory — all paths validated!
    let intermediate = work_dir.strict_join("intermediate.json")?;
    intermediate.write(b"{\"status\": \"processing\"}")?;

    let output = work_dir.strict_join("output.txt")?;
    output.write(b"Final result")?;

    // Try to escape — fails!
    match work_dir.strict_join("../../../etc/passwd") {
        Ok(_) => println!("❌ Escape succeeded (should not happen!)"),
        Err(e) => println!("✅ Escape blocked: {}", e),
    }

    println!("Work directory: {}", work_dir.strictpath_display());
    println!("Output file: {}", output.strictpath_display());

    // When this function returns, `temp` is dropped → directory deleted automatically
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    process_with_temp()?;
    println!("Temp directory has been automatically cleaned up!");
    Ok(())
}
```

**Key benefits:**
- ✅ **RAII cleanup** — temp directory deleted when `TempDir` drops
- ✅ **Boundary enforcement** — even in temp directories, paths can't escape
- ✅ **No manual cleanup** — Rust handles it for you

### Try It: Safe Archive Processing

```rust
use strict_path::PathBoundary;
use tempfile::TempDir;

struct ArchiveExtract;

fn extract_and_process_archive(archive_data: &[u8]) 
    -> Result<Vec<String>, Box<dyn std::error::Error>> 
{
    // Create temp directory for extraction
    let temp = TempDir::new()?;
    let extract_dir: PathBoundary<ArchiveExtract> = 
        PathBoundary::try_new(temp.path())?;

    // Simulate extracting files (in reality, use zip crate)
    let file1 = extract_dir.strict_join("readme.txt")?;
    file1.write(b"Archive contents...")?;

    let file2 = extract_dir.strict_join("data/values.csv")?;
    file2.create_parent_dir_all()?;
    file2.write(b"col1,col2\n1,2")?;

    // Even if archive contains hostile paths, they're validated
    match extract_dir.strict_join("../../../evil.sh") {
        Ok(_) => println!("❌ Hostile path accepted!"),
        Err(e) => println!("✅ Hostile path blocked: {}", e),
    }

    // Collect extracted files
    let mut files = Vec::new();
    files.push(file1.strictpath_display().to_string());
    files.push(file2.strictpath_display().to_string());

    // Temp directory deleted automatically when function returns
    Ok(files)
}
```

## Feature: `app-path` — Portable Application Directories

The `app-path` feature provides portable app-specific paths with environment variable overrides:

```rust
use strict_path::PathBoundary;

struct AppLogs;
struct AppData;

fn setup_app_directories() -> Result<(), Box<dyn std::error::Error>> {
    // Get app-specific log directory with environment override support
    // If MYAPP_LOGS_DIR is set, uses that path
    // Otherwise, uses platform-specific app directory + "logs" subdirectory
    let logs_dir: PathBoundary<AppLogs> = 
        PathBoundary::try_new_app_path("logs", Some("MYAPP_LOGS_DIR"))?;
    
    let error_log = logs_dir.strict_join("errors.log")?;
    error_log.write(b"[ERROR] Example error message\n")?;

    let access_log = logs_dir.strict_join("access.log")?;
    access_log.write(b"[INFO] User accessed /api/data\n")?;

    println!("Logs directory: {}", logs_dir.strictpath_display());

    // Get app-specific data directory with environment override support
    let data_dir: PathBoundary<AppData> = 
        PathBoundary::try_new_app_path("data", Some("MYAPP_DATA_DIR"))?;

    let database = data_dir.strict_join("app.db")?;
    database.write(b"SQLite database content")?;

    println!("Data directory: {}", data_dir.strictpath_display());

    Ok(())
}
```

### Environment Variable Overrides

You can override the default locations using environment variables:

```bash
# Override logs directory
export MYAPP_LOGS_DIR=/custom/log/path

# Override data directory
export MYAPP_DATA_DIR=/custom/data/path
```

**When the environment variable is set, the path is resolved to the final directory — no subdirectory append happens.**

This is useful for:
- ✅ Testing with custom paths
- ✅ Deployment-specific configurations
- ✅ Docker container mounts
- ✅ CI/CD pipelines

## Feature: `serde` — Safe Deserialization with Validation

The `serde` feature adds safe serialization/deserialization with automatic validation:

```rust
use strict_path::{PathBoundary, StrictPath, serde_ext::WithBoundary};
use serde::{Deserialize, Serialize};

struct ConfigFiles;
struct DataFiles;

#[derive(Deserialize, Serialize)]
struct AppConfig {
    app_name: String,
    
    // Deserialize with validation through boundary
    #[serde(deserialize_with = "deserialize_log_file")]
    log_file: StrictPath<ConfigFiles>,
    
    #[serde(deserialize_with = "deserialize_data_file")]
    data_file: StrictPath<DataFiles>,
}

fn deserialize_log_file<'de, D>(deserializer: D) 
    -> Result<StrictPath<ConfigFiles>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let config_dir: PathBoundary<ConfigFiles> = 
        PathBoundary::try_new("config").map_err(serde::de::Error::custom)?;
    
    // Use WithBoundary seed to validate during deserialization
    let seed = WithBoundary(&config_dir);
    seed.deserialize(deserializer)
}

fn deserialize_data_file<'de, D>(deserializer: D) 
    -> Result<StrictPath<DataFiles>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let data_dir: PathBoundary<DataFiles> = 
        PathBoundary::try_new("data").map_err(serde::de::Error::custom)?;
    
    let seed = WithBoundary(&data_dir);
    seed.deserialize(deserializer)
}

fn load_config() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{
        "app_name": "MyApp",
        "log_file": "logs/app.log",
        "data_file": "db/app.db"
    }"#;

    let config: AppConfig = serde_json::from_str(json)?;
    
    println!("App: {}", config.app_name);
    println!("Log file: {}", config.log_file.strictpath_display());
    println!("Data file: {}", config.data_file.strictpath_display());

    // Try loading config with hostile paths
    let evil_json = r#"{
        "app_name": "EvilApp",
        "log_file": "../../../etc/passwd",
        "data_file": "db/app.db"
    }"#;

    match serde_json::from_str::<AppConfig>(evil_json) {
        Ok(_) => println!("❌ Hostile config accepted!"),
        Err(e) => println!("✅ Hostile config rejected: {}", e),
    }

    Ok(())
}
```

**Key point:** Deserialization validates paths through boundaries — **untrusted config files can't escape!**

## Combining Features: Real-World Application

Here's how you'd combine multiple features in a real application:

```rust
use strict_path::{PathBoundary, VirtualRoot};
use tempfile::TempDir;

struct AppConfig;
struct AppLogs;
struct UserFiles;
struct TempProcessing;

struct Application {
    config_dir: PathBoundary<AppConfig>,
    logs_dir: PathBoundary<AppLogs>,
    user_files_root: VirtualRoot<UserFiles>,
}

impl Application {
    fn new(user_id: u64) -> Result<Self, Box<dyn std::error::Error>> {
        // OS-specific config directory
        let config_dir = PathBoundary::try_new_os_config("myapp")?;
        
        // App-specific log directory (with env override support)
        let logs_dir = PathBoundary::try_new_app_path("logs", None)?;
        
        // Per-user virtual root for file isolation
        let user_storage = format!("users/user_{}", user_id);
        let user_files_root = VirtualRoot::try_new_create(user_storage)?;

        Ok(Self {
            config_dir,
            logs_dir,
            user_files_root,
        })
    }

    fn load_config(&self, config_name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let config_file = self.config_dir.strict_join(config_name)?;
        Ok(config_file.read_to_string()?)
    }

    fn log_event(&self, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        let log_file = self.logs_dir.strict_join("app.log")?;
        let mut log = log_file.read_to_string().unwrap_or_default();
        log.push_str(message);
        log.push('\n');
        log_file.write(log.as_bytes())?;
        Ok(())
    }

    fn process_user_file(&self, filename: &str) 
        -> Result<String, Box<dyn std::error::Error>> 
    {
        // Use temp directory for processing
        let temp = TempDir::new()?;
        let temp_dir: PathBoundary<TempProcessing> = 
            PathBoundary::try_new(temp.path())?;

        // Get user file (virtual path)
        let user_file = self.user_files_root.virtual_join(filename)?;
        let data = user_file.read()?;

        // Process in temp directory
        let temp_file = temp_dir.strict_join("processing.tmp")?;
        temp_file.write(&data)?;

        // Log the operation
        self.log_event(&format!("Processed file: {}", filename))?;

        // Return result
        Ok(format!("Processed {} bytes", data.len()))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Application::new(123)?;
    
    // Load config from OS-specific directory
    let config = app.load_config("settings.toml").unwrap_or_default();
    println!("Config: {}", config);

    // Process user file using temp directory
    let result = app.process_user_file("documents/report.pdf")?;
    println!("Result: {}", result);

    Ok(())
}
```

## Key Takeaways

✅ **`dirs` feature** — OS-specific user directories (config, downloads, documents, etc.)  
✅ **`tempfile` feature** — RAII temp directories with boundary enforcement  
✅ **`app-path` feature** — Portable app paths with env override support  
✅ **`serde` feature** — Safe deserialization with automatic validation  
✅ **Combine features** — Build real-world apps with ecosystem integration  
✅ **Boundaries everywhere** — Even external directories enforce security  

## The Final Complete Guarantee

> **By combining all stages, you achieve:**
> 1. ✅ Paths cannot escape boundaries (Stage 1)
> 2. ✅ Paths are in the correct domain (Stage 3)
> 3. ✅ Authorization proven by compiler (Stage 4)
> 4. ✅ Clean virtual UX for users (Stage 5)
> 5. ✅ Ecosystem integration with safety (Stage 6)
> 
> **All enforced at compile time with zero runtime overhead.**

## Feature Combinations

Features can be combined as needed:

```toml
[dependencies]
strict-path = { 
    version = "0.1.0-beta.1", 
    features = ["dirs", "serde", "tempfile", "app-path"] 
}
```

All combinations work seamlessly together - choose the features your application needs.

## Design Philosophy

All optional features:
- **Maintain security**: Never compromise path boundary enforcement
- **Zero-cost when unused**: Features add no overhead if not enabled  
- **Composable**: Features work together seamlessly
- **Platform-aware**: Handle platform differences gracefully
- **Standards-compliant**: Follow established conventions and specifications

## Congratulations! 🎉

You've completed the full tutorial! You now understand:

- ✅ How `StrictPath` prevents path escapes
- ✅ How markers prevent domain mix-ups
- ✅ How `change_marker()` encodes authorization
- ✅ How `VirtualPath` provides user-friendly sandboxing
- ✅ How features integrate with the Rust ecosystem

## What's Next?

Explore these resources to deepen your knowledge:

- **[Real-World Examples](../examples/overview.md)** — Copy-pasteable patterns for web servers, CLI tools, archives
- **[Best Practices](../best_practices.md)** — Decision matrices, design patterns, and guidelines
- **[Anti-Patterns](../anti_patterns.md)** — Common mistakes and how to fix them
- **[OS Directories](../os_directories.md)** — Complete API reference for all OS directory constructors
- **[Axum Tutorial](../axum_tutorial/overview.md)** — Build a complete web service with strict-path

**You're ready to build secure systems!** 🚀

---

**Quick Reference Card:**

```rust
// OS directories
let config = PathBoundary::<MyConfig>::try_new_os_config("app")?;
let downloads = PathBoundary::<Downloads>::try_new_os_downloads()?;

// Temp directories
let temp = TempDir::new()?;
let work = PathBoundary::<Work>::try_new(temp.path())?;

// App paths (with env override)
let logs = PathBoundary::<Logs>::try_new_app_path("logs", None)?;

// Serde validation
#[serde(deserialize_with = "deserialize_with_boundary")]
log_file: StrictPath<ConfigFiles>
```

**[← Back to Tutorial Overview](./overview.md)**
