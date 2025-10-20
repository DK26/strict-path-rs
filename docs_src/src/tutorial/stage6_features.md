# Stage 6: Ecosystem Integration

> *"Compose strict-path with ecosystem tools — security primitives, not wrappers."*

You've mastered the core concepts: boundaries, markers, authorization, and virtual paths. Now you'll learn how to integrate `strict-path` with popular Rust ecosystem crates for real-world applications.

## The Philosophy

**`strict-path` provides security primitives. You compose them with ecosystem tools.**

We don't wrap external crates behind feature flags. Instead, we show you how to use them together effectively — giving you full control and explicit security.

---

## Quick Integration Examples

### Temporary Directories (`tempfile`)

```rust
use strict_path::PathBoundary;
use tempfile::TempDir;

fn process_upload() -> Result<(), Box<dyn std::error::Error>> {
    // Create temp directory with RAII cleanup
    let temp_dir = tempfile::tempdir()?;

    // Establish strict boundary
    let upload_boundary = PathBoundary::try_new(temp_dir.path())?;

    // Safe operations within boundary
    let user_file = upload_boundary.strict_join("user/data.txt")?;
    user_file.create_parent_dir_all()?;
    user_file.write(b"uploaded content")?;

    // Escape attempts are blocked
    match upload_boundary.strict_join("../../etc/passwd") {
        Ok(_) => panic!("Should not escape!"),
        Err(e) => println!("✓ Attack blocked: {}", e),
    }

    Ok(())
    // temp_dir automatically deleted when dropped
}
```

**Why this works**: RAII cleanup from `tempfile`, security from `strict-path`.

---

### Portable App Paths (`app-path`)

```rust
use strict_path::PathBoundary;
use app_path::AppPath;

fn setup_portable_app() -> Result<(), Box<dyn std::error::Error>> {
    // Executable-relative path
    let app_path = AppPath::new("MyPortableApp");
    let app_dir = app_path.get_app_dir();

    // Establish boundary
    let boundary = PathBoundary::try_new_create(&app_dir)?;

    // Safe config access
    let config = boundary.strict_join("config/settings.ini")?;
    config.create_parent_dir_all()?;
    config.write(b"[settings]\nportable=true\n")?;

    println!("App directory: {}", boundary.strictpath_display());

    Ok(())
}
```

**Use cases**: USB drives, CI/CD, containers with custom paths.

---

### OS Directories (`dirs`)

```rust
use strict_path::PathBoundary;

fn setup_config() -> Result<(), Box<dyn std::error::Error>> {
    // Platform-specific config directory
    let config_base = dirs::config_dir()
        .ok_or("No config directory")?;

    // App-specific subdirectory boundary
    let app_config = config_base.join("myapp");
    let boundary = PathBoundary::try_new_create(&app_config)?;

    // Cross-platform locations:
    // Linux:   ~/.config/myapp/
    // Windows: C:\Users\Alice\AppData\Roaming\myapp\
    // macOS:   ~/Library/Application Support/myapp/

    let settings = boundary.strict_join("settings.toml")?;
    settings.write(b"[app]\nversion = '1.0'\n")?;

    Ok(())
}
```

---

### Serialization (`serde` via `FromStr`)

`PathBoundary` and `VirtualRoot` implement `FromStr`, so they deserialize automatically:

```rust
use strict_path::PathBoundary;
use serde::Deserialize;

#[derive(Deserialize)]
struct AppConfig {
    // Deserializes via FromStr automatically
    upload_dir: PathBoundary,
    data_dir: PathBoundary,

    // Validate these manually
    user_paths: Vec<String>,
}

fn load_config() -> Result<(), Box<dyn std::error::Error>> {
    let json = r#"{
        "upload_dir": "./uploads",
        "data_dir": "./data",
        "user_paths": ["file1.txt", "../../etc/passwd"]
    }"#;

    let config: AppConfig = serde_json::from_str(json)?;

    // Boundaries are ready to use
    for path_str in &config.user_paths {
        match config.upload_dir.strict_join(path_str) {
            Ok(safe_path) => {
                safe_path.write(b"uploaded")?;
                println!("✓ {}", safe_path.strictpath_display());
            }
            Err(e) => {
                eprintln!("✗ Blocked '{}': {}", path_str, e);
            }
        }
    }

    Ok(())
}
```

**Key insight**: Explicit validation is a feature, not a bug. Security operations should be visible.

---

## Real-World Application

Combining all integrations:

```rust
use strict_path::{PathBoundary, VirtualRoot};
use tempfile::TempDir;
use serde::Deserialize;

struct AppConfig;
struct UserFiles;
struct TempProcessing;

#[derive(Deserialize)]
struct Config {
    config_dir: PathBoundary<AppConfig>,
}

struct Application {
    config: PathBoundary<AppConfig>,
    user_root: VirtualRoot<UserFiles>,
}

impl Application {
    fn new(user_id: u64) -> Result<Self, Box<dyn std::error::Error>> {
        // OS-specific config
        let config_base = dirs::config_dir()
            .ok_or("No config directory")?;
        let config = PathBoundary::try_new_create(
            config_base.join("myapp")
        )?;

        // Per-user virtual root
        let user_storage = format!("users/user_{}", user_id);
        let user_root = VirtualRoot::try_new_create(user_storage)?;

        Ok(Self { config, user_root })
    }

    fn process_file(&self, filename: &str)
        -> Result<String, Box<dyn std::error::Error>>
    {
        // Temp directory for processing
        let temp = TempDir::new()?;
        let temp_dir: PathBoundary<TempProcessing> =
            PathBoundary::try_new(temp.path())?;

        // Get user file (virtual path)
        let user_file = self.user_root.virtual_join(filename)?;
        let data = user_file.read()?;

        // Process in temp
        let temp_file = temp_dir.strict_join("processing.tmp")?;
        temp_file.write(&data)?;

        Ok(format!("Processed {} bytes", data.len()))
        // temp auto-cleaned
    }
}
```

---

## Why No Feature Flags?

**Previous approach (deprecated):**
```toml
strict-path = { version = "0.1", features = ["tempfile", "dirs", "app-path", "serde"] }
```

**New approach (recommended):**
```toml
strict-path = "0.1"
tempfile = "3.0"
dirs = "5.0"
app-path = "1.0"
```

**Benefits:**

1. ✅ **Full control** - Access all options of external crates
2. ✅ **No version coupling** - Use any version you want
3. ✅ **Explicit dependencies** - Clear what you're using
4. ✅ **Reduced bloat** - Pay only for what you import
5. ✅ **Visible security** - Validation is explicit in code

**Trade-off**: One extra line of code for explicit, secure integration.

---

## Complete Integration Guide

For comprehensive examples, patterns, and best practices, see:

**[📚 Ecosystem Integration Guide →](../ecosystem_integration.md)**

This guide covers:
- Temporary directories with RAII cleanup
- Portable application paths with env overrides
- OS standard directories (cross-platform)
- Serialization/deserialization patterns
- Multi-directory application architecture
- Web API integration examples

---

## Key Takeaways

✅ **Compose, don't wrap** — Use ecosystem crates directly
✅ **Explicit validation** — Security operations are visible
✅ **Full control** — No feature coupling or version constraints
✅ **One extra line** — Small cost for explicit security
✅ **FromStr support** — Boundaries deserialize automatically

## The Final Complete Guarantee

> **By combining all stages, you achieve:**
> 1. ✅ Paths cannot escape boundaries (Stage 1)
> 2. ✅ Paths are in the correct domain (Stage 3)
> 3. ✅ Authorization proven by compiler (Stage 4)
> 4. ✅ Clean virtual UX for users (Stage 5)
> 5. ✅ Ecosystem integration with safety (Stage 6)
>
> **All enforced at compile time with zero runtime overhead.**

---

## Congratulations! 🎉

You've completed the full tutorial! You now understand:

- ✅ How `StrictPath` prevents path escapes
- ✅ How markers prevent domain mix-ups
- ✅ How `change_marker()` encodes authorization
- ✅ How `VirtualPath` provides user-friendly sandboxing
- ✅ How to integrate with the Rust ecosystem

## What's Next?

Explore these resources to deepen your knowledge:

- **[Ecosystem Integration Guide](../ecosystem_integration.md)** — Comprehensive integration patterns
- **[Real-World Examples](../examples/overview.md)** — Copy-pasteable patterns for web servers, CLI tools, archives
- **[Best Practices](../best_practices.md)** — Decision matrices, design patterns, and guidelines
- **[Anti-Patterns](../anti_patterns.md)** — Common mistakes and how to fix them
- **[Axum Tutorial](../axum_tutorial/overview.md)** — Build a complete web service with strict-path

**You're ready to build secure systems!** 🚀

---

**Quick Reference Card:**

```rust
// Temporary directories
let temp = tempfile::tempdir()?;
let boundary = PathBoundary::try_new(temp.path())?;

// Portable app paths
let app_dir = app_path::AppPath::new("MyApp").get_app_dir();
let boundary = PathBoundary::try_new(&app_dir)?;

// OS directories
let config = dirs::config_dir().ok_or("No config")?;
let boundary = PathBoundary::try_new_create(config.join("myapp"))?;

// Deserialization (FromStr)
#[derive(Deserialize)]
struct Config {
    boundary: PathBoundary,  // Automatic via FromStr
    user_path: String,        // Manual validation
}
```

**[← Back to Tutorial Overview](./overview.md)**
