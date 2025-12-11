# OS Standard Directories

> **Recommended: Use the [`dirs`](https://crates.io/crates/dirs) crate directly with `PathBoundary::try_new()`**

This page shows how to integrate `strict-path` with the `dirs` crate for cross-platform OS standard directories.

## Quick Start

```toml
[dependencies]
strict-path = "0.1"
dirs = "5.0"  # Add dirs directly
```

```rust
use strict_path::PathBoundary;

// Platform-specific config directory
let config_base = dirs::config_dir()
    .ok_or("No config directory")?;

// Create app-specific boundary
let app_config = config_base.join("myapp");
let boundary = PathBoundary::try_new_create(&app_config)?;

// Safe operations within boundary
let settings = boundary.strict_join("settings.toml")?;
settings.write(b"[app]\nversion = '1.0'\n")?;
```

---

## Cross-Platform Standards

The `dirs` crate follows established cross-platform directory standards:

### Linux (XDG Base Directory Specification)
- **Config**: `$XDG_CONFIG_HOME` or `~/.config`
- **Data**: `$XDG_DATA_HOME` or `~/.local/share`
- **Cache**: `$XDG_CACHE_HOME` or `~/.cache`
- **Runtime**: `$XDG_RUNTIME_DIR` or `/tmp`

### Windows (Known Folder API)
- **Config**: `%APPDATA%` (Roaming)
- **Data**: `%APPDATA%` (Roaming)
- **Cache**: `%LOCALAPPDATA%`
- **Local Config**: `%LOCALAPPDATA%`
- **Local Data**: `%LOCALAPPDATA%`

### macOS (Apple Standard Directories)
- **Config**: `~/Library/Application Support`
- **Data**: `~/Library/Application Support`
- **Cache**: `~/Library/Caches`

---

## Integration Patterns

### Application Configuration

```rust
use strict_path::PathBoundary;

struct AppConfig;

fn setup_config() -> Result<(), Box<dyn std::error::Error>> {
    let config_base = dirs::config_dir()
        .ok_or("No config directory available")?;

    let app_config = config_base.join("myapp");
    let boundary: PathBoundary<AppConfig> =
        PathBoundary::try_new_create(&app_config)?;

    // Platform-specific locations:
    // Linux:   ~/.config/myapp/
    // Windows: C:\Users\Alice\AppData\Roaming\myapp\
    // macOS:   ~/Library/Application Support/myapp/

    let settings = boundary.strict_join("settings.toml")?;
    settings.write(b"[app]\ntheme = 'dark'\n")?;

    println!("Config saved to: {}", settings.strictpath_display());

    Ok(())
}
```

### Multi-Directory Application

```rust
use strict_path::PathBoundary;

struct Config;
struct Data;
struct Cache;

struct AppDirectories {
    config: PathBoundary<Config>,
    data: PathBoundary<Data>,
    cache: PathBoundary<Cache>,
}

impl AppDirectories {
    fn new(app_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config_base = dirs::config_dir()
            .ok_or("No config directory")?;
        let data_base = dirs::data_dir()
            .ok_or("No data directory")?;
        let cache_base = dirs::cache_dir()
            .ok_or("No cache directory")?;

        Ok(Self {
            config: PathBoundary::try_new_create(config_base.join(app_name))?,
            data: PathBoundary::try_new_create(data_base.join(app_name))?,
            cache: PathBoundary::try_new_create(cache_base.join(app_name))?,
        })
    }
}

fn use_app_directories() -> Result<(), Box<dyn std::error::Error>> {
    let dirs = AppDirectories::new("MyApp")?;

    // Config: user preferences
    let prefs = dirs.config.strict_join("preferences.json")?;
    prefs.write(br#"{"theme": "dark"}"#)?;

    // Data: persistent application data
    let database = dirs.data.strict_join("app.db")?;
    database.write(b"database content")?;

    // Cache: temporary/regenerable data
    let thumbnail = dirs.cache.strict_join("thumbs/image1.jpg")?;
    thumbnail.create_parent_dir_all()?;
    thumbnail.write(b"thumbnail data")?;

    Ok(())
}
```

### User Content Directories

```rust
use strict_path::PathBoundary;

struct Downloads;
struct Documents;

fn access_user_content() -> Result<(), Box<dyn std::error::Error>> {
    // Downloads directory
    if let Some(downloads) = dirs::download_dir() {
        let boundary: PathBoundary<Downloads> =
            PathBoundary::try_new(&downloads)?;

        // Safe access to user-selected file
        let user_input = "report.pdf"; // From file picker or CLI
        let file = boundary.strict_join(user_input)?;

        if file.exists() {
            let data = file.read()?;
            println!("Processing: {} bytes", data.len());
        }
    }

    // Documents directory
    if let Some(documents) = dirs::document_dir() {
        let boundary: PathBoundary<Documents> =
            PathBoundary::try_new(&documents)?;

        let export = boundary.strict_join("exports/data.csv")?;
        export.create_parent_dir_all()?;
        export.write(b"col1,col2\nval1,val2\n")?;

        println!("Exported to: {}", export.strictpath_display());
    }

    Ok(())
}
```

---

## Available Directories (via `dirs` crate)

| Function             | Linux            | Windows                   | macOS                           |
| -------------------- | ---------------- | ------------------------- | ------------------------------- |
| `config_dir()`       | `~/.config`      | `%APPDATA%`               | `~/Library/Application Support` |
| `data_dir()`         | `~/.local/share` | `%APPDATA%`               | `~/Library/Application Support` |
| `cache_dir()`        | `~/.cache`       | `%LOCALAPPDATA%`          | `~/Library/Caches`              |
| `config_local_dir()` | `~/.config`      | `%LOCALAPPDATA%`          | `~/Library/Application Support` |
| `data_local_dir()`   | `~/.local/share` | `%LOCALAPPDATA%`          | `~/Library/Application Support` |
| `download_dir()`     | `~/Downloads`    | `%USERPROFILE%\Downloads` | `~/Downloads`                   |
| `document_dir()`     | `~/Documents`    | `%USERPROFILE%\Documents` | `~/Documents`                   |
| `picture_dir()`      | `~/Pictures`     | `%USERPROFILE%\Pictures`  | `~/Pictures`                    |
| `video_dir()`        | `~/Videos`       | `%USERPROFILE%\Videos`    | `~/Movies`                      |
| `audio_dir()`        | `~/Music`        | `%USERPROFILE%\Music`     | `~/Music`                       |

---

## Complete Example: Cross-Platform App

```rust
use strict_path::PathBoundary;
use serde::{Deserialize, Serialize};

struct AppConfig;
struct AppData;
struct AppCache;

#[derive(Serialize, Deserialize)]
struct UserPreferences {
    theme: String,
    language: String,
}

struct MyApp {
    config_dir: PathBoundary<AppConfig>,
    data_dir: PathBoundary<AppData>,
    cache_dir: PathBoundary<AppCache>,
}

impl MyApp {
    fn new(app_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Get OS-specific directories
        let config_base = dirs::config_dir()
            .ok_or("No config directory")?;
        let data_base = dirs::data_dir()
            .ok_or("No data directory")?;
        let cache_base = dirs::cache_dir()
            .ok_or("No cache directory")?;

        // Create app-specific boundaries
        Ok(Self {
            config_dir: PathBoundary::try_new_create(
                config_base.join(app_name)
            )?,
            data_dir: PathBoundary::try_new_create(
                data_base.join(app_name)
            )?,
            cache_dir: PathBoundary::try_new_create(
                cache_base.join(app_name)
            )?,
        })
    }

    fn save_preferences(&self, prefs: &UserPreferences)
        -> Result<(), Box<dyn std::error::Error>>
    {
        let prefs_file = self.config_dir.strict_join("preferences.json")?;
        let json = serde_json::to_string_pretty(prefs)?;
        prefs_file.write(json.as_bytes())?;
        Ok(())
    }

    fn load_preferences(&self)
        -> Result<UserPreferences, Box<dyn std::error::Error>>
    {
        let prefs_file = self.config_dir.strict_join("preferences.json")?;
        let json = prefs_file.read_to_string()?;
        Ok(serde_json::from_str(&json)?)
    }

    fn save_data(&self, filename: &str, data: &[u8])
        -> Result<(), Box<dyn std::error::Error>>
    {
        let file = self.data_dir.strict_join(filename)?;
        file.create_parent_dir_all()?;
        file.write(data)?;
        Ok(())
    }

    fn cache_thumbnail(&self, id: &str, thumbnail: &[u8])
        -> Result<(), Box<dyn std::error::Error>>
    {
        let cache_file = self.cache_dir
            .strict_join(&format!("thumbnails/{}.jpg", id))?;
        cache_file.create_parent_dir_all()?;
        cache_file.write(thumbnail)?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = MyApp::new("MyAwesomeApp")?;

    // Save user preferences
    let prefs = UserPreferences {
        theme: "dark".to_string(),
        language: "en".to_string(),
    };
    app.save_preferences(&prefs)?;

    // Save application data
    app.save_data("database/users.db", b"user data")?;

    // Cache a thumbnail
    app.cache_thumbnail("image123", b"thumbnail bytes")?;

    // Load preferences back
    let loaded_prefs = app.load_preferences()?;
    println!("Theme: {}", loaded_prefs.theme);

    Ok(())
}
```

---

## Why Direct Integration?

**Benefits of using `dirs` directly:**

1. ✅ **Full control** - Access all `dirs` functions and options
2. ✅ **No version coupling** - Use any version of `dirs` you want
3. ✅ **Explicit dependencies** - Clear what your project uses
4. ✅ **Reduced bloat** - No unnecessary feature flags
5. ✅ **One extra line** - Small price for explicit security

**Pattern:**
```rust
// Get directory from dirs crate
let base_dir = dirs::config_dir().ok_or("No config")?;

// Create boundary with strict-path
let boundary = PathBoundary::try_new_create(base_dir.join("myapp"))?;

// Use safe operations
let file = boundary.strict_join(user_input)?;
```

---

## See Also

- **[Ecosystem Integration Guide](./ecosystem_integration.md)** - Comprehensive integration patterns
- **[Tutorial: Chapter 6](./tutorial/chapter6_features.md)** - Ecosystem integration tutorial
- **[Best Practices](./best_practices.md)** - Application architecture patterns

---

## Legacy Feature Flag (Deprecated)

> ⚠️ **Deprecated**: The `dirs` feature flag is deprecated in favor of direct integration.

The previous feature-based approach:
```toml
strict-path = { version = "0.1", features = ["dirs"] }
```

Provided methods like `PathBoundary::try_new_os_config()`, but this couples `strict-path` to the `dirs` crate version and hides the integration.

**Migration is trivial:**
```rust
// OLD (with dirs feature):
let boundary = PathBoundary::try_new_os_config("myapp")?;

// NEW (direct integration):
let config_base = dirs::config_dir().ok_or("No config")?;
let boundary = PathBoundary::try_new_create(config_base.join("myapp"))?;
```

The new approach gives you full control and makes the integration explicit.
