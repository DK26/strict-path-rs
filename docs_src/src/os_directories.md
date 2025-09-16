# OS Standard Directories

> **Feature**: `dirs` - Enable with `features = ["dirs"]` in your `Cargo.toml`

The `strict-path` crate provides seamless integration with operating system standard directories through the [`dirs`](https://crates.io/crates/dirs) crate. This enables cross-platform applications to securely access user and system directories like configuration, data storage, cache, and user content locations.

**Quick Start:**
```toml
[dependencies]
strict-path = { version = "0.1.0-alpha.4", features = ["dirs"] }
```

## Cross-Platform Standards

The integration follows established cross-platform directory standards:

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

## API Reference

Both `PathBoundary` and `VirtualRoot` provide comprehensive OS directory constructors:

### Application Directories

#### `try_new_os_config(app_name: &str)`
Creates a secure boundary for application configuration storage.

```rust
use strict_path::PathBoundary;

let config_dir = PathBoundary::<()>::try_new_os_config("MyApp")?;
let config_file = config_dir.strict_join("settings.json")?;
config_file.write_string(r#"{"theme": "dark"}"#)?;
```

**Platform paths:**
- Linux: `~/.config/MyApp/`
- Windows: `%APPDATA%/MyApp/`
- macOS: `~/Library/Application Support/MyApp/`

#### `try_new_os_data(app_name: &str)`
Creates a secure boundary for application data storage.

```rust
let data_dir = PathBoundary::<()>::try_new_os_data("MyApp")?;
let database = data_dir.strict_join("app.db")?;
database.write_bytes(b"SQLite database content")?;
```

**Platform paths:**
- Linux: `~/.local/share/MyApp/`
- Windows: `%APPDATA%/MyApp/`
- macOS: `~/Library/Application Support/MyApp/`

#### `try_new_os_cache(app_name: &str)`
Creates a secure boundary for application cache storage.

```rust
let cache_dir = PathBoundary::<()>::try_new_os_cache("MyApp")?;
let thumbnail_cache = cache_dir.strict_join("thumbnails/")?;
thumbnail_cache.create_dir_all()?;
```

**Platform paths:**
- Linux: `~/.cache/MyApp/`
- Windows: `%LOCALAPPDATA%/MyApp/`
- macOS: `~/Library/Caches/MyApp/`

### Platform-Specific Directories

#### `try_new_os_config_local(app_name: &str)` (Windows/Linux only)
Creates a local (non-roaming) config directory boundary.

```rust
#[cfg(any(target_os = "windows", target_os = "linux"))]
let local_config = PathBoundary::<()>::try_new_os_config_local("MyApp")?;
```

**Platform paths:**
- Linux: `~/.config/MyApp/` (same as config)
- Windows: `%LOCALAPPDATA%/MyApp/` (non-roaming)
- macOS: Not available (returns `Err`)

#### `try_new_os_data_local(app_name: &str)` (Windows/Linux only)
Creates a local (non-roaming) data directory boundary.

```rust
#[cfg(any(target_os = "windows", target_os = "linux"))]
let local_data = PathBoundary::<()>::try_new_os_data_local("MyApp")?;
```

### User Content Directories

#### Standard User Folders

```rust
// User's home directory
let home_dir = PathBoundary::<()>::try_new_os_home()?;

// Desktop folder
let desktop_dir = PathBoundary::<()>::try_new_os_desktop()?;

// Documents folder  
let documents_dir = PathBoundary::<()>::try_new_os_documents()?;

// Downloads folder
let downloads_dir = PathBoundary::<()>::try_new_os_downloads()?;
```

#### Media Directories

```rust
// Pictures/Photos
let pictures_dir = PathBoundary::<()>::try_new_os_pictures()?;

// Music/Audio files
let audio_dir = PathBoundary::<()>::try_new_os_audio()?;

// Videos/Movies
let videos_dir = PathBoundary::<()>::try_new_os_videos()?;
```

### System Directories

#### `try_new_os_executables()` (Unix only)
Creates a boundary for user executable binaries.

```rust
#[cfg(unix)]
let bin_dir = PathBoundary::<()>::try_new_os_executables()?;
// Typically ~/.local/bin on Linux
```

#### `try_new_os_runtime()` (Unix only)  
Creates a boundary for runtime files like sockets and PIDs.

```rust
#[cfg(unix)]
let runtime_dir = PathBoundary::<()>::try_new_os_runtime()?;
// Uses $XDG_RUNTIME_DIR or falls back to /tmp
```

#### `try_new_os_state()` (Linux only)
Creates a boundary for application state data.

```rust
#[cfg(target_os = "linux")]
let state_dir = PathBoundary::<()>::try_new_os_state("MyApp")?;
// Uses $XDG_STATE_HOME or ~/.local/state/MyApp
```

## Virtual Root Integration

All OS directory constructors are available on `VirtualRoot` as well:

```rust
use strict_path::VirtualRoot;

// Create virtual root for user documents
let docs_root = VirtualRoot::<()>::try_new_os_documents()?;

// User sees clean virtual paths, system handles real location
let project_file = docs_root.virtual_join("projects/my-app/notes.txt")?;
println!("Virtual path: {}", project_file.virtualpath_display());
// Output: "/projects/my-app/notes.txt"

println!("Real path: {}", project_file.as_unvirtual().strictpath_display());
// Output: "/home/user/Documents/projects/my-app/notes.txt" (Linux example)
```

## Complete Application Example

Here's a realistic media organizer application demonstrating the OS directories integration:

```rust
use strict_path::{PathBoundary, VirtualRoot};
use std::collections::HashMap;

#[derive(Debug)]
struct MediaOrganizerApp {
    config_dir: PathBoundary<()>,
    data_dir: PathBoundary<()>,
    cache_dir: PathBoundary<()>,
}

impl MediaOrganizerApp {
    fn new(app_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize with OS standard directories
        let config_dir = PathBoundary::<()>::try_new_os_config(app_name)?;
        let data_dir = PathBoundary::<()>::try_new_os_data(app_name)?;
        let cache_dir = PathBoundary::<()>::try_new_os_cache(app_name)?;
        
        println!("📁 Config: {}", config_dir.strictpath_display());
        println!("💾 Data: {}", data_dir.strictpath_display());
        println!("🗄️ Cache: {}", cache_dir.strictpath_display());
        
        Ok(Self { config_dir, data_dir, cache_dir })
    }
    
    fn scan_user_media(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Access standard user media directories securely
        let media_directories = vec![
            ("Pictures", PathBoundary::<()>::try_new_os_pictures()?),
            ("Music", PathBoundary::<()>::try_new_os_audio()?),
            ("Videos", PathBoundary::<()>::try_new_os_videos()?),
            ("Downloads", PathBoundary::<()>::try_new_os_downloads()?),
        ];
        
        for (dir_name, dir_path) in media_directories {
            println!("📂 Scanning {}: {}", dir_name, dir_path.strictpath_display());
            
            // In a real app, recursively scan for media files
            // All file operations stay within secure boundaries
            if dir_path.exists() {
                println!("   ✅ Directory accessible and secure");
            }
        }
        
        Ok(())
    }
    
    fn manage_cache(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create cache subdirectories securely
        let thumbnails_dir = self.cache_dir.strict_join("thumbnails")?;
        let metadata_dir = self.cache_dir.strict_join("metadata")?;
        
        thumbnails_dir.create_dir_all()?;
        metadata_dir.create_dir_all()?;
        
        println!("🖼️ Thumbnails: {}", thumbnails_dir.strictpath_display());
        println!("📝 Metadata: {}", metadata_dir.strictpath_display());
        
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = MediaOrganizerApp::new("MediaOrganizer")?;
    app.scan_user_media()?;
    app.manage_cache()?;
    Ok(())
}
```

## Error Handling

OS directory functions return `StrictPathError` when:

- The directory doesn't exist and cannot be created
- Permission denied accessing the directory  
- The OS doesn't support the requested directory type
- Invalid characters in the application name

```rust
use strict_path::{PathBoundary, StrictPathError};

match PathBoundary::<()>::try_new_os_config("My App") {
    Ok(config_dir) => println!("Config: {}", config_dir.strictpath_display()),
    Err(StrictPathError::PathResolutionError(msg)) => {
        eprintln!("Failed to resolve config directory: {}", msg);
    }
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Platform Compatibility

| Method                    | Linux | Windows | macOS | Notes                  |
| ------------------------- | ----- | ------- | ----- | ---------------------- |
| `try_new_os_config`       | ✅     | ✅       | ✅     |                        |
| `try_new_os_data`         | ✅     | ✅       | ✅     |                        |
| `try_new_os_cache`        | ✅     | ✅       | ✅     |                        |
| `try_new_os_config_local` | ✅     | ✅       | ❌     | Returns error on macOS |
| `try_new_os_data_local`   | ✅     | ✅       | ❌     | Returns error on macOS |
| `try_new_os_home`         | ✅     | ✅       | ✅     |                        |
| `try_new_os_desktop`      | ✅     | ✅       | ✅     |                        |
| `try_new_os_documents`    | ✅     | ✅       | ✅     |                        |
| `try_new_os_downloads`    | ✅     | ✅       | ✅     |                        |
| `try_new_os_pictures`     | ✅     | ✅       | ✅     |                        |
| `try_new_os_audio`        | ✅     | ✅       | ✅     |                        |
| `try_new_os_videos`       | ✅     | ✅       | ✅     |                        |
| `try_new_os_executables`  | ✅     | ❌       | ✅     | Unix only              |
| `try_new_os_runtime`      | ✅     | ❌       | ✅     | Unix only              |
| `try_new_os_state`        | ✅     | ❌       | ❌     | Linux only             |

## Integration with `dirs` Crate

This feature integrates with the [`dirs`](https://github.com/dirs-dev/dirs-rs) crate v6.0.0, which provides the underlying OS directory discovery. The `strict-path` crate adds:

- **Security**: All directory access happens within `PathBoundary` restrictions
- **Type Safety**: Compile-time guarantees about directory boundaries
- **Symlink Safety**: Safe resolution of symbolic links and junctions
- **Cross-Platform**: Consistent API across Windows, macOS, and Linux
- **Application Scoping**: Automatic subdirectory creation for app-specific storage

### Relationship to `dirs` Functions

| `strict-path` Method      | `dirs` Function                   | Purpose                    |
| ------------------------- | --------------------------------- | -------------------------- |
| `try_new_os_config`       | `dirs::config_dir()` + join       | App config storage         |
| `try_new_os_data`         | `dirs::data_dir()` + join         | App data storage           |
| `try_new_os_cache`        | `dirs::cache_dir()` + join        | App cache storage          |
| `try_new_os_config_local` | `dirs::config_local_dir()` + join | Local config (non-roaming) |
| `try_new_os_data_local`   | `dirs::data_local_dir()` + join   | Local data (non-roaming)   |
| `try_new_os_home`         | `dirs::home_dir()`                | User home directory        |
| `try_new_os_desktop`      | `dirs::desktop_dir()`             | Desktop folder             |
| `try_new_os_documents`    | `dirs::document_dir()`            | Documents folder           |
| `try_new_os_downloads`    | `dirs::download_dir()`            | Downloads folder           |
| `try_new_os_pictures`     | `dirs::picture_dir()`             | Pictures folder            |
| `try_new_os_audio`        | `dirs::audio_dir()`               | Music/Audio folder         |
| `try_new_os_videos`       | `dirs::video_dir()`               | Videos folder              |
| `try_new_os_executables`  | `dirs::executable_dir()`          | User binaries (Unix)       |
| `try_new_os_runtime`      | `dirs::runtime_dir()`             | Runtime files (Unix)       |
| `try_new_os_state`        | `dirs::state_dir()` + join        | State data (Linux)         |

For more details on the underlying directory locations, see the [`dirs` crate documentation](https://docs.rs/dirs/).

## Best Practices

### 1. Application Naming
Use consistent, filesystem-safe application names:

```rust
// Good
let config = PathBoundary::<()>::try_new_os_config("MyApp")?;

// Avoid special characters that might cause issues
let config = PathBoundary::<()>::try_new_os_config("My App & Tools")?; // Risky
```

### 2. Graceful Fallbacks
Handle platform-specific directories gracefully:

```rust
// Try platform-specific first, fall back to generic
let data_dir = PathBoundary::<()>::try_new_os_data_local("MyApp")
    .or_else(|_| PathBoundary::<()>::try_new_os_data("MyApp"))?;
```

### 3. Directory Creation
Create application subdirectories as needed:

```rust
let config_dir = PathBoundary::<()>::try_new_os_config("MyApp")?;
let themes_dir = config_dir.strict_join("themes")?;
themes_dir.create_dir_all()?;
```

### 4. Cross-Platform Testing
Test your application on all target platforms to verify directory behavior:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_directory_creation() {
        let config_dir = PathBoundary::<()>::try_new_os_config("TestApp").unwrap();
        assert!(config_dir.exists() || config_dir.create_dir_all().is_ok());
    }
}
```

## See Also

- [Real-World Examples](./examples.md) - Complete application examples
- [Getting Started](./chapter_1.md) - Basic `strict-path` concepts
- [`dirs` crate](https://crates.io/crates/dirs) - Underlying OS directory library
- [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html)
- [Windows Known Folder API](https://docs.microsoft.com/en-us/windows/win32/shell/knownfolderid)