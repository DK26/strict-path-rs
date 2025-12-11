# Configuration File Manager

Learn how to safely handle user configuration files with automatic path validation and type-safe file operations.

## The Problem

Applications need to load and save configuration files, but must prevent:
- ❌ Users reading system configuration files (`../../../etc/shadow`)
- ❌ Writing config files outside the app's config directory
- ❌ Accidental path injections from corrupted config data

## The Solution

Use `PathBoundary` to create a jail for configuration files. All config operations stay within the boundary.

## Complete Example

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
        let config_dir = PathBoundary::try_new_create("./app_config")?;
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
        config_path.write(&content)?;

        println!("💾 Saved config to: {}", config_path.strictpath_display());
        Ok(config_path)
    }
    
    fn list_configs(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut configs = Vec::new();
        
        for entry in self.config_dir.read_dir()? {
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

## Key Security Features

### 1. Bounded Configuration Directory
```rust
let config_dir = PathBoundary::try_new_create("./app_config")?;
```
All configuration operations are restricted to this directory.

### 2. Validated File Names
```rust
let config_path = self.config_dir.strict_join(config_name)?;
```
User-provided config names are validated before any file operation.

### 3. Safe Returns
```rust
fn save_config(&self, config_name: &str, config: &AppConfig) -> Result<StrictPath, ...>
```
Returning `StrictPath` ensures callers can only operate on validated paths.

### 4. Automatic Parent Directory Creation
```rust
config_path.write(&content)?;
```
The safe file operations handle parent directory creation automatically.

## Attack Scenarios Prevented

| Attack                                   | Result                  |
| ---------------------------------------- | ----------------------- |
| `load_config("../../../etc/passwd")`     | ❌ Path escape blocked   |
| `save_config("/tmp/evil.json", ...)`     | ❌ Absolute path blocked |
| `load_config("..\\windows\\system.ini")` | ❌ Path escape blocked   |

## Integration with Serde

For more complex deserialization scenarios, use the `serde` feature:

```rust
use strict_path::{PathBoundary, StrictPath, serde_ext::WithBoundary};
use serde::Deserialize;

#[derive(Deserialize)]
struct AppConfig {
    name: String,
    
    // Deserialize with validation through boundary
    #[serde(deserialize_with = "deserialize_config_file")]
    config_file: StrictPath<ConfigFiles>,
}

fn deserialize_config_file<'de, D>(deserializer: D) -> Result<StrictPath<ConfigFiles>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let boundary = PathBoundary::<ConfigFiles>::try_new("./config")?;
    let path_str = String::deserialize(deserializer)?;
    boundary.strict_join(&path_str).map_err(serde::de::Error::custom)
}
```

## OS-Specific Config Locations

For platform-specific config directories, use the `dirs` feature:

```rust
use strict_path::PathBoundary;

fn new_with_os_config() -> Result<Self, Box<dyn std::error::Error>> {
    // Uses XDG on Linux, AppData on Windows, etc.
    let config_dir = PathBoundary::try_new_os_config("myapp")?;
    Ok(Self { config_dir })
}
```

See the [OS Standard Directories](../os_directories.md) chapter for more details.

## Environment Variable Overrides

For deployment flexibility, use the `app-path` feature:

```rust
use strict_path::PathBoundary;

fn new_with_override() -> Result<Self, Box<dyn std::error::Error>> {
    // Checks MYAPP_CONFIG_DIR env var first, falls back to default
    let config_dir = PathBoundary::try_new_app_path("config", Some("MYAPP_CONFIG_DIR"))?;
    Ok(Self { config_dir })
}
```

## Best Practices

1. **Store the boundary** - Keep `PathBoundary` as a field in your manager struct
2. **Validate early** - Use `strict_join()` immediately when receiving config names
3. **Return safe types** - Functions should return `StrictPath` instead of raw strings
4. **Handle missing configs** - Provide sensible defaults when configs don't exist

## Next Steps

- See [CLI Tool](./cli_tool.md) for handling user-provided paths in command-line applications
- See [Type-Safe Context Separation](./type_safe_contexts.md) to learn about using markers for different config types
