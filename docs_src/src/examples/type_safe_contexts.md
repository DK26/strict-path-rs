# Type-Safe Context Separation

Learn how to use marker types to prevent accidentally mixing different storage contexts at compile time. This is one of the most powerful features of strict-path.

## The Problem

Applications often have multiple storage areas for different purposes:
- 🌐 Web assets (CSS, JS, images)
- 📁 User uploads (documents, photos)
- ⚙️ Configuration files
- 🔒 Sensitive data (keys, tokens)

**Without type safety**, you might accidentally:
- ❌ Serve a user's private document as a web asset
- ❌ Write config data to the uploads directory
- ❌ Read a sensitive key file when expecting a CSS file

## The Solution

Use marker types with `StrictPath<Marker>` and `VirtualPath<Marker>` to encode context at the type level. The compiler prevents context mixing.

## Complete Example

```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

// Define marker types for different contexts
struct WebAssets;    // CSS, JS, images
struct UserFiles;    // Uploaded documents
struct ConfigData;   // Application configuration

// Functions enforce context via type system
fn serve_asset(path: &StrictPath<WebAssets>) -> Result<Vec<u8>, std::io::Error> {
    path.read()
}

fn process_upload(path: &StrictPath<UserFiles>) -> Result<(), std::io::Error> {
    // Process user-uploaded file
    let content = path.read_to_string()?;
    println!("Processing user file: {} bytes", content.len());
    Ok(())
}

fn load_config(path: &StrictPath<ConfigData>) -> Result<String, std::io::Error> {
    path.read_to_string()
}

fn example_type_safety() -> Result<(), Box<dyn std::error::Error>> {
    // Create context-specific boundaries
    let assets_root: VirtualRoot<WebAssets> = VirtualRoot::try_new("./public")?;
    let user_id = "alice";
    let uploads_root: VirtualRoot<UserFiles> =
        VirtualRoot::try_new(format!("./uploads/{user_id}"))?;
    let config_boundary: PathBoundary<ConfigData> = PathBoundary::try_new("./config")?;

    // Create paths with proper contexts
    let css: VirtualPath<WebAssets> = assets_root.virtual_join("app.css")?;
    let doc: VirtualPath<UserFiles> = uploads_root.virtual_join("report.pdf")?;
    let cfg: StrictPath<ConfigData> = config_boundary.strict_join("app.toml")?;

    // Type system prevents context mixing
    serve_asset(css.as_unvirtual())?;         // ✅ Correct context
    process_upload(doc.as_unvirtual())?;      // ✅ Correct context  
    load_config(&cfg)?;                       // ✅ Correct context

    // These would be compile errors:
    // serve_asset(doc.as_unvirtual())?;      // ❌ Compile error - wrong context!
    // process_upload(css.as_unvirtual())?;   // ❌ Compile error - wrong context!
    // load_config(css.as_unvirtual())?;      // ❌ Compile error - wrong context!

    Ok(())
}
```

## Key Benefits

### 1. Compile-Time Safety
The compiler catches context mixing errors:
```rust
let css: VirtualPath<WebAssets> = assets_root.virtual_join("app.css")?;
let doc: VirtualPath<UserFiles> = uploads_root.virtual_join("report.pdf")?;

serve_asset(css.as_unvirtual())?;  // ✅ OK
serve_asset(doc.as_unvirtual())?;  // ❌ Compile error!
//          ^^^ expected WebAssets, found UserFiles
```

### 2. Clear Interfaces
Function signatures document what they accept:
```rust
// This function ONLY accepts web assets
fn serve_asset(path: &StrictPath<WebAssets>) -> Result<Vec<u8>, std::io::Error> {
    // No need to check if this is the right type of file
    // The type system guarantees it
    path.read()
}
```

### 3. Refactoring Safety
If you change a function's context requirement:
```rust
// Change signature from WebAssets to ConfigData
fn serve_asset(path: &StrictPath<ConfigData>) -> Result<Vec<u8>, std::io::Error> {
    path.read()
}
```
The compiler finds all call sites that need updating. Zero-cost migration!

### 4. Team Collaboration
New developers can't make context mixing mistakes - the compiler teaches them the correct patterns.

## Real-World Pattern: Multi-Context Web Server

```rust
use strict_path::{PathBoundary, StrictPath, VirtualRoot, VirtualPath};

struct WebAssets;
struct UserUploads;
struct ServerConfig;

struct WebServer {
    assets: VirtualRoot<WebAssets>,
    config: PathBoundary<ServerConfig>,
}

impl WebServer {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            assets: VirtualRoot::try_new("./public")?,
            config: PathBoundary::try_new("./config")?,
        })
    }
    
    // This can ONLY serve web assets
    fn serve_static_file(&self, path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let asset: VirtualPath<WebAssets> = self.assets.virtual_join(path)?;
        Ok(self.read_asset(asset.as_unvirtual())?)
    }
    
    // Helper enforces WebAssets context
    fn read_asset(&self, path: &StrictPath<WebAssets>) -> std::io::Result<Vec<u8>> {
        path.read()
    }
    
    // This can ONLY handle user uploads
    fn save_upload(
        &self,
        uploads_root: &VirtualRoot<UserUploads>,
        filename: &str,
        content: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let upload: VirtualPath<UserUploads> = uploads_root.virtual_join(filename)?;
        self.write_upload(upload.as_unvirtual(), content)?;
        Ok(())
    }
    
    // Helper enforces UserUploads context
    fn write_upload(&self, path: &StrictPath<UserUploads>, content: &[u8]) -> std::io::Result<()> {
        path.create_parent_dir_all()?;
        path.write(content)
    }
    
    // This can ONLY read config files
    fn load_config(&self, name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let cfg: StrictPath<ServerConfig> = self.config.strict_join(name)?;
        Ok(self.read_config(&cfg)?)
    }
    
    // Helper enforces ServerConfig context
    fn read_config(&self, path: &StrictPath<ServerConfig>) -> std::io::Result<String> {
        path.read_to_string()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = WebServer::new()?;
    
    // Each method can only access its designated context
    let css = server.serve_static_file("app.css")?;
    
    // Per-user uploads: construct a VirtualRoot with user_id
    let user_id = "alice";
    let uploads_root: VirtualRoot<UserUploads> =
        VirtualRoot::try_new_create(format!("uploads/{user_id}"))?;
    server.save_upload(&uploads_root, "document.pdf", b"PDF content")?;
    
    let config = server.load_config("server.toml")?;
    
    // These would be impossible to mess up due to type safety:
    // - Can't serve an upload as a static file
    // - Can't save a config as an upload
    // - Can't read an asset as config
    
    Ok(())
}
```

## Advanced: Permission Markers

Combine resource markers with permission markers using tuples:

```rust
use strict_path::{PathBoundary, StrictPath};

// Resource markers
struct Documents;
struct DatabaseFiles;

// Permission markers
struct ReadOnly;
struct ReadWrite;

// Type-safe permission enforcement
fn read_document(path: &StrictPath<(Documents, ReadOnly)>) -> std::io::Result<String> {
    path.read_to_string()
}

fn write_document(
    path: &StrictPath<(Documents, ReadWrite)>,
    content: &str,
) -> std::io::Result<()> {
    path.write(content)
}

fn backup_database(
    source: &StrictPath<(DatabaseFiles, ReadOnly)>,
    dest: &StrictPath<(DatabaseFiles, ReadWrite)>,
) -> std::io::Result<()> {
    let data = source.read()?;
    dest.write(&data)
}

fn example_permissions() -> Result<(), Box<dyn std::error::Error>> {
    let docs_ro: PathBoundary<(Documents, ReadOnly)> = 
        PathBoundary::try_new("./documents")?;
    let docs_rw: PathBoundary<(Documents, ReadWrite)> = 
        PathBoundary::try_new("./documents")?;
    
    let file_ro = docs_ro.strict_join("report.txt")?;
    let file_rw = docs_rw.strict_join("report.txt")?;
    
    // Can read from read-only
    read_document(&file_ro)?;
    
    // Can't write to read-only - compile error!
    // write_document(&file_ro, "new content")?;  // ❌ Compile error!
    
    // Can write to read-write
    write_document(&file_rw, "new content")?;
    
    Ok(())
}
```

## Advanced: Authorization Markers

Use `change_marker()` after authorization checks:

```rust
use strict_path::{PathBoundary, StrictPath};

struct UserFiles;
struct ReadOnly;
struct ReadWrite;

fn authenticate_and_upgrade(
    path: StrictPath<(UserFiles, ReadOnly)>,
    user_has_write_access: bool,
) -> Result<StrictPath<(UserFiles, ReadWrite)>, &'static str> {
    if user_has_write_access {
        // Authorization succeeded - change marker to encode permission
        Ok(path.change_marker())
    } else {
        Err("Access denied")
    }
}

fn write_file(path: &StrictPath<(UserFiles, ReadWrite)>, content: &[u8]) -> std::io::Result<()> {
    path.write(content)
}

// Usage:
let boundary: PathBoundary<(UserFiles, ReadOnly)> = 
    PathBoundary::try_new("./uploads")?;
let file_ro = boundary.strict_join("document.txt")?;

// Can't write yet - read-only marker
// write_file(&file_ro, b"data")?;  // ❌ Compile error!

// After authorization, upgrade to read-write
if let Ok(file_rw) = authenticate_and_upgrade(file_ro, check_permissions()) {
    write_file(&file_rw, b"data")?;  // ✅ Now allowed
}
```

See the [Authorization & Permissions](../tutorial/chapter4_authorization.md) chapter for more details.

## Shared Logic Across Contexts

Use generics when logic applies to any context:

```rust
// Generic over marker type - works with any context
fn get_file_size<M>(path: &StrictPath<M>) -> std::io::Result<u64> {
    path.metadata().map(|m| m.len())
}

// Works with any marker
let asset_size = get_file_size(&css_file)?;
let upload_size = get_file_size(&upload_file)?;
let config_size = get_file_size(&config_file)?;
```

## Best Practices

### 1. Name Markers After Resources
```rust
struct UserDocuments;   // ✅ Clear
struct Documents;       // ⚠️  Which documents?
struct MyMarker;        // ❌ Meaningless
```

### 2. Use Tuples for Multi-Dimensional Context
```rust
StrictPath<(ResourceType, PermissionLevel)>
StrictPath<(UserFiles, ReadWrite)>
```

### 3. Keep Markers Simple
```rust
// ✅ Simple, zero-size
struct WebAssets;

// ❌ Don't add fields
struct WebAssets {
    size_limit: usize,  // Wrong - use runtime checks
}
```

### 4. Document Marker Meaning
```rust
/// Marker for publicly-accessible web assets
/// (CSS, JavaScript, images, fonts)
struct WebAssets;

/// Marker for user-uploaded files
/// (documents, photos, videos)
struct UserUploads;
```

## Integration Tips

### With Web Frameworks
```rust
// Axum route handlers
async fn serve_asset(
    Path(asset_path): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let assets: VirtualRoot<WebAssets> = get_assets_root();
    let asset = assets.virtual_join(&asset_path)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    read_asset(asset.as_unvirtual())
        .map_err(|_| StatusCode::NOT_FOUND)
}

fn read_asset(path: &StrictPath<WebAssets>) -> std::io::Result<Vec<u8>> {
    path.read()
}
```

### With Async Runtimes
Type safety works with async code too:
```rust
async fn read_asset_async(path: &StrictPath<WebAssets>) -> std::io::Result<Vec<u8>> {
    tokio::fs::read(path.interop_path()).await
}
```

## Common Patterns

### Pattern 1: Service with Multiple Contexts
```rust
struct AppService {
    assets: VirtualRoot<WebAssets>,
    uploads: VirtualRoot<UserFiles>,
    config: PathBoundary<ConfigData>,
}
```

### Pattern 2: Generic Helpers
```rust
fn exists<M>(path: &StrictPath<M>) -> bool {
    path.exists()
}
```

### Pattern 3: Marker Transformation
```rust
fn authorize<R>(
    path: StrictPath<(R, ReadOnly)>,
) -> Result<StrictPath<(R, ReadWrite)>, Error> {
    // Check permissions...
    Ok(path.change_marker())
}
```

## Next Steps

- See [Authorization & Permissions](../tutorial/chapter4_authorization.md) for advanced marker patterns
- See [Web Upload Service](./web_upload_service.md) for practical multi-context usage
- See [Tutorial Chapter 3](../tutorial/chapter3_markers.md) for marker basics
