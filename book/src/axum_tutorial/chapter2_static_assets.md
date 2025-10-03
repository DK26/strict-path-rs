# Chapter 2: Static Asset Serving

Now that we have our security boundaries established, let's implement secure static file serving. We'll serve CSS, JavaScript, and images while preventing path traversal attacks.

## The Security Challenge

Static file servers are a common attack vector:
- ❌ `GET /assets/../config/secrets.json` - Try to escape to config
- ❌ `GET /assets/../../etc/passwd` - Try to access system files
- ❌ `GET /assets/../uploads/user_123/private.pdf` - Try to access user files

With strict-path, these attacks are **impossible** because the type system enforces boundaries.

## Create the Assets Route Handler

Create `src/routes/assets.rs`:

```rust
use axum::{
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use strict_path::StrictPath;
use crate::markers::WebAssets;
use crate::state::AppState;

/// Serve a static asset file
/// 
/// Security: The PathBoundary<WebAssets> ensures files can ONLY
/// come from the public/ directory. Path traversal attacks are
/// automatically blocked by strict_join().
pub async fn serve_asset(
    State(state): State<AppState>,
    Path(asset_path): Path<String>,
) -> Result<Response, AppError> {
    // Validate the requested path against the assets boundary
    // This is where security happens - strict_join() prevents escapes
    let safe_path: StrictPath<WebAssets> = state.assets
        .strict_join(&asset_path)
        .map_err(|e| {
            tracing::warn!("❌ Blocked path traversal attempt: {}", asset_path);
            AppError::PathTraversal(e.to_string())
        })?;
    
    // Check if file exists
    if !safe_path.exists() {
        tracing::debug!("Asset not found: {}", asset_path);
        return Err(AppError::NotFound);
    }
    
    // Check if it's actually a file (not a directory)
    if !safe_path.is_file() {
        tracing::warn!("Attempted to serve directory as file: {}", asset_path);
        return Err(AppError::NotFound);
    }
    
    // Read the file - safe because path is validated
    let content = read_asset(&safe_path).await?;
    
    // Determine content type from extension
    let content_type = get_content_type(&safe_path);
    
    tracing::debug!("✅ Serving asset: {} ({})", asset_path, content_type);
    
    // Build response with appropriate content-type
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, content_type)],
        content,
    ).into_response())
}

/// Read asset file - helper enforces WebAssets context
async fn read_asset(path: &StrictPath<WebAssets>) -> Result<Vec<u8>, AppError> {
    tokio::fs::read(path.interop_path())
        .await
        .map_err(|e| AppError::IoError(e.to_string()))
}

/// Determine content-type from file extension
fn get_content_type(path: &StrictPath<WebAssets>) -> &'static str {
    match path.strictpath_extension().and_then(|s| s.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Application errors with appropriate HTTP status codes
#[derive(Debug)]
pub enum AppError {
    PathTraversal(String),
    NotFound,
    IoError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::PathTraversal(msg) => {
                (StatusCode::BAD_REQUEST, format!("Invalid path: {}", msg))
            }
            AppError::NotFound => {
                (StatusCode::NOT_FOUND, "File not found".to_string())
            }
            AppError::IoError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("IO error: {}", msg))
            }
        };
        
        (status, message).into_response()
    }
}
```

## Update Main Router

Update `src/main.rs` to include the assets route:

```rust
use axum::{
    Router,
    routing::get,
};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod markers;
mod state;
mod routes;

use state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "file_sharing_service=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize application state with security boundaries
    let state = AppState::new()?;
    
    tracing::info!("🔒 Security boundaries initialized:");
    tracing::info!("  - Public assets: {}", state.assets.strictpath_display());
    tracing::info!("  - Config files: {}", state.config.strictpath_display());

    // Build our application with routes
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_check))
        // Serve static assets - path parameter is validated by strict_join()
        .route("/assets/*path", get(routes::assets::serve_asset))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("🚀 Server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn root_handler() -> &'static str {
    "File Sharing Service - Use /health to check status"
}

async fn health_check() -> &'static str {
    "OK"
}
```

Create `src/routes/mod.rs`:

```rust
pub mod assets;
```

## Test Asset Serving

Run the server:

```bash
cargo run
```

### Test Valid Paths

```bash
# Should work - file exists in public/
curl http://localhost:3000/assets/css/style.css

# Should work - subdirectory access
curl http://localhost:3000/assets/images/logo.png
```

### Test Attack Scenarios

```bash
# ❌ Try to escape to parent directory
curl http://localhost:3000/assets/../config/secrets.json
# Response: 400 Bad Request - "Invalid path: ..."

# ❌ Try to access system files
curl http://localhost:3000/assets/../../etc/passwd
# Response: 400 Bad Request - "Invalid path: ..."

# ❌ Try to access user uploads
curl http://localhost:3000/assets/../uploads/user_123/file.txt
# Response: 400 Bad Request - "Invalid path: ..."

# ❌ Try absolute path
curl http://localhost:3000/assets//var/log/system.log
# Response: 400 Bad Request - "Invalid path: ..."
```

All attacks are automatically blocked! 🎉

## Understanding the Security

### 1. Validation Happens at the Boundary

```rust
let safe_path: StrictPath<WebAssets> = state.assets
    .strict_join(&asset_path)
    .map_err(|e| {
        tracing::warn!("❌ Blocked path traversal attempt: {}", asset_path);
        AppError::PathTraversal(e.to_string())
    })?;
```

This single line provides complete protection:
- `strict_join()` normalizes the path (resolves `..`, `.`, etc.)
- Checks if the result is within the `public/` boundary
- Returns an error if the path escapes

### 2. Type-Safe Helpers

```rust
async fn read_asset(path: &StrictPath<WebAssets>) -> Result<Vec<u8>, AppError> {
    tokio::fs::read(path.interop_path()).await
        .map_err(|e| AppError::IoError(e.to_string()))
}
```

By accepting `&StrictPath<WebAssets>`, this function:
- ✅ Only accepts validated asset paths
- ✅ Cannot be called with user uploads or config files
- ✅ Compiler enforces the security contract

### 3. Content-Type Based on Extension

```rust
fn get_content_type(path: &StrictPath<WebAssets>) -> &'static str {
    match path.strictpath_extension().and_then(|s| s.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        // ...
    }
}
```

We safely use the validated path to determine content-type. No risk of path manipulation here.

## Why This Is Better Than Standard Approaches

### ❌ Unsafe: String-Based Validation

```rust
// Don't do this!
async fn serve_asset_unsafe(Path(asset_path): Path<String>) -> Response {
    // Manual validation - easy to get wrong
    if asset_path.contains("..") {
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }
    
    // Still vulnerable to attacks like:
    // - Encoded paths (%2e%2e%2f)
    // - Symlinks
    // - Case sensitivity issues on Windows
    
    let full_path = format!("public/{}", asset_path);
    let content = tokio::fs::read(&full_path).await.unwrap();
    // ...
}
```

### ✅ Safe: Type-Based Validation

```rust
// Do this!
let safe_path: StrictPath<WebAssets> = state.assets.strict_join(&asset_path)?;
let content = read_asset(&safe_path).await?;
```

Strict-path handles:
- ✅ Path normalization (`.`, `..`, multiple `/`)
- ✅ Symlink resolution
- ✅ Encoding issues
- ✅ Case sensitivity
- ✅ Platform differences

## Adding More Assets

Create some sample files to serve:

```bash
# Create a JavaScript file
cat > public/js/app.js << 'EOF'
console.log('File sharing service initialized');
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded - ready to upload files');
});
EOF

# Create an image (placeholder)
echo "Sample image data" > public/images/logo.png

# Create a robots.txt
cat > public/robots.txt << 'EOF'
User-agent: *
Disallow: /uploads/
EOF
```

Test them:

```bash
curl http://localhost:3000/assets/js/app.js
curl http://localhost:3000/assets/robots.txt
```

## Handling Index Files

Want to serve `index.html` when accessing `/assets/`? Update the route handler:

```rust
pub async fn serve_asset(
    State(state): State<AppState>,
    Path(asset_path): Path<String>,
) -> Result<Response, AppError> {
    // If path ends with /, append index.html
    let request_path = if asset_path.ends_with('/') || asset_path.is_empty() {
        format!("{}index.html", asset_path)
    } else {
        asset_path
    };
    
    let safe_path: StrictPath<WebAssets> = state.assets
        .strict_join(&request_path)
        .map_err(|e| {
            tracing::warn!("❌ Blocked path traversal attempt: {}", request_path);
            AppError::PathTraversal(e.to_string())
        })?;
    
    // ... rest of the function
}
```

Now `http://localhost:3000/assets/` serves `public/index.html`!

## Performance Optimization

For production, consider adding caching headers:

```rust
use axum::http::header;

pub async fn serve_asset(
    // ... parameters
) -> Result<Response, AppError> {
    // ... validation and reading
    
    // Add cache headers for static assets
    let cache_control = if is_immutable_asset(&safe_path) {
        "public, max-age=31536000, immutable"  // 1 year for versioned assets
    } else {
        "public, max-age=3600"  // 1 hour for other assets
    };
    
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, cache_control),
        ],
        content,
    ).into_response())
}

fn is_immutable_asset(path: &StrictPath<WebAssets>) -> bool {
    // Check if filename contains hash (e.g., app-abc123.js)
    path.strictpath_file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.contains('-') && n.split('-').nth(1).is_some())
        .unwrap_or(false)
}
```

## Key Takeaways

✅ **Single validation point** - `strict_join()` handles all path security  
✅ **Type-safe helpers** - Functions accept `StrictPath<WebAssets>` only  
✅ **Automatic attack blocking** - No manual checks needed  
✅ **Clear error handling** - Failed validation returns appropriate HTTP errors  
✅ **Content-type safety** - Based on validated path extension  

## What's Next?

Now that we can serve static assets securely, let's add user authentication:

**[Chapter 3: User Authentication →](./chapter3_authentication.md)**

In the next chapter, we'll:
- Implement simple session-based authentication
- Create per-user `VirtualRoot` instances
- Use authorization markers with `change_marker()`
- Protect routes with middleware

---

**Navigation:**  
[← Chapter 1](./chapter1_setup.md) | [Tutorial Overview](./overview.md) | [Chapter 3 →](./chapter3_authentication.md)
