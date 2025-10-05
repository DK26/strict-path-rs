# Chapter 1: Project Setup

Let's set up our Axum web service with proper security boundaries from the start. We'll create the project structure, define our marker types, and establish path boundaries for different storage areas.

## Create the Project

```bash
cargo new file-sharing-service
cd file-sharing-service
```

## Add Dependencies

Update your `Cargo.toml`:

```toml
[package]
name = "file-sharing-service"
version = "0.1.0"
edition = "2021"

[dependencies]
# Web framework
axum = "0.7"
tokio = { version = "1", features = ["full"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["fs", "trace"] }

# Security and paths
strict-path = { version = "0.1", features = ["serde"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Utilities
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
uuid = { version = "1.0", features = ["v4", "serde"] }
```

## Define Security Boundaries

Create `src/markers.rs` - this is where we define our type-safe contexts:

```rust
//! Type-safe markers for different storage contexts.
//! 
//! These zero-cost markers prevent accidentally mixing different
//! types of files (e.g., serving user uploads as web assets).

/// Public web assets (CSS, JavaScript, images, fonts)
/// 
/// Files with this marker can be served to anyone without authentication.
pub struct WebAssets;

/// User-uploaded files (documents, photos, videos)
/// 
/// Each user has their own isolated VirtualRoot with this marker.
/// Files are private and require authentication to access.
pub struct UserUploads;

/// Application configuration files
/// 
/// Server configuration, secrets, and settings.
/// Never exposed to users.
pub struct AppConfig;

/// Read-only permission marker
pub struct ReadOnly;

/// Read-write permission marker  
pub struct ReadWrite;
```

## Application State

Create `src/state.rs` - this holds our path boundaries and user sessions:

```rust
use strict_path::{PathBoundary, VirtualRoot};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::markers::{WebAssets, UserUploads, AppConfig};

/// Shared application state passed to all route handlers
#[derive(Clone)]
pub struct AppState {
    /// Path boundary for public web assets
    pub assets: Arc<PathBoundary<WebAssets>>,
    
    /// Path boundary for server configuration
    pub config: Arc<PathBoundary<AppConfig>>,
    
    /// Per-user upload roots (user_id -> VirtualRoot)
    pub user_uploads: Arc<RwLock<HashMap<Uuid, VirtualRoot<UserUploads>>>>,
    
    /// Active user sessions (session_id -> user_id)
    pub sessions: Arc<RwLock<HashMap<String, Uuid>>>,
}

impl AppState {
    /// Create new application state with initialized boundaries
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Create boundary for public assets
        let assets = PathBoundary::try_new_create("public")?;
        
        // Create boundary for config files
        let config = PathBoundary::try_new_create("config")?;
        
        Ok(Self {
            assets: Arc::new(assets),
            config: Arc::new(config),
            user_uploads: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Get or create a VirtualRoot for a specific user
    pub async fn get_user_uploads(
        &self,
        user_id: Uuid,
    ) -> Result<VirtualRoot<UserUploads>, Box<dyn std::error::Error>> {
        let mut uploads = self.user_uploads.write().await;
        
        if let Some(vroot) = uploads.get(&user_id) {
            // Return existing user root
            Ok(vroot.clone())
        } else {
            // Create new isolated storage for this user
            let user_dir = format!("uploads/user_{}", user_id);
            let vroot = VirtualRoot::try_new_create(&user_dir)?;
            uploads.insert(user_id, vroot.clone());
            
            tracing::info!("Created upload directory for user {}", user_id);
            Ok(vroot)
        }
    }
    
    /// Create a new user session
    pub async fn create_session(&self, user_id: Uuid) -> String {
        let session_id = Uuid::new_v4().to_string();
        self.sessions.write().await.insert(session_id.clone(), user_id);
        session_id
    }
    
    /// Get user ID from session ID
    pub async fn get_user_from_session(&self, session_id: &str) -> Option<Uuid> {
        self.sessions.read().await.get(session_id).copied()
    }
}
```

## Main Server Setup

Update `src/main.rs`:

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
    tracing::info!("  - User uploads: uploads/user_<uuid>/");

    // Build our application with routes
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_check))
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

## Project Structure

Create the initial directory structure:

```bash
mkdir -p public/{css,js,images}
mkdir -p config
mkdir -p src/routes
mkdir -p src/middleware
```

Create a sample HTML file in `public/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Sharing Service</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
    <h1>🔐 Secure File Sharing Service</h1>
    <p>Protected by strict-path security boundaries.</p>
</body>
</html>
```

Create `public/css/style.css`:

```css
body {
    font-family: system-ui, -apple-system, sans-serif;
    max-width: 800px;
    margin: 2rem auto;
    padding: 0 1rem;
    background: #f5f5f5;
}

h1 {
    color: #2c3e50;
}
```

## Test the Server

Run the server:

```bash
cargo run
```

You should see:
```
🔒 Security boundaries initialized:
  - Public assets: public
  - Config files: config
  - User uploads: uploads/user_<uuid>/
🚀 Server listening on 127.0.0.1:3000
```

Visit `http://localhost:3000/health` - you should see "OK".

## Understanding the Security Model

Let's examine what we've built:

### 1. Separate Boundaries for Each Context

```rust
pub assets: Arc<PathBoundary<WebAssets>>,
pub config: Arc<PathBoundary<AppConfig>>,
```

Each storage area has its own `PathBoundary` with a different marker type. This means:
- ✅ You **cannot** accidentally serve config files as web assets
- ✅ You **cannot** write user uploads to the config directory
- ✅ The compiler **enforces** these boundaries

### 2. Per-User Isolated Storage

```rust
pub user_uploads: Arc<RwLock<HashMap<Uuid, VirtualRoot<UserUploads>>>>,
```

Each user gets their own `VirtualRoot`:
- ✅ User A **cannot** access User B's files
- ✅ Path traversal attacks (`../other-user/file.txt`) are automatically blocked
- ✅ Each user sees clean paths starting from `/`

### 3. Type-Safe State

```rust
pub async fn get_user_uploads(
    &self,
    user_id: Uuid,
) -> Result<VirtualRoot<UserUploads>, Box<dyn std::error::Error>>
```

Functions return typed paths:
- ✅ You know exactly what type of storage you're working with
- ✅ Can't mix user uploads with web assets
- ✅ Refactoring is safe - compiler finds all usages

## What's Next?

Now that we have our security boundaries established, we'll implement:

1. **[Chapter 2: Static Asset Serving](./chapter2_static_assets.md)** - Serve CSS, JS, and images safely
2. User authentication and session management
3. File upload system with per-user isolation
4. File download and listing with authorization
5. Configuration management and deployment

## Key Takeaways

✅ **Separate boundaries** - One `PathBoundary` per storage context  
✅ **Type-safe markers** - Compiler prevents context mixing  
✅ **Per-user isolation** - `VirtualRoot` for each user  
✅ **Lazy initialization** - User storage created on first access  
✅ **Shared state** - `Arc<RwLock<>>` for thread-safe access  

---

**Next:** [Chapter 2: Static Asset Serving →](./chapter2_static_assets.md)

**Navigation:**  
← [Tutorial Overview](./overview.md) | [Chapter 2 →](./chapter2_static_assets.md)
