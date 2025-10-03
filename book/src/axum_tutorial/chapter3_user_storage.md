# Chapter 3: Per-User Storage with VirtualRoot

This chapter shows how to isolate user file storage using `VirtualRoot<UserUploads>`. Each user gets their own virtual filesystem that cannot access other users' files.

## The Problem: User Isolation

Without proper isolation, users could access each other's files:

```rust
// ❌ UNSAFE: Users can escape their directory
let user_file = format!("./uploads/{}/{}", user_id, filename);
// User sends filename="../other_user/secret.txt"
```

## The Solution: VirtualRoot Per User

`VirtualRoot` creates an isolated view where paths are relative to the user's directory:

```rust
// ✅ SAFE: Isolated per-user virtual filesystem
let user_root = VirtualRoot::<UserUploads>::try_new(
    format!("./uploads/user_{user_id}")
)?;

// User's paths are always within their root
let file = user_root.virtual_join(filename)?; // Can't escape!
```

## Implementation: File Upload Handler

Create `src/routes/upload.rs`:

```rust
use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use strict_path::VirtualRoot;
use crate::{markers::UserUploads, state::AppState, error::AppError};

/// Handle file upload for authenticated user
pub async fn upload_file(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    // Get or create user's virtual root
    let user_root = state.get_user_root(&user_id)?;

    while let Some(field) = multipart.next_field().await? {
        let filename = field
            .file_name()
            .ok_or(AppError::MissingFilename)?
            .to_string();

        // SECURITY: virtual_join validates filename
        // Rejects: "../", absolute paths, special chars
        let file_path = user_root
            .virtual_join(&filename)
            .map_err(|_| AppError::InvalidFilename)?;

        let data = field.bytes().await?;
        
        // Safe: file_path is guaranteed within user's boundary
        file_path.write(data.as_ref())?;
    }

    Ok(StatusCode::CREATED)
}

/// List files in user's directory
pub async fn list_files(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let user_root = state.get_user_root(&user_id)?;
    
    // Convert to StrictPath to read directory
    let root_dir = user_root.as_unvirtual();
    let entries = root_dir.read_dir()?;

    let files: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    Ok(axum::Json(files))
}
```

## Update AppState

Modify `src/state.rs` to manage per-user roots:

```rust
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use strict_path::{PathBoundary, VirtualRoot};
use crate::markers::{WebAssets, UserUploads, AppConfig};

pub struct AppState {
    pub assets: PathBoundary<WebAssets>,
    pub config: PathBoundary<AppConfig>,
    uploads_base: PathBoundary<UserUploads>,
    // Cache of user virtual roots
    user_roots: Arc<RwLock<HashMap<String, VirtualRoot<UserUploads>>>>,
}

impl AppState {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            assets: PathBoundary::try_new_create("./data/assets")?,
            config: PathBoundary::try_new("./data/config")?,
            uploads_base: PathBoundary::try_new_create("./data/uploads")?,
            user_roots: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get or create virtual root for user
    pub fn get_user_root(
        &self,
        user_id: &str,
    ) -> Result<VirtualRoot<UserUploads>, Box<dyn std::error::Error>> {
        // Check cache first
        {
            let cache = self.user_roots.read().unwrap();
            if let Some(root) = cache.get(user_id) {
                return Ok(root.clone());
            }
        }

        // Create new user directory and virtual root
        let user_dir = self.uploads_base.strict_join(user_id)?;
        user_dir.create_dir_all()?;

        let vroot = VirtualRoot::try_new(user_dir.interop_path())?;

        // Cache it
        self.user_roots.write().unwrap().insert(user_id.to_string(), vroot.clone());

        Ok(vroot)
    }
}
```

## Register Routes

Update `src/main.rs`:

```rust
mod routes {
    pub mod assets;
    pub mod upload;
}

use axum::{
    routing::{get, post},
    Router,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::new()?;

    let app = Router::new()
        .route("/assets/*path", get(routes::assets::serve_asset))
        .route("/users/:user_id/files", post(routes::upload::upload_file))
        .route("/users/:user_id/files", get(routes::upload::list_files))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Server running on http://127.0.0.1:3000");
    
    axum::serve(listener, app).await?;
    Ok(())
}
```

## Key Security Properties

1. **User Isolation**: Each `VirtualRoot` is scoped to one user's directory
2. **Path Validation**: `virtual_join()` prevents directory traversal
3. **Type Safety**: `VirtualRoot<UserUploads>` can't mix with `PathBoundary<WebAssets>`
4. **Automatic Caching**: User roots are cached for performance

## Testing the Isolation

```bash
# Upload to user_001
curl -F "file=@test.txt" http://localhost:3000/users/user_001/files

# Try to access user_002's files (will fail)
curl -F "file=@../user_002/secret.txt" http://localhost:3000/users/user_001/files
# Returns 400: InvalidFilename

# List user_001's files (only shows their files)
curl http://localhost:3000/users/user_001/files
```

## What We Learned

- `VirtualRoot` provides per-user filesystem isolation
- `virtual_join()` validates filenames and prevents escapes
- AppState can manage multiple virtual roots efficiently
- Type markers prevent accidentally mixing user storage with other boundaries

---

**Navigation:**  
[← Chapter 2](./chapter2_static_assets.md) | [Tutorial Overview](./overview.md)
