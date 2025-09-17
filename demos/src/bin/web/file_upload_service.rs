// Cargo.toml
// [dependencies]
// strict-path = "0.1.0-alpha.1"
// axum = "0.7"
// tokio = { version = "1.0", features = ["full"] }
// uuid = { version = "1.0", features = ["v4"] }
// serde = { version = "1.0", features = ["derive"] }
// tower = "0.4"
// tower-http = { version = "0.5", features = ["fs"] }

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use strict_path::{PathBoundary, StrictPath, VirtualPath, VirtualRoot};
use uuid::Uuid;

// Type markers for different storage contexts
#[derive(Clone)]
struct UserUploads;
// StaticAssets marker removed; not used in this example.
#[derive(Clone)]
struct TempFiles;

#[derive(Clone)]
struct AppState {
    uploads_root: PathBoundary<UserUploads>,
    temp_dir: PathBoundary<TempFiles>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize secure storage directories
    let uploads_root = PathBoundary::try_new_create("./uploads")?;
    let temp_dir = PathBoundary::try_new_create("./temp")?;

    let state = AppState {
        uploads_root,
        temp_dir,
    };

    // In CI or when EXAMPLES_RUN_SERVER is not set, run a quick offline simulation
    if std::env::var("EXAMPLES_RUN_SERVER").is_err() {
        let user = "demo";
        let user_dir = state.uploads_root.strict_join(user)?;
        let user_vroot: VirtualRoot<UserUploads> =
            VirtualRoot::try_new_create(user_dir.interop_path())?;
        let filename = format!("{}.txt", uuid::Uuid::new_v4());
        let vdest: VirtualPath<UserUploads> = user_vroot.virtual_join(&filename)?;
        save_uploaded_file(vdest.as_unvirtual(), b"demo content").await?;
        let where_to = vdest.virtualpath_display();
        println!("Offline demo: saved {where_to}");
        return Ok(());
    }

    let app = Router::new()
        .route("/", get(upload_form))
        .route("/users/:user/upload", post(handle_upload_user))
        .route(
            "/users/:user/files/:filename",
            get(serve_uploaded_file_user),
        )
        .route("/users/:user/process/:filename", post(process_file_user))
        .with_state(state);

    println!("File upload service running on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn upload_form() -> Html<&'static str> {
    Html(
        r#"
    <!DOCTYPE html>
    <html>
    <head><title>Secure File Upload (Multi-User)</title></head>
    <body>
        <h1>Upload Files Securely (Per User)</h1>
        <p>Enter a username and pick a file; the service stores uploads under <code>./uploads/&lt;user&gt;</code>.</p>
        <p>This demo uses a simplified body (not real multipart) for brevity.</p>
        <form id="uform" onsubmit="return doUpload();">
            <label>User: <input id="user" placeholder="alice" required></label>
            <label>File name: <input id="fname" placeholder="doc.txt" required></label>
            <label>Content: <input id="content" placeholder="hello" required></label>
            <button type="submit">Upload</button>
        </form>
        <p>Try: <code>curl -X POST http://localhost:3000/users/alice/upload -d 'hello'</code></p>
        <p>Then GET: <code>/users/alice/files/doc.txt</code> or process: <code>/users/alice/process/doc.txt</code></p>
        <script>
            async function doUpload() {
                const user = document.getElementById('user').value;
                const fname = document.getElementById('fname').value;
                const body = document.getElementById('content').value;
                const res = await fetch(`/users/${user}/upload?name=${encodeURIComponent(fname)}`, {method:'POST', body});
                alert(await res.text());
                return false;
            }
        </script>
    </body>
    </html>
    "#,
    )
}

async fn handle_upload_user(
    State(state): State<AppState>,
    Path(user): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>, // name?=file
    body: String, // Simplified - in real app use multipart
) -> impl IntoResponse {
    let filename = params
        .get("name")
        .cloned()
        .unwrap_or_else(|| format!("{}.txt", Uuid::new_v4()));
    let file_content = body.as_bytes();

    // Create a VirtualRoot for the user under uploads_root
    let user_dir = match state.uploads_root.strict_join(&user) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid user: {e}")),
    };
    let user_vroot: VirtualRoot<UserUploads> =
        match VirtualRoot::try_new_create(user_dir.interop_path()) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Init failed: {e}"),
                )
            }
        };

    let vdest = match user_vroot.virtual_join(&filename) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid path: {e}")),
    };
    match save_uploaded_file(vdest.as_unvirtual(), file_content).await {
        Ok(_) => (StatusCode::OK, format!("{user}/{filename}")),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Upload failed: {e}"),
        ),
    }
}

async fn save_uploaded_file(
    path: &StrictPath<UserUploads>,
    content: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    path.write(content)?;
    let where_to = path.strictpath_display();
    println!("Saved file to: {where_to}");
    Ok(())
}

async fn serve_uploaded_file_user(
    State(state): State<AppState>,
    Path((user, filename)): Path<(String, String)>,
) -> impl IntoResponse {
    let user_dir = match state.uploads_root.strict_join(&user) {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "User not found".to_string()),
    };
    let user_vroot: VirtualRoot<UserUploads> =
        match VirtualRoot::try_new_create(user_dir.interop_path()) {
            Ok(v) => v,
            Err(_) => return (StatusCode::NOT_FOUND, "Init failed".to_string()),
        };
    let vpath = match user_vroot.virtual_join(&filename) {
        Ok(v) => v,
        Err(_) => return (StatusCode::NOT_FOUND, "File not found".to_string()),
    };
    match serve_user_file(vpath.as_unvirtual()).await {
        Ok(content) => (StatusCode::OK, content),
        Err(_) => (StatusCode::NOT_FOUND, "File not found".to_string()),
    }
}

async fn serve_user_file(
    path: &StrictPath<UserUploads>,
) -> Result<String, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err("File not found".into());
    }
    let content = path.read_to_string()?;
    Ok(content)
}

async fn process_file_user(
    State(state): State<AppState>,
    Path((user, filename)): Path<(String, String)>,
) -> impl IntoResponse {
    match process_user_file(&state.uploads_root, &state.temp_dir, &user, &filename).await {
        Ok(result) => (StatusCode::OK, result),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Processing failed: {e}"),
        ),
    }
}

async fn process_user_file(
    uploads_root: &PathBoundary<UserUploads>,
    temp_dir: &PathBoundary<TempFiles>,
    user: &str,
    filename: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Build a VirtualRoot for the user and validate the file path
    let user_dir = uploads_root.strict_join(user)?;
    let user_vroot: VirtualRoot<UserUploads> =
        VirtualRoot::try_new_create(user_dir.interop_path())?;
    let vpath = user_vroot.virtual_join(filename)?;
    let content = vpath.read_to_string()?;

    // Process the content (example: convert to uppercase)
    let processed = content.to_uppercase();

    // Save processed version to temp area with different PathBoundary type
    let temp_filename = format!("processed_{filename}");
    let temp_path = temp_dir.strict_join(temp_filename)?;
    temp_path.write(&processed)?;

    // Return result path information
    let where_to = temp_path.strictpath_display();
    Ok(format!("Processed file saved to: {where_to}"))
}

// Helper function to demonstrate secure file operations
// cleanup_old_files removed; it was unused in this example.
