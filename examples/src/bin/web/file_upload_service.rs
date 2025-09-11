// Cargo.toml
// [dependencies]
// jailed-path = "0.0.4"
// axum = "0.7"
// tokio = { version = "1.0", features = ["full"] }
// uuid = { version = "1.0", features = ["v4"] }
// serde = { version = "1.0", features = ["derive"] }
// tower = "0.4"
// tower-http = { version = "0.5", features = ["fs"] }

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use strict_path::{PathBoundary, StrictPath};
use uuid::Uuid;

// Type markers for different storage contexts
#[derive(Clone)]
struct UserUploads;
// StaticAssets marker removed; not used in this example.
#[derive(Clone)]
struct TempFiles;

#[derive(Clone)]
struct AppState {
    uploads_dir: PathBoundary<UserUploads>,
    // assets_dir is intentionally unused in this example; remove the field to avoid warnings
    temp_dir: PathBoundary<TempFiles>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize secure storage directories
    let uploads_dir = PathBoundary::try_new_create("./uploads")?;
    let temp_dir = PathBoundary::try_new_create("./temp")?;

    let state = AppState {
        uploads_dir,
        temp_dir,
    };

    // In CI or when EXAMPLES_RUN_SERVER is not set, run a quick offline simulation
    if std::env::var("EXAMPLES_RUN_SERVER").is_err() {
        let filename = format!("{}.txt", uuid::Uuid::new_v4());
        let safe_dest = state
            .uploads_dir
            .strict_join(&filename)?;
        save_uploaded_file(&safe_dest, b"demo content").await?;
        let where_to = safe_dest.strictpath_display();
        println!("Offline demo: saved {where_to}");
        return Ok(())
    }

    let app = Router::new()
        .route("/", get(upload_form))
        .route("/upload", post(handle_upload))
        .route("/files/:filename", get(serve_uploaded_file))
        .route("/process/:filename", post(process_file))
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
    <head><title>Secure File Upload</title></head>
    <body>
        <h1>Upload Files Securely</h1>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">Upload</button>
        </form>
        <h2>Uploaded Files:</h2>
        <div id="files"></div>
        <script>
            fetch('/api/files').then(r => r.json()).then(files => {
                document.getElementById('files').innerHTML = files.map(f => 
                    `<p><a href="/files/${f}">${f}</a> 
                     <button onclick="processFile('${f}')">Process</button></p>`
                ).join('');
            });
            
            function processFile(filename) {
                fetch(`/process/${filename}`, {method: 'POST'})
                    .then(r => r.text())
                    .then(result => alert(result));
            }
        </script>
    </body>
    </html>
    "#,
    )
}

async fn handle_upload(
    State(state): State<AppState>,
    body: String, // Simplified - in real app use multipart
) -> impl IntoResponse {
    // Simulate file upload data - in real app, parse multipart
    let filename = format!("{}.txt", Uuid::new_v4());
    let file_content = body.as_bytes();

    // Validate the requested destination and pass a StrictPath to the saver
    let safe_dest = match state.uploads_dir.strict_join(&filename) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid path: {e}")),
    };
    match save_uploaded_file(&safe_dest, file_content).await {
        Ok(_) => (StatusCode::OK, format!("File uploaded as {filename}")),
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
    path.write_bytes(content)?;
    let where_to = path.strictpath_display();
    println!("Saved file to: {where_to}");
    Ok(())
}

async fn serve_uploaded_file(
    State(state): State<AppState>,
    Path(filename): Path<String>,
) -> impl IntoResponse {
    // Validate then serve via a function that encodes guarantees
    let safe_path = match state.uploads_dir.strict_join(&filename) {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "File not found".to_string()),
    };
    match serve_user_file(&safe_path).await {
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

async fn process_file(
    State(state): State<AppState>,
    Path(filename): Path<String>,
) -> impl IntoResponse {
    match process_user_file(&state.uploads_dir, &state.temp_dir, &filename).await {
        Ok(result) => (StatusCode::OK, result),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Processing failed: {e}"),
        ),
    }
}

async fn process_user_file(
    uploads_dir: &PathBoundary<UserUploads>,
    temp_dir: &PathBoundary<TempFiles>,
    filename: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Validate the source path and pass typed paths into helpers
    let source_path = uploads_dir.strict_join(filename)?;
    let content = source_path.read_to_string()?;

    // Process the content (example: convert to uppercase)
    let processed = content.to_uppercase();

    // Save processed version to temp area with different PathBoundary type
    let temp_filename = format!("processed_{filename}");
    let temp_path = temp_dir.strict_join(temp_filename)?;
    temp_path.write_string(&processed)?;

    // Return result path information
    let where_to = temp_path.strictpath_display();
    Ok(format!("Processed file saved to: {where_to}"))
}

// Helper function to demonstrate secure file operations
// cleanup_old_files removed; it was unused in this example.

