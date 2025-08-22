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
use jailed_path::Jail;
use uuid::Uuid;

// Type markers for different storage contexts
#[derive(Clone)]
struct UserUploads;
// StaticAssets marker removed; not used in this example.
#[derive(Clone)]
struct TempFiles;

#[derive(Clone)]
struct AppState {
    uploads_jail: Jail<UserUploads>,
    // assets_jail is intentionally unused in this example; remove the field to avoid warnings
    temp_jail: Jail<TempFiles>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize secure storage jails
    let uploads_jail = Jail::try_new_create("./uploads")?;
    let temp_jail = Jail::try_new_create("./temp")?;

    let state = AppState {
        uploads_jail,
        temp_jail,
    };

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

    match save_uploaded_file(&state.uploads_jail, &filename, file_content).await {
        Ok(_) => (StatusCode::OK, format!("File uploaded as {filename}")),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Upload failed: {e}"),
        ),
    }
}

async fn save_uploaded_file(
    jail: &Jail<UserUploads>,
    filename: &str,
    content: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // Critical security: validate external filename through jail
    let safe_path = jail.try_path(filename)?;

    // Even if filename was "../../../etc/passwd", it's now safely contained
    safe_path.write_bytes(content)?;

    println!("Saved file to: {}", safe_path.realpath_to_string());
    Ok(())
}

async fn serve_uploaded_file(
    State(state): State<AppState>,
    Path(filename): Path<String>,
) -> impl IntoResponse {
    match serve_user_file(&state.uploads_jail, &filename).await {
        Ok(content) => (StatusCode::OK, content),
        Err(_) => (StatusCode::NOT_FOUND, "File not found".to_string()),
    }
}

async fn serve_user_file(
    jail: &Jail<UserUploads>,
    filename: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Secure file serving - path is validated and contained
    let safe_path = jail.try_path(filename)?;

    if !safe_path.exists() {
        return Err("File not found".into());
    }

    let content = safe_path.read_to_string()?;
    Ok(content)
}

async fn process_file(
    State(state): State<AppState>,
    Path(filename): Path<String>,
) -> impl IntoResponse {
    match process_user_file(&state.uploads_jail, &state.temp_jail, &filename).await {
        Ok(result) => (StatusCode::OK, result),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Processing failed: {e}"),
        ),
    }
}

async fn process_user_file(
    uploads_jail: &Jail<UserUploads>,
    temp_jail: &Jail<TempFiles>,
    filename: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Load from secure uploads area
    let source_path = uploads_jail.try_path(filename)?;
    let content = source_path.read_to_string()?;

    // Process the content (example: convert to uppercase)
    let processed = content.to_uppercase();

    // Save processed version to temp area with different jail type
    let temp_filename = format!("processed_{filename}");
    let temp_path = temp_jail.try_path(temp_filename)?;
    temp_path.write_string(&processed)?;

    // Return result path information
    Ok(format!(
        "Processed file saved to: {}",
        temp_path.realpath_to_string()
    ))
}

// Helper function to demonstrate secure file operations
// cleanup_old_files removed; it was unused in this example.
