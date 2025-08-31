// Axum Static Server with VirtualRoot
//
// Serves files from a jailed directory using Axum. User-provided paths are
// validated via VirtualRoot; handlers read via &VirtualPath to encode guarantees.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use jailed_path::{VirtualPath, VirtualRoot};
use std::fs;

#[derive(Clone)]
struct Assets;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup demo assets
    fs::create_dir_all("axum_assets/css")?;
    fs::write("axum_assets/index.html", "<h1>Hello Axum</h1>")?;
    fs::write("axum_assets/css/site.css", "body{font:14px sans-serif}")?;

    let vroot: VirtualRoot<Assets> = VirtualRoot::try_new("axum_assets")?;

    // In CI or when EXAMPLES_RUN_SERVER is not set, run a quick offline simulation
    if std::env::var("EXAMPLES_RUN_SERVER").is_err() {
        let vp = vroot.try_virtual_path("index.html")?;
        let body = serve_vp(&vp)?;
        println!("Offline demo: {} bytes from {}", body.len(), vp);
        fs::remove_dir_all("axum_assets").ok();
        return Ok(())
    }

    let app = Router::new()
        .route("/", get(root))
        .route("/*path", get(serve))
        .route("/json/*path", get(serve_json))
        .with_state(vroot);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8081").await?;
    println!("Axum server on http://127.0.0.1:8081");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn root() -> impl IntoResponse {
    (StatusCode::OK, "Use /index.html or /css/site.css")
}

async fn serve(
    State(vroot): State<VirtualRoot<Assets>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    match vroot.try_virtual_path(&path) {
        Ok(vp) => match serve_vp(&vp) {
            Ok(body) => (StatusCode::OK, body),
            Err(_) => (StatusCode::NOT_FOUND, String::from("Not found")),
        },
        Err(_) => (StatusCode::BAD_REQUEST, String::from("Invalid path")),
    }
}

fn serve_vp(p: &VirtualPath<Assets>) -> std::io::Result<String> {
    if !p.is_file() {
        return Err(std::io::ErrorKind::NotFound.into());
    }
    p.read_to_string()
}

// Keep handlers simple: validate Path<String> using State<VirtualRoot<Assets>> directly.

#[derive(serde::Serialize)]
struct PathInfo {
    // Serializes as virtual-root string via jailed-path serde feature
    path: VirtualPath<Assets>,
    // Include system path for observability
    system: String,
}

async fn serve_json(
    State(vroot): State<VirtualRoot<Assets>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    match vroot.try_virtual_path(&path) {
        Ok(vp) => {
            let info = PathInfo { path: vp.clone(), system: vp.systempath_to_string_lossy().into_owned() };
            let value = serde_json::to_value(info).unwrap_or_else(|_| serde_json::json!({"error":"serialize"}));
            (StatusCode::OK, Json(value))
        }
        Err(_) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid path"}))),
    }
}
