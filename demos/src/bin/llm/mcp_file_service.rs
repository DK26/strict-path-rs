//! Minimal MCP-style file service demo
//!
//! This demo simulates an MCP client/server that receives JSON requests over stdin
//! to read, write, and list files. The key point is that every received "path"
//! string is validated via VirtualPath (isolated project mode) or StrictPath
//! (system environment mode) before any I/O.
//!
//! Usage examples:
//! - Virtual (isolated project):
//!   cargo run -p strict-path-demos --bin mcp_file_service -- --mode virtual --root ./mcp_project
//! - Strict (system environment):
//!   cargo run -p strict-path-demos --bin mcp_file_service -- --mode strict --root ./data
//!
//! Protocol: JSON-RPC 2.0 over stdio with Content-Length framing (MCP-compatible).
//! Supported methods:
//! - initialize
//! - tools/list
//! - tools/call { name: "file.read"|"file.write"|"file.list", arguments: {...} }

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use strict_path::{PathBoundary, VirtualRoot};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Virtual,
    Strict,
}

#[derive(Parser, Debug)]
#[command(name = "mcp-file-service")]
#[command(about = "MCP-like file service demo with strict/virtual path validation")]
struct Cli {
    /// Operating mode: virtual (isolated) or strict (system)
    #[arg(long, value_enum, default_value_t = Mode::Virtual)]
    mode: Mode,

    /// Base directory for the service (VirtualRoot or PathBoundary)
    #[arg(long)]
    root: String,

    /// Verbose logging
    #[arg(long)]
    verbose: bool,
}

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct JsonRpcResponse<T: Serialize> {
    jsonrpc: &'static str,
    id: Value,
    result: T,
}

#[derive(Serialize)]
struct JsonRpcErrorResponse {
    jsonrpc: &'static str,
    id: Value,
    error: JsonRpcError,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct ReadParams {
    path: String,
}

#[derive(Deserialize)]
struct WriteParams {
    path: String,
    content: String,
}

// Removed legacy OkResponse/ErrResponse wrappers; JSON-RPC responses are used instead.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Virtual => run_virtual(cli),
        Mode::Strict => run_strict(cli),
    }
}

fn run_virtual(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let user_project_root: VirtualRoot<()> =
        VirtualRoot::try_new_create(&cli.root).map_err(|e| anyhow::anyhow!("root init: {e}"))?;

    if cli.verbose {
        let root_display = user_project_root.as_unvirtual().strictpath_display();
        eprintln!("[virtual] Root: {root_display}");
    }

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    loop {
        match read_framed_request(&mut stdin) {
            Ok(Some(req)) => {
                // Minimal JSON-RPC version validation so the `jsonrpc` field is read and honored.
                if let Some(ref v) = req.jsonrpc {
                    if v != "2.0" {
                        let out =
                            respond_err(&req, -32600, format!("Unsupported jsonrpc version: {v}"));
                        write_framed_response(&mut stdout, &out)?;
                        continue;
                    }
                }
                let out = match req.method.as_str() {
                    "initialize" => respond_ok(
                        &req,
                        json!({
                            "protocolVersion": "2024-11-05",
                            "capabilities": {"tools": {}},
                        }),
                    ),
                    "tools/list" => respond_ok(
                        &req,
                        json!({
                            "tools": [
                                {"name": "file.read"},
                                {"name": "file.write"},
                                {"name": "file.list"}
                            ]
                        }),
                    ),
                    "tools/call" => handle_tools_call_virtual(&user_project_root, &req),
                    other => respond_err(&req, -32601, format!("Unknown method: {other}")),
                };
                write_framed_response(&mut stdout, &out)?;
            }
            Ok(None) => break, // EOF
            Err(e) => {
                eprintln!("[error] {e}");
                break;
            }
        }
    }
    Ok(())
}

fn handle_read_virtual(root: &VirtualRoot<()>, params: &Value) -> Value {
    let p: Result<ReadParams, _> = serde_json::from_value(params.clone());
    match p {
        Ok(ReadParams { path }) => match root.virtual_join(&path) {
            Ok(file_vpath) => match file_vpath.read_to_string() {
                Ok(content) => json!({
                    "virtualPath": format!("{}", file_vpath.virtualpath_display()),
                    "content": content,
                }),
                Err(e) => json!({"error": format!("I/O error: {e}")}),
            },
            Err(e) => json!({"error": format!("Invalid path: {e}")}),
        },
        Err(e) => json!({"error": format!("Invalid params: {e}")}),
    }
}

fn handle_write_virtual(root: &VirtualRoot<()>, params: &Value) -> Value {
    let p: Result<WriteParams, _> = serde_json::from_value(params.clone());
    match p {
        Ok(WriteParams { path, content }) => match root.virtual_join(&path) {
            Ok(file_vpath) => {
                if let Err(e) = file_vpath.create_parent_dir_all() {
                    return json!({"error": format!("Create parent error: {e}")});
                }
                match file_vpath.write(&content) {
                    Ok(()) => json!({
                        "virtualPath": format!("{}", file_vpath.virtualpath_display()),
                        "bytes": content.len(),
                    }),
                    Err(e) => json!({"error": format!("I/O error: {e}")}),
                }
            }
            Err(e) => json!({"error": format!("Invalid path: {e}")}),
        },
        Err(e) => json!({"error": format!("Invalid params: {e}")}),
    }
}

fn handle_list_virtual(root: &VirtualRoot<()>, params: &Value) -> Value {
    let p: Result<ReadParams, _> = serde_json::from_value(params.clone());
    match p {
        Ok(ReadParams { path }) => match root.virtual_join(&path) {
            Ok(dir_vpath) => {
                if !dir_vpath.exists() || !dir_vpath.is_dir() {
                    return json!({"error": "Not a directory or does not exist"});
                }
                let mut entries_json = Vec::new();
                match dir_vpath.read_dir() {
                    Ok(read_dir) => {
                        for entry in read_dir.flatten() {
                            if let Some(name) = entry.file_name().to_str() {
                                // Convert to a VirtualPath child for display
                                if let Ok(child) = dir_vpath.virtual_join(name) {
                                    let display = format!("{}", child.virtualpath_display());
                                    entries_json.push(json!({
                                        "name": name,
                                        "virtualPath": display,
                                        "isDir": child.is_dir(),
                                    }));
                                }
                            }
                        }
                        json!({
                            "virtualPath": format!("{}", dir_vpath.virtualpath_display()),
                            "entries": entries_json,
                        })
                    }
                    Err(e) => json!({"error": format!("read_dir error: {e}")}),
                }
            }
            Err(e) => json!({"error": format!("Invalid path: {e}")}),
        },
        Err(e) => json!({"error": format!("Invalid params: {e}")}),
    }
}

fn run_strict(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let system_root: PathBoundary<()> =
        PathBoundary::try_new_create(&cli.root).map_err(|e| anyhow::anyhow!("root init: {e}"))?;
    if cli.verbose {
        eprintln!("[strict] Root: {}", system_root.strictpath_display());
    }

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    loop {
        match read_framed_request(&mut stdin) {
            Ok(Some(req)) => {
                // Minimal JSON-RPC version validation so the `jsonrpc` field is read and honored.
                if let Some(ref v) = req.jsonrpc {
                    if v != "2.0" {
                        let out =
                            respond_err(&req, -32600, format!("Unsupported jsonrpc version: {v}"));
                        write_framed_response(&mut stdout, &out)?;
                        continue;
                    }
                }
                let out = match req.method.as_str() {
                    "initialize" => respond_ok(
                        &req,
                        json!({
                            "protocolVersion": "2024-11-05",
                            "capabilities": {"tools": {}},
                        }),
                    ),
                    "tools/list" => respond_ok(
                        &req,
                        json!({
                            "tools": [
                                {"name": "file.read"},
                                {"name": "file.write"},
                                {"name": "file.list"}
                            ]
                        }),
                    ),
                    "tools/call" => handle_tools_call_strict(&system_root, &req),
                    other => respond_err(&req, -32601, format!("Unknown method: {other}")),
                };
                write_framed_response(&mut stdout, &out)?;
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("[error] {e}");
                break;
            }
        }
    }
    Ok(())
}

fn handle_read_strict(root: &PathBoundary<()>, params: &Value) -> Value {
    let p: Result<ReadParams, _> = serde_json::from_value(params.clone());
    match p {
        Ok(ReadParams { path }) => match root.strict_join(&path) {
            Ok(file_spath) => match file_spath.read_to_string() {
                Ok(content) => json!({
                    "systemPath": format!("{}", file_spath.strictpath_display()),
                    "content": content,
                }),
                Err(e) => json!({"error": format!("I/O error: {e}")}),
            },
            Err(e) => json!({"error": format!("Invalid path: {e}")}),
        },
        Err(e) => json!({"error": format!("Invalid params: {e}")}),
    }
}

fn handle_write_strict(root: &PathBoundary<()>, params: &Value) -> Value {
    let p: Result<WriteParams, _> = serde_json::from_value(params.clone());
    match p {
        Ok(WriteParams { path, content }) => match root.strict_join(&path) {
            Ok(file_spath) => {
                if let Err(e) = file_spath.create_parent_dir_all() {
                    return json!({"error": format!("Create parent error: {e}")});
                }
                match file_spath.write(&content) {
                    Ok(()) => json!({
                        "systemPath": format!("{}", file_spath.strictpath_display()),
                        "bytes": content.len(),
                    }),
                    Err(e) => json!({"error": format!("I/O error: {e}")}),
                }
            }
            Err(e) => json!({"error": format!("Invalid path: {e}")}),
        },
        Err(e) => json!({"error": format!("Invalid params: {e}")}),
    }
}

fn handle_list_strict(root: &PathBoundary<()>, params: &Value) -> Value {
    let p: Result<ReadParams, _> = serde_json::from_value(params.clone());
    match p {
        Ok(ReadParams { path }) => match root.strict_join(&path) {
            Ok(dir_spath) => {
                if !dir_spath.exists() || !dir_spath.is_dir() {
                    return json!({"error": "Not a directory or does not exist"});
                }
                let mut entries_json = Vec::new();
                match dir_spath.read_dir() {
                    Ok(read_dir) => {
                        for entry in read_dir.flatten() {
                            if let Some(name) = entry.file_name().to_str() {
                                // Build a StrictPath child for display
                                if let Ok(child) = dir_spath.strict_join(name) {
                                    entries_json.push(json!({
                                        "name": name,
                                        "systemPath": format!("{}", child.strictpath_display()),
                                        "isDir": child.is_dir(),
                                    }));
                                }
                            }
                        }
                        json!({
                            "systemPath": format!("{}", dir_spath.strictpath_display()),
                            "entries": entries_json,
                        })
                    }
                    Err(e) => json!({"error": format!("read_dir error: {e}")}),
                }
            }
            Err(e) => json!({"error": format!("Invalid path: {e}")}),
        },
        Err(e) => json!({"error": format!("Invalid params: {e}")}),
    }
}

fn handle_tools_call_virtual(root: &VirtualRoot<()>, req: &JsonRpcRequest) -> String {
    let name = req
        .params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
    let payload = match name {
        "file.read" => handle_read_virtual(root, &args),
        "file.write" => handle_write_virtual(root, &args),
        "file.list" => handle_list_virtual(root, &args),
        _ => json!({"error": format!("Unknown tool: {name}")}),
    };
    if let Some(id) = req.id.clone() {
        serde_json::to_string(&JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: payload,
        })
        .unwrap()
    } else {
        String::new()
    }
}

fn handle_tools_call_strict(root: &PathBoundary<()>, req: &JsonRpcRequest) -> String {
    let name = req
        .params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
    let payload = match name {
        "file.read" => handle_read_strict(root, &args),
        "file.write" => handle_write_strict(root, &args),
        "file.list" => handle_list_strict(root, &args),
        _ => json!({"error": format!("Unknown tool: {name}")}),
    };
    if let Some(id) = req.id.clone() {
        serde_json::to_string(&JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: payload,
        })
        .unwrap()
    } else {
        String::new()
    }
}

fn read_framed_request<R: Read>(r: &mut R) -> io::Result<Option<JsonRpcRequest>> {
    // Read headers until CRLFCRLF
    let mut headers = Vec::new();
    let mut single_byte = [0u8; 1];
    let mut header_window = [0u8; 4];
    let mut header_index = 0usize;
    loop {
        let read_count = r.read(&mut single_byte)?;
        if read_count == 0 {
            if headers.is_empty() {
                return Ok(None);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof in headers",
                ));
            }
        }
        headers.push(single_byte[0]);
        header_window[header_index % 4] = single_byte[0];
        header_index += 1;
        if header_window == [b'\r', b'\n', b'\r', b'\n'] {
            break;
        }
        if headers.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    }
    let header_str = String::from_utf8_lossy(&headers);
    let mut len: Option<usize> = None;
    for line in header_str.split("\r\n") {
        let line = line.trim();
        if line.to_ascii_lowercase().starts_with("content-length:") {
            if let Some(v) = line.split(':').nth(1) {
                len = v.trim().parse::<usize>().ok();
            }
        }
    }
    let content_len =
        len.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length"))?;
    let mut body = vec![0u8; content_len];
    r.read_exact(&mut body)?;
    let mut req: JsonRpcRequest = serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("json parse: {e}")))?;
    // Ensure the jsonrpc field is observed and normalized
    if req.jsonrpc.is_none() {
        req.jsonrpc = Some("2.0".to_string());
    }
    Ok(Some(req))
}

fn write_framed_response<W: Write>(w: &mut W, payload: &str) -> io::Result<()> {
    if payload.is_empty() {
        return Ok(());
    }
    let bytes = payload.as_bytes();
    write!(w, "Content-Length: {}\r\n\r\n", bytes.len())?;
    w.write_all(bytes)?;
    w.flush()
}

fn respond_ok(req: &JsonRpcRequest, result: Value) -> String {
    let id = req.id.clone().unwrap_or(json!(null));
    serde_json::to_string(&JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result,
    })
    .unwrap()
}

fn respond_err(req: &JsonRpcRequest, code: i64, message: String) -> String {
    let id = req.id.clone().unwrap_or(json!(null));
    serde_json::to_string(&JsonRpcErrorResponse {
        jsonrpc: "2.0",
        id,
        error: JsonRpcError { code, message },
    })
    .unwrap()
}
