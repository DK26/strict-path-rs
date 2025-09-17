//! MCP file service using the official runtime
//!
//! This demo registers three tools:
//! - file.read  { path: string }
//! - file.write { path: string, content: string }
//! - file.list  { path: string }
//!
//! All received paths are validated through VirtualPath (isolated project) or StrictPath (system).
//!
//! Usage:
//!   cargo run -p strict-path-demos --bin mcp_file_service_rmcp -- --mode virtual --root ./project
//!   cargo run -p strict-path-demos --bin mcp_file_service_rmcp -- --mode strict  --root ./data

use anyhow::Result;
use clap::{Parser, ValueEnum};
use futures::future::BoxFuture;
use futures::FutureExt;
use rmcp::{
    handler::server::{router::tool::CallToolHandlerExt, wrapper::Parameters, ServerHandler},
    model::*,
    service::serve_server,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strict_path::{PathBoundary, VirtualRoot};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Virtual,
    Strict,
}

#[derive(Parser, Debug)]
#[command(name = "mcp-file-service-rmcp")]
#[command(about = "MCP stdio server for safe file I/O using strict-path")]
struct Cli {
    #[arg(long, value_enum, default_value_t = Mode::Virtual)]
    mode: Mode,
    #[arg(long)]
    root: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Virtual => run_virtual(cli).await,
        Mode::Strict => run_strict(cli).await,
    }
}

#[derive(Debug, Clone)]
struct VirtualFileService {
    user_project_root: VirtualRoot<()>,
}

#[derive(Debug, Clone)]
struct StrictFileService {
    system_root: PathBoundary<()>,
}

#[derive(Deserialize, JsonSchema)]
struct ReadArgs {
    path: String,
}

#[derive(Deserialize, JsonSchema)]
struct WriteArgs {
    path: String,
    content: String,
}

#[derive(Serialize, JsonSchema)]
struct ReadResultVirtual {
    #[serde(rename = "virtualPath")]
    virtual_path: String,
    content: String,
}

#[derive(Serialize, JsonSchema)]
struct ReadResultStrict {
    #[serde(rename = "systemPath")]
    system_path: String,
    content: String,
}

#[derive(Serialize, JsonSchema)]
struct WriteResultVirtual {
    #[serde(rename = "virtualPath")]
    virtual_path: String,
    bytes: usize,
}

#[derive(Serialize, JsonSchema)]
struct WriteResultStrict {
    #[serde(rename = "systemPath")]
    system_path: String,
    bytes: usize,
}

#[derive(Serialize, JsonSchema)]
struct ListEntryVirtual {
    name: String,
    #[serde(rename = "virtualPath")]
    virtual_path: String,
    #[serde(rename = "isDir")]
    is_dir: bool,
}

#[derive(Serialize, JsonSchema)]
struct ListEntryStrict {
    name: String,
    #[serde(rename = "systemPath")]
    system_path: String,
    #[serde(rename = "isDir")]
    is_dir: bool,
}

#[derive(Serialize, JsonSchema)]
struct ListResultVirtual {
    #[serde(rename = "virtualPath")]
    virtual_path: String,
    entries: Vec<ListEntryVirtual>,
}

#[derive(Serialize, JsonSchema)]
struct ListResultStrict {
    #[serde(rename = "systemPath")]
    system_path: String,
    entries: Vec<ListEntryStrict>,
}

impl ServerHandler for VirtualFileService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::default()
    }
}

impl ServerHandler for StrictFileService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::default()
    }
}

// ---- Virtual handlers (cloneable function items) ----
fn tool_virtual_file_read(
    svc: &VirtualFileService,
    params: Parameters<ReadArgs>,
) -> BoxFuture<'_, Result<rmcp::Json<ReadResultVirtual>, ErrorData>> {
    async move {
        let Parameters(ReadArgs { path }) = params;
        let file_vpath = svc
            .user_project_root
            .virtual_join(path)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid path: {e}"), None))?;
        let content = file_vpath
            .read_to_string()
            .map_err(|e| ErrorData::internal_error(format!("I/O error: {e}"), None))?;
        let result = ReadResultVirtual {
            virtual_path: format!("{}", file_vpath.virtualpath_display()),
            content,
        };
        Ok(rmcp::Json(result))
    }
    .boxed()
}

fn tool_virtual_file_write(
    svc: &VirtualFileService,
    params: Parameters<WriteArgs>,
) -> BoxFuture<'_, Result<rmcp::Json<WriteResultVirtual>, ErrorData>> {
    async move {
        let Parameters(WriteArgs { path, content }) = params;
        let file_vpath = svc
            .user_project_root
            .virtual_join(path)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid path: {e}"), None))?;
        file_vpath
            .create_parent_dir_all()
            .map_err(|e| ErrorData::internal_error(format!("Create parent error: {e}"), None))?;
        file_vpath
            .write(&content)
            .map_err(|e| ErrorData::internal_error(format!("I/O error: {e}"), None))?;
        let result = WriteResultVirtual {
            virtual_path: format!("{}", file_vpath.virtualpath_display()),
            bytes: content.len(),
        };
        Ok(rmcp::Json(result))
    }
    .boxed()
}

fn tool_virtual_file_list(
    svc: &VirtualFileService,
    params: Parameters<ReadArgs>,
) -> BoxFuture<'_, Result<rmcp::Json<ListResultVirtual>, ErrorData>> {
    async move {
        let Parameters(ReadArgs { path }) = params;
        let dir_vpath = svc
            .user_project_root
            .virtual_join(path)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid path: {e}"), None))?;
        if !dir_vpath.exists() || !dir_vpath.is_dir() {
            return Err(ErrorData::invalid_params(
                "Not a directory or does not exist",
                None,
            ));
        }
        let mut entries = Vec::new();
        for entry in dir_vpath
            .read_dir()
            .map_err(|e| ErrorData::internal_error(format!("read_dir: {e}"), None))?
            .flatten()
        {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(child) = dir_vpath.virtual_join(name) {
                    entries.push(ListEntryVirtual {
                        name: name.to_string(),
                        virtual_path: format!("{}", child.virtualpath_display()),
                        is_dir: child.is_dir(),
                    });
                }
            }
        }
        let result = ListResultVirtual {
            virtual_path: format!("{}", dir_vpath.virtualpath_display()),
            entries,
        };
        Ok(rmcp::Json(result))
    }
    .boxed()
}

// ---- Strict handlers (cloneable function items) ----
fn tool_strict_file_read(
    svc: &StrictFileService,
    params: Parameters<ReadArgs>,
) -> BoxFuture<'_, Result<rmcp::Json<ReadResultStrict>, ErrorData>> {
    async move {
        let Parameters(ReadArgs { path }) = params;
        let file_spath = svc
            .system_root
            .strict_join(path)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid path: {e}"), None))?;
        let content = file_spath
            .read_to_string()
            .map_err(|e| ErrorData::internal_error(format!("I/O error: {e}"), None))?;
        let result = ReadResultStrict {
            system_path: format!("{}", file_spath.strictpath_display()),
            content,
        };
        Ok(rmcp::Json(result))
    }
    .boxed()
}

fn tool_strict_file_write(
    svc: &StrictFileService,
    params: Parameters<WriteArgs>,
) -> BoxFuture<'_, Result<rmcp::Json<WriteResultStrict>, ErrorData>> {
    async move {
        let Parameters(WriteArgs { path, content }) = params;
        let file_spath = svc
            .system_root
            .strict_join(path)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid path: {e}"), None))?;
        file_spath
            .create_parent_dir_all()
            .map_err(|e| ErrorData::internal_error(format!("Create parent error: {e}"), None))?;
        file_spath
            .write(&content)
            .map_err(|e| ErrorData::internal_error(format!("I/O error: {e}"), None))?;
        let result = WriteResultStrict {
            system_path: format!("{}", file_spath.strictpath_display()),
            bytes: content.len(),
        };
        Ok(rmcp::Json(result))
    }
    .boxed()
}

fn tool_strict_file_list(
    svc: &StrictFileService,
    params: Parameters<ReadArgs>,
) -> BoxFuture<'_, Result<rmcp::Json<ListResultStrict>, ErrorData>> {
    async move {
        let Parameters(ReadArgs { path }) = params;
        let dir_spath = svc
            .system_root
            .strict_join(path)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid path: {e}"), None))?;
        if !dir_spath.exists() || !dir_spath.is_dir() {
            return Err(ErrorData::invalid_params(
                "Not a directory or does not exist",
                None,
            ));
        }
        let mut entries = Vec::new();
        for entry in dir_spath
            .read_dir()
            .map_err(|e| ErrorData::internal_error(format!("read_dir: {e}"), None))?
            .flatten()
        {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(child) = dir_spath.strict_join(name) {
                    entries.push(ListEntryStrict {
                        name: name.to_string(),
                        system_path: format!("{}", child.strictpath_display()),
                        is_dir: child.is_dir(),
                    });
                }
            }
        }
        let result = ListResultStrict {
            system_path: format!("{}", dir_spath.strictpath_display()),
            entries,
        };
        Ok(rmcp::Json(result))
    }
    .boxed()
}

async fn run_virtual(cli: Cli) -> Result<()> {
    let service = VirtualFileService {
        user_project_root: VirtualRoot::try_new_create(&cli.root)?,
    };

    let router = rmcp::handler::server::router::Router::new(service)
        .with_tool(
            tool_virtual_file_read
                .name("file.read")
                .description("Read a UTF-8 file from the project root")
                .parameters::<ReadArgs>(),
        )
        .with_tool(
            tool_virtual_file_write
                .name("file.write")
                .description("Write a UTF-8 file under the project root")
                .parameters::<WriteArgs>(),
        )
        .with_tool(
            tool_virtual_file_list
                .name("file.list")
                .description("List a directory under the project root")
                .parameters::<ReadArgs>(),
        );

    // Serve over stdio
    let running = serve_server(router, (tokio::io::stdin(), tokio::io::stdout())).await?;
    running.waiting().await.ok();
    Ok(())
}

async fn run_strict(cli: Cli) -> Result<()> {
    let service = StrictFileService {
        system_root: PathBoundary::try_new_create(&cli.root)?,
    };

    let router = rmcp::handler::server::router::Router::new(service)
        .with_tool(
            tool_strict_file_read
                .name("file.read")
                .description("Read a UTF-8 file from the system root")
                .parameters::<ReadArgs>(),
        )
        .with_tool(
            tool_strict_file_write
                .name("file.write")
                .description("Write a UTF-8 file under the system root")
                .parameters::<WriteArgs>(),
        )
        .with_tool(
            tool_strict_file_list
                .name("file.list")
                .description("List a directory under the system root")
                .parameters::<ReadArgs>(),
        );

    let running = serve_server(router, (tokio::io::stdin(), tokio::io::stdout())).await?;
    running.waiting().await.ok();
    Ok(())
}
