//! Tenant/User VirtualRoot demo
//!
//! This demo shows how to use VirtualRoot correctly: a stable service root,
//! a per-tenant directory, then a per-user directory inside each tenant.
//! All user-visible operations run through VirtualPath; any interop uses
//! interop_path() on a derived StrictPath only when unavoidable.
//!
//! Try:
//!   cargo run -p strict-path-demos --bin tenant_user_virtual_root -- --root ./demo_data/tenants --tenant acme --user bob

use anyhow::{Context, Result};
use clap::Parser;
use strict_path::{PathBoundary, VirtualPath, VirtualRoot};

#[derive(Parser, Debug)]
struct Cli {
    /// Service base directory where all tenants live
    #[arg(long, default_value = "./demo_data/tenants")]
    root: String,
    /// Tenant identifier (validated segment)
    #[arg(long)]
    tenant: String,
    /// User identifier (validated segment)
    #[arg(long)]
    user: String,
}

#[derive(Clone, Copy)]
struct ServiceRoot;
#[derive(Clone, Copy)]
struct TenantRoot;
#[derive(Clone, Copy)]
struct UserSpace;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 1) Stable policy root: PathBoundary<ServiceRoot>
    let service_root: PathBoundary<ServiceRoot> =
        PathBoundary::try_new_create(&cli.root).context("init service root")?;

    // 2) Validate tenant and user segments, derive per-tenant boundary
    validate_segment(&cli.tenant)?;
    let tenant_dir = service_root
        .strict_join(&cli.tenant)
        .context("tenant join")?;
    let tenant_boundary: PathBoundary<TenantRoot> = tenant_dir
        .try_into_boundary_create()
        .context("tenant boundary")?
        .change_marker::<TenantRoot>();

    // 3) Derive per-user boundary inside tenant and virtualize to get a VirtualRoot<UserSpace>
    validate_segment(&cli.user)?;
    let user_dir = tenant_boundary
        .strict_join(&cli.user)
        .context("user join")?;
    let user_boundary = user_dir
        .try_into_boundary_create()
        .context("user boundary")?
        .change_marker::<UserSpace>();
    let user_vroot: VirtualRoot<UserSpace> = user_boundary.clone().virtualize();

    // All user-visible work happens via VirtualPath off user_vroot
    let note: VirtualPath<UserSpace> = user_vroot
        .virtual_join("docs/welcome.txt")
        .context("virtual join")?;
    note.create_parent_dir_all().context("mkdir -p docs")?;
    note.write("Welcome to your workspace!\n")
        .context("write note")?;

    let body = note.read_to_string().context("read note")?;
    println!(
        "tenant={tenant}, user={user}, vpath={}, bytes={}",
        tenant = cli.tenant,
        user = cli.user,
        vpath = note.virtualpath_display(),
        bytes = body.len(),
    );

    // List user's docs directory as VirtualPaths and print
    let docs = user_vroot.virtual_join("docs").context("join docs")?;
    if docs.exists() {
        let mut entries = Vec::new();
        for entry in docs.read_dir().context("read_dir docs")? {
            if let Ok(dirent) = entry {
                if let Some(name) = dirent.file_name().to_str() {
                    if let Ok(child) = docs.virtual_join(name) {
                        entries.push(child);
                    }
                }
            }
        }
        entries.sort_by_key(|p| p.virtualpath_display().to_string());
        println!("docs:");
        for e in entries {
            println!("  {}", e.virtualpath_display());
        }
    }

    Ok(())
}

fn validate_segment(seg: &str) -> Result<()> {
    if seg.is_empty() || seg.contains(['/', '\\']) || seg.contains("..") {
        anyhow::bail!("invalid segment: {seg}");
    }
    Ok(())
}
