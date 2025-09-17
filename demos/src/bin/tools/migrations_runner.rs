// Secure Migrations Runner
//
// Demonstrates running filesystem-based migrations with strict jails:
// - MigrationsDir: location of migration scripts
// - BackupDir: destination for pre-migration backups
//
// All functions that touch the filesystem accept typed paths (`&StrictPath<_>`),
// so the compiler enforces the correct path boundary is used at each step.

use anyhow::Result;
use std::fs;
use strict_path::{PathBoundary, StrictPath};

#[derive(Clone)]
struct MigrationsDir;

#[derive(Clone)]
struct BackupDir;

fn main() -> Result<()> {
    // Setup example structure
    fs::create_dir_all("example_db/migrations")?;
    fs::create_dir_all("example_db/backups")?;
    fs::write(
        "example_db/migrations/001_init.sql",
        "-- init\nCREATE TABLE t(x INT);",
    )?;
    fs::write(
        "example_db/migrations/002_add_col.sql",
        "-- add col\nALTER TABLE t ADD COLUMN y INT;",
    )?;

    // Create jails
    let mig = PathBoundary::<MigrationsDir>::try_new("example_db/migrations")?;
    let bak = PathBoundary::<BackupDir>::try_new("example_db/backups")?;

    // Plan: backup then apply each migration script
    let plan = vec!["001_init.sql", "002_add_col.sql"]; // usually discovered via directory listing

    // Backup
    let backup_name = format!("backup_{}.sql", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let backup_path = bak.strict_join(backup_name)?;
    create_backup(&backup_path)?;

    // Apply migrations
    for script in plan {
        let script_path = mig.strict_join(script)?;
        apply_migration(&script_path)?;
    }

    println!(
        "✅ Migrations complete. Backups at: {}",
        bak.strictpath_display()
    );

    // Cleanup demo dirs (in real life, keep them)
    fs::remove_dir_all("example_db").ok();
    Ok(())
}

// Signatures encode guarantees: only operates on the backups PathBoundary
fn create_backup(target: &StrictPath<BackupDir>) -> Result<()> {
    target.create_parent_dir_all()?;
    target.write("-- simulated backup\n-- (write real dump here)")?;
    Ok(())
}

// Signatures encode guarantees: only operates on the migrations PathBoundary
fn apply_migration(script: &StrictPath<MigrationsDir>) -> Result<()> {
    let sql = script.read_to_string()?;
    // Simulate applying SQL to a database
    let file = script.strictpath_display();
    let bytes = sql.len();
    println!("▶ Applying {file} ({bytes} bytes)");
    Ok(())
}
