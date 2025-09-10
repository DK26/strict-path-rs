// Secure Migrations Runner
//
// Demonstrates running filesystem-based migrations with strict jails:
// - MigrationsDir: location of migration scripts
// - BackupDir: destination for pre-migration backups
//
// All functions that touch the filesystem accept typed paths (`&JailedPath<_>`),
// so the compiler enforces the correct jail is used at each step.

use anyhow::Result;
use jailed_path::{Jail, JailedPath};
use std::fs;

#[derive(Clone)]
struct MigrationsDir;

#[derive(Clone)]
struct BackupDir;

fn main() -> Result<()> {
    // Setup example structure
    fs::create_dir_all("example_db/migrations")?;
    fs::create_dir_all("example_db/backups")?;
    fs::write("example_db/migrations/001_init.sql", "-- init\nCREATE TABLE t(x INT);")?;
    fs::write(
        "example_db/migrations/002_add_col.sql",
        "-- add col\nALTER TABLE t ADD COLUMN y INT;",
    )?;

    // Create jails
    let mig = Jail::<MigrationsDir>::try_new("example_db/migrations")?;
    let bak = Jail::<BackupDir>::try_new("example_db/backups")?;

    // Plan: backup then apply each migration script
    let plan = vec!["001_init.sql", "002_add_col.sql"]; // usually discovered via directory listing

    // Backup
    let backup_name = format!("backup_{}.sql", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let backup_path = bak.jailed_join(backup_name)?;
    create_backup(&backup_path)?;

    // Apply migrations
    for script in plan {
        let script_path = mig.jailed_join(script)?;
        apply_migration(&script_path)?;
    }

    println!("✅ Migrations complete. Backups at: {}", bak.jailedpath_display());

    // Cleanup demo dirs (in real life, keep them)
    fs::remove_dir_all("example_db").ok();
    Ok(())
}

// Signatures encode guarantees: only operates on the backups jail
fn create_backup(target: &JailedPath<BackupDir>) -> Result<()> {
    target.create_parent_dir_all()?;
    target.write_string("-- simulated backup\n-- (write real dump here)")?;
    Ok(())
}

// Signatures encode guarantees: only operates on the migrations jail
fn apply_migration(script: &JailedPath<MigrationsDir>) -> Result<()> {
    let sql = script.read_to_string()?;
    // Simulate applying SQL to a database
    let file = script.jailedpath_to_string_lossy();
    let bytes = sql.len();
    println!("▶ Applying {file} ({bytes} bytes)");
    Ok(())
}



