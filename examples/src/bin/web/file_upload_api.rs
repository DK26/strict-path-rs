//! Multi-Tenant File Upload API Example
//!
//! This example simulates a secure file upload API for a multi-tenant system.
//! Each tenant has their own designated directory for uploads, and it is critical
//! that one tenant cannot access or overwrite the files of another.
//!
//! This example demonstrates:
//! 1.  Creating a per-tenant "jail" to ensure strict file system isolation.
//! 2.  Handling file uploads securely by validating user-provided filenames.
//! 3.  Safely performing file operations (write, read, delete) within the tenant's jail.
//! 4.  Showing how traversal attacks are neutralized, preventing cross-tenant access.
//!
//! ## Usage
//!
//! Run the example with: `cargo run --example file_upload_api`

use anyhow::Result;
use jailed_path::Jail;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const UPLOAD_BASE_DIR: &str = "multi_tenant_uploads";

/// Represents our multi-tenant file storage system.
struct TenantStorage {
    base_path: String,
    tenant_jails: HashMap<String, Jail<()>>,
}

impl TenantStorage {
    /// Initializes the storage system.
    fn new(base_path: &str) -> Self {
        // Create the base directory for all uploads.
        fs::create_dir_all(base_path).expect("Failed to create base upload directory");
        println!("Initialized storage base at: {base_path}");
        Self {
            base_path: base_path.to_string(),
            tenant_jails: HashMap::new(),
        }
    }

    /// Retrieves or creates a jail for a specific tenant.
    /// This ensures that all operations for a tenant are confined to their directory.
    fn get_or_create_tenant_jail(
        &mut self,
        tenant_id: &str,
    ) -> Result<Jail<()>, jailed_path::JailedPathError> {
        if let Some(jail) = self.tenant_jails.get(tenant_id) {
            return Ok(jail.clone());
        }

        let tenant_dir = Path::new(&self.base_path).join(tenant_id);
        // Use `try_new_create` to create the directory if it doesn't exist.
        let jail = Jail::<()>::try_new_create(tenant_dir)?;
        self.tenant_jails
            .insert(tenant_id.to_string(), jail.clone());
        println!(
            "Created jail for tenant '{}' at: {}",
            tenant_id,
            jail.path().display()
        );
        Ok(jail)
    }

    /// Simulates a file upload.
    fn upload_file(&mut self, tenant_id: &str, filename: &str, content: &[u8]) -> Result<()> {
        let jail = self.get_or_create_tenant_jail(tenant_id)?;
        // Safely resolve the user-provided filename within the tenant's jail.
        let safe_path = jail.try_path(filename)?;
        println!("Tenant '{tenant_id}' uploading to virtual path: {safe_path}");
        safe_path.write_bytes(content)?;
        println!(
            "Successfully wrote {} bytes to real path: {}",
            content.len(),
            safe_path.realpath_to_string()
        );
        Ok(())
    }

    /// Reads a file for a tenant.
    fn read_file(&mut self, tenant_id: &str, filename: &str) -> Result<Vec<u8>> {
        let jail = match self.get_or_create_tenant_jail(tenant_id) {
            Ok(j) => j,
            Err(_) => return Ok(Vec::new()),
        };
        let safe_path = match jail.try_path(filename) {
            Ok(p) => p,
            Err(_) => return Ok(Vec::new()),
        };
        println!("Tenant '{tenant_id}' reading from virtual path: {safe_path}");
        Ok(safe_path.read_bytes()?)
    }

    /// Deletes a file for a tenant.
    fn delete_file(&mut self, tenant_id: &str, filename: &str) -> Result<()> {
        let jail = match self.get_or_create_tenant_jail(tenant_id) {
            Ok(j) => j,
            Err(_) => return Ok(()),
        };
        let safe_path = match jail.try_path(filename) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        println!("Tenant '{tenant_id}' deleting virtual path: {safe_path}");
        safe_path.remove_file()?;
        Ok(())
    }
}

fn main() -> Result<()> {
    // Initialize the storage system.
    let mut storage = TenantStorage::new(UPLOAD_BASE_DIR);

    println!("\n--- Scenario 1: Tenant 'acme' uploads a valid file ---");
    if let Err(e) = storage.upload_file("acme", "invoice.pdf", b"PDF content for acme") {
        eprintln!("Upload failed: {e}");
    }

    println!("\n--- Scenario 2: Tenant 'globex' uploads a valid file ---");
    if let Err(e) = storage.upload_file("globex", "report.docx", b"DOCX content for globex") {
        eprintln!("Upload failed: {e}");
    }

    println!(
        "\n--- Scenario 3: Tenant 'acme' tries to access 'globex' data with a traversal attack ---"
    );
    // This malicious path will be clamped inside the 'acme' jail.
    // Instead of reaching `multi_tenant_uploads/globex/report.docx`,
    // it will resolve to `multi_tenant_uploads/acme/globex/report.docx`.
    let malicious_path = "../globex/report.docx";
    match storage.read_file("acme", malicious_path) {
        Ok(_) => println!("Read succeeded unexpectedly (but was safely contained)."),
        Err(e) => {
            println!("Read failed as expected: {e}");
        }
    }

    println!("\n--- Scenario 4: Tenant 'acme' tries to write into 'globex' directory ---");
    // This will also be clamped. The file will be written inside acme's directory.
    if let Err(e) = storage.upload_file("acme", "../globex/new_file.txt", b"Trying to break out") {
        eprintln!("Upload failed: {e}");
    } else {
        // Verify that the file was created inside acme's jail, not globex's.
        let expected_path = Path::new(UPLOAD_BASE_DIR)
            .join("acme")
            .join("globex")
            .join("new_file.txt");
        assert!(expected_path.exists());
        println!(
            "Attack neutralized: File created at '{}' instead of in globex's directory.",
            expected_path.display()
        );
    }

    println!("\n--- Scenario 5: Tenant 'globex' deletes their own file securely ---");
    if let Err(e) = storage.delete_file("globex", "report.docx") {
        eprintln!("Delete failed: {e}");
    } else {
        let expected_path = Path::new(UPLOAD_BASE_DIR)
            .join("globex")
            .join("report.docx");
        assert!(!expected_path.exists());
        println!("Successfully deleted '{}'", expected_path.display());
    }

    // Clean up the created directory
    fs::remove_dir_all(UPLOAD_BASE_DIR).ok();
    println!("\nCleaned up base directory.");
    Ok(())
}
