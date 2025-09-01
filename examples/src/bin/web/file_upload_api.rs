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
use jailed_path::{VirtualPath, VirtualRoot};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const UPLOAD_BASE_DIR: &str = "multi_tenant_uploads";

/// Represents our multi-tenant file storage system.
struct TenantStorage {
    base_path: String,
    tenant_roots: HashMap<String, VirtualRoot<()>>,
}

impl TenantStorage {
    /// Initializes the storage system.
    fn new(base_path: &str) -> Self {
        // Create the base directory for all uploads.
        fs::create_dir_all(base_path).expect("Failed to create base upload directory");
        println!("Initialized storage base at: {base_path}");
        Self { base_path: base_path.to_string(), tenant_roots: HashMap::new() }
    }

    /// Retrieves or creates a virtual root for a specific tenant.
    /// This ensures that all operations for a tenant are confined to their directory.
    fn get_or_create_tenant_root(
        &mut self,
        tenant_id: &str,
    ) -> Result<VirtualRoot<()>, jailed_path::JailedPathError> {
        if let Some(vr) = self.tenant_roots.get(tenant_id) {
            return Ok(vr.clone());
        }

        let tenant_dir = Path::new(&self.base_path).join(tenant_id);
        // Create virtual root (creates directory if needed via try_new_create on inner jail)
        let vroot = VirtualRoot::<()>::try_new_create(tenant_dir)?;
        self.tenant_roots.insert(tenant_id.to_string(), vroot.clone());
        println!(
            "Created vroot for tenant '{}' at: {}",
            tenant_id,
            vroot.path().display()
        );
        Ok(vroot)
    }

    /// Upload to a VirtualPath for the tenant (encodes guarantees in the signature).
    fn upload_file_vpath(&self, tenant_id: &str, vp: &VirtualPath<()>, content: &[u8]) -> Result<()> {
        println!("Tenant '{tenant_id}' uploading to: {vp}");
        vp.create_parent_dir_all()?;
        vp.write_bytes(content)?;
        println!(
            "Successfully wrote {} bytes to System path: {}",
            content.len(),
            vp.systempath_to_string_lossy()
        );
        Ok(())
    }

    /// Read from a VirtualPath for the tenant.
    fn read_file_vpath(&self, tenant_id: &str, vp: &VirtualPath<()>) -> Result<Vec<u8>> {
        println!("Tenant '{tenant_id}' reading from: {vp}");
        Ok(vp.read_bytes()?)
    }

    /// Delete a file at a VirtualPath for the tenant.
    fn delete_file_vpath(&self, tenant_id: &str, vp: &VirtualPath<()>) -> Result<()> {
        println!("Tenant '{tenant_id}' deleting: {vp}");
        vp.remove_file()?;
        Ok(())
    }
}

fn main() -> Result<()> {
    // Initialize the storage system.
    let mut storage = TenantStorage::new(UPLOAD_BASE_DIR);

    println!("\n--- Scenario 1: Tenant 'acme' uploads a valid file ---");
    if let Ok(vroot) = storage.get_or_create_tenant_root("acme") {
        let dest = vroot.virtualpath_join("invoice.pdf")?;
        if let Err(e) = storage.upload_file_vpath("acme", &dest, b"PDF content for acme") {
            eprintln!("Upload failed: {e}");
        }
    } else {
        eprintln!("Upload failed: could not create jail for tenant 'acme'");
    }

    println!("\n--- Scenario 2: Tenant 'globex' uploads a valid file ---");
    if let Ok(vroot) = storage.get_or_create_tenant_root("globex") {
        let dest = vroot.virtualpath_join("report.docx")?;
        if let Err(e) = storage.upload_file_vpath("globex", &dest, b"DOCX content for globex") {
            eprintln!("Upload failed: {e}");
        }
    } else {
        eprintln!("Upload failed: could not create jail for tenant 'globex'");
    }

    println!(
        "\n--- Scenario 3: Tenant 'acme' tries to access 'globex' data with a traversal attack ---"
    );
    // This malicious path will be clamped inside the 'acme' jail.
    // Instead of reaching `multi_tenant_uploads/globex/report.docx`,
    // it will resolve to `multi_tenant_uploads/acme/globex/report.docx`.
    let malicious_path = "../globex/report.docx";
    if let Ok(vroot) = storage.get_or_create_tenant_root("acme") {
        let safe = vroot.virtualpath_join(malicious_path)?; // clamped inside 'acme'
        let _ = storage.read_file_vpath("acme", &safe);
        println!("Read attempted at clamped path: {safe}");
    }

    println!("\n--- Scenario 4: Tenant 'acme' tries to write into 'globex' directory ---");
    // This will also be clamped. The file will be written inside acme's directory.
    if let Ok(vroot) = storage.get_or_create_tenant_root("acme") {
        let safe = vroot.virtualpath_join("../globex/new_file.txt")?; // clamped inside 'acme'
        storage
            .upload_file_vpath("acme", &safe, b"Trying to break out")
            .ok();
        println!("Attack neutralized: File created at '{safe}'");
    }

    println!("\n--- Scenario 5: Tenant 'globex' deletes their own file securely ---");
    if let Ok(vroot) = storage.get_or_create_tenant_root("globex") {
        let path = vroot.virtualpath_join("report.docx")?;
        if let Err(e) = storage.delete_file_vpath("globex", &path) {
            eprintln!("Delete failed: {e}");
        } else {
            println!("Successfully deleted '{path}'");
        }
    }

    // Clean up the created directory
    fs::remove_dir_all(UPLOAD_BASE_DIR).ok();
    println!("\nCleaned up base directory.");
    Ok(())
}



