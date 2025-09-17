//! Multi-Tenant File Upload API Example
//!
//! This example simulates a secure file upload API for a multi-tenant system.
//! Each tenant has their own designated directory for uploads, and it is critical
//! that one tenant cannot access or overwrite the files of another.
//!
//! This example demonstrates:
//! 1.  Creating a per-tenant path boundary to ensure strict file system isolation.
//! 2.  Handling file uploads securely by validating user-provided filenames.
//! 3.  Safely performing file operations (write, read, delete) within the tenant's PathBoundary.
//! 4.  Showing how traversal attacks are neutralized, preventing cross-tenant access.
//!
//! ## Usage
//!
//! Run the example with: `cargo run --example file_upload_api`

use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use strict_path::{VirtualPath, VirtualRoot};

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
        Self {
            base_path: base_path.to_string(),
            tenant_roots: HashMap::new(),
        }
    }

    /// Retrieves or creates a virtual root for a specific tenant.
    /// This ensures that all operations for a tenant are confined to their directory.
    fn get_or_create_tenant_root(
        &mut self,
        tenant_id: &str,
    ) -> Result<VirtualRoot<()>, strict_path::StrictPathError> {
        if let Some(vr) = self.tenant_roots.get(tenant_id) {
            return Ok(vr.clone());
        }

        let tenant_dir = Path::new(&self.base_path).join(tenant_id);
        // Create virtual root (creates directory if needed via try_new_create on inner PathBoundary)
        let vroot = VirtualRoot::<()>::try_new_create(tenant_dir)?;
        self.tenant_roots
            .insert(tenant_id.to_string(), vroot.clone());
        let root_display = vroot.as_unvirtual().strictpath_display();
        println!("Created vroot for tenant '{tenant_id}' at: {root_display}");
        Ok(vroot)
    }

    /// Upload to a VirtualPath for the tenant (encodes guarantees in the signature).
    fn upload_file_vpath(
        &self,
        tenant_id: &str,
        vp: &VirtualPath<()>,
        content: &[u8],
    ) -> Result<()> {
        let vdisp = vp.virtualpath_display();
        println!("Tenant '{tenant_id}' uploading to: {vdisp}");
        vp.create_parent_dir_all()?;
        vp.write(content)?;
        let bytes = content.len();
        let sdisp = vp.as_unvirtual().strictpath_display();
        println!("Successfully wrote {bytes} bytes to System path: {sdisp}");
        Ok(())
    }

    /// Read from a VirtualPath for the tenant.
    fn read_file_vpath(&self, tenant_id: &str, vp: &VirtualPath<()>) -> Result<Vec<u8>> {
        let vdisp = vp.virtualpath_display();
        println!("Tenant '{tenant_id}' reading from: {vdisp}");
        Ok(vp.read()?)
    }

    /// Delete a file at a VirtualPath for the tenant.
    fn delete_file_vpath(&self, tenant_id: &str, vp: &VirtualPath<()>) -> Result<()> {
        let vdisp = vp.virtualpath_display();
        println!("Tenant '{tenant_id}' deleting: {vdisp}");
        vp.remove_file()?;
        Ok(())
    }
}

fn main() -> Result<()> {
    // Initialize the storage system.
    let mut storage = TenantStorage::new(UPLOAD_BASE_DIR);

    println!("\n--- Scenario 1: Tenant 'acme' uploads a valid file ---");
    if let Ok(vroot) = storage.get_or_create_tenant_root("acme") {
        let dest = vroot.virtual_join("invoice.pdf")?;
        if let Err(e) = storage.upload_file_vpath("acme", &dest, b"PDF content for acme") {
            eprintln!("Upload failed: {e}");
        }
    } else {
        eprintln!("Upload failed: could not create path boundary for tenant 'acme'");
    }

    println!("\n--- Scenario 2: Tenant 'globex' uploads a valid file ---");
    if let Ok(vroot) = storage.get_or_create_tenant_root("globex") {
        let dest = vroot.virtual_join("report.docx")?;
        if let Err(e) = storage.upload_file_vpath("globex", &dest, b"DOCX content for globex") {
            eprintln!("Upload failed: {e}");
        }
    } else {
        eprintln!("Upload failed: could not create path boundary for tenant 'globex'");
    }

    println!(
        "\n--- Scenario 3: Tenant 'acme' tries to access 'globex' data with a traversal attack ---"
    );
    // This malicious path will be clamped inside the 'acme' path boundary.
    // Instead of reaching `multi_tenant_uploads/globex/report.docx`,
    // it will resolve to `multi_tenant_uploads/acme/globex/report.docx`.
    let malicious_path = "../globex/report.docx";
    if let Ok(vroot) = storage.get_or_create_tenant_root("acme") {
        let safe = vroot.virtual_join(malicious_path)?; // clamped inside 'acme'
        let _ = storage.read_file_vpath("acme", &safe);
        let vdisp = safe.virtualpath_display();
        println!("Read attempted at clamped path: {vdisp}");
    }

    println!("\n--- Scenario 4: Tenant 'acme' tries to write into 'globex' directory ---");
    // This will also be clamped. The file will be written inside acme's directory.
    if let Ok(vroot) = storage.get_or_create_tenant_root("acme") {
        let safe = vroot.virtual_join("../globex/new_file.txt")?; // clamped inside 'acme'
        storage
            .upload_file_vpath("acme", &safe, b"Trying to break out")
            .ok();
        let vdisp = safe.virtualpath_display();
        println!("Attack neutralized: File created at '{vdisp}'");
    }

    println!("\n--- Scenario 5: Tenant 'globex' deletes their own file securely ---");
    if let Ok(vroot) = storage.get_or_create_tenant_root("globex") {
        let path = vroot.virtual_join("report.docx")?;
        if let Err(e) = storage.delete_file_vpath("globex", &path) {
            eprintln!("Delete failed: {e}");
        } else {
            let vdisp = path.virtualpath_display();
            println!("Successfully deleted '{vdisp}'");
        }
    }

    // Clean up the created directory
    fs::remove_dir_all(UPLOAD_BASE_DIR).ok();
    println!("\nCleaned up base directory.");
    Ok(())
}
