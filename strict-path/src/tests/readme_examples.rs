// Test that README.md examples compile and work correctly

#[test]
fn readme_policy_types_example() -> Result<(), Box<dyn std::error::Error>> {
    use crate::PathBoundary;
    #[cfg(feature = "virtual-path")]
    use crate::VirtualRoot;

    // Use temp dir for test isolation (README shows relative paths for clarity)
    #[cfg(feature = "tempfile")]
    let uploads_dir = tempfile::TempDir::new()?;
    #[cfg(not(feature = "tempfile"))]
    let uploads_dir = {
        let path = std::path::PathBuf::from("./test_uploads_readme");
        std::fs::create_dir_all(&path)?;
        path
    };

    // 1. Define the boundary - paths are contained within ./uploads
    let uploads_boundary: crate::PathBoundary = PathBoundary::try_new(
        #[cfg(feature = "tempfile")]
        &uploads_dir,
        #[cfg(not(feature = "tempfile"))]
        &uploads_dir,
    )?;

    // 2. Validate untrusted user input against the boundary
    let user_file = uploads_boundary.strict_join("documents/report.pdf")?;

    // 3. Safe I/O operations - guaranteed within boundary
    user_file.create_parent_dir_all()?;
    user_file.write(b"file contents")?;
    let contents = user_file.read_to_string()?;
    assert_eq!(contents, "file contents");

    // 4. Escape attempts are detected and rejected
    match uploads_boundary.strict_join("../../etc/passwd") {
        Ok(_) => panic!("Escapes should be caught!"),
        Err(e) => println!("Attack blocked: {e}"), // PathEscapesBoundary error
    }

    // Virtual filesystem for multi-tenant isolation (requires "virtual-path" feature)
    #[cfg(feature = "virtual-path")]
    {
        #[cfg(feature = "tempfile")]
        let tenant_dir = tempfile::TempDir::new()?;
        #[cfg(not(feature = "tempfile"))]
        let tenant_dir = {
            let path = std::path::PathBuf::from("./test_tenant_readme");
            std::fs::create_dir_all(&path)?;
            path
        };

        let tenant_vroot: crate::VirtualRoot = VirtualRoot::try_new(
            #[cfg(feature = "tempfile")]
            &tenant_dir,
            #[cfg(not(feature = "tempfile"))]
            &tenant_dir,
        )?;
        let tenant_file = tenant_vroot.virtual_join("../../../sensitive")?;
        // Escape attempt is silently clamped - stays within tenant_data
        println!("Virtual path: {}", tenant_file.virtualpath_display()); // Shows: "/sensitive"
        assert_eq!(tenant_file.virtualpath_display().to_string(), "/sensitive");

        // Cleanup (TempDir auto-cleans, manual cleanup for fallback)
        #[cfg(not(feature = "tempfile"))]
        std::fs::remove_dir_all(tenant_dir).ok();
    }

    // Cleanup (TempDir auto-cleans, manual cleanup for fallback)
    #[cfg(not(feature = "tempfile"))]
    std::fs::remove_dir_all(uploads_dir).ok();
    Ok(())
}

#[test]
fn readme_one_liner_sugar_example() -> Result<(), Box<dyn std::error::Error>> {
    use crate::StrictPath;
    #[cfg(feature = "virtual-path")]
    use crate::VirtualPath;

    // Concise form - boundary created inline
    let config_file: crate::StrictPath =
        StrictPath::with_boundary_create("./config")?.strict_join("app.toml")?;
    config_file.write(b"settings")?;

    #[cfg(feature = "virtual-path")]
    {
        let asset: crate::VirtualPath =
            VirtualPath::with_root_create("./public")?.virtual_join("images/logo.png")?;
        asset.create_parent_dir_all()?;
        asset.write(b"logo data")?;

        // Cleanup
        let root: crate::VirtualPath = VirtualPath::with_root("./public")?;
        root.remove_dir_all().ok();
    }

    // Cleanup
    let root: crate::StrictPath = StrictPath::with_boundary("./config")?;
    root.remove_dir_all().ok();
    Ok(())
}

#[test]
fn readme_disaster_prevention_example() -> Result<(), Box<dyn std::error::Error>> {
    use crate::StrictPath;

    let user_input = "../../../etc/passwd";

    // ❌ This single line can destroy your server
    // std::fs::write(user_input, data)?;

    // ✅ This single line makes it mathematically impossible
    let boundary: crate::StrictPath = StrictPath::with_boundary_create("uploads")?;
    let result = boundary.strict_join(user_input);
    // Returns Err(PathEscapesBoundary) - attack blocked!
    assert!(result.is_err());

    // Cleanup
    boundary.remove_dir_all().ok();
    Ok(())
}
