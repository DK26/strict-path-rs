// Test that README.md examples compile and work correctly

#[test]
fn readme_policy_types_example() -> Result<(), Box<dyn std::error::Error>> {
    use crate::PathBoundary;
    #[cfg(feature = "virtual-path")]
    use crate::VirtualRoot;

    // 1. Define the boundary - paths are contained within ./uploads
    let uploads_boundary: crate::PathBoundary = PathBoundary::try_new_create("./uploads")?;

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
        let tenant_id = "alice";
        let tenant_vroot: crate::VirtualRoot =
            VirtualRoot::try_new_create(format!("./tenant_data/{tenant_id}"))?;
        let tenant_file = tenant_vroot.virtual_join("../../../sensitive")?;
        // Escape attempt is silently clamped - stays within tenant_data
        println!("Virtual path: {}", tenant_file.virtualpath_display()); // Shows: "/sensitive"
        assert_eq!(tenant_file.virtualpath_display().to_string(), "/sensitive");
        // Cleanup (not shown in README)
        let _ = tenant_vroot.remove_dir_all();
    }

    // Cleanup (not shown in README)
    let _ = uploads_boundary.remove_dir_all();
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

    // ? This single line makes it mathematically impossible
    let boundary: crate::StrictPath = StrictPath::with_boundary_create("uploads")?;
    let result = boundary.strict_join(user_input);
    // Returns Err(PathEscapesBoundary) - attack blocked!
    assert!(result.is_err());

    // Cleanup
    boundary.remove_dir_all().ok();
    Ok(())
}

#[test]
fn readme_typical_workflow_strict_links_example() -> Result<(), Box<dyn std::error::Error>> {
    use crate::PathBoundary;

    // 1) Establish boundary
    let boundary: crate::PathBoundary = PathBoundary::try_new_create("./link_demo")?;

    // 2) Validate target path from untrusted input
    let target = boundary.strict_join("data/target.txt")?;
    target.create_parent_dir_all()?;
    target.write(b"hello")?;

    // 3) Create a sibling hard link under the same directory
    target.strict_hard_link("alias.txt")?;

    let alias = boundary.strict_join("data/alias.txt")?;
    assert_eq!(alias.read_to_string()?, "hello");

    // Cleanup (not shown in README)
    let _ = boundary.remove_dir_all();
    Ok(())
}

#[cfg(feature = "virtual-path")]
#[test]
fn readme_typical_workflow_virtual_links_example() -> Result<(), Box<dyn std::error::Error>> {
    use crate::VirtualRoot;

    // 1) Establish virtual root
    let tenant_id = "tenant42";
    let vroot: crate::VirtualRoot =
        VirtualRoot::try_new_create(format!("./vlink_demo/{tenant_id}"))?;

    // 2) Validate target in virtual space (absolute is clamped to root)
    let vtarget = vroot.virtual_join("/data/target.txt")?;
    vtarget.create_parent_dir_all()?;
    vtarget.write(b"hi")?;

    // 3) Create a sibling hard link (virtual semantics)
    vtarget.virtual_hard_link("alias.txt")?;

    let valias = vroot.virtual_join("/data/alias.txt")?;
    assert_eq!(valias.read_to_string()?, "hi");

    // Cleanup (not shown in README)
    let _ = vroot.remove_dir_all();
    Ok(())
}
