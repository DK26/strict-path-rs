use crate::PathBoundary;
use std::fs;
use std::io::{Read, Write};

#[test]
fn test_virtual_path_join_and_parent() {
    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let jailed = temp_dir.strict_join("foo/bar.txt").unwrap();
    let virtual_path = jailed.virtualize();

    // join (inside PathBoundary)
    let joined = virtual_path.virtual_join("baz.txt").unwrap();
    assert_eq!(
        format!("{}", joined.virtualpath_display()),
        "/foo/bar.txt/baz.txt"
    );

    // join (outside PathBoundary, expect clamping)
    let outside = virtual_path.virtual_join("../../../../etc/passwd").unwrap();
    assert_eq!(format!("{}", outside.virtualpath_display()), "/etc/passwd");

    // parent (inside PathBoundary)
    let parent = virtual_path.virtualpath_parent().unwrap();
    assert!(parent.is_some());
    let actual_parent = parent.unwrap();
    assert_eq!(format!("{}", actual_parent.virtualpath_display()), "/foo");

    // parent (at PathBoundary root)
    let root_virtual: crate::path::virtual_path::VirtualPath<()> =
        crate::path::virtual_path::VirtualPath::with_root(temp_dir.as_ref()).unwrap();
    let parent_none = root_virtual.virtualpath_parent().unwrap();
    assert!(parent_none.is_none());
}

#[test]
fn test_virtual_path_pathbuf_methods() {
    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let restricted = temp_dir.strict_join("foo/bar.txt").unwrap();
    let virtual_path = restricted.virtualize();

    // with_file_name (inside PathBoundary)
    let with_name = virtual_path
        .virtualpath_with_file_name("newname.txt")
        .unwrap();
    assert_eq!(
        format!("{}", with_name.virtualpath_display()),
        "/foo/newname.txt"
    );

    // with_file_name (potential escape attempt)
    let root_virtual: crate::path::virtual_path::VirtualPath<()> =
        crate::path::virtual_path::VirtualPath::with_root(temp_dir.as_ref()).unwrap();
    let escape_attempt = root_virtual
        .virtualpath_with_file_name("../../etc/passwd")
        .unwrap();
    assert_eq!(
        format!("{}", escape_attempt.virtualpath_display()),
        "/etc/passwd"
    );

    // with_extension (inside PathBoundary)
    let with_ext = virtual_path.virtualpath_with_extension("log").unwrap();
    assert_eq!(
        format!("{}", with_ext.virtualpath_display()),
        "/foo/bar.log"
    );

    // unvirtual -> strict -> System path suffix
    let strict_again = virtual_path.unvirtual();
    let inner = strict_again.unstrict();
    let expected_path = temp_dir.path().join("foo/bar.txt");
    assert_eq!(inner.to_string_lossy(), expected_path.to_string_lossy());
}

#[test]
fn test_strict_path_create_file() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let strict = boundary.strict_join("logs/output.txt").unwrap();
    strict.create_parent_dir_all().unwrap();

    let mut file = strict.create_file().unwrap();
    file.write_all(b"hello strict").unwrap();
    drop(file);

    let mut file = strict.open_file().unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content, "hello strict");
}

#[test]
fn test_virtual_path_create_file() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let strict = boundary.strict_join("reports/summary.txt").unwrap();
    strict.create_parent_dir_all().unwrap();
    let virtual_path = strict.clone().virtualize();

    let mut file = virtual_path.create_file().unwrap();
    file.write_all(b"virtual summary").unwrap();
    drop(file);

    let mut file = virtual_path.open_file().unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    assert_eq!(content, "virtual summary");
}

#[test]
#[cfg(unix)] // Symlinks work reliably on Unix systems
fn test_virtual_path_symlink_edge_cases() {
    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // Create directory structure with symlinks
    let docs_dir = temp.path().join("docs");
    let shared_dir = temp.path().join("shared");
    let outside_target = temp.path().join("target.txt");

    fs::create_dir_all(&docs_dir).unwrap();
    fs::create_dir_all(&shared_dir).unwrap();
    fs::write(&outside_target, "target content").unwrap();

    // Create a legitimate symlink inside PathBoundary pointing to another location inside PathBoundary
    let link_path = shared_dir.join("link_to_target");
    std::os::unix::fs::symlink(&outside_target, &link_path).unwrap();

    // Create VirtualPath starting from docs
    let start_path = temp_dir.strict_join("docs/start.txt").unwrap();
    let virtual_start = start_path.virtualize();

    // Test Case 1: Legitimate symlink traversal that stays within PathBoundary
    // Virtual layer is lexical: display shows the link component, not the resolved target
    let legitimate_link = virtual_start
        .virtual_join("../shared/link_to_target")
        .unwrap();
    let sys_path = legitimate_link.clone().unvirtual();
    eprintln!(
        "legitimate_link display = {} (sys = {:?})",
        legitimate_link.virtualpath_display(),
        sys_path.interop_path()
    );
    assert_eq!(
        format!("{}", legitimate_link.virtualpath_display()),
        "/docs/shared/link_to_target"
    );

    // Test Case 2: Path traversal through symlink that would escape, but gets clamped
    // /docs/start.txt + ../shared/link_to_target/../../../../etc/passwd
    // Virtual layer clamps first to the virtual root
    let traversal_through_link = virtual_start
        .virtual_join("../shared/link_to_target/../../../../etc/passwd")
        .unwrap();
    // This should be clamped to /etc/passwd in virtual space, then point to restriction_boundary/etc/passwd in system space
    assert_eq!(
        format!("{}", traversal_through_link.virtualpath_display()),
        "/etc/passwd"
    );

    // Test Case 3: Verify symlink outside the path restriction remains lexical in virtual space
    // Create a symlink that points outside the path restriction
    let outside_dir = temp.path().parent().unwrap().join("outside");
    let malicious_file = outside_dir.join("sensitive.txt");
    fs::create_dir_all(&outside_dir).unwrap();
    fs::write(&malicious_file, "sensitive data").unwrap();

    let malicious_link = shared_dir.join("bad_link");
    std::os::unix::fs::symlink(&malicious_file, &malicious_link).unwrap();

    // Try to access through virtual path - should be clamped and contained
    let safe_access = virtual_start.virtual_join("../shared/bad_link").unwrap();
    // Virtual display remains the link name; boundary checking protects system paths
    assert!(safe_access
        .virtualpath_display()
        .to_string()
        .contains("bad_link"));

    // Test Case 4: Complex traversal with multiple .. that should be clamped
    let complex_traversal = virtual_start
        .virtual_join("../../../../../../../shared/link_to_target")
        .unwrap();
    // Virtual layer clamps; the display should show the clamped path within virtual space
    // With symlink clamping (0.4.0), the symlink target gets clamped to virtual root
    let complex_disp = format!("{}", complex_traversal.virtualpath_display());
    assert!(
        complex_disp == "/shared/link_to_target"
            || complex_disp == "/target.txt"
            || complex_disp.contains("/target.txt"), // macOS may show full clamped path
        "unexpected complex traversal display: {complex_disp}"
    );
}

#[test]
#[cfg(windows)]
fn test_virtual_path_windows_symlink_edge_cases() {
    let temp = tempfile::tempdir().unwrap();
    let temp_dir: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    // Create directory structure
    let docs_dir = temp.path().join("docs");
    let shared_dir = temp.path().join("shared");
    let target_file = temp.path().join("target.txt");

    fs::create_dir_all(&docs_dir).unwrap();
    fs::create_dir_all(&shared_dir).unwrap();
    fs::write(&target_file, "target content").unwrap();

    // Create VirtualPath starting from docs
    let start_path = temp_dir.strict_join("docs/start.txt").unwrap();
    let virtual_start = start_path.virtualize();

    // Test Case 1: Path traversal that should be clamped
    let traversal = virtual_start
        .virtual_join("../../../../etc/passwd")
        .unwrap();
    assert_eq!(
        format!("{}", traversal.virtualpath_display()),
        "/etc/passwd"
    );

    // Test Case 2: Complex traversal with Windows paths
    let windows_traversal = virtual_start
        .virtual_join("..\\..\\..\\..\\Windows\\System32\\config\\SAM")
        .unwrap();
    // Should be clamped to virtual root area
    assert_eq!(
        format!("{}", windows_traversal.virtualpath_display()),
        "/Windows/System32/config/SAM"
    );

    // Test Case 3: UNC path handling in virtual space
    let unc_like = virtual_start
        .virtual_join("../../../shared/target.txt")
        .unwrap();
    assert_eq!(
        format!("{}", unc_like.virtualpath_display()),
        "/shared/target.txt"
    );
}
