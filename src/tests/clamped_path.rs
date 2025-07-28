use crate::clamped_path::ClampedPath;
use std::path::Path;

#[test]
fn test_clamped_path_type_safety() {
    // Test that ClampedPath can be created from user input and clamps traversal
    let clamped = ClampedPath::new("../../../etc/passwd");
    assert_eq!(clamped.as_path(), Path::new("etc/passwd"));
}

#[test]
fn test_clamped_path_additional_crossplatform_cases() {
    use std::path::Path;
    // Only traversal
    let clamped = ClampedPath::new("..");
    assert_eq!(clamped.as_path(), Path::new(""));
    let clamped = ClampedPath::new("../..");
    assert_eq!(clamped.as_path(), Path::new(""));
    // Root only
    let clamped = ClampedPath::new("/");
    assert_eq!(clamped.as_path(), Path::new(""));
    // Mixed separators (should normalize)
    let clamped = ClampedPath::new("a/b/../c.txt");
    assert_eq!(clamped.as_path(), Path::new("a/c.txt"));
    let clamped = ClampedPath::new("a\\b/../c.txt");
    #[cfg(windows)]
    assert_eq!(clamped.as_path(), Path::new("a/c.txt"));
    #[cfg(not(windows))]
    assert_eq!(clamped.as_path(), Path::new("c.txt"));
    // Redundant current dir
    let clamped = ClampedPath::new("././foo.txt");
    assert_eq!(clamped.as_path(), Path::new("foo.txt"));
    // UNC path (Windows only)
    #[cfg(windows)]
    {
        let clamped = ClampedPath::new("\\\\server\\share\\folder\\..\\file.txt");
        assert_eq!(clamped.as_path(), Path::new("file.txt"));
    }
    // Path with only dots
    let clamped = ClampedPath::new(".../foo.txt");
    assert_eq!(clamped.as_path(), Path::new(".../foo.txt"));
    // Path with trailing separator
    let clamped = ClampedPath::new("foo/bar/");
    assert_eq!(clamped.as_path(), Path::new("foo/bar"));
}

#[test]
fn test_clamped_path_handles_virtual_root() {
    // Test absolute path handling
    let clamped1 = ClampedPath::new("/user/file.txt");
    let clamped2 = ClampedPath::new("user/file.txt");
    assert_eq!(clamped1.as_path(), clamped2.as_path());
    assert_eq!(clamped1.as_path(), Path::new("user/file.txt"));
}

#[test]
fn test_clamped_path_edge_cases() {
    // Edge: empty path
    let clamped = ClampedPath::new("");
    assert_eq!(clamped.as_path(), Path::new(""));
    // Edge: current dir
    let clamped = ClampedPath::new(".");
    assert_eq!(clamped.as_path(), Path::new(""));
    // Edge: excessive traversal
    let clamped = ClampedPath::new("../../../../foo.txt");
    assert_eq!(clamped.as_path(), Path::new("foo.txt"));
    // Edge: complex traversal
    let clamped = ClampedPath::new("a/b/../../../sensitive.txt");
    assert_eq!(clamped.as_path(), Path::new("sensitive.txt"));
    // Edge: Windows drive prefix (should ignore)
    #[cfg(windows)]
    {
        let clamped = ClampedPath::new("C:\\foo\\..\\bar.txt");
        assert_eq!(clamped.as_path(), Path::new("bar.txt"));
    }
}
