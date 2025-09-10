// Comprehensive tests for comparison implementations
use crate::{Jail, VirtualRoot};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn test_jailed_path_comparisons() {
    let temp_dir = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new_create(temp_dir.path()).unwrap();

    // Create test file
    let test_file = jail.jailed_join("test.txt").unwrap();
    fs::write(test_file.interop_path(), "test content").unwrap();

    // JailedPath vs JailedPath (same type)
    let path1 = jail.jailed_join("test.txt").unwrap();
    let path2 = jail.jailed_join("test.txt").unwrap();
    assert_eq!(path1, path2);

    let different_path = jail.jailed_join("different.txt").unwrap();
    assert_ne!(path1, different_path);

    // JailedPath vs Path (system path comparison)
    // Note: On Windows, paths are canonicalized so we compare the canonical form
    let system_path = temp_dir.path().join("test.txt");
    let canonical_system = system_path.canonicalize().unwrap_or(system_path.clone());
    assert_eq!(test_file, canonical_system.as_path());
    assert_eq!(test_file, &canonical_system);

    // JailedPath vs PathBuf
    assert_eq!(test_file, canonical_system);

    // JailedPath vs &str
    let system_path_str = canonical_system.to_string_lossy();
    assert_eq!(test_file, system_path_str.as_ref());
}

#[test]
fn test_virtual_path_comparisons() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(temp_dir.path()).unwrap();

    // Create test file
    let vpath = vroot.virtual_join("docs/test.txt").unwrap();
    if let Some(parent) = vpath.virtualpath_parent().unwrap() {
        fs::create_dir_all(parent.unvirtual().interop_path()).unwrap();
    }
    fs::write(vpath.interop_path(), "test content").unwrap();

    // VirtualPath vs VirtualPath (same type)
    let vpath1 = vroot.virtual_join("docs/test.txt").unwrap();
    let vpath2 = vroot.virtual_join("docs/test.txt").unwrap();
    assert_eq!(vpath1, vpath2);

    let different_vpath = vroot.virtual_join("docs/different.txt").unwrap();
    assert_ne!(vpath1, different_vpath);

    // VirtualPath vs JailedPath (system path comparison)
    let jailed = vpath.clone().unvirtual();
    assert_eq!(vpath, jailed);
    assert_eq!(jailed, vpath);

    // VirtualPath vs Path (virtual path comparison)
    assert_eq!(vpath, Path::new("/docs/test.txt"));
    assert_eq!(vpath, Path::new("docs/test.txt")); // Should add leading slash

    // VirtualPath vs PathBuf (virtual path comparison)
    assert_eq!(vpath, PathBuf::from("/docs/test.txt"));
    assert_eq!(vpath, PathBuf::from("docs/test.txt"));

    // Test ordering
    let vpath_a = vroot.virtual_join("a.txt").unwrap();
    let vpath_b = vroot.virtual_join("b.txt").unwrap();
    assert!(vpath_a < vpath_b);
    assert!(vpath_a < Path::new("/b.txt"));
    // Note: Can't compare Path with VirtualPath directly due to orphan rules
    // so we test the reverse comparison by flipping the assertion
    assert!((vpath_b > Path::new("/a.txt")));
}

#[test]
fn test_jail_comparisons() {
    let temp_dir1 = tempfile::tempdir().unwrap();
    let temp_dir2 = tempfile::tempdir().unwrap();

    let jail1: Jail = Jail::try_new_create(temp_dir1.path()).unwrap();
    let jail2: Jail = Jail::try_new_create(temp_dir1.path()).unwrap(); // Same path
    let jail3: Jail = Jail::try_new_create(temp_dir2.path()).unwrap(); // Different path

    // Jail vs Jail (same type)
    assert_eq!(jail1, jail2); // Same underlying path
    assert_ne!(jail1, jail3); // Different underlying paths

    // Jail vs VirtualRoot (system path comparison)
    let vroot1: VirtualRoot = VirtualRoot::try_new_create(temp_dir1.path()).unwrap();
    let vroot2: VirtualRoot = VirtualRoot::try_new_create(temp_dir2.path()).unwrap();
    assert_eq!(jail1, vroot1); // Same underlying path
    assert_ne!(jail1, vroot2); // Different underlying paths

    // Jail vs Path (system path comparison)
    let canonical_temp1 = temp_dir1
        .path()
        .canonicalize()
        .unwrap_or_else(|_| temp_dir1.path().to_path_buf());
    let canonical_temp2 = temp_dir2
        .path()
        .canonicalize()
        .unwrap_or_else(|_| temp_dir2.path().to_path_buf());
    assert_eq!(jail1, canonical_temp1.as_path());
    assert_ne!(jail1, canonical_temp2.as_path());

    // Jail vs PathBuf (system path comparison)
    assert_eq!(jail1, canonical_temp1);
    assert_ne!(jail1, canonical_temp2);

    // Test ordering
    // Note: Ordering depends on actual temp directory paths
    if temp_dir1.path() < temp_dir2.path() {
        assert!(jail1 < jail3);
    } else {
        assert!(jail3 < jail1);
    }
}

#[test]
fn test_virtual_root_comparisons() {
    let temp_dir1 = tempfile::tempdir().unwrap();
    let temp_dir2 = tempfile::tempdir().unwrap();

    let vroot1: VirtualRoot = VirtualRoot::try_new_create(temp_dir1.path()).unwrap();
    let vroot2: VirtualRoot = VirtualRoot::try_new_create(temp_dir1.path()).unwrap(); // Same path
    let vroot3: VirtualRoot = VirtualRoot::try_new_create(temp_dir2.path()).unwrap(); // Different path

    // VirtualRoot vs VirtualRoot (same type)
    assert_eq!(vroot1, vroot2); // Same underlying path
    assert_ne!(vroot1, vroot3); // Different underlying paths

    // VirtualRoot vs Jail (system path comparison)
    let jail1 = Jail::try_new_create(temp_dir1.path()).unwrap();
    let jail2 = Jail::try_new_create(temp_dir2.path()).unwrap();
    assert_eq!(vroot1, jail1); // Same underlying path
    assert_ne!(vroot1, jail2); // Different underlying paths

    // VirtualRoot vs Path (virtual root comparison - always "/")
    assert_eq!(vroot1, Path::new("/"));
    assert_eq!(vroot2, Path::new("/"));
    assert_eq!(vroot3, Path::new("/"));
    assert_ne!(vroot1, Path::new("/some/path"));

    // VirtualRoot vs PathBuf (virtual root comparison - always "/")
    assert_eq!(vroot1, PathBuf::from("/"));
    assert_ne!(vroot1, PathBuf::from("/some/path"));

    // Test ordering - all VirtualRoots compare as "/" so they're equal
    assert_eq!(
        vroot1.partial_cmp(Path::new("/")),
        Some(std::cmp::Ordering::Equal)
    );
    assert_eq!(
        vroot1.partial_cmp(Path::new("/a")),
        Some(std::cmp::Ordering::Less)
    );
    assert_eq!(
        vroot1.partial_cmp(Path::new("")),
        Some(std::cmp::Ordering::Greater)
    ); // "/" should be greater than ""
}

#[test]
fn test_cross_type_path_comparisons() {
    let temp_dir = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new_create(temp_dir.path()).unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(temp_dir.path()).unwrap();

    // Create test paths
    let jailed_path = jail.jailed_join("test.txt").unwrap();
    let virtual_path = vroot.virtual_join("test.txt").unwrap();

    // Cross-type comparisons should work both ways
    assert_eq!(jailed_path, virtual_path);
    assert_eq!(virtual_path, jailed_path);

    // Jail vs VirtualRoot
    assert_eq!(jail, vroot);
    assert_eq!(vroot, jail);

    // Different files should not be equal
    let jailed_different = jail.jailed_join("different.txt").unwrap();
    let virtual_different = vroot.virtual_join("different.txt").unwrap();
    assert_ne!(jailed_path, virtual_different);
    assert_ne!(virtual_path, jailed_different);
}

#[test]
fn test_hash_consistency() {
    use std::collections::HashMap;

    let temp_dir = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new_create(temp_dir.path()).unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(temp_dir.path()).unwrap();

    let jailed_path1 = jail.jailed_join("test.txt").unwrap();
    let jailed_path2 = jail.jailed_join("test.txt").unwrap();
    let virtual_path1 = vroot.virtual_join("test.txt").unwrap();
    let virtual_path2 = vroot.virtual_join("test.txt").unwrap();

    // Test that equal JailedPaths have equal hashes
    let mut jailed_map = HashMap::new();
    jailed_map.insert(jailed_path1.clone(), "value1");
    jailed_map.insert(jailed_path2.clone(), "value2");

    // Since jailed_path1 == jailed_path2, they should hash to the same bucket
    assert_eq!(jailed_map.len(), 1);
    assert_eq!(jailed_map.get(&jailed_path1), Some(&"value2"));

    // Test that equal VirtualPaths have equal hashes
    let mut virtual_map = HashMap::new();
    virtual_map.insert(virtual_path1.clone(), "value1");
    virtual_map.insert(virtual_path2.clone(), "value2");

    // Since virtual_path1 == virtual_path2, they should hash to the same bucket
    assert_eq!(virtual_map.len(), 1);
    assert_eq!(virtual_map.get(&virtual_path1), Some(&"value2"));

    // Test Jail and VirtualRoot hashing
    let jail2: Jail = Jail::try_new_create(temp_dir.path()).unwrap();
    let mut jail_root_map = HashMap::new();
    jail_root_map.insert(jail.clone(), "jail_value");
    jail_root_map.insert(jail2.clone(), "jail_value2");

    // Since jail == jail2, they should hash to the same bucket
    assert_eq!(jail_root_map.len(), 1);
    assert_eq!(jail_root_map.get(&jail), Some(&"jail_value2"));
}

#[test]
#[cfg(windows)]
fn test_windows_path_normalization() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(temp_dir.path()).unwrap();
    let vpath = vroot.virtual_join("docs\\test.txt").unwrap();

    // Virtual path comparisons should normalize backslashes to forward slashes
    assert_eq!(vpath, Path::new("/docs/test.txt"));
    assert_eq!(vpath, Path::new("\\docs\\test.txt"));
    assert_eq!(vpath, Path::new("docs/test.txt"));
    assert_eq!(vpath, Path::new("docs\\test.txt"));

    // VirtualRoot should always compare as "/"
    assert_eq!(vroot, Path::new("/"));
    assert_eq!(vroot, Path::new("\\"));
}

#[test]
fn test_ordering_consistency() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(temp_dir.path()).unwrap();

    let vpath_a = vroot.virtual_join("a.txt").unwrap();
    let vpath_b = vroot.virtual_join("b.txt").unwrap();
    let vpath_c = vroot.virtual_join("c.txt").unwrap();

    // Test transitivity: if a < b and b < c, then a < c
    assert!(vpath_a < vpath_b);
    assert!(vpath_b < vpath_c);
    assert!(vpath_a < vpath_c);

    // Test with Path comparisons (one direction only due to orphan rules)
    assert!(vpath_a < Path::new("/b.txt"));
    assert!(vpath_a < Path::new("/c.txt"));

    // Test symmetry: if a < b, then !(b < a)
    assert!((vpath_b >= vpath_a));
}

#[test]
fn test_edge_cases() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new_create(temp_dir.path()).unwrap();

    // Root virtual path
    let root_vpath = vroot.virtual_join("").unwrap();
    assert_eq!(root_vpath, Path::new("/"));

    // Nested paths
    let nested = vroot.virtual_join("a/b/c/d.txt").unwrap();
    assert_eq!(nested, Path::new("/a/b/c/d.txt"));
    assert_eq!(nested, Path::new("a/b/c/d.txt"));

    // Paths with special characters (that are allowed)
    let special = vroot.virtual_join("file with spaces.txt").unwrap();
    assert_eq!(special, Path::new("/file with spaces.txt"));

    // Empty path components are handled by virtual_join
    let clean = vroot.virtual_join("./test.txt").unwrap();
    assert_eq!(clean, Path::new("/test.txt"));
}
