use crate::PathBoundary;
#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;

#[cfg(feature = "virtual-path")]
#[test]
fn virtualpath_create_parent_dir_all_creates_chain() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().join("root");
    std::fs::create_dir_all(&root).unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(&root).unwrap();
    let vp = vroot.virtual_join("a/b/c/file.txt").unwrap();

    // No parents exist yet under root
    assert!(!root.join("a").exists());

    // Recursively create parent chain up to "a/b/c"
    vp.create_parent_dir_all().unwrap();
    assert!(root.join("a/b/c").is_dir());
}

#[cfg(feature = "virtual-path")]
#[test]
fn virtualpath_create_parent_dir_non_recursive_fails_when_grandparents_missing() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().join("root");
    std::fs::create_dir_all(&root).unwrap();

    // Pre-create only the top-level parent "a"; leave "a/b" missing
    std::fs::create_dir_all(root.join("a")).unwrap();

    let vroot: VirtualRoot = VirtualRoot::try_new(&root).unwrap();
    let vp = vroot.virtual_join("a/b/c/file.txt").unwrap();

    // Non-recursive create should fail because "a/b" is missing
    let res = vp.create_parent_dir();
    assert!(res.is_err());
    assert!(!root.join("a/b/c").exists());
}

#[test]
fn strictpath_parent_helpers_parity() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().join("root");
    std::fs::create_dir_all(&root).unwrap();

    let restriction: PathBoundary = PathBoundary::try_new(&root).unwrap();
    let jp = restriction.strict_join("x/y/z").unwrap();

    // Recursive parent creation
    jp.create_parent_dir_all().unwrap();
    assert!(root.join("x/y").is_dir());

    // Non-recursive when immediate grandparent missing should fail
    let jp2 = restriction.strict_join("m/n/o/p").unwrap();
    // Create only m; leave m/n missing
    std::fs::create_dir_all(root.join("m")).unwrap();
    let res = jp2.create_parent_dir();
    assert!(res.is_err());
}

#[cfg(feature = "virtual-path")]
#[test]
fn root_parent_helpers_are_noops() {
    let td = tempfile::tempdir().unwrap();
    let root_jp: crate::path::strict_path::StrictPath<()> =
        crate::path::strict_path::StrictPath::with_boundary(td.path()).unwrap();
    let root_vp: crate::path::virtual_path::VirtualPath<()> =
        crate::path::virtual_path::VirtualPath::with_root(td.path()).unwrap();

    // Root has no parent; helpers should be Ok and no-ops
    root_jp.create_parent_dir().unwrap();
    root_jp.create_parent_dir_all().unwrap();
    root_vp.create_parent_dir().unwrap();
    root_vp.create_parent_dir_all().unwrap();
}

#[test]
fn create_dir_non_recursive_requires_parent() {
    let td = tempfile::tempdir().unwrap();
    let restriction: crate::PathBoundary = crate::PathBoundary::try_new(td.path()).unwrap();
    let missing_parent = restriction.strict_join("p/newdir").unwrap();
    assert!(missing_parent.create_dir().is_err());

    // Create the parent, then non-recursive create should succeed
    let parent = restriction.strict_join("p").unwrap();
    parent.create_dir_all().unwrap();
    missing_parent.create_dir().unwrap();
    assert!(td.path().join("p/newdir").is_dir());
}

#[cfg(feature = "virtual-path")]
#[test]
fn virtualpath_create_dir_non_recursive_behaves_like_system() {
    let td = tempfile::tempdir().unwrap();
    let vroot: crate::VirtualRoot = crate::VirtualRoot::try_new(td.path()).unwrap();
    let vp = vroot.virtual_join("a/b").unwrap();
    // Parent missing, non-recursive create fails
    assert!(vp.create_dir().is_err());
    // After creating parent, it works
    vroot.virtual_join("a").unwrap().create_dir_all().unwrap();
    vp.create_dir().unwrap();
    assert!(td.path().join("a/b").is_dir());
}

#[cfg(feature = "virtual-path")]
#[test]
fn parent_dir_all_is_idempotent() {
    let td = tempfile::tempdir().unwrap();
    let vroot: crate::VirtualRoot = crate::VirtualRoot::try_new(td.path()).unwrap();
    let vp = vroot.virtual_join("x/y/z/file.txt").unwrap();
    vp.create_parent_dir_all().unwrap();
    vp.create_parent_dir_all().unwrap();
    assert!(td.path().join("x/y/z").is_dir());
}

#[cfg(feature = "virtual-path")]
#[test]
fn virtual_semantics_for_parent_helpers() {
    let td = tempfile::tempdir().unwrap();
    let vroot: crate::VirtualRoot = crate::VirtualRoot::try_new(td.path()).unwrap();
    // Path attempts to traverse above; virtual semantics clamp to "/q/r.txt"
    let vp = vroot.virtual_join("a/../../q/r.txt").unwrap();
    assert_eq!(format!("{}", vp.virtualpath_display()), "/q/r.txt");
    vp.create_parent_dir_all().unwrap();
    // Only q is created under the restricted path root; no stray "a"
    assert!(td.path().join("q").is_dir());
    assert!(!td.path().join("a").exists());
}
