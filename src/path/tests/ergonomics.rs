use crate::VirtualRoot;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

// Ensure module path aligns with crate structure

#[test]
fn jailed_and_virtual_compare_with_path_like_types() {
    // create a temp virtual root directory
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    let vroot = VirtualRoot::<()>::try_new(root).expect("create vroot");

    // create a path inside the jail
    let vp = vroot.try_path_virtual("foo/bar.txt").expect("make virtual");
    let jp = vp.clone().unvirtual();

    // Comparisons: JailedPath should compare equal to its underlying real Path
    assert_eq!(jp, jp.path());
    // VirtualPath compares equal to the full real path (same as inner JailedPath)
    // Use the exact canonical path that the JailedPath stores to avoid
    // mismatches with platform-specific canonicalization (verbatim prefixes).
    let real_pb: PathBuf = jp.path().to_path_buf();
    assert_eq!(vp, real_pb);

    // Comparisons against PathBuf
    let pb: PathBuf = jp.path().to_path_buf();
    assert_eq!(jp, pb);
    // the virtual presentation still displays differently from the real path
    let vpb: PathBuf = PathBuf::from("/foo/bar.txt");
    assert_ne!(vp, vpb);

    // PartialOrd checks against canonical paths
    assert!(jp <= pb);
    assert!(vp >= real_pb.as_path());
}

#[test]
fn hashing_and_collections_works() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let vroot = VirtualRoot::<()>::try_new(root).expect("create vroot");

    let vp = vroot.try_path_virtual("a/b").expect("make virtual");
    let jp = vp.clone().unvirtual();

    // Hash the JailedPath and the underlying PathBuf and ensure same hash
    let mut h1 = DefaultHasher::new();
    jp.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    // Hash the same underlying path that JailedPath stores
    jp.path().hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());

    // Hash the VirtualPath and ensure it matches inner JailedPath hash
    let mut h3 = DefaultHasher::new();
    vp.hash(&mut h3);
    assert_eq!(h3.finish(), h1.finish());
}

#[test]
fn jailedpath_explicit_ergonomics() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let vroot = VirtualRoot::<()>::try_new(root).expect("create vroot");

    let vp = vroot.try_path_virtual("x/y/z.txt").expect("make virtual");
    let jp = vp.unvirtual();

    // equality with the underlying Path
    let real = jp.path().to_path_buf();
    assert_eq!(jp, real.as_path());

    // equality with PathBuf
    assert_eq!(jp, real);

    // PartialOrd
    assert!(jp >= real.as_path());

    // Hash matches underlying Path
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    let mut h1 = DefaultHasher::new();
    jp.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    jp.path().hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn realpath_as_os_str_works_with_external_apis() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let vroot = VirtualRoot::<()>::try_new(root).expect("create vroot");

    // Create a virtual path and write a file using the jailed/system API
    let vp = vroot.try_path_virtual("ext_api.txt").expect("make virtual");
    let jp = vp.clone().unvirtual();
    jp.write_string("hello external api").expect("write file");

    // Now pass the realpath as an &OsStr (which implements AsRef<Path>) into std::fs::metadata
    let meta = std::fs::metadata(vp.realpath_as_os_str()).expect("metadata should succeed");
    assert!(meta.is_file());
}
