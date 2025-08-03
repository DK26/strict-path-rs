use crate::jailed_path::JailedPath;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn create_jailed_path(path: impl AsRef<Path>) -> (JailedPath, Arc<PathBuf>) {
    let temp = tempfile::tempdir().unwrap();
    let jail_root_path = temp.path().to_path_buf();
    let jail_root = Arc::new(
        crate::validator::validated_path::ValidatedPath::<crate::validator::validated_path::Raw>::new(
            &jail_root_path,
        )
        .canonicalize()
        .unwrap(),
    );
    let validated_path = crate::validator::validated_path::ValidatedPath::<
        crate::validator::validated_path::Raw,
    >::new(path.as_ref())
    .clamp()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed_path: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path);
    (jailed_path, Arc::new(jail_root_path))
}

#[test]
fn test_starts_with_virtual() {
    let (jailed_path, _) = create_jailed_path("foo/bar.txt");

    // Debug what we're actually working with
    println!("Virtual path: {:?}", jailed_path.virtual_path_to_string());
    println!("Virtual display: {}", jailed_path.virtual_display());
    println!(
        "Starts with 'foo': {}",
        jailed_path.starts_with_virtual("foo")
    );
    println!(
        "Starts with 'foo/bar': {}",
        jailed_path.starts_with_virtual("foo/bar")
    );

    // Test path semantics - uses proper path operations, not string mixing
    assert!(jailed_path.starts_with_virtual("foo"));
    assert!(jailed_path.starts_with_virtual(Path::new("foo")));
    assert!(jailed_path.starts_with_virtual(Path::new("foo").join("bar.txt"))); // Full path match
    assert!(!jailed_path.starts_with_virtual("bar"));
    assert!(!jailed_path.starts_with_virtual(Path::new("foo").join("bar"))); // Partial path doesn't match
}

#[test]
fn test_string_conversions() {
    let (jailed_path, _) = create_jailed_path("foo/bar.txt");

    // virtual_path_to_string() uses platform separators
    let virtual_string = jailed_path.virtual_path_to_string().unwrap();
    let expected_platform = if cfg!(windows) {
        "foo\\bar.txt"
    } else {
        "foo/bar.txt"
    };
    assert_eq!(virtual_string, expected_platform);

    // virtual_display() and Display trait use forward slashes consistently
    assert_eq!(jailed_path.virtual_display(), "/foo/bar.txt");
    assert_eq!(format!("{jailed_path}"), "/foo/bar.txt");

    // virtual_path_to_string_lossy() also uses platform separators
    let expected_lossy = if cfg!(windows) {
        "foo\\bar.txt"
    } else {
        "foo/bar.txt"
    };
    assert_eq!(jailed_path.virtual_path_to_string_lossy(), expected_lossy);
}

#[test]
fn test_methods_on_root_jailed_path() {
    let (jailed_path, _) = create_jailed_path("");

    let with_name = jailed_path.virtual_with_file_name("new.txt");
    assert!(with_name.is_some());
    assert_eq!(with_name.unwrap().virtual_path(), PathBuf::from("new.txt"));

    // Can't add extension to root path (no filename)
    let with_ext_result = jailed_path.virtual_with_extension("log");
    assert!(
        with_ext_result.is_none(),
        "virtual_with_extension on root should return None"
    );
}

#[test]
fn test_bytes_conversion() {
    let (jailed_path, _jail_root) = create_jailed_path("foo/bar.txt");
    // to_bytes() returns the real, canonicalized path bytes
    let real_bytes = jailed_path.to_bytes();
    let real_path_string = jailed_path.real_path_to_string_lossy().into_owned();
    let expected_bytes = real_path_string.as_bytes().to_vec();
    assert_eq!(real_bytes, expected_bytes);

    // Test the other into_bytes method too
    let (jailed_path2, _) = create_jailed_path("foo/bar.txt");
    let real_path_string2 = jailed_path2.real_path_to_string_lossy().into_owned();
    let expected_bytes2 = real_path_string2.as_bytes().to_vec();
    assert_eq!(jailed_path2.into_bytes(), expected_bytes2);
}
