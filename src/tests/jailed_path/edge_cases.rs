use crate::jailed_path::JailedPath;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn create_jailed_path(path: impl AsRef<Path>) -> (JailedPath, Arc<PathBuf>) {
    let temp = tempfile::tempdir().unwrap();
    let jail_root_path = temp.path().to_path_buf();
    let jail_root = Arc::new(
        crate::validator::stated_path::StatedPath::<crate::validator::stated_path::Raw>::new(
            &jail_root_path,
        )
        .canonicalize()
        .unwrap()
        .verify_exists()
        .unwrap(),
    );
    let validated_path = crate::validator::stated_path::StatedPath::<
        crate::validator::stated_path::Raw,
    >::new(path.as_ref())
    .virtualize()
    .join_jail(&jail_root)
    .canonicalize()
    .unwrap()
    .boundary_check(&jail_root)
    .unwrap();
    let jailed_path: JailedPath = JailedPath::new(Arc::clone(&jail_root), validated_path);
    (jailed_path, Arc::new(jail_root_path))
}

#[test]
fn test_string_conversions() {
    let (jailed_path, jail_root_path) = create_jailed_path("foo/bar.txt");

    // to_string_virtual() uses forward slashes consistently
    assert_eq!(jailed_path.to_string_virtual(), "/foo/bar.txt");
    assert_eq!(format!("{jailed_path}"), "/foo/bar.txt");

    // to_string_real() uses platform separators
    let real_string = jailed_path.to_string_real();
    // Use the returned jail root (second element) to build expected platform string
    // Note: create_jailed_path returns (JailedPath, Arc<PathBuf>)
    let jail_root_buf = Arc::clone(&jail_root_path);
    let _expected_platform = if cfg!(windows) {
        format!("{}\\{}", jail_root_buf.to_string_lossy(), "foo\\bar.txt")
    } else {
        format!("{}/foo/bar.txt", jail_root_buf.to_string_lossy())
    };
    assert!(
        real_string.ends_with(r"foo\bar.txt") || real_string.ends_with("foo/bar.txt"),
        "Real path should end with the jailed path"
    );
}

#[test]
fn test_methods_on_root_jailed_path() {
    let (jailed_path, _) = create_jailed_path("");

    let with_name = jailed_path.with_file_name("new.txt");
    assert!(with_name.is_some());
    assert_eq!(with_name.unwrap().to_string_virtual(), "/new.txt");

    // Can't add extension to root path (no filename)
    let with_ext_result = jailed_path.with_extension("log");
    assert!(
        with_ext_result.is_none(),
        "with_extension on root should return None"
    );
}
