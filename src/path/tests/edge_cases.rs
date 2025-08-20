use crate::jail::Jail;

#[test]
fn test_string_conversions() {
    let temp = tempfile::tempdir().unwrap();
    let jail = Jail::<()>::try_new(temp.path()).unwrap();
    let jailed_path = jail.try_path("foo/bar.txt").unwrap();
    let virtual_path = jailed_path.clone().virtualize();

    // Display uses forward slashes consistently
    assert_eq!(format!("{virtual_path}"), "/foo/bar.txt");

    // realpath_to_string() uses platform separators
    let real_string = jailed_path.realpath_to_string();
    let expected_suffix = if cfg!(windows) {
        "foo\\bar.txt"
    } else {
        "foo/bar.txt"
    };
    assert!(
        real_string.ends_with(expected_suffix),
        "Real path should end with the jailed path"
    );
}

#[test]
fn test_methods_on_root_jailed_path() {
    let temp = tempfile::tempdir().unwrap();
    let jail = Jail::<()>::try_new(temp.path()).unwrap();
    let jailed_path = jail.try_path("").unwrap();
    let virtual_path = jailed_path.virtualize();

    let with_name = virtual_path.with_file_name_virtual("new.txt").unwrap();
    assert_eq!(format!("{with_name}"), "/new.txt");

    // Can't add extension to root path (no filename)
    let with_ext_result = virtual_path.with_extension_virtual("log");
    assert!(
        with_ext_result.is_err(),
        "with_extension on root should error"
    );
}
