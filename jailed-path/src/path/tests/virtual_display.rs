use crate::validator::jail::Jail;

#[test]
fn virtualpath_display_is_rooted_and_forward_slashed() {
    let temp = tempfile::tempdir().unwrap();
    let jail = Jail::<()>::try_new(temp.path()).unwrap();

    // Non-root path
    let jp = jail.try_path("foo/bar.txt").unwrap();
    let vp = jp.virtualize();
    assert_eq!(format!("{vp}"), "/foo/bar.txt");
    assert_eq!(vp.virtualpath_to_string_lossy(), "/foo/bar.txt");

    // Root path
    let root_vp = jail.try_path("").unwrap().virtualize();
    assert_eq!(format!("{root_vp}"), "/");
}
