use crate::PathBoundary;

#[test]
fn virtualpath_display_is_rooted_and_forward_slashed() {
    let temp = tempfile::tempdir().unwrap();
    let restriction = PathBoundary::<()>::try_new(temp.path()).unwrap();

    // Non-root path
    let jp = restriction.strict_join("foo/bar.txt").unwrap();
    let vp = jp.virtualize();
    assert_eq!(format!("{}", vp.virtualpath_display()), "/foo/bar.txt");
    assert_eq!(vp.virtualpath_display().to_string(), "/foo/bar.txt");

    // Root path
    let root_vp = restriction.strict_join("").unwrap().virtualize();
    assert_eq!(format!("{}", root_vp.virtualpath_display()), "/");
}
