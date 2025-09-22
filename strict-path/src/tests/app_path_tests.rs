// Tests for app-path feature constructors on PathBoundary and VirtualRoot
#![cfg(feature = "app-path")]

use crate::{PathBoundary, VirtualRoot};
use std::env;

fn with_temp_env<K: AsRef<str>, V: AsRef<str>, F: FnOnce()>(key: K, val: V, f: F) {
    let key = key.as_ref().to_string();
    let old = env::var(&key).ok();
    env::set_var(&key, val.as_ref());
    f();
    // restore
    if let Some(old_val) = old {
        env::set_var(&key, old_val);
    } else {
        env::remove_var(&key);
    }
}

#[test]
fn path_boundary_app_path_basic_and_env_override() {
    // Basic: relative to executable dir (we just ensure API works and directory is created)
    let jail: PathBoundary = PathBoundary::try_new_app_path("sp_test_basic", None).unwrap();
    assert!(jail.exists());

    // Env override takes precedence
    let tempdir = tempfile::tempdir().unwrap();
    let override_dir = tempdir.path().join("override_loc");
    let env_key = "SP_APP_PATH_TEST";

    with_temp_env(env_key, override_dir.to_string_lossy(), || {
        let jail2: PathBoundary =
            PathBoundary::try_new_app_path("sp_test_env", Some(env_key)).unwrap();
        // Should have created under override_dir
        assert!(jail2.exists());
        let created = &override_dir;
        assert!(created.exists(), "expected {:?} to exist", created);

        // Create a child file safely to validate join works
        let file = jail2.strict_join("child.txt").unwrap();
        file.create_parent_dir_all().unwrap();
        file.write(b"ok").unwrap();
        assert!(file.exists());
    });
}

#[test]
fn path_boundary_app_path_with_env_helper() {
    let tempdir = tempfile::tempdir().unwrap();
    let override_dir = tempdir.path().join("override_loc2");
    let env_key = "SP_APP_PATH_TEST2";

    with_temp_env(env_key, override_dir.to_string_lossy(), || {
        let jail: PathBoundary =
            PathBoundary::try_new_app_path_with_env("sp_test_with_env", env_key).unwrap();
        assert!(jail.exists());
        let created = &override_dir;
        assert!(created.exists());
    });
}

#[test]
fn virtual_root_app_path_basic_and_env_override() {
    // Basic
    let vroot: VirtualRoot = VirtualRoot::try_new_app_path("vp_test_basic", None).unwrap();
    assert!(vroot.exists());

    let tempdir = tempfile::tempdir().unwrap();
    let override_dir = tempdir.path().join("override_loc3");
    let env_key = "SP_APP_PATH_TEST3";

    with_temp_env(env_key, override_dir.to_string_lossy(), || {
        let vroot2: VirtualRoot =
            VirtualRoot::try_new_app_path("vp_test_env", Some(env_key)).unwrap();
        assert!(vroot2.exists());
        let created = &override_dir;
        assert!(created.exists());

        let vp = vroot2.virtual_join("docs/file.txt").unwrap();
        vp.create_parent_dir_all().unwrap();
        vp.write(b"data").unwrap();
        assert!(vp.exists());
        assert_eq!(vp.virtualpath_display().to_string(), "/docs/file.txt");
    });
}

#[test]
fn virtual_root_app_path_with_env_helper() {
    let tempdir = tempfile::tempdir().unwrap();
    let override_dir = tempdir.path().join("override_loc4");
    let env_key = "SP_APP_PATH_TEST4";

    with_temp_env(env_key, override_dir.to_string_lossy(), || {
        let vroot: VirtualRoot =
            VirtualRoot::try_new_app_path_with_env("vp_test_with_env", env_key).unwrap();
        assert!(vroot.exists());
        let created = &override_dir;
        assert!(created.exists());
    });
}
