//! VirtualRoot container boundary tests for /proc/PID/root magic symlinks.
//!
//! These tests complement `proc_magic_symlink.rs` and verify that `VirtualRoot`
//! correctly isolates paths when rooted at a Linux namespace boundary.

// Gated via #[cfg(all(target_os = "linux", feature = "virtual-path"))] in mod.rs

use super::proc_magic_symlink::get_proc_self_root;
use crate::VirtualRoot;

/// VirtualRoot test: Creating virtual root at /proc/self/root
#[test]
fn virtualroot_proc_root_maintains_isolation() {
    let proc_self_root = get_proc_self_root();

    if let Ok(vroot) = VirtualRoot::<()>::try_new(&proc_self_root) {
        let vroot_path_str = vroot.interop_path().to_string_lossy().to_string();

        // Must preserve namespace
        assert!(
            vroot_path_str.starts_with("/proc/self/root"),
            "VirtualRoot lost namespace context: {vroot_path_str}"
        );
    }
}

/// VirtualRoot test: Virtual join clamps traversal within namespace
#[test]
fn virtualroot_virtual_join_clamps_to_namespace() {
    let proc_self_root = get_proc_self_root();

    if let Ok(vroot) = VirtualRoot::<()>::try_new(&proc_self_root) {
        // Virtual join clamps traversal
        match vroot.virtual_join("../../../etc/passwd") {
            Ok(vpath) => {
                // Virtual path must stay within the /proc/self/root namespace
                let system_path = vpath.as_unvirtual().strictpath_display().to_string();
                assert!(
                    system_path.starts_with("/proc/self/root"),
                    "VirtualPath escaped namespace: {system_path}"
                );

                // Virtual display should show clamped path
                let virtual_display = vpath.virtualpath_display().to_string();
                assert!(
                    virtual_display.starts_with('/'),
                    "Virtual display must be rooted: {virtual_display}"
                );
            }
            Err(e) => {
                eprintln!("Virtual join error (acceptable): {e:?}");
            }
        }
    }
}

/// VirtualRoot test: Virtual path display is isolated from host
#[test]
fn virtualroot_display_is_isolated() {
    let proc_self_root = get_proc_self_root();

    if let Ok(vroot) = VirtualRoot::<()>::try_new(&proc_self_root) {
        if let Ok(vpath) = vroot.virtual_join("etc/passwd") {
            // Virtual display should show /etc/passwd (virtual view)
            let display = vpath.virtualpath_display().to_string();
            assert!(display.starts_with('/'));

            // Should NOT leak the real host path
            assert!(
                !display.contains("/proc/self/root"),
                "Virtual display leaked namespace path: {display}"
            );
        }
    }
}

/// VirtualRoot test: Absolute inputs clamp to virtual namespace
#[test]
fn virtualroot_absolute_input_clamped_to_namespace() {
    let proc_self_root = get_proc_self_root();

    if let Ok(vroot) = VirtualRoot::<()>::try_new(&proc_self_root) {
        // Absolute path input should be clamped to the virtual root
        match vroot.virtual_join("/etc/shadow") {
            Ok(vpath) => {
                let system_path = vpath.as_unvirtual().strictpath_display().to_string();
                assert!(
                    system_path.starts_with("/proc/self/root"),
                    "Absolute input escaped namespace: {system_path}"
                );
            }
            Err(e) => {
                eprintln!("Absolute input clamping error (acceptable): {e:?}");
            }
        }
    }
}
