// Tests for known CVE patterns, unicode edge cases, concurrent usage, long paths,
// and Windows-specific attack vectors via strict_join and virtual_join.

#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
#[cfg(feature = "virtual-path")]
use crate::{PathBoundary, StrictPathError};
#[cfg(feature = "virtual-path")]
use std::path::{Component, Path};
#[cfg(feature = "virtual-path")]
use std::sync::Arc;
#[cfg(feature = "virtual-path")]
use std::thread;

#[cfg(feature = "virtual-path")]
#[test]
fn test_known_cve_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(restriction.interop_path()).unwrap();

    let attack_patterns = vec![
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\system32\\config\\sam",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..",
        "../../../../../../proc/self/environ",
        "../../../var/log/auth.log",
        "....//....//....//etc/shadow",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "file:///etc/passwd",
        "\\\\server\\share\\sensitive.txt",
        ".ssh/id_rsa",
        "../.env",
        "../../config/database.yml",
    ];

    for pattern in attack_patterns {
        let candidate = Path::new(pattern);
        let has_parent = candidate
            .components()
            .any(|component| matches!(component, Component::ParentDir));
        let looks_like_scheme = pattern.starts_with("file://");
        let is_absolute = candidate.is_absolute();
        let looks_absolute = is_absolute || looks_like_scheme;
        let should_succeed_strict = !has_parent && !looks_absolute;

        match restriction.strict_join(pattern) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Attack pattern '{pattern}' escaped restriction: {validated_path:?}"
                );
            }
            Err(err) => {
                if should_succeed_strict {
                    panic!("strict_join rejected '{pattern}': {err:?}");
                }
                match err {
                    StrictPathError::PathEscapesBoundary { .. }
                    | StrictPathError::PathResolutionError { .. } => {}
                    other => panic!("Unexpected error variant for pattern '{pattern}': {other:?}"),
                }
            }
        }

        match vroot.virtual_join(pattern) {
            Ok(virtual_path) => {
                assert!(
                    virtual_path
                        .as_unvirtual()
                        .strictpath_starts_with(vroot.interop_path()),
                    "Virtual join for '{pattern}' escaped restriction"
                );

                let display = virtual_path.virtualpath_display().to_string();
                assert!(
                    display.starts_with('/'),
                    "Virtual display must be rooted for '{pattern}': {display}"
                );

                if has_parent || looks_absolute {
                    let has_parent_segment = display.split('/').any(|segment| segment == "..");
                    assert!(
                        !has_parent_segment,
                        "Virtual display leaked parent segments for '{pattern}': {display}"
                    );
                }
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                assert!(
                    looks_absolute,
                    "Unexpected virtual_join failure for pattern '{pattern}'"
                );
            }
            Err(other) => panic!("Unexpected virtual_join error for '{pattern}': {other:?}"),
        }
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_unicode_edge_cases() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let unicode_patterns = vec![
        "файл.txt",
        "测试文件.log",
        "🔒secure.dat",
        "file\u{202E}gnp.txt",
        "file\u{200D}hidden.txt",
        "café/naïve.json",
        "file\u{FEFF}bom.txt",
        "\u{1F4C1}folder/test.txt",
    ];

    for pattern in unicode_patterns {
        match restriction.strict_join(pattern) {
            Ok(validated_path) => {
                assert!(validated_path.strictpath_starts_with(restriction.interop_path()));
            }
            Err(_e) => {
                // Rejections are acceptable; test ensures no panics and no escapes
            }
        }
    }
}

// Unicode normalization: both NFC and NFD forms should remain contained.
#[cfg(feature = "virtual-path")]
#[test]
fn test_unicode_normalization_forms_are_contained() {
    let td = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(td.path()).unwrap();

    // "café" in NFC and NFD
    let nfc = "café/report.txt"; // U+00E9
    let nfd = "cafe\u{0301}/report.txt"; // 'e' + COMBINING ACUTE

    for inp in [nfc, nfd] {
        let jp = restriction.strict_join(inp).unwrap();
        assert!(jp.strictpath_starts_with(restriction.interop_path()));

        let vroot: VirtualRoot = VirtualRoot::try_new(restriction.interop_path()).unwrap();
        let vp = vroot.virtual_join(inp).unwrap();
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
        // Virtual display is rooted and forward slashed
        let virtual_display = vp.virtualpath_display().to_string();
        assert!(virtual_display.starts_with('/'));
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_concurrent_validator_usage() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: Arc<PathBoundary> = Arc::new(PathBoundary::try_new(temp.path()).unwrap());
    let mut handles = vec![];

    for i in 0..5 {
        let restriction_clone = Arc::clone(&restriction);
        let handle = thread::spawn(move || {
            for j in 0..50 {
                let path = format!("thread_{i}/file_{j}.txt");
                let result = restriction_clone.strict_join(&path);
                assert!(result.is_ok(), "Thread {i} iteration {j} failed");

                let validated_path = result.unwrap();
                // Test the actual path containment (what we really care about)
                assert!(validated_path.strictpath_starts_with(restriction_clone.interop_path()));
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_long_path_handling() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let long_component = "a".repeat(64);
    let long_path = format!("{long_component}/{long_component}/{long_component}/{long_component}",);

    let validated_path = restriction
        .strict_join(&long_path)
        .unwrap_or_else(|err| panic!("long path should be accepted: {err:?}"));
    assert!(validated_path.strictpath_starts_with(restriction.interop_path()));

    let traversal_attack = "../".repeat(10) + "etc/passwd";
    let err = restriction
        .strict_join(&traversal_attack)
        .expect_err("traversal should be rejected by strict_join");
    match err {
        StrictPathError::PathEscapesBoundary { .. } => {}
        other => panic!("Unexpected error for traversal attack '{traversal_attack}': {other:?}"),
    }

    let vroot: VirtualRoot = VirtualRoot::try_new(restriction.interop_path()).unwrap();
    let virtual_path = vroot
        .virtual_join(&traversal_attack)
        .unwrap_or_else(|err| panic!("virtual join should clamp traversal: {err:?}"));
    let expected_path = "/etc/passwd".to_string();
    assert_eq!(
        virtual_path.virtualpath_display().to_string(),
        expected_path
    );
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_specific_attacks() {
    let temp = tempfile::tempdir().unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let windows_patterns = vec![
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "LPT1",
        "file.txt:",
        "file.txt::$DATA",
        "\\\\?\\C:\\Windows\\System32",
        "\\\\server\\share",
    ];

    for pattern in windows_patterns {
        let candidate = Path::new(pattern);
        let is_absolute = candidate.is_absolute();

        let result = restriction.strict_join(pattern);
        if is_absolute {
            let err = result.expect_err("strict_join must reject absolute Windows escape patterns");
            match err {
                StrictPathError::PathEscapesBoundary { .. } => {}
                other => {
                    panic!("Unexpected error variant for absolute pattern '{pattern}': {other:?}")
                }
            }
            continue;
        }

        match result {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Pattern '{pattern}' escaped restriction"
                );
            }
            Err(StrictPathError::PathResolutionError { .. }) => {
                // Reserved device names and ADS forms may fail resolution on some systems.
            }
            Err(other) => panic!("Unexpected error for Windows pattern '{pattern}': {other:?}"),
        }
    }
}
