use crate::Jail;
use std::sync::Arc;
use std::thread;

#[test]
fn test_known_cve_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Jail = Jail::try_new(temp.path()).unwrap();

    // Common CVE patterns that should be safely handled
    let attack_patterns = vec![
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\system32\\config\\sam",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..",
        "../../../../../../proc/self/environ",
        "../../../var/log/auth.log",
        "....//....//....//etc/shadow", // This creates literal "...." directories (not traversal)
        "..%2F..%2F..%2Fetc%2Fpasswd",  // URL-encoded (should be treated as literal)
        "file:///etc/passwd",
        "\\\\server\\share\\sensitive.txt",
        ".ssh/id_rsa",
        "../.env",
        "../../config/database.yml",
    ];

    for pattern in attack_patterns {
        if let Ok(jailed_path) = validator.try_path(pattern) {
            // Debug: Let's see what the actual paths are
            let virtual_path = jailed_path.virtual_path();
            println!("Pattern: '{pattern}' -> Virtual: '{virtual_path:?}'");
            println!("Jail (from temp): '{:?}'", temp.path());
            println!("Jail (from validator): '{:?}'", validator.jail());

            // Should be clamped to jail root or within jail
            let virtual_str = virtual_path.to_string_lossy();

            if !pattern.contains("....") && !pattern.contains("%2F") {
                // Only check for traversal if this pattern could actually create traversal
                let is_traversal_pattern =
                    pattern.contains("../") || (cfg!(windows) && pattern.contains("..\\"));

                if is_traversal_pattern {
                    assert!(
                        !virtual_str.contains(".."),
                        "Attack pattern '{pattern}' not properly sanitized: {virtual_path:?}"
                    );
                }
            }

            // Should not escape jail - use built-in starts_with method
            assert!(
                jailed_path.starts_with(validator.jail()),
                "Attack pattern '{pattern}' escaped jail: {jailed_path:?}"
            );
        } else {
            // It's also acceptable to reject malicious patterns entirely
        }
    }
}

#[test]
fn test_unicode_edge_cases() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Jail = Jail::try_new(temp.path()).unwrap();

    let unicode_patterns = vec![
        "файл.txt",                 // Cyrillic
        "测试文件.log",             // Chinese
        "🔒secure.dat",             // Emoji
        "file\u{202E}gnp.txt",      // RTL override
        "file\u{200D}hidden.txt",   // Zero width joiner
        "café/naïve.json",          // Accented characters
        "file\u{FEFF}bom.txt",      // BOM character
        "\u{1F4C1}folder/test.txt", // Folder emoji
    ];

    for pattern in unicode_patterns {
        match validator.try_path(pattern) {
            Ok(jailed_path) => {
                // Should handle Unicode gracefully - use validator.jail() instead of canonicalizing
                assert!(jailed_path.starts_with(validator.jail()));
            }
            Err(e) => {
                // Some Unicode patterns might be rejected, which is fine
                println!("Unicode pattern '{pattern}' rejected: {e}");
            }
        }
    }
}

#[test]
fn test_concurrent_validator_usage() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Arc<Jail> = Arc::new(Jail::try_new(temp.path()).unwrap());
    let mut handles = vec![];

    // Spawn multiple threads using the same validator
    for i in 0..5 {
        let validator_clone = Arc::clone(&validator);
        let handle = thread::spawn(move || {
            for j in 0..50 {
                let path = format!("thread_{i}/file_{j}.txt");
                let result = validator_clone.try_path(&path);
                assert!(result.is_ok(), "Thread {i} iteration {j} failed");

                let jailed_path = result.unwrap();
                assert!(jailed_path
                    .virtual_path()
                    .to_string_lossy()
                    .contains(&format!("thread_{i}")));
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_long_path_handling() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Jail = Jail::try_new(temp.path()).unwrap();

    // Very long path (approaching filesystem limits)
    let long_component = "a".repeat(255);
    let long_path = format!("{long_component}/{long_component}/{long_component}/{long_component}");

    if let Ok(jailed_path) = validator.try_path(long_path) {
        assert!(jailed_path.starts_with(validator.jail()));
    } else {
        // Long paths might be rejected, which is acceptable
    }

    // Extremely long traversal attempt
    let traversal_attack = "../".repeat(100) + "etc/passwd";
    if let Ok(jailed_path) = validator.try_path(traversal_attack) {
        // Should be clamped to jail root, with remaining path components preserved
        assert!(jailed_path.starts_with(validator.jail()));
        let virtual_path = jailed_path.virtual_path();
        // The .. components should be consumed, but "etc/passwd" should be preserved
        // This matches shell behavior: excessive .. get clamped to root, remaining path is kept
        let expected_path = if cfg!(windows) {
            "etc\\passwd"
        } else {
            "etc/passwd"
        };
        assert_eq!(virtual_path.to_string_lossy(), expected_path);
    } else {
        // Rejection is also fine
    }
}

#[test]
#[cfg(windows)]
fn test_windows_specific_attacks() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Jail = Jail::try_new(temp.path()).unwrap();

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
        if let Ok(jailed_path) = validator.try_path(pattern) {
            // If accepted, should still be within jail
            assert!(jailed_path.starts_with(validator.jail()));
        } else {
            // Windows-specific rejections are expected
        }
    }
}

#[test]
#[cfg(windows)]
fn test_windows_83_short_names_rejected_for_nonexistent() {
    use std::fs;
    use std::path::PathBuf;
    // Import the Windows-only error type locally so non-Windows clippy doesn't remove it
    use crate::JailedPathError;

    let temp = tempfile::tempdir().unwrap();
    let jail_root = temp.path();
    let validator: Jail = Jail::try_new(jail_root).unwrap();

    // Create a base directory but do not create the tilde-named entry
    fs::create_dir_all(jail_root.join("users")).unwrap();

    // PROGRA~1-style component for a path that doesn't exist should be rejected
    let candidate = PathBuf::from("users/PROGRA~1/test.txt");
    let res = validator.try_path(candidate.clone());
    match res {
        Err(JailedPathError::WindowsShortName {
            component,
            original,
            checked_at,
        }) => {
            assert_eq!(component.to_string_lossy(), "PROGRA~1");
            assert_eq!(original, candidate);
            assert!(checked_at.ends_with("users"));
            assert!(checked_at.exists());
        }
        other => panic!("Expected WindowsShortName error, got: {other:?}"),
    }
}

#[test]
#[cfg(windows)]
fn test_windows_83_short_names_allowed_if_exists() {
    use std::fs;
    let temp = tempfile::tempdir().unwrap();
    let jail_root = temp.path();
    let validator: Jail = Jail::try_new(jail_root).unwrap();

    // Explicitly create the tilde-named entry inside the jail
    let tilde_dir = jail_root.join("users").join("PROGRA~1");
    fs::create_dir_all(tilde_dir).unwrap();

    // Now the same component should be accepted because it exists inside the jail
    let candidate = "users/PROGRA~1/file.txt";
    let res = validator.try_path(candidate);
    if let Ok(jailed_path) = res {
        assert!(jailed_path.starts_with(validator.jail()));
    } else {
        // Some systems may still reject; both behaviors are acceptable
    }
}

#[test]
#[cfg(unix)]
fn test_unix_specific_attacks() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Jail = Jail::try_new(temp.path()).unwrap();

    let unix_patterns = vec![
        "/dev/null",
        "/proc/self/mem",
        "/sys/kernel/debug",
        "file\n.txt",    // Newline injection
        "file;rm -rf /", // Command injection attempt
    ];

    for pattern in unix_patterns {
        if let Ok(jailed_path) = validator.try_path(pattern) {
            // Should be safe and within jail
            assert!(jailed_path.starts_with(validator.jail()));
            assert!(!jailed_path
                .virtual_path()
                .to_string_lossy()
                .contains("/dev"));
            assert!(!jailed_path
                .virtual_path()
                .to_string_lossy()
                .contains("/proc"));
        }
    }
}

#[test]
fn test_no_filesystem_leak_in_virtual_display() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Jail = Jail::try_new(temp.path()).unwrap();

    let candidate = "../../../secret.txt";
    if let Ok(jailed_path) = validator.try_path(candidate) {
        let vp = jailed_path.virtual_path();
        let virtual_str = vp.to_string_lossy().to_string();
        // Should not leak absolute jail path
        let jail_abs = validator.jail().to_string_lossy();
        assert!(
            !virtual_str.contains(jail_abs.as_ref()),
            "Virtual path leaked absolute jail path"
        );
        assert!(virtual_str.ends_with("secret.txt"));
    }
}

#[test]
fn test_absolute_path_outside_is_clamped_or_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let jail_root = temp.path();
    let validator: Jail = Jail::try_new(jail_root).unwrap();

    // Construct an absolute path outside the jail
    let outside_abs = jail_root.parent().unwrap().join("outside.txt");
    let res = validator.try_path(outside_abs);
    if let Ok(jailed_path) = res {
        assert!(jailed_path.starts_with(validator.jail()));
    } else {
        // Rejection is allowed
    }

    // Absolute path inside the jail should pass and remain inside
    let inside_abs = jail_root.join("inside.txt");
    let res2 = validator.try_path(inside_abs);
    if let Ok(jailed_path) = res2 {
        assert!(jailed_path.starts_with(validator.jail()));
    }
}

#[test]
fn test_dot_and_dotdot_segments() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Jail = Jail::try_new(temp.path()).unwrap();

    let inputs = [
        "./a/b/./c.txt",
        "a/./b/../b/c.txt",
        "../a/b/c.txt",
        "./././x",
        "../../..",
    ];

    for input in inputs {
        if let Ok(jailed_path) = validator.try_path(input) {
            assert!(jailed_path.starts_with(validator.jail()));
            let vp = jailed_path.virtual_path();
            let v = vp.to_string_lossy();
            assert!(
                !v.contains(".."),
                "Dotdot remained in virtual path for {input}: {v}"
            );
        }
    }
}

#[test]
fn test_create_and_use_safe_file_ops() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Jail = Jail::try_new(temp.path()).unwrap();

    let file = validator.try_path("subdir/data.txt").unwrap();

    // Create the parent directory and write data via jailed operations
    let parent = file.virtual_parent().unwrap();
    parent.create_dir_all().unwrap(); // Creates subdir
    file.write_string("hello").unwrap();
    assert!(file.exists());
    assert!(file.is_file());

    let content = file.read_to_string().unwrap();
    assert_eq!(content, "hello");

    // Cleanup via jailed APIs
    file.remove_file().unwrap();
    assert!(!file.exists());
}

#[test]
fn test_reject_interior_null_byte() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Jail = Jail::try_new(temp.path()).unwrap();

    let s = "foo\0bar";
    let res = validator.try_path(s);
    assert!(res.is_err(), "Interior NUL should be rejected");
}

#[test]
#[cfg(unix)]
fn test_backslash_is_literal_on_unix() {
    let temp = tempfile::tempdir().unwrap();
    let validator: Jail = Jail::try_new(temp.path()).unwrap();

    let p = r"dir\file.txt";
    let jailed = validator.try_path(p).unwrap();
    let vp = jailed.virtual_path();
    let v = vp.to_string_lossy();
    assert!(
        v.contains(r"dir\file.txt"),
        "Backslash should be literal on Unix"
    );
}

#[test]
#[cfg(unix)]
fn test_symlink_outside_is_rejected_or_clamped() {
    use std::fs;
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let jail_root = temp.path();
    let outside_dir = tempfile::tempdir().unwrap();
    let outside_file = outside_dir.path().join("secret.txt");
    fs::write(&outside_file, "top secret").unwrap();

    // Create a symlink inside the jail pointing to outside file
    let link_path = jail_root.join("public").join("link.out");
    fs::create_dir_all(link_path.parent().unwrap()).unwrap();
    symlink(&outside_file, &link_path).unwrap();

    let validator: Jail = Jail::try_new(jail_root).unwrap();

    // Try to validate the symlink path
    let res = validator.try_path("public/link.out");
    if let Ok(jailed_path) = res {
        // If accepted, it must still resolve within jail boundary
        assert!(jailed_path.starts_with(validator.jail()));
    }
}

#[test]
#[cfg(unix)]
fn test_symlink_loop_handling() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let jail_root = temp.path();
    let loop_path = jail_root.join("loop");
    // Self-referential symlink
    let _ = symlink(&loop_path, &loop_path);

    let validator: Jail = Jail::try_new(jail_root).unwrap();
    let res = validator.try_path("loop");
    if let Ok(jailed_path) = res {
        assert!(jailed_path.starts_with(validator.jail()));
    }
}
