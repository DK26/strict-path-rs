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

            // Note: "...." is a valid directory name, not traversal
            // Note: "%2F" is URL-encoded and treated as literal
            // Note: Windows backslash paths like "..\\..\\file" are treated as literal paths on Unix
            //       (backslashes are not path separators on Unix)
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
        }
        // Windows-specific rejections are expected
    }
}

#[test]
#[cfg(windows)]
fn test_windows_83_short_names_rejected_for_nonexistent() {
    use std::fs;
    use std::path::PathBuf;

    let temp = tempfile::tempdir().unwrap();
    let jail_root = temp.path();
    let validator: Jail = Jail::try_new(jail_root).unwrap();

    // Create a base directory but do not create the tilde-named entry
    fs::create_dir_all(jail_root.join("users")).unwrap();

    // PROGRA~1-style component for a path that doesn't exist should be rejected
    let candidate = PathBuf::from("users/PROGRA~1/test.txt");
    let res = validator.try_path(candidate);
    assert!(res.is_err(), "8.3 short name pattern should be rejected for non-existent components on Windows");
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
