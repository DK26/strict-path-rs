use crate::Jail;
use std::sync::Arc;
use std::thread;

#[test]
fn test_known_cve_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();

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
        if let Ok(jailed_path) = jail.try_path(pattern) {
            let virtual_path = jailed_path.clone().virtualize();
            let virtual_os_str = virtual_path.virtualpath_as_os_str();
            let virtual_str = virtual_os_str.to_string_lossy();

            if !pattern.contains("....") && !pattern.contains("%2F") {
                let is_traversal_pattern =
                    pattern.contains("../") || (cfg!(windows) && pattern.contains("..\\\\"));

                if is_traversal_pattern {
                    assert!(
                        !virtual_str.contains(".."),
                        "Attack pattern '{pattern}' not properly sanitized: {virtual_os_str:?}"
                    );
                }
            }

            assert!(
                jailed_path.starts_with_real(jail.path()),
                "Attack pattern '{pattern}' escaped jail: {jailed_path:?}"
            );
        }
    }
}

#[test]
fn test_unicode_edge_cases() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();

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
        match jail.try_path(pattern) {
            Ok(jailed_path) => {
                assert!(jailed_path.starts_with_real(jail.path()));
            }
            Err(_e) => {
                // Rejections are acceptable; test ensures no panics and no escapes
            }
        }
    }
}

#[test]
fn test_concurrent_validator_usage() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Arc<Jail> = Arc::new(Jail::try_new(temp.path()).unwrap());
    let mut handles = vec![];

    for i in 0..5 {
        let jail_clone = Arc::clone(&jail);
        let handle = thread::spawn(move || {
            for j in 0..50 {
                let path = format!("thread_{i}/file_{j}.txt");
                let result = jail_clone.try_path(&path);
                assert!(result.is_ok(), "Thread {i} iteration {j} failed");

                let jailed_path = result.unwrap();
                let virtual_path = jailed_path.virtualize();
                assert!(format!("{virtual_path}").contains(&format!("/thread_{i}")));
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_long_path_handling() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();

    let long_component = "a".repeat(64);
    let long_path = format!("{long_component}/{long_component}/{long_component}/{long_component}",);

    if let Ok(jailed_path) = jail.try_path(long_path) {
        assert!(jailed_path.starts_with_real(jail.path()));
    }

    let traversal_attack = "../".repeat(10) + "etc/passwd";
    if let Ok(jailed_path) = jail.try_path(traversal_attack) {
        assert!(jailed_path.starts_with_real(jail.path()));
        let virtual_path = jailed_path.virtualize();
        let virtual_os_str = virtual_path.virtualpath_as_os_str();
        let expected_path = "/etc/passwd";
        assert_eq!(virtual_os_str.to_string_lossy(), expected_path);
    }
}

#[test]
#[cfg(windows)]
fn test_windows_specific_attacks() {
    let temp = tempfile::tempdir().unwrap();
    let jail: Jail = Jail::try_new(temp.path()).unwrap();

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
        if let Ok(jailed_path) = jail.try_path(pattern) {
            assert!(jailed_path.starts_with_real(jail.path()));
        }
    }
}
