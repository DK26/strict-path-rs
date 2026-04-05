// Tests for mixed separators, percent encoding, non-UTF8 input, deep traversal clamping,
// Unicode separator/dot lookalikes, embedded NULs, and Windows-specific edge cases
// (ADS, reserved names, NT path prefixes, UNC/verbatim paths, drive-relative paths).

#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;
#[cfg(feature = "virtual-path")]
use crate::{PathBoundary, StrictPathError};

#[cfg(feature = "virtual-path")]
#[test]
fn test_mixed_separators_and_encoded_inputs() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // These are odd strings a user/attacker might pass in
    // Mixed separators and encoded inputs; display is always forward-slashed.
    // The first case differs by platform: on Windows, backslash is a separator; on Unix, it's a character.
    let mut cases = vec![
        ("a//b////c", "/a/b/c"),
        ("./././d", "/d"),
        ("b/%2e%2e/c", "/b/%2e%2e/c"), // percent-encoded is not decoded by us
        ("\u{202E}rtl.txt", "/\u{202E}rtl.txt"),
    ];
    if cfg!(windows) {
        cases.insert(0, ("a\\b/../c.txt", "/a/c.txt"));
    } else {
        cases.insert(0, ("a\\b/../c.txt", "/c.txt"));
    }

    for (inp, expected_prefix) in cases {
        let vp = vroot
            .virtual_join(inp)
            .expect("join should clamp to PathBoundary");
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
        let virtual_display = vp.virtualpath_display().to_string();
        assert!(virtual_display.starts_with(expected_prefix), "{inp} => {virtual_display}");
    }
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(unix)]
fn test_non_utf8_component_handling() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Make a non-UTF8 name like b"bad\xFFname"
    let raw = OsStr::from_bytes(b"bad\xFFname");
    let vp = vroot
        .virtual_join(raw)
        .expect("non-utf8 should be acceptable at Path level");
    assert!(vp
        .as_unvirtual()
        .strictpath_starts_with(vroot.interop_path()));
}

#[cfg(feature = "virtual-path")]
#[test]
fn test_super_deep_traversal_clamps_to_root() {
    let td = tempfile::tempdir().unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(td.path()).unwrap();

    // Lots of parent components should clamp to virtual root
    let deep = "../".repeat(50) + "a/b";
    let vp = vroot
        .virtual_join(&deep)
        .expect("deep traversal should clamp");
    assert_eq!(vp.virtualpath_display().to_string(), "/a/b");
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_trailing_dots_spaces() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Windows normalizes trailing dots/spaces at FS layer; we only ensure clamping
    let cases = vec!["dir.\\file.", "dir \\file ", "con.\\nul "];

    for c in cases {
        let vp = vroot.virtual_join(c).expect("should clamp to PathBoundary");
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
    }
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_ads_and_reserved_names() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // We don't try to write these; just ensure containment or clean error.
    let cases = vec![
        "file.txt:stream",
        "file.txt::$DATA",
        "CON",
        "NUL",
        "AUX",
        "COM1",
        "LPT1",
    ];

    for c in cases {
        match vroot.virtual_join(c) {
            Ok(vp) => assert!(vp
                .as_unvirtual()
                .strictpath_starts_with(vroot.interop_path())),
            Err(_e) => { /* acceptable: rejected safely */ }
        }
    }
}

// White-box: Windows namespace escapes should be rejected by virtual join.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_unc_and_verbatim_escape_rejected() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("PathBoundary");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Treat these as virtual-rooted requests; ensure the result stays inside the restriction.
    let cases = vec![
        "\\\\server\\share\\sensitive.txt",
        "\\\\?\\C:\\Windows\\System32\\config\\SAM",
        "\\\\.\\PhysicalDrive0\\nul",
    ];

    for b in cases {
        let vp = vroot
            .virtual_join(b)
            .expect("absolute/namespace input should be clamped to PathBoundary");
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
    }
}

// White-box: Windows drive-relative paths (e.g., "C:..\\foo") must not enable escape.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_drive_relative_rejected() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("PathBoundary");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Drive-relative forms must not escape; we clamp and allow inside the restriction.
    let candidates = vec!["C:..\\Windows", "D:..\\..\\temp\\file.txt"];
    for c in candidates {
        let vp = vroot
            .virtual_join(c)
            .expect("drive-relative input should be clamped to PathBoundary");
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
    }
}

// White-box: Windows NT path prefix variants should be clamped to the restriction.
#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_windows_nt_prefix_variants_clamped() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    let cases = vec![
        r"\\??\\C:\\Windows\\System32\\config\\SAM",
        r"\\??\\UNC\\server\\share\\sensitive.txt",
    ];

    for c in cases {
        match vroot.virtual_join(c) {
            Ok(vp) => {
                assert!(vp
                    .as_unvirtual()
                    .strictpath_starts_with(vroot.interop_path()));
                // Virtual display remains rooted and forward-slashed.
                let v = vp.virtualpath_display().to_string();
                assert!(v.starts_with('/'));
                assert!(!v.contains("\\\\??\\\\"));
            }
            Err(_e) => {
                // Clean rejection is acceptable
            }
        }
    }
}

// Black-box: Unicode SEPARATOR lookalikes (fraction slash, fullwidth solidus, etc.) must
// not be interpreted as path separators for traversal. Verifies the README claim
// "Unicode normalization bypasses (..∕..∕etc∕passwd)".
#[cfg(feature = "virtual-path")]
#[test]
fn test_unicode_separator_lookalikes_do_not_traverse() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let restriction: PathBoundary = PathBoundary::try_new(&restriction_dir).unwrap();
    let vroot: VirtualRoot<()> = VirtualRoot::try_new(&restriction_dir).unwrap();

    // U+2215 DIVISION SLASH ∕
    // U+2044 FRACTION SLASH ⁄
    // U+FF0F FULLWIDTH SOLIDUS ／
    // U+29F8 BIG SOLIDUS ⧸
    // These look like `/` but must NOT be treated as separators for traversal.
    let separator_lookalike_attacks: &[(&str, &str)] = &[
        (
            "..\u{2215}..\u{2215}etc\u{2215}passwd",
            "DIVISION SLASH U+2215",
        ),
        (
            "..\u{2044}..\u{2044}etc\u{2044}passwd",
            "FRACTION SLASH U+2044",
        ),
        (
            "..\u{FF0F}..\u{FF0F}etc\u{FF0F}passwd",
            "FULLWIDTH SOLIDUS U+FF0F",
        ),
        (
            "..\u{29F8}..\u{29F8}etc\u{29F8}passwd",
            "BIG SOLIDUS U+29F8",
        ),
        // Mixed: real `..` with Unicode separators
        (
            "..\u{2215}etc/passwd",
            "mixed DIVISION SLASH and real slash",
        ),
    ];

    for (attack_input, description) in separator_lookalike_attacks {
        // StrictPath: must either contain within boundary or reject cleanly
        match restriction.strict_join(attack_input) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(restriction.interop_path()),
                    "Unicode separator attack '{description}' escaped boundary: {validated_path:?}"
                );
                // The path should treat Unicode separators as literal filename characters
                // (not as directory separators), so no traversal occurs.
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Clean rejection is also acceptable
            }
            Err(other) => panic!("Unexpected error for '{description}': {other:?}"),
        }

        // VirtualPath: must clamp within boundary
        match vroot.virtual_join(attack_input) {
            Ok(virtual_path) => {
                assert!(
                    virtual_path
                        .as_unvirtual()
                        .strictpath_starts_with(vroot.interop_path()),
                    "Virtual join for '{description}' escaped boundary"
                );
                let display = virtual_path.virtualpath_display().to_string();
                assert!(
                    display.starts_with('/'),
                    "Virtual display must be rooted for '{description}': {display}"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Clean rejection also acceptable
            }
            Err(other) => panic!("Unexpected virtual error for '{description}': {other:?}"),
        }
    }
}

// Black-box: Unicode dot lookalikes should not be treated as traversal; ensure clamping.
#[cfg(feature = "virtual-path")]
#[test]
fn test_unicode_dot_lookalike_does_not_traverse() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // U+2024 (One Dot Leader) and U+FF0E (Fullwidth Full Stop)
    let cases = vec![
        (
            "dir/\u{2024}\u{2024}/file.txt".to_string(),
            "/dir/\u{2024}\u{2024}/file.txt".to_string(),
        ),
        (
            "dir/\u{FF0E}\u{FF0E}/file.txt".to_string(),
            "/dir/\u{FF0E}\u{FF0E}/file.txt".to_string(),
        ),
    ];

    for (inp, expected_virtual_prefix) in cases {
        let vp = vroot
            .virtual_join(&inp)
            .expect("join should clamp to PathBoundary");
        assert!(vp
            .as_unvirtual()
            .strictpath_starts_with(vroot.interop_path()));
        let virtual_display = vp.virtualpath_display().to_string();
        assert!(
            virtual_display.starts_with(&expected_virtual_prefix),
            "{inp} => {virtual_display}"
        );
    }
}

// White-box: Embedded NUL should not enable escapes. We don't perform I/O here.
#[cfg(feature = "virtual-path")]
#[test]
fn test_embedded_nulls_are_not_exploitable() {
    use std::ffi::{OsStr, OsString};

    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Construct an OsString with an embedded NUL in a platform-portable way
    // On Rust, OsString can hold a NUL; any filesystem I/O may fail, so we avoid I/O.
    let mut s = OsString::from("prefix");
    s.push(OsStr::new("\u{0000}"));
    s.push(OsStr::new("suffix.txt"));

    match vroot.virtual_join(&s) {
        Ok(vp) => {
            assert!(vp
                .as_unvirtual()
                .strictpath_starts_with(vroot.interop_path()));
            // Do not attempt to write/read; just ensure virtual view is rooted
            let virtual_display = vp.virtualpath_display().to_string();
            assert!(virtual_display.starts_with('/'));
        }
        Err(_e) => {
            // Acceptable: embedded NUL rejected safely
        }
    }
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_winrar_ads_traversal_payload_is_clamped() {
    // Simulate the CVE-2025-8088-like payload: an ADS stream name with traversal
    // e.g., "decoy.txt:..\\..\\evil.exe". Ensure it cannot escape the PathBoundary and
    // does not create files outside the restriction. If ADS is unsupported, we accept
    // a clean error, but still verify no escape occurred.

    let td = tempfile::tempdir().unwrap();
    let base = td.path();
    let restriction_dir = base.join("PathBoundary");
    let outside_dir = base.join("outside");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // Ensure the decoy file exists (ADS writes typically require the base file)
    let decoy = vroot.virtual_join("decoy.txt").expect("join decoy");
    decoy.write("decoy").unwrap();

    // The malicious entry name used by attackers
    let payload = "decoy.txt:..\\..\\evil.exe";
    let vp = vroot
        .virtual_join(payload)
        .expect("ADS payload should be clamped to PathBoundary");

    // Must remain within the PathBoundary from a system path perspective
    assert!(vp
        .as_unvirtual()
        .strictpath_starts_with(vroot.interop_path()));

    // Attempt to write the payload; on NTFS this writes an ADS on decoy.txt.
    // On filesystems without ADS support this may error; both outcomes are acceptable
    // as long as no file is created outside the restriction.
    match vp.write("malware-bytes") {
        Ok(()) => {
            // Optional: attempt to read the ADS back to confirm write stayed attached to decoy
            let read_back = vp.read_to_string();
            if let Ok(contents) = read_back {
                assert_eq!(contents, "malware-bytes");
            }
        }
        Err(_e) => {
            // Acceptable on filesystems without ADS support
        }
    }

    // Critical assertion: no file named 'evil.exe' appears outside the PathBoundary
    assert!(!outside_dir.join("evil.exe").exists());
    assert!(!base.join("evil.exe").exists());

    // And nothing escaped to the filesystem root of the temp hierarchy either
    assert!(!restriction_dir.join("..\\evil.exe").exists());

    // The virtual display should remain rooted and not contain raw drive paths
    let virtual_display = vp.virtualpath_display().to_string();
    assert!(
        virtual_display.starts_with('/'),
        "virtual path must be rooted: {virtual_display}"
    );
}

#[cfg(feature = "virtual-path")]
#[test]
#[cfg(windows)]
fn test_winrar_like_edge_cases() {
    let td = tempfile::tempdir().unwrap();
    let restriction_dir = td.path().join("j");
    std::fs::create_dir_all(&restriction_dir).unwrap();
    let vroot: crate::VirtualRoot<()> = crate::VirtualRoot::try_new(&restriction_dir).unwrap();

    // WinRAR-adjacent tricky names: ensure clamping or safe rejection.
    let cases: &[&str] = &[
        // Device/global roots and odd prefixes
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\etc\\hosts",
        // Forward-slash drive and single-leading-backslash (absolute on Windows)
        "C:/Windows/System32/config/SAM",
        "\\Windows\\System32\\drivers\\etc\\hosts",
        // UNC with double forward slashes
        "//server/share/boot.ini",
        // Startup-like and ProgramData-like targets (social engineering payloads)
        "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/payload.lnk",
        "ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/payload.vbs",
        // Deep traversal mixed with separators
        "..\\..//Windows/../Temp/evil.dll",
    ];

    for c in cases {
        match vroot.virtual_join(c) {
            Ok(vp) => {
                assert!(
                    vp.as_unvirtual()
                        .strictpath_starts_with(vroot.interop_path()),
                    "escaped PathBoundary for input: {c} -> {}",
                    vp.as_unvirtual().strictpath_to_string_lossy()
                );
                // Nothing should point to real system locations; it's virtual-rooted
                let v = vp.virtualpath_display().to_string();
                assert!(v.starts_with('/'), "virtual must be rooted: {v}");
            }
            Err(_e) => {
                // Clean rejection also acceptable; key is no escape.
            }
        }
    }

    // Also validate that creating parents stays inside the PathBoundary when allowed
    let ok = "ProgramData/MyApp/Updates/update.bin";
    let vp = vroot.virtual_join(ok).expect("should clamp");
    vp.create_parent_dir_all().expect("create parents");
    assert!(vp
        .as_unvirtual()
        .strictpath_starts_with(vroot.interop_path()));
}
