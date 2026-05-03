use super::*;
use std::io;
use std::path::{Path, PathBuf};

#[test]
fn truncate_path_display_preserves_short_paths() {
    let path = Path::new("safe/path.txt");
    let rendered = truncate_path_display(path, 256);
    assert_eq!(rendered, path.to_string_lossy());
}

#[test]
fn truncate_path_display_scrubs_log_injection_characters() {
    let path = Path::new("safe/\nforged\r\x1b[2J\u{0085}\u{202e};tail.txt");
    let rendered = truncate_path_display(path, 256);

    for forbidden in ['\n', '\r', '\x1b', '\u{0085}', '\u{202e}', ';'] {
        assert!(
            !rendered.contains(forbidden),
            "error path display leaked injection character U+{:04X}: {:?}",
            forbidden as u32,
            rendered
        );
    }
}

#[test]
fn truncate_path_display_inserts_ellipsis_for_long_paths() {
    let segment = "verylongcomponent".repeat(20);
    let path = PathBuf::from(format!("/root/{segment}/tail.txt"));
    let max_len = 48;
    let rendered = truncate_path_display(&path, max_len);
    assert!(rendered.chars().count() <= max_len);
    assert!(rendered.contains("..."));
}

#[test]
fn strict_path_error_sources_are_reported() {
    let invalid = StrictPathError::InvalidRestriction {
        restriction: PathBuf::from("/root"),
        source: io::Error::other("boom"),
    };
    assert!(invalid.source().is_some());

    let resolution = StrictPathError::PathResolutionError {
        path: PathBuf::from("/root/file"),
        source: io::Error::other("fail"),
    };
    assert!(resolution.source().is_some());

    let escape = StrictPathError::PathEscapesBoundary {
        attempted_path: PathBuf::from("/escape"),
        restriction_boundary: PathBuf::from("/root"),
    };
    assert!(escape.source().is_none());
}

#[test]
fn path_escape_display_mentions_attempt_and_boundary() {
    let error = StrictPathError::PathEscapesBoundary {
        attempted_path: PathBuf::from("/tmp/attempt"),
        restriction_boundary: PathBuf::from("/tmp/restriction"),
    };
    let rendered = error.to_string();
    assert!(rendered.contains("escapes"));
    assert!(rendered.contains("restriction boundary"));
    assert!(rendered.contains("/tmp/attempt"));
    assert!(rendered.contains("/tmp/restriction"));
}

#[test]
fn strict_path_error_display_scrubs_untrusted_paths() {
    let malicious_path = PathBuf::from("/tmp/evil\nFORGED\r\x1b[2J\u{0085}\u{202e};.txt");
    let cases = [
        StrictPathError::InvalidRestriction {
            restriction: malicious_path.clone(),
            source: io::Error::other("invalid\nSOURCE;"),
        },
        StrictPathError::PathResolutionError {
            path: malicious_path.clone(),
            source: io::Error::other("resolution\rSOURCE;"),
        },
        StrictPathError::PathEscapesBoundary {
            attempted_path: malicious_path,
            restriction_boundary: PathBuf::from("/tmp/root\rFORGED"),
        },
    ];

    for error in cases {
        let rendered = error.to_string();
        for forbidden in ['\n', '\r', '\x1b', '\u{0085}', '\u{202e}', ';'] {
            assert!(
                !rendered.contains(forbidden),
                "StrictPathError display leaked injection character U+{:04X}: {:?}",
                forbidden as u32,
                rendered
            );
        }
    }
}
