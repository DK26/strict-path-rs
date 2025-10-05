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
        source: io::Error::new(io::ErrorKind::Other, "boom"),
    };
    assert!(invalid.source().is_some());

    let resolution = StrictPathError::PathResolutionError {
        path: PathBuf::from("/root/file"),
        source: io::Error::new(io::ErrorKind::Other, "fail"),
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
    assert!(rendered.contains("escapes path restriction boundary"));
    assert!(rendered.contains("/tmp/attempt"));
    assert!(rendered.contains("/tmp/restriction"));
}
