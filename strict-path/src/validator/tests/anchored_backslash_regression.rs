#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
#[test]
fn anchored_canonicalize_missing_backslash_regression() {
    // Recreate conditions that previously produced a malformed verbatim drive path
    // of the form "\\\\?\\C:Users\\..." (missing a backslash after the drive colon).
    // We call soft_canonicalize::anchored_canonicalize directly to capture the raw output
    // (our crate wraps this with a normalization guard).

    let tmp = tempfile::tempdir().unwrap();
    let anchor = std::fs::canonicalize(tmp.path()).unwrap();
    // Candidate with a leading root (absolute-like in virtual semantics)
    let candidate = Path::new("/data/dir");

    let raw = soft_canonicalize::anchored_canonicalize(&anchor, candidate)
        .expect("anchored canonicalize should succeed");
    let s = raw.to_string_lossy();

    // Detect malformed verbatim drive form: "\\\\?\\<Drive>:<not a backslash>..."
    let mut observed_bug = false;
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 3 && (b[0] as char).is_ascii_alphabetic() && b[1] == b':' {
            // If bug exists, b[2] will not be a backslash
            if b[2] != b'\\' && b[2] != b'/' {
                observed_bug = true;
            }
        }
    }

    // Fail the test if the upstream bug is present so it can be tracked visibly.
    assert!(
        !observed_bug,
        "soft-canonicalize::anchored_canonicalize returned malformed verbatim drive path: raw='{s}'"
    );

    // Regardless of upstream behavior, our wrapper must normalize to a correct form.
    // Call through our normalized wrapper and assert the result has a backslash after the colon.
    let boundary: crate::PathBoundary = crate::PathBoundary::try_new(tmp.path()).unwrap();
    let anchored = crate::validator::path_history::PathHistory::new(candidate.to_path_buf())
        .canonicalize_anchored(&boundary)
        .expect("normalized anchored canonicalize must succeed");
    let fixed = anchored.to_string_lossy();
    if let Some(rest) = fixed.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 3 && (b[0] as char).is_ascii_alphabetic() && b[1] == b':' {
            assert_eq!(
                b[2], b'\\',
                "normalized path must have backslash after drive colon: {fixed}"
            );
        }
    }

    // Additional safety: ensure normalized path is correct when not failing above.
}
