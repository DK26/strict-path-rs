// Proof tests: demonstrate that canonicalization-based validation handles attack vectors
// that string-blocklist libraries must pattern-match individually.
//
// These inputs would require dedicated blocklist entries in a string-matching library.
// In strict-path, canonicalization resolves all of them: the OS interprets the
// path literally (percent signs, HTML entities, etc. are just characters), so they
// either map to a real path inside the boundary or fail to resolve — no blocklist needed.

use crate::{PathBoundary, StrictPathError};

// ============================================================
// Encoding attack vectors — canonicalization treats these as
// literal characters, not decoded sequences
// ============================================================

/// UTF-8 overlong encoding patterns (e.g. %c0%ae for ".") are used to bypass
/// string filters. Canonicalization never URL-decodes, so these are literal names.
#[test]
fn test_overlong_utf8_encoding_is_literal() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let overlong_payloads = [
        "%c0%ae%c0%ae/%c0%af",   // overlong ../.
        "%c0%ae%c0%ae%c0%afetc", // overlong ../etc
        "%e0%80%ae%e0%80%ae/",   // 3-byte overlong ..
        "%c1%9c",                // overlong backslash
        "%c0%2e%c0%2e",          // invalid mixed
    ];

    for attack_input in overlong_payloads {
        match boundary.strict_join(attack_input) {
            Ok(validated_path) => {
                // Accepted as a literal directory name containing percent chars
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Overlong encoding '{attack_input}' escaped boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {
                // Also acceptable — parent dir not found
            }
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

/// HTML entity encoding (&#46; = ".", &#47; = "/") could bypass web-layer
/// string filters. The filesystem treats these as literal characters.
#[test]
fn test_html_entity_encoding_is_literal() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let html_entity_payloads = [
        "&#46;&#46;&#47;etc/passwd",      // ../../etc/passwd
        "&#x2e;&#x2e;/secret",            // hex entities
        "&#46;&#46;&#47;&#46;&#46;&#47;", // double traversal
    ];

    for attack_input in html_entity_payloads {
        match boundary.strict_join(attack_input) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "HTML entity '{attack_input}' escaped boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {}
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

/// Hex escape sequences (\x2e = ".", \x2f = "/") are another encoding trick.
/// Filesystem treats backslash-x literally (on Unix) or as separator (on Windows).
#[test]
fn test_hex_escape_sequences_are_literal() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let hex_payloads = [
        "\\x2e\\x2e\\x2f",       // .../
        "\\x2e\\x2e/secret.txt", // ../secret.txt
        "\\x5c\\x2e\\x2e",       // \.
    ];

    for attack_input in hex_payloads {
        match boundary.strict_join(attack_input) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Hex escape '{attack_input}' escaped boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {}
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

// ============================================================
// Unicode attack vectors — canonicalization resolves the real
// path; exotic Unicode chars are just literal filenames
// ============================================================

/// Zero-width characters (U+200B space, U+200C non-joiner, U+FEFF BOM) could
/// be injected to create visually identical but distinct paths.
#[test]
fn test_zero_width_characters_cannot_escape() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let zero_width_payloads = [
        "safe\u{200B}file.txt",      // zero-width space in name
        "\u{200C}../..\u{200C}",     // zero-width non-joiner around traversal
        "\u{200B}../\u{200B}secret", // zero-width space around traversal
        "\u{FEFF}file.txt",          // BOM prefix
    ];

    for attack_input in zero_width_payloads {
        match boundary.strict_join(attack_input) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Zero-width char in '{attack_input}' escaped boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {}
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

/// Code-page-specific homoglyphs: ¥ (U+00A5) maps to \ in CP932 (Japanese),
/// ₩ (U+20A9) maps to \ in CP949 (Korean). Canonicalization resolves
/// the actual path — these are just Unicode characters on modern systems.
#[test]
fn test_code_page_homoglyphs_cannot_escape() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let homoglyph_payloads = [
        "..\u{00A5}..\\etc",    // ¥ (CP932 backslash)
        "..\u{20A9}..\\secret", // ₩ (CP949 backslash)
        "..\u{00B4}etc/passwd", // ´ (CP1253 forward slash)
    ];

    for attack_input in homoglyph_payloads {
        match boundary.strict_join(attack_input) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Code page homoglyph in '{attack_input}' escaped boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {}
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

// ============================================================
// Protocol scheme vectors — filesystem paths can't start with
// protocols, so canonicalization rejects or contains them
// ============================================================

/// Protocol schemes beyond file:// — HTTP, FTP, data:, etc.
/// None of these are valid relative filesystem paths.
#[test]
fn test_protocol_schemes_cannot_escape() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let protocol_payloads = [
        "http://evil.com/malware",
        "https://evil.com/payload",
        "ftp://attacker/exploit",
        "data:text/html,<script>alert(1)</script>",
        "jar:file:///tmp/evil.jar!/payload",
        "php://filter/convert.base64-encode/resource=index",
    ];

    for attack_input in protocol_payloads {
        match boundary.strict_join(attack_input) {
            Ok(validated_path) => {
                // If somehow accepted (as literal dir names), must stay in boundary
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Protocol scheme '{attack_input}' escaped boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {}
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

// ============================================================
// Whitespace exploitation — canonicalization normalizes these;
// the resolved path either exists inside the boundary or doesn't
// ============================================================

/// Tab characters, form feeds, and other exotic whitespace in path segments.
#[test]
fn test_whitespace_exploitation_cannot_escape() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let whitespace_payloads = [
        "..\t/secret",      // tab between components
        ".. /etc/passwd",   // space in traversal
        ".\t./../../etc",   // tab in dot-dot
        "safe\x0Bfile.txt", // vertical tab
        "safe\x0Cfile.txt", // form feed
    ];

    for attack_input in whitespace_payloads {
        match boundary.strict_join(attack_input) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Whitespace exploit '{attack_input}' escaped boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {}
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

// ============================================================
// Tilde expansion — canonicalization treats ~ as a literal
// character, not a home directory shortcut
// ============================================================

/// Shell-style tilde expansion should not be interpreted by the path validator.
#[test]
fn test_tilde_expansion_is_literal() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let tilde_payloads = [
        "~/secret.txt",
        "~root/.ssh/authorized_keys",
        "~admin/../../../etc/shadow",
    ];

    for attack_input in tilde_payloads {
        match boundary.strict_join(attack_input) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Tilde expansion '{attack_input}' escaped boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {}
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

// ============================================================
// Environment variable patterns — canonicalization treats
// $VAR and %VAR% as literal characters
// ============================================================

/// Environment variable syntax in paths should never be expanded.
#[test]
fn test_env_var_syntax_is_literal() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let env_payloads = [
        "$USER/.ssh/id_rsa",
        "${HOME}/secret",
        "%USERPROFILE%\\Desktop",
        "%SystemRoot%\\System32\\config\\SAM",
    ];

    for attack_input in env_payloads {
        match boundary.strict_join(attack_input) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Env var '{attack_input}' escaped boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {}
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}

// ============================================================
// Combined multi-encoding attacks — real-world attackers chain
// multiple encoding layers
// ============================================================

/// Triple encoding, mixed encoding layers, and combined attack vectors.
#[test]
fn test_multi_layer_encoding_attacks() {
    let temp = tempfile::tempdir().unwrap();
    let boundary: PathBoundary = PathBoundary::try_new(temp.path()).unwrap();

    let multi_encoding_payloads = [
        "%25252e%25252e%25252f",                 // triple URL-encoded ../
        "..%c0%af..%c0%afetc/passwd",            // overlong slash + traversal
        "..%252f..%252f..%252fetc/shadow",       // double-encoded /
        "%2e%2e%5c%2e%2e%5cetc%5cpasswd",        // URL-encoded with backslash
        "..%u002f..%u002fetc/passwd",            // Unicode %u encoding
        "\u{FF0E}\u{FF0E}/\u{FF0E}\u{FF0E}/etc", // fullwidth dots and separator
    ];

    for attack_input in multi_encoding_payloads {
        match boundary.strict_join(attack_input) {
            Ok(validated_path) => {
                assert!(
                    validated_path.strictpath_starts_with(boundary.interop_path()),
                    "Multi-encoding attack '{attack_input}' escaped boundary"
                );
            }
            Err(StrictPathError::PathEscapesBoundary { .. })
            | Err(StrictPathError::PathResolutionError { .. }) => {}
            Err(other) => panic!("Unexpected error for '{attack_input}': {other:?}"),
        }
    }
}
