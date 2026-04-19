//! F6 — `virtualpath_display` leaks Unicode injection characters above 0x7F.
//!
//! `sanitize_display_component` only covers C0 controls (< 0x20), DEL (0x7F),
//! and `;`.  Characters above 0x7F that are still dangerous in user-facing
//! output are NOT scrubbed:
//!
//!   - C1 controls (U+0080–U+009F): U+0085 NEL acts as a newline in HTTP,
//!     XML, and many log parsers — enabling log/header injection.
//!   - U+2028 LINE SEPARATOR / U+2029 PARAGRAPH SEPARATOR: ECMAScript treats
//!     these as line terminators, so they break embedded JSON strings and can
//!     cause XSS when a virtual path is serialised into a `<script>` block.
//!   - Unicode directional overrides (U+202A–U+202E, U+2066–U+2069, U+200E/U+200F):
//!     RIGHT-TO-LEFT OVERRIDE (U+202E) visually reverses filename characters,
//!     enabling "Trojan Source"-style extension spoofing: a file named
//!     `exec\u{202e}txt.` is displayed as `exec.txt` while its real extension
//!     is different.
//!
//! All tests in this file are **initially failing** — they document the missing
//! sanitization.  Add the relevant code points to `sanitize_display_component`
//! in `virtual_path/mod.rs` to make them pass.

#[cfg(feature = "virtual-path")]
use crate::VirtualRoot;

// ---------------------------------------------------------------------------
// Helper: build a VirtualPath with the given (non-existent) name component
// and return the display string.
// ---------------------------------------------------------------------------

#[cfg(feature = "virtual-path")]
fn display_of(name: &str) -> String {
    let td = tempfile::tempdir().unwrap();
    let vroot: VirtualRoot = VirtualRoot::try_new(td.path()).unwrap();
    let vpath = vroot.virtual_join(name).unwrap();
    vpath.virtualpath_display().to_string()
}

// ---------------------------------------------------------------------------
// F6-A  C1 control characters (U+0080–U+009F)
// ---------------------------------------------------------------------------

/// U+0085 NEXT LINE (NEL) is treated as a newline by HTTP parsers, XML, and
/// many structured-log consumers.  A filename containing it must be scrubbed.
#[cfg(feature = "virtual-path")]
#[test]
fn f6a_virtualpath_display_scrubs_nel_u0085() {
    let display = display_of("foo\u{0085}bar");
    assert!(
        !display.contains('\u{0085}'),
        "virtualpath_display leaked U+0085 NEL (acts as newline in HTTP/XML): {:?}",
        display
    );
}

/// Spot-check several more C1 controls that are injection-capable in specific
/// contexts (CRLF surrogates, ANSI look-alikes).
#[cfg(feature = "virtual-path")]
#[test]
fn f6a_virtualpath_display_scrubs_c1_range() {
    // U+008D (REVERSE LINE FEED), U+008F (SINGLE SHIFT THREE), U+0090 (DCS),
    // U+009B (CSI — C1 ANSI escape introducer), U+009C (STRING TERMINATOR)
    for &cp in &[0x008Du32, 0x008F, 0x0090, 0x009B, 0x009C] {
        let ch = char::from_u32(cp).unwrap();
        let name = format!("foo{ch}bar");
        let display = display_of(&name);
        assert!(
            !display.contains(ch),
            "virtualpath_display leaked C1 control U+{:04X} in {:?}",
            cp,
            display
        );
    }
}

// ---------------------------------------------------------------------------
// F6-B  ECMAScript line terminators (U+2028 / U+2029)
// ---------------------------------------------------------------------------

/// U+2028 LINE SEPARATOR is a line terminator in ECMAScript. When a virtual
/// path is JSON-serialised into a `<script>` tag, this character breaks the
/// string literal and may enable XSS.
#[cfg(feature = "virtual-path")]
#[test]
fn f6b_virtualpath_display_scrubs_line_separator_u2028() {
    let display = display_of("foo\u{2028}bar");
    assert!(
        !display.contains('\u{2028}'),
        "virtualpath_display leaked U+2028 LINE SEPARATOR: {:?}",
        display
    );
}

/// U+2029 PARAGRAPH SEPARATOR has the same ECMAScript line-terminator status.
#[cfg(feature = "virtual-path")]
#[test]
fn f6b_virtualpath_display_scrubs_paragraph_separator_u2029() {
    let display = display_of("foo\u{2029}bar");
    assert!(
        !display.contains('\u{2029}'),
        "virtualpath_display leaked U+2029 PARAGRAPH SEPARATOR: {:?}",
        display
    );
}

// ---------------------------------------------------------------------------
// F6-C  Unicode directional override / embedding characters
// ---------------------------------------------------------------------------

/// U+202E RIGHT-TO-LEFT OVERRIDE visually reverses following characters.
/// A filename `"exec\u{202e}txt."` renders as `"exec.txt"` in many terminals
/// and file managers while the actual bytes are `"exec\u{202e}txt."`.  This is
/// the "Trojan Source" class of attack (CVE-2021-42574 analogue for filenames).
#[cfg(feature = "virtual-path")]
#[test]
fn f6c_virtualpath_display_scrubs_right_to_left_override_u202e() {
    let display = display_of("exec\u{202e}txt.");
    assert!(
        !display.contains('\u{202e}'),
        "virtualpath_display leaked U+202E RIGHT-TO-LEFT OVERRIDE (Trojan Source): {:?}",
        display
    );
}

/// Cover the full directional embedding/override range U+202A–U+202E.
#[cfg(feature = "virtual-path")]
#[test]
fn f6c_virtualpath_display_scrubs_directional_embedding_range() {
    for cp in 0x202Au32..=0x202E {
        let ch = char::from_u32(cp).unwrap();
        let name = format!("a{ch}b");
        let display = display_of(&name);
        assert!(
            !display.contains(ch),
            "virtualpath_display leaked directional char U+{:04X} in {:?}",
            cp,
            display
        );
    }
}

/// Cover the Unicode directional isolate range U+2066–U+2069 (LRI, RLI, FSI, PDI).
#[cfg(feature = "virtual-path")]
#[test]
fn f6c_virtualpath_display_scrubs_directional_isolate_range() {
    for cp in 0x2066u32..=0x2069 {
        let ch = char::from_u32(cp).unwrap();
        let name = format!("a{ch}b");
        let display = display_of(&name);
        assert!(
            !display.contains(ch),
            "virtualpath_display leaked directional isolate U+{:04X} in {:?}",
            cp,
            display
        );
    }
}

/// U+200F RIGHT-TO-LEFT MARK and U+200E LEFT-TO-RIGHT MARK alter text direction
/// without being visible glyphs, causing subtle display corruption.
#[cfg(feature = "virtual-path")]
#[test]
fn f6c_virtualpath_display_scrubs_directional_marks() {
    for &cp in &[0x200Eu32, 0x200F] {
        let ch = char::from_u32(cp).unwrap();
        let name = format!("file{ch}.txt");
        let display = display_of(&name);
        assert!(
            !display.contains(ch),
            "virtualpath_display leaked directional mark U+{:04X} in {:?}",
            cp,
            display
        );
    }
}
