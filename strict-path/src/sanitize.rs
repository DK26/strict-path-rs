//! Shared sanitization for untrusted strings crossing display/log boundaries.

/// Replace dangerous Unicode characters with `_` for safe Display output.
///
/// WHY: strict-path display surfaces are often embedded in user-facing channels
/// (HTTP responses, logs, terminal prints). The following categories are
/// injection primitives:
/// - C0 controls (< 0x20): `\n`/`\r` CRLF splitting, `\x1b` ANSI escapes, NUL
/// - DEL (0x7F): terminal erase behavior on some emulators
/// - C1 controls (0x80-0x9F): U+0085 NEL acts as newline in HTTP/XML/log parsers
/// - U+2028/U+2029 (Line/Paragraph Separator): ECMAScript line terminators
/// - Unicode directional overrides (U+202A-U+202E, U+2066-U+2069, U+200E/U+200F):
///   visually reverse filename characters, enabling extension-spoofing attacks
/// - `;` (semicolon): shell command separator; display output may feed downstream shell readers
#[inline]
pub(crate) fn sanitize_untrusted_display_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let cp = ch as u32;
        let needs_replace = ch == ';'
            || cp < 0x20
            || cp == 0x7F
            || (0x80..=0x9F).contains(&cp)
            || cp == 0x2028
            || cp == 0x2029
            || cp == 0x200E
            || cp == 0x200F
            || (0x202A..=0x202E).contains(&cp)
            || (0x2066..=0x2069).contains(&cp);
        if needs_replace {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sanitize_untrusted_display_text;

    #[test]
    fn preserves_plain_text() {
        assert_eq!(
            sanitize_untrusted_display_text("safe/path-_.txt"),
            "safe/path-_.txt"
        );
    }

    #[test]
    fn scrubs_each_injection_character_class() {
        let dangerous = [
            '\n',       // C0 newline
            '\r',       // C0 carriage return
            '\x1b',     // C0 ANSI escape
            '\x7f',     // DEL
            '\u{0085}', // C1 NEL
            '\u{009b}', // C1 CSI
            '\u{2028}', // line separator
            '\u{2029}', // paragraph separator
            '\u{200e}', // left-to-right mark
            '\u{200f}', // right-to-left mark
            '\u{202e}', // right-to-left override
            '\u{2066}', // left-to-right isolate
            ';',        // shell separator
        ];

        let input: String = dangerous.iter().collect();
        let expected = "_".repeat(dangerous.len());

        assert_eq!(sanitize_untrusted_display_text(&input), expected);
    }
}
