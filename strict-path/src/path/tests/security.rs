// This file has been split into thematic submodules. All tests have been moved to:
//   security_traversal.rs       - CVE patterns, unicode, concurrent, long path, Windows attacks
//   security_symlink_escape.rs  - Symlink/junction escape, TOCTOU, zip/tar slip extraction
//   security_input_encoding.rs  - Mixed separators, non-UTF8, deep traversal, Windows edge cases
//   security_io.rs              - I/O operations (append/write/read) through symlinks, circular symlinks
