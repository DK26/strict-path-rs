mod advanced_security;
mod advanced_security_bypass;
mod advanced_security_ntfs;
mod create_parent;
mod creation;
mod cve_2025_11001;
mod cve_2025_11001_archive;
mod cve_2025_11001_core;
mod filesystem;
mod filesystem_append;
mod filesystem_copy;
mod filesystem_io;
mod filesystem_metadata;
mod marker;
mod method_coverage;
mod methods;
// Linux /proc/PID/root magic symlink security tests (soft-canonicalize issue #44)
#[cfg(target_os = "linux")]
mod proc_comprehensive_coverage;
#[cfg(target_os = "linux")]
mod proc_indirect_symlink;
#[cfg(target_os = "linux")]
mod proc_magic_symlink;
#[cfg(target_os = "linux")]
mod proc_magic_symlink_regression;
#[cfg(all(target_os = "linux", feature = "virtual-path"))]
mod proc_magic_symlink_vpath;
mod read_dir_and_conversions;
mod rename;
mod security;
mod security_input_encoding;
mod security_io;
mod security_symlink_escape;
mod security_traversal;
mod symlink_following_external;
mod symlink_helpers;
mod symlink_methods;
mod symlink_resolution;
mod symlink_virtual_clamping;
#[cfg(feature = "virtual-path")]
mod virtual_display;
#[cfg(feature = "virtual-path")]
mod virtual_path_accessors;
#[cfg(windows)]
mod windows_junction_prefix;
