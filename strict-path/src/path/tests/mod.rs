mod advanced_security;
mod create_parent;
mod creation;
mod cve_2025_11001;
mod filesystem;
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
mod read_dir_and_conversions;
mod rename;
mod security;
mod symlink_methods;
#[cfg(feature = "virtual-path")]
mod virtual_display;
#[cfg(feature = "virtual-path")]
mod virtual_path_accessors;
#[cfg(windows)]
mod windows_junction_prefix;
