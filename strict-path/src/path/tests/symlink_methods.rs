// This file has been split into thematic submodules. All tests have been moved to:
//   symlink_helpers.rs           - Junction/symlink/hard-link creation helpers, metadata, escape rejection
//   symlink_virtual_clamping.rs  - Virtual symlink/hard-link/copy/rename with absolute path clamping
//   symlink_following_external.rs - Following symlinks/junctions pointing outside the virtual root
