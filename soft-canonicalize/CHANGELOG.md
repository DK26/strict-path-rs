# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-07-18

### Added
- Initial release of `soft-canonicalize` crate
- `soft_canonicalize()` function for pure path canonicalization
- Support for non-existing paths through logical path resolution
- Cross-platform compatibility (Windows, macOS, Linux)
- Comprehensive test suite with 7 test cases covering:
  - Existing path canonicalization
  - Non-existing path handling
  - Deep nested non-existing paths
  - Relative path resolution
  - Directory traversal (`..`) component handling
  - Mixed existing/non-existing path resolution
  - Root boundary traversal protection
- Zero-dependency implementation using only std
- Security-focused algorithm with mathematical path resolution
- Comprehensive documentation with examples
- Basic usage example demonstrating all major features
- Security demo example showing directory traversal prevention

### Features
- **Pure Algorithm**: No filesystem modification during canonicalization
- **Directory Traversal Security**: Logical resolution of `..` components before filesystem access
- **Symlink Resolution**: Proper handling of symlinks in existing path portions
- **Performance**: O(n) time complexity with minimal filesystem access
- **Cross-Platform**: Handles Windows drive letters, UNC paths, and Unix absolute paths
- **Zero-Cost**: Minimal memory overhead with efficient path processing

### Documentation
- Comprehensive README with usage examples
- API documentation with detailed algorithm explanation
- Security considerations and best practices
- Performance characteristics and complexity analysis
- Cross-platform compatibility notes
- Comparison with existing canonicalization solutions
