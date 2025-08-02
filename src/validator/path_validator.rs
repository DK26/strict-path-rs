use super::validated_path::*;
use crate::jailed_path::JailedPath;
use crate::{JailedPathError, Result};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;

/// A secure path validator that constrains all file system operations to a specific directory (jail).
///
/// **CRITICAL SECURITY RULE: All file paths MUST be validated through this validator before use.**
/// Direct use of `Path`, `PathBuf`, or string paths for file operations bypasses all security guarantees.
///
/// ## Core Purpose
///
/// This validator is the **ONLY** way to create `JailedPath` instances. It prevents directory traversal
/// attacks by ensuring all validated paths remain within the specified jail directory boundary.
///
/// ## How It Works (Simple)
///
/// 1. **Set Jail Boundary**: Create validator with `PathValidator::with_jail("/safe/directory")`
/// 2. **Validate Paths**: Call `validator.try_path("user/input/path")` for every path
/// 3. **Use Safely**: Only use the returned `JailedPath` for file operations
/// 4. **Security**: Attempts to escape (like `../../../etc/passwd`) are automatically prevented
///
/// ## Security Features
///
/// - **Path Traversal Protection**: Neutralizes `../`, `./`, and absolute paths that try to escape
/// - **Symlink Resolution**: Resolves symbolic links and validates their targets stay within jail
/// - **Cross-Platform**: Works consistently on Windows, macOS, and Linux
/// - **Non-Existent Path Support**: Can validate paths for file creation (paths don't need to exist)
///
/// ## Examples
///
/// ```rust
/// use jailed_path::PathValidator;
/// use jailed_path::JailedPathError;
/// use std::fs;
/// use tempfile::tempdir;
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let temp_dir = tempdir()?;
///     let jail_path = temp_dir.path();
///     fs::create_dir_all(jail_path.join("uploads"))?;
///     fs::write(jail_path.join("uploads/existing_file.txt"), "test")?;
///     let validator = PathValidator::<()>::with_jail(jail_path.join("uploads"))?;
///
///     // Existing files work
///     let _path = validator.try_path("existing_file.txt")?;
///
///     // Non-existent files for writing also work  
///     let _path = validator.try_path("user123/new_document.pdf")?;
///
///     // Traversal attacks are clamped to the jail root (no error is returned)
///     let _ = validator.try_path("../../../sensitive.txt")?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PathValidator<Marker = ()> {
    jail: Arc<ValidatedPath<(Raw, Canonicalized)>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> PathValidator<Marker> {
    /// Like try_path, but normalizes all backslashes to slashes before validation.
    /// Use this for any external or untrusted string path to ensure cross-platform consistency.
    #[inline]
    pub fn try_path_normalized(&self, path_str: &str) -> Result<JailedPath<Marker>> {
        let normalized = path_str.replace('\\', "/");
        self.try_path(normalized)
    }

    /// Creates a new PathValidator with the specified jail directory.
    ///
    /// **This is the FIRST step in secure path validation - create your validator once and reuse it.**
    ///
    /// # Arguments
    /// * `jail` - The directory that will serve as the security boundary. All validated paths
    ///   must remain within this directory and its subdirectories.
    ///
    /// # Returns
    /// * `Ok(PathValidator)` - If the jail is valid
    /// * `Err(JailedPathError)` - If validation fails (see Errors section)
    ///
    /// # Errors
    /// This method returns an error in the following cases:
    ///
    /// ## `JailedPathError::PathResolutionError`
    /// - Permission denied when accessing the jail path
    /// - The jail path contains invalid characters or exceeds system limits
    /// - I/O errors during path canonicalization
    ///
    /// ## `JailedPathError::InvalidJail`
    /// - The jail path exists but is not a directory (e.g., it's a file or special device)
    ///
    /// # Important Notes
    /// - The jail directory does NOT need to exist when creating the validator
    /// - Store this validator and reuse it for all path validations in your application
    /// - Never bypass this validator - it's your only protection against path traversal attacks
    ///
    /// # Examples
    /// ```rust
    /// use jailed_path::PathValidator;
    /// use jailed_path::JailedPathError;
    /// use std::fs;
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     fs::create_dir_all("valid_jail")?;
    ///     // ✅ Valid jail directory
    ///     let _validator = PathValidator::<()>::with_jail("valid_jail")?;
    ///
    ///     // Non-existent directory is allowed (validator is created)
    ///     let _ = PathValidator::<()>::with_jail("does_not_exist")?;
    ///
    ///     fs::write("not_a_dir.txt", "content")?;
    ///     // ❌ Path exists but is not a directory
    ///     assert!(PathValidator::<()>::with_jail("not_a_dir.txt").is_err());
    ///     fs::remove_file("not_a_dir.txt").ok();
    ///     fs::remove_dir_all("valid_jail").ok();
    ///     Ok(())
    /// }
    /// ```
    pub fn with_jail<P: AsRef<Path>>(jail: P) -> Result<Self> {
        let jail_path = jail.as_ref();
        let validated_path = ValidatedPath::<Raw>::new(jail_path);
        let canonicalized = validated_path.canonicalize()?;

        if canonicalized.exists() && !canonicalized.is_dir() {
            let error = std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "The specified jail path exists but is not a directory.",
            );
            return Err(JailedPathError::invalid_jail(
                jail_path.to_path_buf(),
                error,
            ));
        }

        Ok(Self {
            jail: Arc::new(canonicalized),
            _marker: PhantomData,
        })
    }

    /// Validates a user-provided path and returns a secure `JailedPath` for file operations.
    ///
    /// **This is the SECOND step in secure path validation - call this for EVERY user path.**
    ///
    /// # Arguments
    /// * `candidate_path` - The path to validate (from user input, configuration, etc.)
    ///
    /// # Returns
    /// * `Ok(JailedPath)` - A validated path that is guaranteed safe to use for file operations
    /// * `Err(JailedPathError)` - If the path cannot be made safe (usually symlink escapes)
    ///
    /// # Security Process (Automatic)
    ///
    /// 1. **Path Traversal Protection**: Converts `../../../etc/passwd` → safely contained within jail
    /// 2. **Symlink Resolution**: Resolves all symbolic links and verifies they stay within jail  
    /// 3. **Boundary Enforcement**: Ensures final path is within the jail directory
    ///
    /// # What Gets Fixed vs Rejected
    ///
    /// **✅ FIXED (No Error)**: Basic traversal attempts like `../`, `./`, absolute paths
    /// **❌ REJECTED (Error)**: Symbolic links that point outside the jail directory
    ///
    /// # Common Usage
    /// - Validating file upload paths from users
    /// - Validating configuration file paths  
    /// - ANY path before file operations (read, write, create, delete)
    ///
    /// # Example
    /// ```rust
    /// use jailed_path::PathValidator;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let validator = PathValidator::<()>::with_jail("/safe/uploads")?;
    ///
    /// // ✅ Safe - creates /safe/uploads/user123/document.pdf
    /// let safe_path = validator.try_path("user123/document.pdf")?;
    ///
    /// // ✅ Safe - traversal attempt blocked, becomes /safe/uploads/
    /// let blocked = validator.try_path("../../../etc/passwd")?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>> {
        // STEP 1: Clamp the candidate path
        let clamped = ValidatedPath::<Raw>::new(candidate_path.as_ref()).clamp();

        // STEP 2: Join to jail root (type-state: ((Raw, Clamped), JoinedJail))
        let joined = clamped.join_jail(&self.jail);

        // STEP 3: Canonicalize (type-state: (((Raw, Clamped), JoinedJail), Canonicalized))
        let canon = joined.canonicalize()?;

        // STEP 4: Boundary check (type-state: ((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked))
        let checked = canon.boundary_check(&self.jail)?;

        Ok(JailedPath::new(self.jail.clone(), checked))
    }

    #[inline]
    pub fn jail(&self) -> &Path {
        &self.jail
    }
}
