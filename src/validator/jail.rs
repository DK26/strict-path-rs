use super::stated_path::*;
use crate::jailed_path::JailedPath;
use crate::{JailedPathError, Result};
use std::io::{Error as IoError, ErrorKind};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;

/// A secure jail that constrains all file system operations to a specific directory.
///
/// **CRITICAL SECURITY RULE: All file paths MUST be validated through this jail before use.**
/// Direct use of `Path`, `PathBuf`, or string paths for file operations bypasses all security guarantees.
///
/// ## Core Purpose
///
/// This jail is the **ONLY** way to create `JailedPath` instances. It prevents directory traversal
/// attacks by ensuring all validated paths remain within the specified jail directory boundary.
///
/// ## How It Works (Simple)
///
/// 1. **Set Jail Boundary**: Create jail with `Jail::try_new("/safe/directory")`
/// 2. **Validate Paths**: Call `jail.try_path("user/input/path")` for every path
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
/// use jailed_path::Jail;
/// use jailed_path::JailedPathError;
/// use std::fs;
/// use tempfile::tempdir;
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let temp_dir = tempdir()?;
///     let jail_path = temp_dir.path();
///     fs::create_dir_all(jail_path.join("uploads"))?;
///     fs::write(jail_path.join("uploads/existing_file.txt"), "test")?;
///     let jail = Jail::<()>::try_new(jail_path.join("uploads"))?;
///
///     // Existing files work
///     let _path = jail.try_path("existing_file.txt")?;
///
///     // Non-existent files for writing also work  
///     let _path = jail.try_path("user123/new_document.pdf")?;
///
///     // Traversal attacks have their roots stripped and are then canonicalized (no error is returned)
///     let _ = jail.try_path("../../../sensitive.txt")?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Jail<Marker = ()> {
    jail: Arc<StatedPath<((Raw, Canonicalized), Exists)>>,
    _marker: PhantomData<Marker>,
}

impl<Marker> Jail<Marker> {
    /// Creates a new Jail with the specified directory boundary.
    ///
    /// **This is the FIRST step in secure path validation - create your jail once and reuse it.**
    ///
    /// # Arguments
    /// * `jail_path` - The directory that will serve as the security boundary. All validated paths
    ///   must remain within this directory and its subdirectories.
    ///
    /// # Returns
    /// * `Ok(Jail)` - If the jail is valid
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
    /// - The jail directory MUST exist when calling `Jail::try_new`. The API now
    ///   canonicalizes and verifies the path exists to avoid surprising runtime
    ///   errors later in the validation pipeline.
    /// - Store this jail and reuse it for all path validations in your application
    /// - Never bypass this jail - it's your only protection against path traversal attacks
    ///
    /// # Examples
    /// ```rust
    /// use jailed_path::Jail;
    /// use jailed_path::JailedPathError;
    /// use std::fs;
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     fs::create_dir_all("valid_jail")?;
    ///     // ✅ Valid jail directory
    ///     let _jail = Jail::<()>::try_new("valid_jail")?;
    ///
    ///     // ❌ Non-existent directory will fail
    ///     assert!(Jail::<()>::try_new("does_not_exist").is_err());
    ///
    ///     fs::write("not_a_dir.txt", "content")?;
    ///     // ❌ Path exists but is not a directory
    ///     assert!(Jail::<()>::try_new("not_a_dir.txt").is_err());
    ///     fs::remove_file("not_a_dir.txt").ok();
    ///     fs::remove_dir_all("valid_jail").ok();
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn try_new<P: AsRef<Path>>(jail_path: P) -> Result<Self> {
        let jail_path = jail_path.as_ref();
        let raw = StatedPath::<Raw>::new(jail_path);

        let canonicalized = raw.canonicalize()?;

        let verified_exists = match canonicalized.verify_exists() {
            Some(path) => path,
            None => {
                let io = IoError::new(
                    ErrorKind::NotFound,
                    "The specified jail path does not exist.",
                );
                return Err(JailedPathError::invalid_jail(jail_path.to_path_buf(), io));
            }
        };

        if !verified_exists.is_dir() {
            let error = IoError::new(
                ErrorKind::InvalidInput,
                "The specified jail path exists but is not a directory.",
            );
            return Err(JailedPathError::invalid_jail(
                jail_path.to_path_buf(),
                error,
            ));
        }

        Ok(Self {
            jail: Arc::new(verified_exists),
            _marker: PhantomData,
        })
    }

    /// Create a new jail, creating the directory if it doesn't exist.
    ///
    /// This is an explicit alternative to `try_new()` for cases where you want
    /// to create the jail directory structure. Use this when you need to ensure
    /// the jail directory exists and are comfortable with directory creation.
    ///
    /// # Security Considerations
    ///
    /// - Creates parent directories as needed with `std::fs::create_dir_all()`
    /// - Only use when directory creation is intentional and safe
    /// - Avoid in production containers where filesystem should be read-only
    /// - Prevents typos in jail paths (unlike `try_new()` which requires existing dirs)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use jailed_path::Jail;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Create jail directory if it doesn't exist
    /// let jail = Jail::<()>::try_new_create("app/user_uploads")?;
    /// let file = jail.try_path("user123/avatar.jpg")?;
    /// # std::fs::remove_dir_all("app").ok();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `JailedPathError::Io` if:
    /// - Directory creation fails due to permissions
    /// - Path exists but is not a directory
    /// - Filesystem is read-only or full
    /// - Invalid path characters (platform-specific)
    pub fn try_new_create<P: AsRef<Path>>(root: P) -> Result<Self> {
        let root_path = root.as_ref();

        // Create the directory (and parents) if it doesn't exist
        if !root_path.exists() {
            std::fs::create_dir_all(root_path)
                .map_err(|e| JailedPathError::invalid_jail(root_path.to_path_buf(), e))?;
        }

        // Now use the standard try_new() logic for validation
        Self::try_new(root_path)
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
    /// 4. **Windows-only Hardening**: Early precheck rejects non-existent components that look like
    ///    DOS 8.3 short names (e.g., `PROGRA~1`), returning a specialized error variant so the caller
    ///    can choose a recovery strategy. Existing short-name components inside the jail are allowed.
    ///
    /// # What Gets Fixed vs Rejected
    ///
    /// **✅ FIXED (No Error)**: Basic traversal attempts like `../`, `./`, absolute paths
    /// **❌ REJECTED (Error)**: Symbolic links that point outside the jail directory
    ///
    /// On Windows, non-existent components resembling 8.3 short names are also rejected with
    /// `JailedPathError::WindowsShortName`.
    ///
    /// # Common Usage
    /// - Validating file upload paths from users
    /// - Validating configuration file paths  
    /// - ANY path before file operations (read, write, create, delete)
    ///
    /// # Example
    /// ```rust
    /// use jailed_path::Jail;
    /// use std::fs;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Create a temporary directory for the example
    /// fs::create_dir_all("safe_uploads")?;
    /// let jail = Jail::<()>::try_new("safe_uploads")?;
    ///
    /// // ✅ Safe - creates safe_uploads/user123/document.pdf
    /// let safe_path = jail.try_path("user123/document.pdf")?;
    ///
    /// // ✅ Safe - traversal attempt blocked, becomes safe_uploads/
    /// let blocked = jail.try_path("../../../etc/passwd")?;
    ///
    /// fs::remove_dir_all("safe_uploads").ok();
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>> {
        // STEP 1: Strip root components from the candidate path
        let clamped = StatedPath::<Raw>::new(candidate_path.as_ref()).virtualize();

        // Windows-only hardening: reject DOS 8.3 short names (tilde form) in any
        // non-existent component, since their eventual long-name resolution is ambiguous.
        // This prevents surprising boundary comparisons if a future long name gets created.
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::path::Component;

            // Keep the original user path for error reporting (Windows only)
            let original_user_path = candidate_path.as_ref().to_path_buf();

            // If the input was an absolute path, we will strip roots to make it jail-relative.
            // In that case, skip the 8.3 short-name precheck to avoid false positives from
            // absolute prefixes (e.g., C:\Users\RUNNER~1\...) present in CI environments.
            if candidate_path.as_ref().is_absolute() {
                // Proceed without the short-name precheck; root stripping + boundary check still apply.
            } else {
                fn is_potential_83_short_name(os: &OsStr) -> bool {
                    let s = os.to_string_lossy();
                    // Heuristic: presence of '~' followed by at least one ASCII digit
                    if let Some(pos) = s.find('~') {
                        s[pos + 1..]
                            .chars()
                            .next()
                            .is_some_and(|ch| ch.is_ascii_digit())
                    } else {
                        false
                    }
                }

                // Build up from the canonicalized jail path and check which components don't exist.
                let mut probe = self.jail.as_ref().to_path_buf();
                for comp in clamped.components() {
                    match comp {
                        Component::CurDir => continue,
                        Component::ParentDir => continue, // shouldn't appear post-root-strip, but ignore defensively
                        Component::RootDir | Component::Prefix(_) => continue, // root stripping removed these
                        Component::Normal(name) => {
                            probe.push(name);
                            if !probe.exists() && is_potential_83_short_name(name) {
                                // Emit specialized error so callers can decide recovery
                                // checked_at is the parent directory where this component would live
                                let mut checked_at = probe.clone();
                                let _ = checked_at.pop();
                                return Err(JailedPathError::windows_short_name(
                                    name.to_os_string(),
                                    original_user_path,
                                    checked_at,
                                ));
                            }
                            // Once a non-existent component is found, all following components are also non-existent.
                            // We still scan remaining components to catch additional tilde segments, but we do not need
                            // to touch the filesystem for them.
                        }
                    }
                }
            }
        }

        // STEP 2: Join to jail root (type-state: ((Raw, RootStripped), JoinedJail))
        let joined = clamped.join_jail(&self.jail);

        // STEP 3: Canonicalize (type-state: (((Raw, RootStripped), JoinedJail), Canonicalized))
        let canon = joined.canonicalize()?;

        // STEP 4: Boundary check (type-state: ((((Raw, RootStripped), JoinedJail), Canonicalized), BoundaryChecked))
        let checked = canon.boundary_check(&self.jail)?;

        Ok(JailedPath::new(self.jail.clone(), checked))
    }

    /// Returns a reference to the jail's root path.
    ///
    /// This provides a safe, read-only way to access the jail's boundary for logging,
    /// assertions, or integration with other APIs that need a `&Path`.
    ///
    /// # Security
    ///
    /// This is **safe** to expose because the `Jail` itself is just a validator. The real
    /// security guarantee comes from the `JailedPath` type, which can only be created
    /// through validation and does not expose its internal path.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use jailed_path::Jail;
    /// # use std::path::Path;
    /// # use std::fs;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// fs::create_dir_all("app_storage")?;
    /// let jail = Jail::<()>::try_new("app_storage")?;
    /// let jailed_path = jail.try_path("user/file.txt")?;
    ///
    /// // Use the jail's path for assertions or logging
    /// assert!(jailed_path.starts_with_real(jail.path()));
    /// println!("Jail is located at: {}", jail.path().display());
    /// fs::remove_dir_all("app_storage").ok();
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn path(&self) -> &Path {
        &self.jail
    }
}

impl<Marker> std::fmt::Display for Jail<Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path().display())
    }
}
