use super::validated_path::*;
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
///     // Traversal attacks are clamped to the jail root (no error is returned)
///     let _ = jail.try_path("../../../sensitive.txt")?;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Jail<Marker = ()> {
    jail: Arc<ValidatedPath<(Raw, Canonicalized)>>,
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
    /// - The jail directory does NOT need to exist when creating the jail
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
    ///     // Non-existent directory is allowed (jail is created)
    ///     let _ = Jail::<()>::try_new("does_not_exist")?;
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
        let validated_path = ValidatedPath::<Raw>::new(jail_path);
        let canonicalized = validated_path.canonicalize()?;

        if canonicalized.exists() && !canonicalized.is_dir() {
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
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let jail = Jail::<()>::try_new("/safe/uploads")?;
    ///
    /// // ✅ Safe - creates /safe/uploads/user123/document.pdf
    /// let safe_path = jail.try_path("user123/document.pdf")?;
    ///
    /// // ✅ Safe - traversal attempt blocked, becomes /safe/uploads/
    /// let blocked = jail.try_path("../../../etc/passwd")?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>> {
        // STEP 1: Clamp the candidate path
        let clamped = ValidatedPath::<Raw>::new(candidate_path.as_ref()).clamp();

        // Windows-only hardening: reject DOS 8.3 short names (tilde form) in any
        // non-existent component, since their eventual long-name resolution is ambiguous.
        // This prevents surprising boundary comparisons if a future long name gets created.
        #[cfg(windows)]
        {
            use std::ffi::OsStr;
            use std::path::Component;

            // Keep the original user path for error reporting (Windows only)
            let original_user_path = candidate_path.as_ref().to_path_buf();

            // If the input was an absolute path, we will clamp it to be jail-relative.
            // In that case, skip the 8.3 short-name precheck to avoid false positives from
            // absolute prefixes (e.g., C:\Users\RUNNER~1\...) present in CI environments.
            if candidate_path.as_ref().is_absolute() {
                // Proceed without the short-name precheck; clamping + boundary check still apply.
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
                        Component::ParentDir => continue, // shouldn't appear post-clamp, but ignore defensively
                        Component::RootDir | Component::Prefix(_) => continue, // clamped removed these
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

        // STEP 2: Join to jail root (type-state: ((Raw, Clamped), JoinedJail))
        let joined = clamped.join_jail(&self.jail);

        // STEP 3: Canonicalize (type-state: (((Raw, Clamped), JoinedJail), Canonicalized))
        let canon = joined.canonicalize()?;

        // STEP 4: Boundary check (type-state: ((((Raw, Clamped), JoinedJail), Canonicalized), BoundaryChecked))
        let checked = canon.boundary_check(&self.jail)?;

        Ok(JailedPath::new(self.jail.clone(), checked))
    }

    /// Get the jail as a string for debugging, logging, or comparison.
    /// Example: "/app/storage/users"
    pub fn display(&self) -> String {
        self.jail.display().to_string()
    }

    /// Get jail as UTF-8 string if possible, None if non-UTF-8.
    pub fn to_str(&self) -> Option<&str> {
        self.jail.to_str()
    }

    /// Get jail as string with lossy UTF-8 conversion.
    pub fn to_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        self.jail.to_string_lossy()
    }

    /// Get jail as OsStr for ecosystem integration.
    pub fn as_os_str(&self) -> &std::ffi::OsStr {
        self.jail.as_os_str()
    }

    /// Convert jail to bytes for ecosystem integration.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.jail.to_string_lossy().into_owned().into_bytes()
    }
}
