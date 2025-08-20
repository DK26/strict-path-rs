use super::stated_path::*;
use crate::jailed_path::JailedPath;
use crate::{JailedPathError, Result};
#[cfg(windows)]
use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[cfg(windows)]
fn is_potential_83_short_name(os: &OsStr) -> bool {
    let s = os.to_string_lossy();
    // Heuristic: presence of '~' followed by at least one ASCII digit
    if let Some(pos) = s.find('~') {
        // FIXME: Fix this smelly code to use the type system
        s[pos + 1..]
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit())
    } else {
        false
    }
}

pub(crate) fn validate<Marker>(
    path: impl AsRef<Path>,
    jail: &Jail<Marker>,
) -> Result<JailedPath<Marker>> {
    #[cfg(windows)]
    {
        // Keep the original user path for error reporting (Windows only)
        let original_user_path = path.as_ref().to_path_buf();

        // Skip the precheck for absolute inputs to avoid false positives from system/CI prefixes
        if !path.as_ref().is_absolute() {
            // Build up from the jail root so we can report the parent directory where a suspect
            // component would live (checked_at). Pushing components does not access the FS.
            let mut probe = jail.path().to_path_buf();

            for comp in path.as_ref().components() {
                match comp {
                    Component::CurDir | Component::ParentDir => continue,
                    Component::RootDir | Component::Prefix(_) => continue,
                    Component::Normal(name) => {
                        // If the component looks like an 8.3 short name (tilde + digit),
                        // reject early and return the specialized error with the parent dir.
                        if is_potential_83_short_name(name) {
                            return Err(JailedPathError::windows_short_name(
                                name.to_os_string(),
                                original_user_path,
                                probe.clone(), // parent directory where this component would live
                            ));
                        }
                        // advance probe for the next component
                        probe.push(name);
                    }
                }
            }
        }
    }

    // Treat incoming paths as system-facing: do not virtualize/clamp here.
    // Virtualization (clamping to the virtual root) is the responsibility of
    // `VirtualRoot::try_path_virtual`.
    //
    // Important: interpret relative candidate paths as jail-relative. Previously
    // canonicalizing a relative path would resolve it against the process
    // working directory (CWD), which could cause valid jail-relative paths to
    // appear outside the jail. Instead, join the candidate against the jail
    // root before canonicalization so validation happens in the jail namespace.
    let target_path = if path.as_ref().is_absolute() {
        path.as_ref().to_path_buf()
    } else {
        jail.path().join(path.as_ref())
    };

    let validated_path = StatedPath::<Raw>::new(target_path)
        .canonicalize()?
        .boundary_check(jail.as_ref())?;

    // JailedPath stores an Arc<Jail> internally; allocate a new Arc here by cloning the
    // inner `Arc<StatedPath<...>>` and constructing a fresh `Jail` value so we don't
    // require `Marker: Clone` on the `Jail` type itself.
    Ok(JailedPath::new(
        Arc::new(Jail {
            path: jail.path.clone(),
            _marker: PhantomData,
        }),
        validated_path,
    ))
}

/// Make sure provided path is always inside the jail, which behaves as a virtual root
pub(crate) fn virtualize_to_jail<Marker>(path: impl AsRef<Path>, jail: &Jail<Marker>) -> PathBuf {
    use std::ffi::OsString;
    // If the caller provided an absolute path that already lives inside the jail,
    // return it unchanged to avoid joining the jail twice (double-virtualization).
    // If the caller provided an absolute path that already lives inside the jail
    // and does not contain any `..` or `.` components, return it unchanged to
    // avoid joining the jail twice (double-virtualization). If it contains
    // parent or current-dir components, fall through and normalize/clamp so
    // traversal attempts are handled safely.
    if path.as_ref().is_absolute() && path.as_ref().starts_with(jail.path()) {
        let mut has_parent_or_cur = false;
        for comp in path.as_ref().components() {
            if matches!(comp, Component::ParentDir | Component::CurDir) {
                has_parent_or_cur = true;
                break;
            }
        }
        if !has_parent_or_cur {
            return path.as_ref().to_path_buf();
        }
    }
    let mut normalized = PathBuf::new();
    let mut depth = 0i32; // Track how deep we are from the jail root
    let components = path.as_ref().components();
    let _is_abs_input = path.as_ref().is_absolute();
    #[cfg(unix)]
    let is_abs_input = _is_abs_input;
    // Remove all root components (RootDir, Prefix) and implement clamping
    for comp in components {
        match comp {
            Component::RootDir | Component::Prefix(_) => continue, // Strip absolute paths
            Component::CurDir => continue, // Skip current directory references
            Component::ParentDir => {
                // Clamping: if we're below jail root, go up; otherwise ignore
                if depth > 0 {
                    normalized.pop();
                    depth -= 1;
                }
            }
            Component::Normal(name) => {
                // Convert component to string for inspection/sanitization.
                let s = name.to_string_lossy();

                // If the original input was an absolute system path, rewrite
                // common system prefixes to a safe external marker so the
                // virtual display cannot be mistaken for raw system locations.
                #[cfg(unix)]
                {
                    if is_abs_input && (s == "dev" || s == "proc" || s == "sys") {
                        let mut safe = OsString::from("__external__");
                        safe.push(s.as_ref());
                        normalized.push(safe);
                        depth += 1;
                        continue;
                    }
                }

                // Sanitize dangerous characters commonly used in injections
                // (apply for both absolute and relative inputs).
                let cleaned = s.replace(['\n', ';'], "_");
                if cleaned != s {
                    normalized.push(OsString::from(cleaned));
                    depth += 1;
                    continue;
                }

                normalized.push(name);
                depth += 1;
            }
        }
    }

    // join against the jail root path
    jail.path().join(normalized)
}

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
/// use jailed_path::VirtualRoot;
/// use jailed_path::JailedPathError;
/// use std::fs;
/// use tempfile::tempdir;
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let temp_dir = tempdir()?;
///     let jail_path = temp_dir.path();
///     fs::create_dir_all(jail_path.join("uploads"))?;
///     fs::write(jail_path.join("uploads/existing_file.txt"), "test")?;
///     let jail = Jail::<()>::try_new(jail_path.join("uploads"))?;
///     let vroot = VirtualRoot::<()>::try_new(jail_path.join("uploads"))?;
///
///     // Existing files work
///     let _path = jail.try_path("existing_file.txt")?;
///
///     // Non-existent files for writing also work  
///     let _path = jail.try_path("user123/new_document.pdf")?;
///
///     // Traversal attacks should be clamped by the user-facing `VirtualRoot`.
///     // `Jail::try_path` is system-facing and will reject attempts that escape the jail.
///     let blocked = vroot.try_path_virtual("../../../sensitive.txt")?;
///     let _jailed = blocked.unvirtual();
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Jail<Marker = ()> {
    path: Arc<StatedPath<((Raw, Canonicalized), Exists)>>,
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
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    /// # }
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
            path: Arc::new(verified_exists),
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
    /// use jailed_path::{Jail, VirtualRoot};
    /// use std::fs;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Create a temporary directory for the example
    /// fs::create_dir_all("safe_uploads")?;
    /// let jail = Jail::<()>::try_new("safe_uploads")?;
    /// let vroot = VirtualRoot::<()>::try_new("safe_uploads")?;
    ///
    /// // ✅ Safe - creates safe_uploads/user123/document.pdf (system-facing)
    /// let safe_path = jail.try_path("user123/document.pdf")?;
    ///
    /// // ✅ User-facing traversal attempts should be clamped using VirtualRoot
    /// let blocked = vroot.try_path_virtual("../../../etc/passwd")?;
    /// let jailed = blocked.unvirtual();
    /// assert!(jailed.starts_with_real(jail.path()));
    ///
    /// fs::remove_dir_all("safe_uploads").ok();
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn try_path<P: AsRef<Path>>(&self, candidate_path: P) -> Result<JailedPath<Marker>> {
        // System-facing: directly validate the provided path (canonicalize + boundary_check).
        // IMPORTANT: do NOT virtualize here — virtualization/clamping belongs to
        // `VirtualRoot::try_path_virtual`. Callers that need user-style semantics
        // should call that API instead.
        validate(candidate_path, self)
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
        // Directly access the inner Arc<StatedPath<...>> and convert to `&Path`.
        // This is idiomatic inside the impl and avoids verbose fully-qualified
        // trait calls in this hot path.
        self.path.as_ref().as_ref()
    }

    // Note: direct access to the inner Arc is available via `self.path.clone()`.
    // The previous `inner_arc()` helper was removed because calling `self.path.clone()`
    // is clear and idiomatic; keep `Jail`'s fields encapsulated but clonable.

    // prefer `path()` to access the jail root as a `&Path`.
}

impl<Marker> std::fmt::Display for Jail<Marker> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path().display())
    }
}

impl<Marker> AsRef<Path> for Jail<Marker> {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

// Allow the `validator` to borrow the inner `StatedPath` via `AsRef` so
// code like `jail.as_ref()` yields `&StatedPath<...>` when used inside the
// validator module. This keeps `StatedPath` usage internal but convenient
// for functions that operate on it.
impl<Marker> AsRef<StatedPath<((Raw, Canonicalized), Exists)>> for Jail<Marker> {
    fn as_ref(&self) -> &StatedPath<((Raw, Canonicalized), Exists)> {
        self.path.as_ref()
    }
}
