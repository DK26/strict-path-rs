//! Marker transformation demo
//!
//! Demonstrates how to escalate permissions type-safely using `StrictPath::change_marker`
//! after authenticating a user.

use std::fmt;

use strict_path::{PathBoundary, StrictPath};

// Domain marker: describes what filesystem contents are stored
#[derive(Clone, Copy)]
struct ProjectDocuments;

// Permission markers: represent the current permission level (not accumulation)
#[derive(Clone, Copy)]
struct ReadOnly; // Can only read

#[derive(Clone, Copy)]
struct ReadWrite; // Can read and write (supersedes ReadOnly)

#[derive(Clone, Copy)]
struct AdminAccess; // Can read, write, and delete (supersedes ReadWrite)

#[derive(Clone, Copy)]
enum Role {
    Reader,
    Writer,
    Admin,
}

#[derive(Clone)]
struct AuthenticatedUser {
    name: String,
    role: Role,
}

impl AuthenticatedUser {
    fn new(name: &str, role: Role) -> Self {
        Self {
            name: name.to_string(),
            role,
        }
    }

    fn can_read(&self) -> bool {
        matches!(self.role, Role::Reader | Role::Writer | Role::Admin)
    }

    fn can_write(&self) -> bool {
        matches!(self.role, Role::Writer | Role::Admin)
    }

    fn is_admin(&self) -> bool {
        matches!(self.role, Role::Admin)
    }
}

#[derive(Debug)]
struct AccessDenied {
    action: &'static str,
    user: String,
}

impl AccessDenied {
    fn new(action: &'static str, user: &AuthenticatedUser) -> Self {
        Self {
            action,
            user: user.name.clone(),
        }
    }
}

impl fmt::Display for AccessDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} may not perform {}", self.user, self.action)
    }
}

impl std::error::Error for AccessDenied {}

type AccessResult<T> = Result<T, AccessDenied>;

fn authenticate_user(
    user: &AuthenticatedUser,
    path: StrictPath<ProjectDocuments>,
) -> AccessResult<StrictPath<(ProjectDocuments, ReadOnly)>> {
    if user.can_read() {
        Ok(path.change_marker())
    } else {
        Err(AccessDenied::new("read", user))
    }
}

fn authorize_writer(
    path: StrictPath<(ProjectDocuments, ReadOnly)>,
    user: &AuthenticatedUser,
) -> AccessResult<StrictPath<(ProjectDocuments, ReadWrite)>> {
    if user.can_write() {
        Ok(path.change_marker()) // Escalate from ReadOnly to ReadWrite
    } else {
        Err(AccessDenied::new("write", user))
    }
}

fn authorize_admin(
    path: StrictPath<(ProjectDocuments, ReadWrite)>,
    user: &AuthenticatedUser,
) -> AccessResult<StrictPath<(ProjectDocuments, AdminAccess)>> {
    if user.is_admin() {
        Ok(path.change_marker()) // Escalate from ReadWrite to AdminAccess
    } else {
        Err(AccessDenied::new("admin override", user))
    }
}

fn read_document(path: &StrictPath<(ProjectDocuments, ReadOnly)>) -> std::io::Result<String> {
    path.read_to_string()
}

fn write_document(
    path: &StrictPath<(ProjectDocuments, ReadWrite)>,
    contents: &str,
) -> std::io::Result<()> {
    path.write(contents)
}

fn delete_document(path: &StrictPath<(ProjectDocuments, AdminAccess)>) -> std::io::Result<()> {
    path.remove_file()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let boundary: PathBoundary<ProjectDocuments> = PathBoundary::try_new_create(tmp.path())?;
    let requested = "projects/roadmap.md";

    let base_path: StrictPath<ProjectDocuments> = boundary.strict_join(requested)?;
    base_path.create_parent_dir_all()?;
    base_path.write("Q4 roadmap draft\n")?;

    let reader = AuthenticatedUser::new("Alex", Role::Reader);
    let reader_scope = authenticate_user(&reader, base_path.clone())?;
    println!(
        "{} has read-only access to {}",
        reader.name,
        reader_scope.strictpath_display()
    );
    if let Err(err) = authorize_writer(reader_scope, &reader) {
        println!("{} denied escalation: {}", reader.name, err);
    }

    let writer = AuthenticatedUser::new("Riley", Role::Writer);
    let writer_reader_scope = authenticate_user(&writer, base_path.clone())?;
    let original = read_document(&writer_reader_scope)?;
    println!(
        "{} reads {} ({} bytes)",
        writer.name,
        writer_reader_scope.strictpath_display(),
        original.len()
    );

    let writer_scope = authorize_writer(writer_reader_scope, &writer)?;
    write_document(&writer_scope, "Q4 roadmap draft\n- updated by writer\n")?;
    println!("{} updated the roadmap", writer.name);

    if let Err(err) = authorize_admin(writer_scope.clone(), &writer) {
        println!("{} denied escalation: {}", writer.name, err);
    }

    let admin = AuthenticatedUser::new("Morgan", Role::Admin);
    let admin_reader = authenticate_user(&admin, base_path)?;
    let admin_writer = authorize_writer(admin_reader, &admin)?;
    let admin_scope = authorize_admin(admin_writer, &admin)?;
    println!(
        "{} removing {}",
        admin.name,
        admin_scope.strictpath_display()
    );
    delete_document(&admin_scope)?;

    Ok(())
}
