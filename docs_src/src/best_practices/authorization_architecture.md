# Authorization Architecture with Markers

> *Move authorization bugs from "runtime disasters" into "won't compile" problems.*

Marker types enable **compile-time authorization architectures** where the compiler mathematically proves that any path with an authorization-requiring marker went through proper authorization.

This chapter shows three levels of authorization patterns: basic authentication, permission tuples, and dynamic elevation.

---

## Core Concept: Markers as Proof

**Key insight**: A marker with a private field can **only be constructed** by authorized code. Functions requiring that marker have compile-time proof that authorization happened.

```rust,no_run
struct UserHome { 
    _proof: ()  // Private field = can't construct outside this module
}

// This function signature enforces authentication
fn read_user_file(file: &strict_path::StrictPath<UserHome>) -> std::io::Result<String> {
    // Guaranteed: path is validated AND user was authenticated
    file.read_to_string()
}
```

**Without a `UserHome` marker, you cannot call `read_user_file()`.** The compiler enforces this.

---

## Level 1: Basic Authentication Markers

Use markers with private fields to prove authentication happened.

### Implementation

```rust,no_run
use strict_path::{PathBoundary, StrictPath};

// Marker describes user's home directory with compile-time proof
struct UserHome { 
    _proof: ()  // Private field prevents construction outside this module
}

impl UserHome {
    /// Authenticates user and returns authorization marker
    pub fn authenticate(token: &AuthToken) -> Result<Self, AuthError> {
        // Real authentication logic here (verify JWT, session, etc.)
        if verify_token(token)? {
            Ok(UserHome { _proof: () })  // Grant marker after verification
        } else {
            Err(AuthError::InvalidToken)
        }
    }
}

// Functions require pre-authorized paths
fn read_user_file(file: &StrictPath<UserHome>) -> std::io::Result<String> {
    // Guaranteed: path is safe AND user was authenticated
    file.read_to_string()
}

fn list_user_files(dir: &PathBoundary<UserHome>) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in dir.strict_join("")?.read_dir()? {
        let entry = entry?;
        names.push(entry.file_name().to_string_lossy().to_string());
    }
    Ok(names)
}

// Usage: authentication required to get marker
fn handle_request(
    token: &AuthToken,
    filename: &str
) -> Result<String, Box<dyn std::error::Error>> {
    // Authentication checkpoint
    let _auth = UserHome::authenticate(token)?;
    
    // Create boundary with authorized marker
    let username = token.username();
    let home_dir = PathBoundary::<UserHome>::try_new(format!("/home/{username}"))?;
    
    // Path inherits authorization from boundary
    let file = home_dir.strict_join(filename)?;
    
    // Function call proves authentication happened
    Ok(read_user_file(&file)?)
}

// Stub types for example
struct AuthToken { username: String }
impl AuthToken {
    fn username(&self) -> &str { &self.username }
}
enum AuthError { InvalidToken }
fn verify_token(_token: &AuthToken) -> Result<(), AuthError> { Ok(()) }
```

### Key Pattern Elements

1. **Private `_proof` field** prevents external construction
2. **`authenticate()` constructor** verifies credentials before granting marker
3. **Functions accept `&StrictPath<UserHome>`** = compile-time proof
4. **Wrong marker = compile error** (can't pass `StrictPath<AdminFiles>` to `read_user_file()`)

**Benefits:**
- Impossible to bypass authentication (can't construct marker without verifying)
- Refactoring changes propagate through type system
- Authentication logic centralized in marker constructor

---

## Level 2: Tuple Markers for Permissions

Encode **both domain and permission level** in the type using tuple markers.

### Implementation

```rust,no_run
use strict_path::{PathBoundary, StrictPath};

// Domain markers
struct SystemFiles;
struct UserDocuments;

// Permission markers (private construction)
struct ReadOnly { _proof: () }
struct ReadWrite { _proof: () }
struct AdminPermission { _proof: () }

impl ReadOnly {
    pub fn grant_read(user: &User) -> Result<Self, PermissionError> {
        if user.can_read_system_files() {
            Ok(ReadOnly { _proof: () })
        } else {
            Err(PermissionError::Denied)
        }
    }
}

impl ReadWrite {
    pub fn grant_write(user: &User) -> Result<Self, PermissionError> {
        if user.can_write_documents() {
            Ok(ReadWrite { _proof: () })
        } else {
            Err(PermissionError::Denied)
        }
    }
}

impl AdminPermission {
    pub fn grant_admin(user: &User) -> Result<Self, PermissionError> {
        if user.is_admin() {
            Ok(AdminPermission { _proof: () })
        } else {
            Err(PermissionError::Denied)
        }
    }
}

// Functions encode both domain and permission requirements
fn view_system_file(
    path: &StrictPath<(SystemFiles, ReadOnly)>
) -> std::io::Result<String> {
    path.read_to_string()  // Can read but not modify
}

fn modify_system_file(
    path: &StrictPath<(SystemFiles, AdminPermission)>,
    data: &[u8]
) -> std::io::Result<()> {
    path.write(data)  // Requires admin permission
}

fn edit_user_document(
    path: &StrictPath<(UserDocuments, ReadWrite)>,
    data: &[u8]
) -> std::io::Result<()> {
    path.write(data)  // User documents + write permission
}

// Usage: Permission matrix enforced at compile time
fn user_workflow(user: &User) -> Result<(), Box<dyn std::error::Error>> {
    // Grant appropriate permissions
    let _read_perm = ReadOnly::grant_read(user)?;
    let _write_perm = ReadWrite::grant_write(user)?;
    
    // Create boundaries with permission markers
    let system_dir = PathBoundary::<(SystemFiles, ReadOnly)>::try_new("/etc")?;
    let docs_dir = PathBoundary::<(UserDocuments, ReadWrite)>::try_new("/home/user/docs")?;
    
    // Operations matched to permissions
    let config = system_dir.strict_join("app.conf")?;
    let content = view_system_file(&config)?;  // ✅ ReadOnly matches
    
    let doc = docs_dir.strict_join("notes.txt")?;
    edit_user_document(&doc, b"updated")?;  // ✅ ReadWrite matches
    
    // ❌ Compile error: wrong permission level
    // modify_system_file(&config, b"hacked")?;
    //   Expected: (SystemFiles, AdminPermission)
    //   Found:    (SystemFiles, ReadOnly)
    
    Ok(())
}

// Stub types
struct User { role: Role }
enum Role { Regular, Admin }
impl User {
    fn can_read_system_files(&self) -> bool { true }
    fn can_write_documents(&self) -> bool { !matches!(self.role, Role::Admin) }
    fn is_admin(&self) -> bool { matches!(self.role, Role::Admin) }
}
enum PermissionError { Denied }
```

### Permission Matrix Enforced by Compiler

| Function                | Required Marker                   | What it Proves                         |
| ----------------------- | --------------------------------- | -------------------------------------- |
| `view_system_file()`    | `(SystemFiles, ReadOnly)`         | Domain = system, Permission = read     |
| `modify_system_file()`  | `(SystemFiles, AdminPermission)`  | Domain = system, Permission = admin    |
| `edit_user_document()`  | `(UserDocuments, ReadWrite)`      | Domain = user docs, Permission = write |

**Key insight**: Wrong domain OR wrong permission = compile error. The type system enforces your entire permission matrix.

---

## Level 3: Dynamic Authorization with `change_marker()`

Sometimes permission levels change after **runtime checks**. Use `change_marker()` to transform markers after verification.

### Implementation

```rust,no_run
use strict_path::StrictPath;

struct Documents;
struct ReadOnly { _proof: () }
struct ReadWrite { _proof: () }

impl ReadWrite {
    fn elevate(user: &User) -> Result<Self, PermissionError> {
        if user.has_write_permission() {
            Ok(ReadWrite { _proof: () })
        } else {
            Err(PermissionError::Denied)
        }
    }
}

fn escalate_permissions(
    user: &User,
    file: StrictPath<(Documents, ReadOnly)>
) -> Result<(), Box<dyn std::error::Error>> {
    // Start with read-only access
    let content = file.read_to_string()?;
    println!("Current content: {content}");
    
    // Check if user can write
    if let Ok(_write_perm) = ReadWrite::elevate(user) {
        // ✅ CORRECT: change_marker() after authorization check
        let writable: StrictPath<(Documents, ReadWrite)> = file.change_marker();
        writable.write(b"updated content")?;
        println!("Updated successfully");
    } else {
        println!("Read-only access - cannot modify");
    }
    
    Ok(())
}

// Stub types
struct User { can_write: bool }
impl User {
    fn has_write_permission(&self) -> bool { self.can_write }
}
enum PermissionError { Denied }
```

### Critical Rule: Verify Before Transform

**NEVER use `change_marker()` without authorization:**

```rust,no_run
use strict_path::StrictPath;

struct Documents;
struct ReadOnly;
struct ReadWrite;

// ❌ WRONG: Speculative marker change without verification
fn escalate_wrong(file: StrictPath<(Documents, ReadOnly)>) -> StrictPath<(Documents, ReadWrite)> {
    file.change_marker()  // No authorization check!
}

// ✅ CORRECT: Verify authorization first
fn escalate_correct(
    user: &User,
    file: StrictPath<(Documents, ReadOnly)>
) -> Result<StrictPath<(Documents, ReadWrite)>, PermissionError> {
    if user.has_write_permission() {
        Ok(file.change_marker())  // Transform after verification
    } else {
        Err(PermissionError::Denied)
    }
}

struct User { can_write: bool }
impl User {
    fn has_write_permission(&self) -> bool { self.can_write }
}
enum PermissionError { Denied }
```

**When to use `change_marker()`:**
- After authenticating/authorizing a user and granting different permissions
- When escalating or downgrading access levels based on runtime checks
- When reinterpreting a path's security context after validation

**When NOT to use `change_marker()`:**
- When converting between path types (conversions preserve markers automatically)
- Without verifying authorization first (NEVER change markers speculatively)

---

## Architecture Comparison Table

| Level           | Marker Pattern                     | Compile-Time Guarantee                  | Runtime Check Location       | Use Case                        |
| --------------- | ---------------------------------- | --------------------------------------- | ---------------------------- | ------------------------------- |
| **Basic Auth**  | `StrictPath<UserHome>`             | User was authenticated                  | Marker construction          | Prove login happened            |
| **Permissions** | `StrictPath<(Domain, Permission)>` | User has specific permission in domain  | Permission grant             | Enforce permission matrix       |
| **Dynamic**     | `change_marker()` after check      | Authorization verified before transform | Before `change_marker()`     | Runtime permission escalation   |

---

## Real-World Example: Multi-Level Authorization

```rust,no_run
use strict_path::{PathBoundary, StrictPath};

// Domain markers
struct ProjectFiles;

// Permission markers
struct Viewer { _proof: () }
struct Editor { _proof: () }
struct Owner { _proof: () }

impl Viewer {
    fn authenticate(user: &User, project_id: &str) -> Result<Self, AuthError> {
        if user.can_view(project_id) {
            Ok(Viewer { _proof: () })
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

impl Editor {
    fn promote_from_viewer(user: &User, project_id: &str) -> Result<Self, AuthError> {
        if user.can_edit(project_id) {
            Ok(Editor { _proof: () })
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

impl Owner {
    fn promote_from_editor(user: &User, project_id: &str) -> Result<Self, AuthError> {
        if user.is_owner(project_id) {
            Ok(Owner { _proof: () })
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

// Functions with different permission requirements
fn read_project_file(file: &StrictPath<(ProjectFiles, Viewer)>) -> std::io::Result<String> {
    file.read_to_string()
}

fn update_project_file(
    file: &StrictPath<(ProjectFiles, Editor)>,
    data: &[u8]
) -> std::io::Result<()> {
    file.write(data)
}

fn delete_project(dir: &PathBoundary<(ProjectFiles, Owner)>) -> std::io::Result<()> {
    std::fs::remove_dir_all(dir.strict_join("")?.interop_path())
}

// Workflow: Dynamic permission escalation
fn handle_project_request(
    user: &User,
    project_id: &str,
    action: Action
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Basic authentication
    let _viewer = Viewer::authenticate(user, project_id)?;
    let project_dir = PathBoundary::<(ProjectFiles, Viewer)>::try_new(
        format!("/projects/{project_id}")
    )?;
    
    match action {
        Action::Read(filename) => {
            let file = project_dir.strict_join(&filename)?;
            let content = read_project_file(&file)?;
            println!("Content: {content}");
        },
        
        Action::Edit(filename, data) => {
            // Step 2: Escalate to Editor
            let _editor = Editor::promote_from_viewer(user, project_id)?;
            let project_dir_edit: PathBoundary<(ProjectFiles, Editor)> = 
                project_dir.change_marker();
            
            let file = project_dir_edit.strict_join(&filename)?;
            update_project_file(&file, data.as_bytes())?;
        },
        
        Action::Delete => {
            // Step 3: Escalate to Owner
            let _owner = Owner::promote_from_editor(user, project_id)?;
            let project_dir_owner: PathBoundary<(ProjectFiles, Owner)> = 
                project_dir.change_marker();
            
            delete_project(&project_dir_owner)?;
        },
    }
    
    Ok(())
}

// Stub types
struct User { id: String, permissions: Vec<String> }
impl User {
    fn can_view(&self, _project: &str) -> bool { true }
    fn can_edit(&self, project: &str) -> bool { 
        self.permissions.contains(&format!("edit:{project}"))
    }
    fn is_owner(&self, project: &str) -> bool {
        self.permissions.contains(&format!("own:{project}"))
    }
}
enum Action { Read(String), Edit(String, String), Delete }
enum AuthError { Forbidden }
```

**Key patterns in this example:**
- Viewer → Editor → Owner escalation chain
- Each level requires explicit runtime check
- `change_marker()` called after verification
- Compiler prevents calling higher-privilege functions with lower-privilege markers

---

## Summary: Authorization Levels

**Choose the right level for your needs:**

| Need                                  | Use Pattern                     | Example                               |
| ------------------------------------- | ------------------------------- | ------------------------------------- |
| **Prove login happened**              | Basic marker                    | `StrictPath<UserHome>`                |
| **Enforce permission matrix**         | Tuple markers                   | `StrictPath<(Domain, Permission)>`    |
| **Runtime permission changes**        | `change_marker()` after check   | `file.change_marker::<ReadWrite>()`  |

**Core principle**: Move authorization from "runtime checks we hope happen" to "compile-time proofs the compiler enforces."

---

## Learn More

- **[Best Practices Overview →](../best_practices.md)** - Core guidelines and decision matrices
- **[Policy & Reuse Patterns →](./policy_and_reuse.md)** - Why and when to use policy types
- **[Real-World Patterns →](./real_world_patterns.md)** - Production examples with authorization
- **[Common Operations →](./common_operations.md)** - How to use authorized paths

