# Advanced Marker Types: Authorization Security

> **Building on Marker Fundamentals**: This section shows advanced marker patterns for authorization security. If you're new to markers, read the [Type-System Guarantees section](./type_system_guarantees.md) first to understand basic marker concepts.

## From Basic Markers to Authorization-Aware Markers

You've already learned that markers describe **what** paths contain and prevent cross-domain mix-ups:

```rust
struct PublicAssets;  // CSS, JS, images
struct UserUploads;   // User documents

let public_assets_dir: PathBoundary<PublicAssets> = PathBoundary::try_new("public")?;
let user_uploads_dir: PathBoundary<UserUploads> = PathBoundary::try_new("uploads")?;

let css_file: StrictPath<PublicAssets> = public_assets_dir.strict_join("style.css")?;
let doc_file: StrictPath<UserUploads> = user_uploads_dir.strict_join("report.pdf")?;
```

But what if creating these markers required **authorization**? What if you could only construct `UserUploads` after proving you're allowed to access user uploads?

## The Vision: Authorization-Aware Markers

The key insight: **markers still describe content, but their construction requires proof of authorization**.

- **Marker name**: Describes what the path contains (`UserProfile`, `AdminConfig`)
- **Private constructor**: Requires authentication to create the marker  
- **Function signatures**: Work with meaningful domain types, ensuring both path safety AND authorization

## Basic Authorization-Aware Markers

The core concept is elegantly simple: **the marker describes what the path contains**, but the marker can only be constructed through proper authorization.

```rust
use strict_path::{PathBoundary, StrictPath};

// Marker describes the domain/content - what the path contains
struct UserProfile {
    // Private field prevents external construction
    _proof: (),
}

impl UserProfile {
    // Only way to create this marker - requires actual authentication
    pub fn authenticate_for_profile_access(credentials: &Credentials) -> Result<Self, AuthError> {
        if verify_user_credentials(credentials)? {
            Ok(UserProfile { _proof: () })
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }
}

// Functions work with meaningful path types
fn read_profile_data(path: &StrictPath<UserProfile>) -> io::Result<String> {
    // If this function is called, user is guaranteed to be authorized for profile access
    path.read_to_string()
}

fn update_profile_data(path: &StrictPath<UserProfile>, content: &str) -> io::Result<()> {
    // Same guarantee here
    path.write(content)
}

// Usage - authentication is required to get the marker
let profile_access = UserProfile::authenticate_for_profile_access(&user_credentials)?;
let user_profiles_dir: PathBoundary<UserProfile> = PathBoundary::try_new("profiles")?;
let profile_file: StrictPath<UserProfile> = user_profiles_dir.strict_join("user_123.json")?;

// These work because we proved authorization to access UserProfile content
read_profile_data(&profile_file)?;
update_profile_data(&profile_file, "updated profile data")?;

// Without authentication, you can't even create the StrictPath<UserProfile>
// The marker is meaningful (describes profiles) AND requires authorization to construct!
```

## Advanced: Tuple Markers for Resource + Permission

The most expressive approach combines resource types with permission levels using tuple markers:

```rust
// Resource types (what the path contains) - no proof needed
struct SystemFiles;
struct UserDocuments;
struct ConfigFiles;

// Permission levels (how you can access it) - require proof
struct UserPermission { _proof: () }
struct AdminPermission { _proof: () }
struct ReadOnly { _proof: () }
struct ReadWrite { _proof: () }
struct ExecuteOnly { _proof: () }

impl ReadOnly {
    pub fn authenticate_readonly(credentials: &Credentials) -> Result<Self, AuthError> {
        verify_readonly_access(credentials)?;
        Ok(ReadOnly { _proof: () })
    }
}

impl AdminPermission {
    pub fn authenticate_admin(credentials: &Credentials) -> Result<Self, AuthError> {
        verify_admin_credentials(credentials)?;
        Ok(AdminPermission { _proof: () })
    }
}

// Smart authentication that returns the complete tuple marker
fn authenticate_system_access(user_id: u64, password: &str) -> Result<(SystemFiles, ReadOnly), AuthError> {
    if verify_user_credentials(user_id, password)? {
        Ok((SystemFiles, ReadOnly { _proof: () }))
    } else {
        Err(AuthError::InvalidCredentials)
    }
}

fn authenticate_admin_access(user_id: u64, password: &str) -> Result<(SystemFiles, AdminPermission), AuthError> {
    if verify_admin_credentials(user_id, password)? {
        Ok((SystemFiles, AdminPermission { _proof: () }))
    } else {
        Err(AuthError::AccessDenied)
    }
}

// Functions enforce specific resource + permission combinations
fn read_system_file(path: &StrictPath<(SystemFiles, ReadOnly)>) -> io::Result<String> {
    path.read_to_string()
}

fn manage_system_file(path: &StrictPath<(SystemFiles, AdminPermission)>) -> io::Result<()> {
    path.write("admin changes")
}

fn read_user_document(path: &StrictPath<(UserDocuments, ReadWrite)>) -> io::Result<String> {
    path.read_to_string()
}

fn execute_system_binary(path: &StrictPath<(SystemFiles, ExecuteOnly)>) -> io::Result<std::process::Output> {
    std::process::Command::new(path.interop_path()).output()
}

// Usage - authentication returns the complete tuple marker
let system_marker = authenticate_system_access(user_id, password)?; // Returns (SystemFiles, ReadOnly)
let system_files_dir: PathBoundary<(SystemFiles, ReadOnly)> = PathBoundary::try_new("system")?;
let system_file: StrictPath<(SystemFiles, ReadOnly)> = system_files_dir.strict_join("config.txt")?;

// Function calls are type-safe - wrong permission level = compile error
read_system_file(&system_file)?; // ✅ OK - has ReadOnly permission
// manage_system_file(&system_file)?; // ❌ Compile error - needs AdminPermission!

// Admin access
let admin_marker = authenticate_admin_access(admin_id, admin_password)?; // Returns (SystemFiles, AdminPermission)  
let admin_system_dir: PathBoundary<(SystemFiles, AdminPermission)> = PathBoundary::try_new("system")?;
let admin_file: StrictPath<(SystemFiles, AdminPermission)> = admin_system_dir.strict_join("sensitive.conf")?;

manage_system_file(&admin_file)?; // ✅ OK - has AdminPermission
read_system_file(&admin_file.as_unvirtual())?; // ❌ Would be compile error - type mismatch!
```

**The power**: You can create very specific authorization matrices:
- `StrictPath<(SystemFiles, ReadOnly)>` - Can read system files, can't modify
- `StrictPath<(UserDocuments, ReadWrite)>` - Can read/write user docs, can't access system files
- `StrictPath<(ConfigFiles, AdminPermission)>` - Only admins can access config files
- `StrictPath<(SystemFiles, ExecuteOnly)>` - Can execute system binaries, can't read their content

**Key insight**: Authentication functions can return the complete tuple marker, making the API even more ergonomic - you get both the resource type and proven permission in one call!

## Different Permission Levels (Alternative Pattern)

For simpler cases where resources don't need separate authentication:

```rust
// Markers describe content domains, but require different levels of auth to construct
struct UserDocuments { _proof: () }
struct AdminConfig { _proof: () }
struct SystemLogs { _proof: () }

impl UserDocuments {
    pub fn authenticate_for_documents(token: &Token) -> Result<Self, AuthError> {
        verify_user_token(token)?; // Basic user auth
        Ok(UserDocuments { _proof: () })
    }
}

impl AdminConfig {
    pub fn authenticate_for_config(token: &Token) -> Result<Self, AuthError> {
        verify_admin_token(token)?; // Admin-level auth required
        Ok(AdminConfig { _proof: () })
    }
}

impl SystemLogs {
    pub fn authenticate_for_logs(token: &Token) -> Result<Self, AuthError> {
        verify_system_token(token)?; // System-level auth required
        Ok(SystemLogs { _proof: () })
    }
}

// Functions work with meaningful domain types
fn read_document(path: &StrictPath<UserDocuments>) -> io::Result<String> {
    path.read_to_string()
}

fn read_config(path: &StrictPath<AdminConfig>) -> io::Result<String> {
    path.read_to_string()
}

fn read_logs(path: &StrictPath<SystemLogs>) -> io::Result<String> {
    path.read_to_string()
}

fn update_config(path: &StrictPath<AdminConfig>, content: &str) -> io::Result<()> {
    path.write(content)
}

// Usage
let doc_access = UserDocuments::authenticate_for_documents(&user_token)?;
let admin_access = AdminConfig::authenticate_for_config(&admin_token)?;
let system_access = SystemLogs::authenticate_for_logs(&system_token)?;

let user_documents_dir: PathBoundary<UserDocuments> = PathBoundary::try_new("documents")?;
let admin_config_dir: PathBoundary<AdminConfig> = PathBoundary::try_new("config")?;
let system_logs_dir: PathBoundary<SystemLogs> = PathBoundary::try_new("logs")?;

let user_doc: StrictPath<UserDocuments> = user_documents_dir.strict_join("report.pdf")?;
let app_config: StrictPath<AdminConfig> = admin_config_dir.strict_join("settings.json")?;
let system_log: StrictPath<SystemLogs> = system_logs_dir.strict_join("app.log")?;

// Clear, meaningful operations
read_document(&user_doc)?; // ✅ OK - reading user documents
read_config(&app_config)?; // ✅ OK - reading admin config  
read_logs(&system_log)?;   // ✅ OK - reading system logs
update_config(&app_config, "new settings")?; // ✅ OK - admin can update config

// Impossible operations become compile errors:
// update_config(&user_doc, "hack")?; // ❌ Can't pass UserDocuments to AdminConfig function
// read_logs(&user_doc)?; // ❌ Can't pass UserDocuments to SystemLogs function
```

## Capability-Based Authorization

For more sophisticated authorization, we can encode specific capabilities:

```rust
use std::marker::PhantomData;

// Capability types
struct CanRead;
struct CanWrite; 
struct CanDelete;
struct CanAdmin;

// Marker combines domain + user + capabilities
struct UserDocument<User, Caps>(PhantomData<(User, Caps)>);

// Type-level capability checking
trait HasCapability<Cap> {}

// Grant read capability to various permission combinations
impl<U> HasCapability<CanRead> for UserDocument<U, (CanRead,)> {}
impl<U> HasCapability<CanRead> for UserDocument<U, (CanRead, CanWrite)> {}
impl<U> HasCapability<CanRead> for UserDocument<U, (CanRead, CanWrite, CanDelete)> {}

// Grant write capability only when explicitly present
impl<U> HasCapability<CanWrite> for UserDocument<U, (CanRead, CanWrite)> {}
impl<U> HasCapability<CanWrite> for UserDocument<U, (CanRead, CanWrite, CanDelete)> {}

// Grant delete capability only when explicitly present  
impl<U> HasCapability<CanDelete> for UserDocument<U, (CanRead, CanWrite, CanDelete)> {}

// Functions enforce capabilities at compile time
fn read_file<M>(path: &StrictPath<M>) -> io::Result<String>
where 
    M: HasCapability<CanRead>
{
    path.read_to_string()
}

fn write_file<M>(path: &StrictPath<M>, content: &str) -> io::Result<()>
where 
    M: HasCapability<CanWrite>
{
    path.write(content)
}

fn delete_file<M>(path: &StrictPath<M>) -> io::Result<()>
where 
    M: HasCapability<CanDelete>
{
    path.remove_file()
}
```

## Authorization Token Integration

The key challenge is connecting runtime authentication with compile-time types:

```rust
// Proof of authorization required to create capability-aware paths
struct AuthToken<User, Caps> {
    user_id: User,
    capabilities: Caps,
    expires_at: SystemTime,
    signature: [u8; 32], // HMAC or similar
}

impl<User, Caps> AuthToken<User, Caps> {
    fn verify(&self) -> Result<(), AuthError> {
        // Verify signature, expiration, etc.
        if SystemTime::now() > self.expires_at {
            return Err(AuthError::TokenExpired);
        }
        // Verify HMAC signature...
        Ok(())
    }
}

// Create authorized paths only with valid tokens
fn create_authorized_boundary<U, C>(
    workspace_path: impl AsRef<Path>,
    auth_token: AuthToken<U, C>
) -> Result<PathBoundary<UserDocument<U, C>>, AuthError> {
    auth_token.verify()?;
    PathBoundary::try_new_create(workspace_path)
        .map_err(AuthError::PathBoundary)
}

// Usage with JWT-style tokens
let alice_readonly_token: AuthToken<UserId(123), (CanRead,)> = 
    parse_jwt_token(request.headers.authorization)?;

let alice_workspace_dir = create_authorized_boundary(
    "workspace/alice", 
    alice_readonly_token
)?;

let document: StrictPath<UserDocument<UserId(123), (CanRead,)>> = 
    alice_workspace_dir.strict_join("document.txt")?;

// Alice can read (capability proven at compile time)
let content = read_file(&document)?; // ✅ Compiles

// Alice cannot write (would be compile error)  
// write_file(&document, "new content")?; // ❌ Missing CanWrite capability
```

## Advanced: Role-Based Access Control (RBAC)

For enterprise applications, we can model complex role hierarchies:

```rust
// Define roles
struct Guest;
struct User; 
struct Moderator;
struct Admin;

// Role hierarchy via trait implementations
trait RoleHierarchy<Role> {}

impl RoleHierarchy<Guest> for User {} // User includes Guest permissions
impl RoleHierarchy<Guest> for Moderator {}
impl RoleHierarchy<User> for Moderator {} // Moderator includes User permissions  
impl RoleHierarchy<Guest> for Admin {}
impl RoleHierarchy<User> for Admin {}
impl RoleHierarchy<Moderator> for Admin {} // Admin includes all permissions

// Resource access patterns
struct PublicContent<Role>(PhantomData<Role>);
struct UserContent<Role>(PhantomData<Role>); 
struct AdminContent<Role>(PhantomData<Role>);

// Access control rules
trait CanAccess<Resource> {}

impl<R> CanAccess<PublicContent<Guest>> for R where R: RoleHierarchy<Guest> {}
impl<R> CanAccess<UserContent<User>> for R where R: RoleHierarchy<User> {}
impl<R> CanAccess<AdminContent<Admin>> for R where R: RoleHierarchy<Admin> {}

// Type-safe resource access
fn access_resource<Role, Resource>(
    path: &StrictPath<Resource>
) -> io::Result<String>
where 
    Role: CanAccess<Resource>
{
    path.read_to_string()
}

// Usage
let admin_files: StrictPath<AdminContent<Admin>> = create_admin_path(admin_token)?;
let user_files: StrictPath<UserContent<User>> = create_user_path(user_token)?;

// Admin can access everything (role hierarchy)
access_resource::<Admin, _>(&admin_files)?; // ✅ Admin accessing admin content
access_resource::<Admin, _>(&user_files)?;  // ✅ Admin accessing user content

// Regular user cannot access admin content
access_resource::<User, _>(&user_files)?;   // ✅ User accessing user content
// access_resource::<User, _>(&admin_files)?; // ❌ Compile error!
```

## Integration Patterns

### Web Server Integration

```rust
// Axum extractor that creates type-safe paths
#[async_trait]
impl<T> FromRequestParts<T> for AuthorizedPath<UserDocument<UserId, Caps>>
where
    T: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts, 
        state: &T
    ) -> Result<Self, Self::Rejection> {
        // Extract JWT from headers
        let token = extract_jwt(&parts.headers)?;
        
        // Parse capabilities from token
        let auth_token: AuthToken<UserId, Caps> = parse_token(token)?;
        
        // Create authorized boundary
    let user_uploads_dir = create_authorized_boundary(
            format!("uploads/{}", auth_token.user_id), 
            auth_token
        )?;
        
    Ok(AuthorizedPath { boundary: user_uploads_dir })
    }
}

// Handler function with compile-time authorization
async fn upload_file(
    AuthorizedPath(user_uploads_dir): AuthorizedPath<UserDocument<UserId, (CanWrite,)>>,
    filename: String,
    body: Bytes
) -> Result<StatusCode, AppError> {
    let file_path = user_uploads_dir.strict_join(&filename)?;
    write_file(&file_path, &body).await?; // ✅ Compile-time proven authorized
    Ok(StatusCode::CREATED)
}
```

### Database Integration

```rust
// Connect authorization with database queries
async fn load_user_document<const USER_ID: u64>(
    db: &Database,
    document_id: DocumentId,
    _proof: &StrictPath<UserDocument<ConstUserId<USER_ID>, (CanRead,)>>
) -> Result<Document, DatabaseError> {
    // The StrictPath proves the caller is authorized for USER_ID
    sqlx::query_as!(
        Document,
        "SELECT * FROM documents WHERE id = $1 AND user_id = $2",
        document_id.as_uuid(),
        USER_ID as i64
    )
    .fetch_one(db)
    .await
}
```

## Benefits & Trade-offs

### Benefits

1. **Compile-Time Authorization**: Many permission violations become type errors
2. **Zero Runtime Cost**: All authorization types erased at compile time  
3. **Impossible to Bypass**: Function signatures enforce authorization requirements
4. **Self-Documenting**: Code clearly shows what permissions are required
5. **Refactoring Safety**: Permission changes cause compile errors in all affected code

### Trade-offs

1. **Complexity**: Type signatures become more sophisticated
2. **Learning Curve**: Developers need to understand the authorization type system
3. **Rigidity**: Some dynamic authorization patterns may be harder to express
4. **Token Management**: Still need robust runtime token validation and lifecycle

### When to Use

**Good fit for:**
- Applications with well-defined, static permission models
- Systems where authorization errors are costly to debug
- Teams comfortable with advanced Rust type system features
- Long-lived applications where compile-time safety pays off

**Consider alternatives for:**
- Rapid prototyping where authorization requirements are still changing
- Systems with highly dynamic permission models
- Teams new to Rust or advanced type system concepts
- Simple applications where runtime checks are sufficient

## Implementation Strategy

**The beauty of this approach: it requires NO new API!** 

This sophisticated authorization system works entirely with strict-path's existing marker system:
- Same `PathBoundary<Marker>` and `StrictPath<Marker>` types
- Same `strict_join()`, `interop_path()`, and file operations
- Zero changes to the core strict-path library

You simply define more sophisticated marker types in your application code and let Rust's type system do the work. The authorization logic lives in:
1. **Your marker type definitions** (the capability traits and implementations)
2. **Your constructor functions** (where you verify auth tokens before creating boundaries)  
3. **Your function signatures** (where you specify required capabilities)

The key insight is leveraging Rust's zero-cost abstractions and existing strict-path APIs to move authorization logic from runtime to compile-time, without any library changes.

## Conclusion

By extending strict-path's marker system with sophisticated authorization types, we can create **compile-time authorization guarantees** that complement the existing path boundary security. This approach represents a new frontier in secure systems design, where the type system becomes an active participant in authorization enforcement.

While this adds complexity, the benefits of catching authorization bugs at compile time - rather than in production - make it compelling for security-critical applications.