use jailed_path::{JailedPathError, PathValidator, JailedPath};

// Define marker types for different resource categories
pub struct ImageResource;
pub struct UserData;

fn main() -> Result<(), JailedPathError> {
    let current_dir = std::env::current_dir().unwrap();
    
    // Unmarked validator (no generics needed)
    let generic_validator: PathValidator = PathValidator::with_jail(&current_dir)?;
    let generic_path: JailedPath = generic_validator.path("Cargo.toml")?;
    println!("Generic path: {}", generic_path.display());
    
    // Marked validator for images
    let image_validator: PathValidator<ImageResource> = PathValidator::with_jail(&current_dir)?;
    let image_path: JailedPath<ImageResource> = image_validator.path("Cargo.toml")?;
    println!("Image resource path: {}", image_path.display());
    
    // Marked validator for user data
    let user_validator: PathValidator<UserData> = PathValidator::with_jail(&current_dir)?;
    let user_path: JailedPath<UserData> = user_validator.path("Cargo.toml")?;
    println!("User data path: {}", user_path.display());
    
    // This would be a compile error if uncommented:
    // process_images(user_path); // Cannot pass UserData to function expecting ImageResource
    
    println!("Marker types provide compile-time type safety!");
    Ok(())
}

// Function that only accepts image resource paths
fn process_images(_path: JailedPath<ImageResource>) {
    println!("Processing image...");
}

// Function that only accepts user data paths  
fn process_user_data(_path: JailedPath<UserData>) {
    println!("Processing user data...");
}
