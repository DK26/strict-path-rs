// S3 Mirror Demo
//
// Mirrors files from a local jail to an S3 bucket. All keys are derived
// from VirtualPath (virtual root), while data reads use JailedPath.

#[cfg(not(feature = "with-aws"))]
fn main() {
    eprintln!("Rebuild with --features with-aws to run this example.");
}

#[cfg(feature = "with-aws")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use aws_config::BehaviorVersion;
    use aws_sdk_s3::types::ByteStream;
    use aws_sdk_s3::Client;
    use jailed_path::{Jail, VirtualPath, VirtualRoot};
    use std::fs;
    use walkdir::WalkDir;

    #[derive(Clone)]
    struct Src;

    // Setup demo source
    fs::create_dir_all("mirror_src/sub")?;
    fs::write("mirror_src/file.txt", b"hello s3\n")?;
    fs::write("mirror_src/sub/inner.txt", b"inner\n")?;

    let bucket = std::env::var("S3_BUCKET").unwrap_or_else(|_| "my-bucket".to_string());
    let prefix = std::env::var("S3_PREFIX").unwrap_or_default();

    let jail: Jail<Src> = Jail::try_new("mirror_src")?;
    let vroot: VirtualRoot<Src> = VirtualRoot::try_new("mirror_src")?;

    // Use a mock unless explicitly enabled with EXAMPLES_S3_RUN=1
    let use_real = std::env::var("EXAMPLES_S3_RUN").ok().as_deref() == Some("1");
    let s3 = if use_real {
        let conf = aws_config::load_defaults(BehaviorVersion::latest()).await;
        Some(Client::new(&conf))
    } else {
        None
    };

    let root = jail.try_path(".")?;
    for entry in WalkDir::new(root.systempath_as_os_str()) {
        let entry = entry?;
        let p = entry.path();
        let rel = match p.strip_prefix(root.systempath_as_os_str()) {
            Ok(r) if !r.as_os_str().is_empty() => r,
            _ => continue,
        };
        let rel_str = rel.to_string_lossy().to_string();
        let jp = jail.try_path(&rel_str)?;
        if jp.is_file() {
            let vp: VirtualPath<Src> = vroot.try_virtual_path(&rel_str)?;
            let key_part = vp.to_string().trim_start_matches('/');
            let key = if prefix.is_empty() {
                key_part.to_string()
            } else {
                format!("{}/{}", prefix.trim_end_matches('/'), key_part)
            };
            if let Some(ref s3c) = s3 {
                let body = ByteStream::from_path(jp.systempath_as_os_str()).await?;
                s3c.put_object().bucket(&bucket).key(&key).body(body).send().await?;
                println!("Uploaded s3://{}/{}", bucket, key);
            } else {
                println!("MOCK upload s3://{}/{} from {}", bucket, key, jp.systempath_to_string());
            }
        }
    }

    fs::remove_dir_all("mirror_src").ok();
    Ok(())
}
