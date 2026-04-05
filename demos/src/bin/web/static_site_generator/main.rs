// Secure static site generator using strict-path for all file operations.
// Demonstrates using PathBoundary to enforce directory restrictions across
// source, output, and theme content areas.

use clap::{Parser, Subcommand};

mod builder;
mod init;
mod types;

#[derive(Parser)]
#[command(name = "static-gen")]
#[command(about = "Secure static site generator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new site project
    Init {
        /// Project directory
        #[arg(short, long, default_value = ".")]
        path: String,
    },
    /// Build the site
    Build {
        /// Source directory
        #[arg(short, long, default_value = "src")]
        source: String,
        /// Output directory
        #[arg(short, long, default_value = "dist")]
        output: String,
        /// Theme directory
        #[arg(short, long, default_value = "themes/default")]
        theme: String,
    },
    /// Serve the site locally (development)
    Serve {
        /// Output directory to serve
        #[arg(short, long, default_value = "dist")]
        output: String,
        /// Port to serve on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => init::init_site(&path),
        Commands::Build {
            source,
            output,
            theme,
        } => builder::build_site(&source, &output, &theme),
        Commands::Serve { output, port } => builder::serve_site(&output, port),
    }
}
