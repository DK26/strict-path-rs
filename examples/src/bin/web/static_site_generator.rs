// Secure Static Site Generator (comprehensive, policy-compliant)
//
// Demonstrates using jailed-path to build a static site safely:
// - Init: scaffolds src/, themes/default/, static/, and a default config
// - Build: converts Markdown in src/pages and src/posts to HTML in dist/, copies assets
// - Serve: prints info (placeholder; no network by default)

use clap::{Parser, Subcommand};
use jailed_path::{Jail, JailedPath};
use pulldown_cmark::{html, Options, Parser as MarkdownParser};
use serde::{Deserialize, Serialize};
use tera::{Context, Tera};
use walkdir::WalkDir;

// Type markers for different site contexts
struct SourceContent;
struct OutputSite;
struct ThemeAssets;

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
        /// Port to serve on (placeholder)
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct SiteConfig {
    title: String,
    description: String,
    author: String,
    base_url: String,
    theme: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PageFrontmatter {
    title: String,
    date: Option<chrono::DateTime<chrono::Utc>>,
    draft: Option<bool>,
    tags: Option<Vec<String>>, 
    layout: Option<String>,
}

struct Page {
    frontmatter: PageFrontmatter,
    _raw_markdown: String,
    html_content: String,
    relative_path: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { path } => init_site(&path),
        Commands::Build { source, output, theme } => build_site(&source, &output, &theme),
        Commands::Serve { output, port } => serve_site(&output, port),
    }
}

fn init_site(project_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing new static site project in: {project_path}");
    let project: Jail<SourceContent> = Jail::try_new_create(project_path)?;

    // Directory structure
    for dir in [
        "src/pages",
        "src/posts",
        "themes/default/layouts",
        "themes/default/assets",
        "static",
    ] {
        let dir_path = project.jailed_join(dir)?;
        dir_path.create_dir_all()?;
        println!("Created: {dir}");
    }

    // Default config
    let config = SiteConfig {
        title: "My Static Site".to_string(),
        description: "A secure static site built with jailed-path".to_string(),
        author: "Site Author".to_string(),
        base_url: "https://example.com".to_string(),
        theme: "default".to_string(),
    };
    let config_path = project.jailed_join("site.yaml")?;
    config_path.write_string(&serde_yaml::to_string(&config)?)?;
    println!("Created: site.yaml");

    // Sample page with frontmatter
    let index_md = project.jailed_join("src/pages/index.md")?;
    index_md.write_string(
        "---\n\
title: Home\n\
draft: false\n\
---\n\
# Welcome\n\
Hello from a secure static site generator!\n",
    )?;

    // Base layout
    let base_layout = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="{{ site.description }}" />
    <title>{{ page.title }} - {{ site.title }}</title>
    <link rel="stylesheet" href="/assets/style.css" />
    {% block head %}{% endblock %}
    </head>
<body>
    <header>
        <h1><a href="/">{{ site.title }}</a></h1>
        <p>{{ site.description }}</p>
    </header>
    <main>
        {% block content %}{% endblock %}
    </main>
    <footer>
        <p>&copy; 2024 {{ site.author }}</p>
    </footer>
</body>
</html>"#;
    let base_path = project.jailed_join("themes/default/layouts/base.html")?;
    base_path.write_string(base_layout)?;

    // Page layout
    let page_layout = r#"{% extends "base.html" %}

{% block content %}
<article>
    <h1>{{ page.title }}</h1>
    {{ page.content | safe }}
</article>
{% endblock %}"#;
    let page_path = project.jailed_join("themes/default/layouts/page.html")?;
    page_path.write_string(page_layout)?;

    // Post layout
    let post_layout = r#"{% extends "base.html" %}

{% block content %}
<article>
    <header>
        <h1>{{ page.title }}</h1>
        {% if page.date %}
        <time datetime="{{ page.date | date(format='%Y-%m-%d') }}">
            {{ page.date | date(format='%B %d, %Y') }}
        </time>
        {% endif %}
        {% if page.tags %}
        <div class="tags">
            {% for tag in page.tags %}
            <span class="tag">#{{ tag }}</span>
            {% endfor %}
        </div>
        {% endif %}
    </header>
    {{ page.content | safe }}
</article>
{% endblock %}"#;
    let post_path = project.jailed_join("themes/default/layouts/post.html")?;
    post_path.write_string(post_layout)?;

    // Basic CSS
    let css_content = r#"/* Default theme styles */
body {
    font-family: system-ui, -apple-system, sans-serif;
    line-height: 1.6;
    max-width: 800px;
    margin: 0 auto;
    padding: 20px;
    color: #333;
}

header {
    border-bottom: 2px solid #eee;
    padding-bottom: 20px;
    margin-bottom: 40px;
}

header h1 a { text-decoration: none; color: #2563eb; }

article { margin-bottom: 40px; }

.tags { margin: 10px 0; }
.tag { background: #f3f4f6; padding: 2px 8px; border-radius: 4px; font-size: 0.9em; margin-right: 5px; }

footer { border-top: 1px solid #eee; padding-top: 20px; margin-top: 40px; text-align: center; color: #666; }

code { background: #f8f9fa; padding: 2px 4px; border-radius: 3px; }
pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
"#;
    let css_path = project.jailed_join("themes/default/assets/style.css")?;
    css_path.write_string(css_content)?;

    println!("Project initialized. Run 'static-gen build' to build your site.");
    Ok(())
}

fn build_site(source_path: &str, output_path: &str, theme_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Building static site...");
    println!("Source: {source_path}");
    println!("Output: {output_path}");
    println!("Theme: {theme_path}");

    let source_jail: Jail<SourceContent> = Jail::try_new_create(source_path)?;
    let output_jail: Jail<OutputSite> = Jail::try_new_create(output_path)?;
    let theme_jail: Jail<ThemeAssets> = Jail::try_new_create(theme_path)?;

    // Load site configuration
    let config = load_site_config(&source_jail)?;
    println!("Loaded config: {}", config.title);

    // Set up template engine
    let mut tera = Tera::default();
    load_templates(&mut tera, &theme_jail)?;

    // Collect pages and posts
    let mut pages: Vec<Page> = Vec::new();
    pages.extend(process_content_directory(&source_jail, "pages")?);
    pages.extend(process_content_directory(&source_jail, "posts")?);
    println!("Processed {} content files", pages.len());

    // Render pages
    for page in &pages {
        generate_page_html(page, &config, &tera, &output_jail)?;
    }

    // Copy assets and static files
    copy_theme_assets(&theme_jail, &output_jail)?;
    copy_static_files(&source_jail, &output_jail)?;

    println!("Site built successfully in: {output_path}");
    Ok(())
}

fn load_site_config(source_jail: &Jail<SourceContent>) -> Result<SiteConfig, Box<dyn std::error::Error>> {
    let config_path = source_jail.jailed_join("site.yaml")?;
    let config_content = config_path.read_to_string()?;
    Ok(serde_yaml::from_str(&config_content)?)
}

fn load_templates(tera: &mut Tera, theme_jail: &Jail<ThemeAssets>) -> Result<(), Box<dyn std::error::Error>> {
    let layouts_dir = theme_jail.jailed_join("layouts")?;
    if !layouts_dir.exists() {
        return Err("Theme layouts directory not found".into());
    }
    for entry in WalkDir::new(layouts_dir.interop_path()) {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension().and_then(|ext| ext.to_str()) == Some("html") {
            let relative = entry.path().strip_prefix(layouts_dir.interop_path())?;
            let template_name = relative.to_string_lossy().replace('\\', "/");
            let template_path = theme_jail.jailed_join(format!("layouts/{template_name}"))?;
            let template_source = template_path.read_to_string()?;
            tera.add_raw_template(&template_name, &template_source)?;
        }
    }
    Ok(())
}

fn process_content_directory(source_jail: &Jail<SourceContent>, dir_name: &str) -> Result<Vec<Page>, Box<dyn std::error::Error>> {
    let content_root = source_jail.jailed_join(dir_name)?;
    let mut pages = Vec::new();
    if !content_root.exists() { return Ok(pages); }
    for entry in WalkDir::new(content_root.interop_path()) {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension().and_then(|ext| ext.to_str()) == Some("md") {
            let relative = entry.path().strip_prefix(content_root.interop_path())?;
            let relative_str = relative.to_string_lossy().replace('\\', "/");
            let content_path = source_jail.jailed_join(format!("{dir_name}/{relative_str}"))?;
            let page = process_markdown_file(&content_path, &relative_str)?;
            pages.push(page);
        }
    }
    Ok(pages)
}

fn process_markdown_file(file_path: &JailedPath<SourceContent>, relative_path: &str) -> Result<Page, Box<dyn std::error::Error>> {
    let file_content = file_path.read_to_string()?;
    // Expect frontmatter delimited by ---\n ... \n---\n
    let parts: Vec<&str> = file_content.splitn(3, "---").collect();
    if parts.len() != 3 {
        return Err("Invalid frontmatter format".into());
    }
    let frontmatter_yaml = parts[1];
    let markdown_body = parts[2];

    let frontmatter: PageFrontmatter = serde_yaml::from_str(frontmatter_yaml)?;
    if frontmatter.draft.unwrap_or(false) {
        return Err("Draft content skipped".into());
    }

    // Render markdown
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    let parser = MarkdownParser::new_ext(markdown_body, options);
    let mut html_buf = String::new();
    html::push_html(&mut html_buf, parser);

    Ok(Page {
        frontmatter,
        _raw_markdown: markdown_body.to_string(),
        html_content: html_buf,
        relative_path: relative_path.to_string(),
    })
}

fn generate_page_html(page: &Page, config: &SiteConfig, tera: &Tera, output_jail: &Jail<OutputSite>) -> Result<(), Box<dyn std::error::Error>> {
    // Choose layout
    let layout_name = page.frontmatter.layout.clone().unwrap_or_else(|| {
        if page.relative_path.starts_with("posts/") { "post.html".to_string() } else { "page.html".to_string() }
    });

    // Context
    let mut context = Context::new();
    context.insert("site", &serde_json::json!({
        "title": config.title,
        "description": config.description,
        "author": config.author,
        "base_url": config.base_url,
        "theme": config.theme,
    }));
    context.insert(
        "page",
        &serde_json::json!({
            "title": page.frontmatter.title,
            "date": page.frontmatter.date,
            "tags": page.frontmatter.tags,
            "content": page.html_content,
        }),
    );

    // Render
    let html = tera.render(&layout_name, &context).or_else(|_| tera.render(&format!("{layout_name}.tera"), &context))?;

    // Output location
    let mut output_rel = page.relative_path.clone();
    if output_rel.ends_with(".md") { output_rel = output_rel.replace(".md", ".html"); }
    let output_file = output_jail.jailed_join(&output_rel)?;
    output_file.create_parent_dir_all()?;
    output_file.write_string(&html)?;
    println!("Generated: {output_rel}");
    Ok(())
}

fn copy_theme_assets(theme_jail: &Jail<ThemeAssets>, output_jail: &Jail<OutputSite>) -> Result<(), Box<dyn std::error::Error>> {
    let assets_dir = theme_jail.jailed_join("assets")?;
    if !assets_dir.exists() { return Ok(()); }
    let out_assets = output_jail.jailed_join("assets")?;
    out_assets.create_dir_all()?;
    for entry in WalkDir::new(assets_dir.interop_path()) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let relative = entry.path().strip_prefix(assets_dir.interop_path())?;
            let relative_str = relative.to_string_lossy().replace('\\', "/");
            let src = theme_jail.jailed_join(format!("assets/{relative_str}"))?;
            let dst = out_assets.jailed_join(&relative_str)?;
            dst.create_parent_dir_all()?;
            dst.write_bytes(&src.read_bytes()?)?;
            println!("Copied asset: {relative_str}");
        }
    }
    Ok(())
}

fn copy_static_files(source_jail: &Jail<SourceContent>, output_jail: &Jail<OutputSite>) -> Result<(), Box<dyn std::error::Error>> {
    let static_dir = source_jail.jailed_join("static")?;
    if !static_dir.exists() { return Ok(()); }
    for entry in WalkDir::new(static_dir.interop_path()) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let relative = entry.path().strip_prefix(static_dir.interop_path())?;
            let relative_str = relative.to_string_lossy().replace('\\', "/");
            let src = source_jail.jailed_join(format!("static/{relative_str}"))?;
            let dst = output_jail.jailed_join(&relative_str)?;
            dst.create_parent_dir_all()?;
            dst.write_bytes(&src.read_bytes()?)?;
            println!("Copied static file: {relative_str}");
        }
    }
    Ok(())
}

fn serve_site(output_path: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting development server (placeholder)");
    println!("Serving: {output_path}");
    println!("URL: http://localhost:{port}");
    println!("Add a real HTTP server for live preview if desired.");
    // Validate output root exists
    let output_jail: Jail<OutputSite> = Jail::try_new_create(output_path)?;
    let index_file = output_jail.jailed_join("index.html")?;
    if index_file.exists() {
        println!("Found index.html - site ready to serve");
    } else {
        println!("No index.html found. Run 'static-gen build' first.");
    }
    Ok(())
}
