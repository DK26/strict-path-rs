use serde::{Deserialize, Serialize};

// Type markers for different site contexts
pub struct SourceContent;
pub struct OutputSite;
pub struct ThemeAssets;

#[derive(Serialize, Deserialize, Debug)]
pub struct SiteConfig {
    pub title: String,
    pub description: String,
    pub author: String,
    pub base_url: String,
    pub theme: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PageFrontmatter {
    pub title: String,
    pub date: Option<chrono::DateTime<chrono::Utc>>,
    pub draft: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub layout: Option<String>,
}

pub struct Page {
    pub frontmatter: PageFrontmatter,
    pub _content: String,
    pub html_content: String,
    pub relative_path: String,
}
