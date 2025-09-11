// QuickNotes - A portable note-taking application
//
// Demonstrates app-path + jailed-path integration for a simple note app.
// - Stores all data relative to the executable (portable)
// - Uses type-safe filesystem access with Jails and VirtualRoot

#![cfg_attr(not(feature = "with-app-path"), allow(unused))]

#[cfg(not(feature = "with-app-path"))]
compile_error!("Enable with --features with-app-path to run this example");

use app_path::app_path;
use strict_path::{PathBoundary, StrictPath, VirtualPath, VirtualRoot};
use std::fs;
use std::io::{self, Write};

#[derive(Clone)]
struct Config;
#[derive(Clone)]
struct Notes;
#[derive(Clone)]
struct Cache;
#[derive(Clone)]
struct Logs;

struct AppStorage {
    config_jail: PathBoundary<Config>,
    notes_root: VirtualRoot<Notes>,
    cache_jail: PathBoundary<Cache>,
    logs_jail: PathBoundary<Logs>,
}

struct AppConfig {
    auto_save: bool,
    theme: String,
    max_recent: usize,
}

struct QuickNotes {
    config: AppConfig,
    storage: AppStorage,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = QuickNotes::new()?;
    app.run()
}

impl QuickNotes {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        println!("QuickNotes - Portable Note Taking");
        println!("===================================");

        // Discover application directories (portable by default)
        let config_dir = app_path!("config", env = "QUICKNOTES_CONFIG");
        let notes_dir = app_path!("notes", env = "QUICKNOTES_NOTES");
        let cache_dir = app_path!("cache", env = "QUICKNOTES_CACHE");
        let logs_dir = app_path!("logs", env = "QUICKNOTES_LOGS");

        println!("Application directories:");
        println!("  Config: {}", config_dir.display());
        println!("  Notes:  {}", notes_dir.display());
        println!("  Cache:  {}", cache_dir.display());
        println!("  Logs:   {}", logs_dir.display());
        println!();

        let storage = AppStorage {
            config_jail: PathBoundary::try_new_create(&config_dir)?,
            notes_root: VirtualRoot::try_new_create(&notes_dir)?,
            cache_jail: PathBoundary::try_new_create(&cache_dir)?,
            logs_jail: PathBoundary::try_new_create(&logs_dir)?,
        };

        let config = Self::load_or_create_config(&storage.config_jail)?;
        Self::log_event(&storage.logs_jail, "Application started")?;
        Ok(Self { config, storage })
    }

    fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            self.show_menu()?;
            print!("> ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            match input.trim() {
                "1" => self.create_note()?,
                "2" => self.list_notes()?,
                "3" => self.read_note()?,
                "4" => self.search_notes()?,
                "5" => self.show_settings()?,
                "6" => self.cleanup_cache()?,
                "q" | "quit" => {
                    Self::log_event(&self.storage.logs_jail, "Application shutdown")?;
                    break;
                }
                _ => println!("Invalid choice. Try again."),
            }
            println!();
        }
        println!("Goodbye!");
        Ok(())
    }

    fn show_menu(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("=== QuickNotes Menu ===");
        println!("1. Create new note");
        println!("2. List all notes");
        println!("3. Read note");
        println!("4. Search notes");
        println!("5. Settings");
        println!("6. Cleanup cache");
        println!("q. Quit");
        Ok(())
    }

    fn create_note(&self) -> Result<(), Box<dyn std::error::Error>> {
        print!("Enter note title: ");
        io::stdout().flush()?;
        let mut title = String::new();
        io::stdin().read_line(&mut title)?;
        let title = title.trim();
        if title.is_empty() {
            println!("Title cannot be empty.");
            return Ok(());
        }

        print!("Enter note content (end with empty line):\n");
        let mut content = String::new();
        loop {
            let mut line = String::new();
            match io::stdin().read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if line.trim().is_empty() { break; }
                    content.push_str(&line);
                }
                Err(_) => break,
            }
        }

        let safe = title.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        let filename = format!("{safe}.txt");
        let note_path: VirtualPath<Notes> = self.storage.notes_root.virtual_join(&filename)?;
        let ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let body = format!("Title: {title}\nCreated: {ts}\n\n{content}");
        note_path.write_string(&body)?;

        self.update_recent_cache(&filename)?;
        Self::log_event(&self.storage.logs_jail, &format!("Created note: {title}"))?;
        println!("Note '{title}' created successfully!");
        Ok(())
    }

    fn list_notes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let notes_dir = self.storage.notes_root.virtual_join("")?;
        let mut notes = Vec::new();
        for entry in fs::read_dir(notes_dir.interop_path())? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".txt") {
                    notes.push(name.trim_end_matches(".txt").to_string());
                }
            }
        }
        if notes.is_empty() {
            println!("No notes found. Create your first note!");
        } else {
            println!("Available notes:");
            for (i, note) in notes.iter().enumerate() {
                println!("  {}. {}", i + 1, note);
            }
        }
        Ok(())
    }

    fn read_note(&self) -> Result<(), Box<dyn std::error::Error>> {
        print!("Enter note title to read: ");
        io::stdout().flush()?;
        let mut title = String::new();
        io::stdin().read_line(&mut title)?;
        let title = title.trim();
        let filename = format!("{}.txt", title.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_"));
        let note_path: VirtualPath<Notes> = self.storage.notes_root.virtual_join(&filename)?;
        if !note_path.exists() {
            println!("Note '{title}' not found.");
            return Ok(());
        }
        let content = note_path.read_to_string()?;
        println!("\n{}", "=".repeat(50));
        println!("{content}");
        println!("{}", "=".repeat(50));
        self.update_recent_cache(&filename)?;
        Self::log_event(&self.storage.logs_jail, &format!("Read note: {title}"))?;
        Ok(())
    }

    fn search_notes(&self) -> Result<(), Box<dyn std::error::Error>> {
        print!("Enter search term: ");
        io::stdout().flush()?;
        let mut query = String::new();
        io::stdin().read_line(&mut query)?;
        let query = query.trim().to_lowercase();

        let notes_dir = self.storage.notes_root.virtual_join("")?;
        let mut matches = Vec::new();
        for entry in fs::read_dir(notes_dir.interop_path())? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".txt") {
                    let note_path = self.storage.notes_root.virtual_join(name)?;
                    let content = note_path.read_to_string()?;
                    if content.to_lowercase().contains(&query) {
                        matches.push(name.trim_end_matches(".txt").to_string());
                    }
                }
            }
        }
        if matches.is_empty() {
            println!("No notes found containing '{query}'");
        } else {
            println!("Notes containing '{query}':");
            for note in matches { println!("  - {note}"); }
        }
        Ok(())
    }

    fn show_settings(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Current settings:");
        println!("  Auto-save: {}", self.config.auto_save);
        println!("  Theme: {}", self.config.theme);
        println!("  Max recent notes: {}", self.config.max_recent);
        Ok(())
    }

    fn cleanup_cache(&self) -> Result<(), Box<dyn std::error::Error>> {
        let cache_dir = self.storage.cache_jail.strict_join("")?;
        let mut cleaned = 0usize;
        if cache_dir.exists() {
            for entry in fs::read_dir(cache_dir.interop_path())? {
                let entry = entry?;
                if entry.path().is_file() {
                    fs::remove_file(entry.path())?;
                    cleaned += 1;
                }
            }
        }
        println!("Cleaned {cleaned} cache files.");
        let msg = format!("Cache cleanup: {cleaned} files removed");
        Self::log_event(&self.storage.logs_jail, &msg)?;
        Ok(())
    }

    fn load_or_create_config(config_jail: &PathBoundary<Config>) -> Result<AppConfig, Box<dyn std::error::Error>> {
        let config_path: StrictPath<Config> = config_jail.strict_join("settings.toml")?;
        if config_path.exists() {
            let content = config_path.read_to_string()?;
            let auto_save = content.contains("auto_save = true");
            let theme = if content.contains("theme = \"light\"") { "light" } else { "dark" };
            let max_recent = 10;
            Ok(AppConfig { auto_save, theme: theme.to_string(), max_recent })
        } else {
            let default_config = AppConfig { auto_save: true, theme: "dark".to_string(), max_recent: 10 };
            let auto = default_config.auto_save;
            let theme = &default_config.theme;
            let max = default_config.max_recent;
            let content = format!("auto_save = {auto}\ntheme = \"{theme}\"\nmax_recent = {max}\n");
            config_path.write_string(&content)?;
            Ok(default_config)
        }
    }

    fn update_recent_cache(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let recent_path: StrictPath<Cache> = self.storage.cache_jail.strict_join("recent.txt")?;
        let mut recent: Vec<String> = if recent_path.exists() {
            recent_path.read_to_string()?.lines().map(String::from).collect()
        } else {
            Vec::new()
        };
        recent.retain(|f| f != filename);
        recent.insert(0, filename.to_string());
        recent.truncate(self.config.max_recent);
        recent_path.write_string(&recent.join("\n"))?;
        Ok(())
    }

    fn log_event(logs_jail: &PathBoundary<Logs>, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        let log_path: StrictPath<Logs> = logs_jail.strict_join("app.log")?;
        let ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let entry = format!("[{ts}] {message}\n");
        if log_path.exists() {
            let mut content = log_path.read_to_string()?;
            content.push_str(&entry);
            log_path.write_string(&content)?;
        } else {
            log_path.write_string(&entry)?;
        }
        Ok(())
    }
}

