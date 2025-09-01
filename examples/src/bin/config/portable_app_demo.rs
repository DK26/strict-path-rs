// QuickNotes - A portable note-taking application
//
// This application demonstrates real-world usage of app-path + jailed-path
// by implementing a simple but complete note-taking app that:
// - Stores all data relative to the executable (portable)
// - Organizes files securely in separate areas (config, notes, cache, logs)
// - Provides type-safe file operations
// - Supports environment overrides for deployment

#[cfg(not(feature = "with-app-path"))]
compile_error!("This example requires the 'with-app-path' feature. Run with: cargo run --bin portable_app_demo --features with-app-path");

use app_path::app_path;
use jailed_path::{Jail, VirtualRoot, JailedPath, VirtualPath};
use std::fs;
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = QuickNotes::new()?;
    app.run()
}

struct QuickNotes {
    config: AppConfig,
    storage: AppStorage,
}

#[derive(Clone)] struct Config;
#[derive(Clone)] struct Notes; 
#[derive(Clone)] struct Cache;
#[derive(Clone)] struct Logs;

struct AppStorage {
    config_jail: Jail<Config>,
    notes_root: VirtualRoot<Notes>,
    cache_jail: Jail<Cache>, 
    logs_jail: Jail<Logs>,
}

struct AppConfig {
    auto_save: bool,
    theme: String,
    max_recent: usize,
}

impl QuickNotes {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        println!("📝 QuickNotes - Portable Note Taking");
        println!("===================================");
        
        // Setup application directories
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
            config_jail: Jail::try_new_create(&config_dir)?,
            notes_root: VirtualRoot::try_new_create(&notes_dir)?,
            cache_jail: Jail::try_new_create(&cache_dir)?,
            logs_jail: Jail::try_new_create(&logs_dir)?,
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
            let choice = input.trim();
            
            match choice {
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
        
        print!("Enter note content (end with Ctrl+D or empty line):\n");
        let mut content = String::new();
        loop {
            let mut line = String::new();
            match io::stdin().read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    if line.trim().is_empty() {
                        break;
                    }
                    content.push_str(&line);
                }
                Err(_) => break,
            }
        }
        
        let safe_title = title.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        let filename = format!("{}.txt", safe_title);
        let note_path: VirtualPath<Notes> = self.storage.notes_root.virtualpath_join(&filename)?;
        
        note_path.write_string(&format!("Title: {}\nCreated: {}\n\n{}", 
            title, 
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            content
        ))?;
        
        self.update_recent_cache(&filename)?;
        Self::log_event(&self.storage.logs_jail, &format!("Created note: {}", title))?;
        
        println!("Note '{}' created successfully!", title);
        Ok(())
    }
    
    fn list_notes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let notes_dir = self.storage.notes_root.virtualpath_join("")?;
        let entries = fs::read_dir(notes_dir.as_path())?;
        
        let mut notes = Vec::new();
        for entry in entries {
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
        
        let safe_title = title.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        let filename = format!("{}.txt", safe_title);
        let note_path: VirtualPath<Notes> = self.storage.notes_root.virtualpath_join(&filename)?;
        
        if !note_path.exists() {
            println!("Note '{}' not found.", title);
            return Ok(());
        }
        
        let content = note_path.read_to_string()?;
        println!("\n{}", "=".repeat(50));
        println!("{}", content);
        println!("{}", "=".repeat(50));
        
        self.update_recent_cache(&filename)?;
        Self::log_event(&self.storage.logs_jail, &format!("Read note: {}", title))?;
        
        Ok(())
    }
    
    fn search_notes(&self) -> Result<(), Box<dyn std::error::Error>> {
        print!("Enter search term: ");
        io::stdout().flush()?;
        let mut query = String::new();
        io::stdin().read_line(&mut query)?;
        let query = query.trim().to_lowercase();
        
        let notes_dir = self.storage.notes_root.virtualpath_join("")?;
        let entries = fs::read_dir(notes_dir.as_path())?;
        
        let mut matches = Vec::new();
        for entry in entries {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".txt") {
                    let note_path = self.storage.notes_root.virtualpath_join(name)?;
                    let content = note_path.read_to_string()?;
                    if content.to_lowercase().contains(&query) {
                        matches.push(name.trim_end_matches(".txt").to_string());
                    }
                }
            }
        }
        
        if matches.is_empty() {
            println!("No notes found containing '{}'", query);
        } else {
            println!("Notes containing '{}':", query);
            for note in matches {
                println!("  - {}", note);
            }
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
        let cache_dir = self.storage.cache_jail.systempath_join("")?;
        let entries = fs::read_dir(cache_dir.as_path())?;
        
        let mut cleaned = 0;
        for entry in entries {
            let entry = entry?;
            if entry.path().is_file() {
                fs::remove_file(entry.path())?;
                cleaned += 1;
            }
        }
        
        println!("Cleaned {} cache files.", cleaned);
        Self::log_event(&self.storage.logs_jail, &format!("Cache cleanup: {} files removed", cleaned))?;
        Ok(())
    }
    
    fn load_or_create_config(config_jail: &Jail<Config>) -> Result<AppConfig, Box<dyn std::error::Error>> {
        let config_path: JailedPath<Config> = config_jail.systempath_join("settings.toml")?;
        
        if config_path.exists() {
            let content = config_path.read_to_string()?;
            // Simple parsing - in real app would use toml crate
            let auto_save = content.contains("auto_save = true");
            let theme = if content.contains("theme = \"light\"") { "light" } else { "dark" };
            let max_recent = 10; // default
            
            Ok(AppConfig {
                auto_save,
                theme: theme.to_string(),
                max_recent,
            })
        } else {
            let default_config = AppConfig {
                auto_save: true,
                theme: "dark".to_string(),
                max_recent: 10,
            };
            
            let config_content = format!(
                "auto_save = {}\ntheme = \"{}\"\nmax_recent = {}\n",
                default_config.auto_save,
                default_config.theme,
                default_config.max_recent
            );
            
            config_path.write_string(&config_content)?;
            Ok(default_config)
        }
    }
    
    fn update_recent_cache(&self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let recent_path: JailedPath<Cache> = self.storage.cache_jail.systempath_join("recent.txt")?;
        
        let mut recent = if recent_path.exists() {
            recent_path.read_to_string()?
                .lines()
                .map(String::from)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        
        // Remove if already exists
        recent.retain(|f| f != filename);
        // Add to front
        recent.insert(0, filename.to_string());
        // Keep only max_recent
        recent.truncate(self.config.max_recent);
        
        recent_path.write_string(&recent.join("\n"))?;
        Ok(())
    }
    
    fn log_event(logs_jail: &Jail<Logs>, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        let log_path: JailedPath<Logs> = logs_jail.systempath_join("app.log")?;
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let entry = format!("[{}] {}\n", timestamp, message);
        
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

// Type markers for compile-time safety
#[derive(Clone)] struct Config;
#[derive(Clone)] struct Notes;  
#[derive(Clone)] struct Cache;
#[derive(Clone)] struct Logs;
