Please refer to `AGENTS.md` at the repository root for all operational guidance, coding and docs conventions, CI usage, API rules, and contribution practices.

Key sections in `AGENTS.md`:
- Local CI Parity (how to run CI locally on Windows/Unix/WSL)
- Before Committing (commit message and staged-diff expectations)
- Code Style (clippy, rustfmt, Rust API guidelines)
- Documentation Guidelines (README/lib.rs/API docs alignment)
- Path Handling Rules and API & Conversion Rules (security-critical)
- Do / Don’t (for agents and automation)

CRITICAL:
- You are not allowed to use `git restore` or any `git` command that overrides current state of files, especially not because of small corruptions you may cause  
- You are not allowed to do any `git` related commands without verifying current status  
- You are not allowed to execute any modification to any part of the code, without fully understanding why it exists  
- You are not allowed to create new APIs without consulting  
- You are not allowed to generate code without understanding the established framework, principles and code style  
