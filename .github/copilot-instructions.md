# Before committing

- If running on a Windows machine, run `.\ci-local.ps1`
- If running on a Unix-based system, run `./ci-local.sh`
- If WSL is available, run `bash ci-local.sh` to test also on Linux

# When committing    

- run `git diff --staged`, summarize the changes, try to understand what these changes mean, and write a commit message with that summary. Do not include or mention anything that is not reflected in the code diff. e.g., changes you may have made in the current session but were not evident within `git diff --staged` output

# When bumping version  

- run `git diff` against the last tagged release, summarize the changes:
    - update CHANGELOG.md accordingly. Include only high level changes that can interest users
    - update the version number in the relevant files (Cargo.toml, lib.rs, CHANGELOG.md, README.md)
    - commit the changes with a meaningful commit message
    - create a tag for the next release version
    - provide a PR summary in markdown source code format so it can be copied and pasted. Do not include code examples

# Documentations README.md / lib.rs  

- if modifying README.md, make sure that the structure is consistent with the rest of the documentation
- README.md purpose is to introduce our crate the best way possible and should only contain information that helps understanding why is it useful, and how to easily use it and what are its cool, most useful features  
- changes in documentations between README.md and lib.rs, must be aligned whenever makes sense
- assume each thing you are considering removing or changing, may have taken a lot of time and consideration to come up with. try to understand why it is there first and if you'd like to change it, have a discussion first on how to proceed
- code examples should start from the simplest usage to more advanced use cases

# Generated API documentations

- when documenting APIs, make sure you make it clear to both human and LLM in the most efficient way, what it is for and how to use it correctly. The purpose is avoiding misuse of the API, especially by LLMs  

# Rust Code Style

- Use Clippy best practices `cargo clippy --all-targets --all-features -- -D warnings`
- Use `rustfmt` for code formatting ` cargo fmt --all -- --check`
- When you produce new Rust code, make sure you follow the Rust API guidelines and best practices. 

# Roadmap  

- Make sure our roadmap documents are refelcting accuratly the implemented reality in our source code  

