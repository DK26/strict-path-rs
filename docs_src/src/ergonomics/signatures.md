# Function Signatures

Encode guarantees so misuse is hard:

- Accept validated paths directly when the caller did validation:
  - `fn process(file: &StrictPath<MyMarker>) -> io::Result<()> { ... }`
  - `fn read(user_file: &VirtualPath<MyMarker>) -> io::Result<Vec<u8>> { ... }`
- Validate inside helpers by accepting policy + untrusted segment:
  - `fn write(cfg: &PathBoundary<MyMarker>, name: &str) -> io::Result<()> { ... }`
  - `fn upload(vroot: &VirtualRoot<MyMarker>, filename: &str) -> io::Result<()> { ... }`
- Don’t construct boundaries/roots inside helpers—policy lives at the call site.
- Prefer domain names over type names: `uploads_root`, `config_dir`, `user_project_root`.
