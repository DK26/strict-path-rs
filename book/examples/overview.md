# Real-World Examples

This section shows practical, real-world scenarios where strict-path helps secure your applications. Each example includes complete, runnable code that you can adapt to your own projects.

## 📚 Example Categories

### Web Applications
- **[Web File Upload Service](./web_upload_service.md)** - Build a secure file upload service with per-user isolation
- **[Multi-User Document Storage](./multi_user_storage.md)** - Implement user sandboxing where each user feels they have their own filesystem

### Application Development
- **[Configuration File Manager](./config_manager.md)** - Safely handle user configuration files with automatic validation
- **[CLI Tool with Safe Paths](./cli_tool.md)** - Process user-provided file paths in command-line tools

### Security-Critical Operations
- **[Archive Extraction](./archive_extraction.md)** - Extract ZIP files safely without zip-slip vulnerabilities
- **[Type-Safe Context Separation](./type_safe_contexts.md)** - Use marker types to prevent mixing storage contexts at compile time

## 🎯 Common Patterns

All examples follow the same security pattern:

1. **Create a boundary** - Define your safe area with `PathBoundary` or `VirtualRoot`
2. **Validate external input** - Always use `strict_join()` or `virtual_join()` for untrusted paths
3. **Use safe types** - Operate through `StrictPath` or `VirtualPath` for all file operations
4. **Let the compiler help** - Type signatures encode security guarantees

## 🔐 What Makes These Secure?

- **No path escapes** - Users can't use `../` or absolute paths to escape boundaries
- **Compile-time safety** - Wrong marker types won't compile
- **Clear interfaces** - Function signatures document what paths they accept
- **Maintainable** - Security isn't something to remember, it's in the type system

## 💡 Using These Examples

Each example is:
- ✅ **Complete** - Includes all necessary imports and error handling
- ✅ **Runnable** - Copy-paste and adapt to your needs
- ✅ **Explained** - Comments highlight security patterns and key concepts
- ✅ **Battle-tested** - Shows real attack vectors that are automatically blocked

Choose an example that matches your use case and start building secure applications!
