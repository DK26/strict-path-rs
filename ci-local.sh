#!/bin/bash
# ci-local.sh - Cross-platform CI Test Runner
# Run all CI checks locally before pushing

set -e

# Try to find cargo in common locations  
if ! command -v cargo &> /dev/null; then
    # Try common cargo locations across platforms
    CARGO_PATHS=(
        "$HOME/.cargo/bin/cargo"
        "$HOME/.cargo/bin/cargo.exe" 
        "/c/Users/$(whoami)/.cargo/bin/cargo.exe"
        "/home/$(whoami)/.cargo/bin/cargo"
        "$(pwd)/../.cargo/bin/cargo"
    )
    
    for cargo_path in "${CARGO_PATHS[@]}"; do
        if [[ -x "$cargo_path" ]]; then
            export PATH="$(dirname "$cargo_path"):$PATH"
            echo "✓ Found cargo at: $cargo_path"
            break
        fi
    done
    
    # Final check
    if ! command -v cargo &> /dev/null; then
        echo "❌ cargo not found. Make sure Rust is installed."
        echo ""
        echo "To run CI tests:"
        echo "  • Make sure 'cargo --version' works in your terminal"
        echo "  • Or install Rust from https://rustup.rs/"
        exit 1
    fi
fi

echo "✓ Using cargo: $(command -v cargo)"

# Check Rust version and warn about nightly vs stable differences
RUST_VERSION=$(rustc --version)
echo "🦀 Rust version: $RUST_VERSION"

if echo "$RUST_VERSION" | grep -q "nightly"; then
    echo "⚠️  WARNING: You're using nightly Rust, but GitHub Actions uses stable!"
    echo "   Some nightly-only APIs might work locally but fail in CI."
    echo "   Consider testing with: rustup default stable"
elif echo "$RUST_VERSION" | grep -qE "1\.(8[8-9]|9[0-9]|[0-9]{3})"; then
    echo "⚠️  WARNING: You're using a newer Rust version than GitHub Actions stable!"
    echo "   GitHub Actions uses the latest stable release."
fi
echo

echo "🔧 Auto-fixing common issues before CI checks"
echo

run_check() {
    local name="$1"
    local command="$2"
    
    echo "Running: $name"
    echo "Command: $command"
    
    start_time=$(date +%s)
    
    if eval "$command"; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo "✓ $name completed in ${duration}s"
        echo
        return 0
    else
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo "✗ $name failed after ${duration}s"
        echo "❌ CI checks failed. Fix issues before pushing."
        exit 1
    fi
}

run_fix() {
    local name="$1"
    local command="$2"
    
    echo "Auto-fixing: $name"
    echo "Command: $command"
    
    start_time=$(date +%s)
    
    if eval "$command"; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo "✓ $name auto-fix completed in ${duration}s"
        echo
        return 0
    else
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo "✗ $name auto-fix failed after ${duration}s"
        echo "⚠️  Continuing with CI checks anyway..."
        echo
        return 1
    fi
}

# Try a primary MSRV command and fall back to a manifest-scoped variant if it fails
run_check_try() {
    local name="$1"
    local primary_cmd="$2"
    local fallback_cmd="$3"

    echo "Running (try primary then fallback): $name"
    echo "Primary: $primary_cmd"
    if eval "$primary_cmd"; then
        echo "✓ Primary succeeded"
        echo
        return 0
    else
        echo "⚠️  Primary MSRV command failed; attempting fallback..."
        echo "Fallback: $fallback_cmd"
        if eval "$fallback_cmd"; then
            echo "✓ Fallback succeeded"
            echo
            return 0
        else
            echo "✗ Both primary and fallback failed for: $name"
            exit 1
        fi
    fi
}

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]]; then
    echo "❌ Cargo.toml not found. Are you in the project root?"
    exit 1
fi

# Validate file encodings first (critical for Cargo publish)
echo "🔍 Validating UTF-8 encoding for critical files..."

check_utf8_encoding() {
    local file="$1"
    
    # Check if file exists
    if [[ ! -f "$file" ]]; then
        echo "❌ File not found: $file"
        return 1
    fi
    
    # Method 1: Use file command if available (most reliable)
    if command -v file >/dev/null 2>&1; then
        local file_output=$(file "$file")
        # Check for UTF-8, ASCII, text files, or source files (which are typically UTF-8)
        if echo "$file_output" | grep -q "UTF-8\|ASCII\|text\|[Ss]ource"; then
            echo "✅ $file: UTF-8 encoding verified (file command)"
            return 0
        else
            echo "❌ $file is not UTF-8 encoded:"
            echo "   File command output: $file_output"
            return 1
        fi
    fi
    
    # Method 2: Check for UTF-16 BOM (Windows PowerShell sometimes creates these)
    if command -v xxd >/dev/null 2>&1; then
        if head -c 2 "$file" | xxd | grep -q "fffe\|feff"; then
            echo "❌ $file appears to be UTF-16 encoded (found BOM)"
            echo "   Fix with: iconv -f utf-16 -t utf-8 '$file' -o '$file'"
            return 1
        fi
    elif command -v od >/dev/null 2>&1; then
        if head -c 2 "$file" | od -t x1 | grep -q "ff fe\|fe ff"; then
            echo "❌ $file appears to be UTF-16 encoded (found BOM)"
            echo "   Fix with: iconv -f utf-16 -t utf-8 '$file' -o '$file'"
            return 1
        fi
    fi
    
    # Method 3: Try to read with Python UTF-8 (fallback)
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "
import sys
try:
    with open('$file', 'r', encoding='utf-8') as f:
        f.read()
    print('✅ $file: UTF-8 encoding verified (Python check)')
except UnicodeDecodeError as e:
    print('❌ $file: Not valid UTF-8 -', str(e))
    sys.exit(1)
        "; then
            return 0
        else
            return 1
        fi
    fi
    
    # If no validation method available, warn but continue
    echo "⚠️  Cannot verify encoding for $file (no validation tools available)"
    echo "   Assuming UTF-8. Install 'file' command for proper validation."
    return 0
}

check_no_bom() {
    local file="$1"
    
    # Check for UTF-8 BOM (EF BB BF) which should not be present
    if command -v xxd >/dev/null 2>&1; then
        if head -c 3 "$file" | xxd | grep -qE "ef[ ]?bb[ ]?bf"; then
            echo "❌ $file contains UTF-8 BOM (should be UTF-8 without BOM)"
            echo "   This can cause issues with Cargo publish and GitHub Actions"
            echo "   Fix with: tail -c +4 '$file' > temp && mv temp '$file'"
            return 1
        fi
        echo "✅ $file: No BOM detected (correct)"
    elif command -v od >/dev/null 2>&1; then
        if head -c 3 "$file" | od -t x1 | grep -qE "ef[ ]?bb[ ]?bf"; then
            echo "❌ $file contains UTF-8 BOM (should be UTF-8 without BOM)"
            echo "   This can cause issues with Cargo publish and GitHub Actions"
            echo "   Fix with: tail -c +4 '$file' > temp && mv temp '$file'"
            return 1
        fi
        echo "✅ $file: No BOM detected (correct)"
    fi
    
    return 0
}

# Check critical files for encoding issues
echo "📄 Checking README.md..."
check_utf8_encoding "README.md" || exit 1
check_no_bom "README.md" || exit 1

echo "📄 Checking Cargo.toml..."
check_utf8_encoding "Cargo.toml" || exit 1

echo "📄 Checking Rust source files..."
if find strict-path/src -name "*.rs" -type f | head -1 >/dev/null 2>&1; then
    find strict-path/src -name "*.rs" -type f | while read file; do
        check_utf8_encoding "$file" || exit 1
    done
    echo "✅ All Rust source files in strict-path/src: UTF-8 encoding verified"
elif find src -name "*.rs" -type f | head -1 >/dev/null 2>&1; then
    find src -name "*.rs" -type f | while read file; do
        check_utf8_encoding "$file" || exit 1
    done
    echo "✅ All Rust source files in src/: UTF-8 encoding verified"
elif find demos/src -name "*.rs" -type f | head -1 >/dev/null 2>&1; then
    find demos/src -name "*.rs" -type f | while read file; do
        check_utf8_encoding "$file" || exit 1
    done
    echo "✅ All Rust source files in demos/src: UTF-8 encoding verified"
else
    echo "⚠️  No Rust source files found in strict-path/src, src/ or demos/src; skipping source file encoding check"
fi

echo "🎉 All file encoding checks passed!"
echo

# Auto-fix common issues first
echo "🔧 Auto-fixing common issues..."
run_fix "Format" "cargo fmt --all"
run_fix "Format demos" "(cd demos && cargo fmt --all)"
run_fix "Clippy Fixable Issues" "cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features"
run_fix "Format (after clippy fix)" "cargo fmt --all"
run_fix "Format demos (after clippy fix)" "(cd demos && cargo fmt --all)"
echo "🦀 Now running CI checks (same as GitHub Actions)..."
echo

# Run all CI checks in order
run_check "Format Check" '
    set -e
    if ! cargo fmt --all -- --check; then
        echo "❌ Formatting check failed. Run cargo fmt --all to fix."
        echo "Here is what would be changed:"
        cargo fmt --all -- --check --verbose || true
        exit 1
    fi
'

run_check "Format Check demos" '
    set -e
    # Run in a subshell to avoid leaking directory changes
    (
      cd demos
      if ! cargo fmt --all -- --check; then
          echo "❌ Demos formatting check failed. Run cd demos && cargo fmt --all to fix."
          echo "Here is what would be changed:"
          cargo fmt --all -- --check --verbose || true
          exit 1
      fi
    )
'
# Lint and tests on the latest installed Rust toolchain
run_check "Clippy Lint" "cargo clippy --all-targets --all-features -- -D warnings"
# Build library examples
run_check "Build examples (library)" "cargo build -p strict-path --examples --all-features"
# Lint demos across feature matrix (we do not build/run demos in CI)
run_check "Clippy Demos (matrix)" '
    # Run in a subshell to avoid leaking directory changes
    (
        set -e
        cd demos
        for FEATS in "" \
                                 "with-zip" \
                                 "with-app-path" \
                                 "with-dirs" \
                                 "with-tempfile" \
                                 "with-rmcp" \
                                 "with-aws" \
                                 "with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp" \
                                 "with-zip,with-app-path,with-dirs,with-tempfile,with-aws,with-rmcp"; do
            if [ -z "$FEATS" ]; then
                echo "==> Clippy demos with features: <none>"
                cargo clippy --all-targets -- -D warnings
            else
                echo "==> Clippy demos with features: $FEATS"
                cargo clippy --all-targets --features "$FEATS" -- -D warnings
            fi
        done
    )
'

# Run demos tests across feature sets
# Run workspace tests for the library only
run_check "Tests (library all features)" "cargo test -p strict-path --all-features --verbose"
# Doc tests are included in 'cargo test --verbose', so no separate --doc run needed
run_check "Documentation" "RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --document-private-items --all-features"

# Build mdbook documentation
echo "📚 Building mdbook documentation..."
if command -v mdbook &> /dev/null; then
    run_check "Build mdbook docs" "(cd docs_src && mdbook build)"
else
    echo "⚠️  mdbook not found. Installing..."
    if cargo install mdbook --locked; then
        echo "✓ mdbook installed successfully"
        run_check "Build mdbook docs" "(cd docs_src && mdbook build)"
    else
        echo "❌ Failed to install mdbook. Skipping documentation build."
        echo "💡 To install manually: cargo install mdbook"
        echo "💡 Then run: cd docs_src && mdbook build"
    fi
fi

# Security audit (same as GitHub Actions)
echo "🔍 Running security audit..."
if command -v cargo-audit &> /dev/null; then
    run_check "Security Audit" "cargo audit"
else
    echo "⚠️  cargo-audit not found. Installing..."
    if cargo install cargo-audit --locked; then
        echo "✓ cargo-audit installed successfully"
        run_check "Security Audit" "cargo audit"
    else
        echo "❌ Failed to install cargo-audit. Skipping security audit."
        echo "💡 To install manually: cargo install cargo-audit"
    fi
fi
if command -v rustup &> /dev/null; then
    if rustup toolchain list | grep -q "1.71.0"; then
        echo "✓ Found Rust 1.71.0 toolchain, checking MSRV compatibility..."

        # Ensure Clippy is installed for MSRV
        if ! rustup component list --toolchain 1.71.0 | grep -q "clippy.*(installed)"; then
            echo "🔧 Installing Clippy for Rust 1.71.0..."
            rustup component add clippy --toolchain 1.71.0
        fi

        # Run MSRV checks scoped to the library package only
        run_fix "MSRV Clippy Auto-fix" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo clippy -p strict-path --lib --fix --allow-dirty --allow-staged --all-features" || true
        run_check_try "MSRV Check (Rust 1.71.0)" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo check -p strict-path --lib --locked --verbose" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo check -p strict-path --lib --locked --verbose"
        run_check_try "MSRV Clippy Lint" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo clippy --locked -p strict-path --lib --all-features -- -D warnings" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo clippy --locked -p strict-path --lib --all-features -- -D warnings"
        run_check_try "MSRV Test" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo test -p strict-path --lib --locked --verbose" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo test -p strict-path --lib --locked --verbose"
    else
        echo "⚠️  Rust 1.71.0 not installed. Installing for MSRV check..."
        if rustup toolchain install 1.71.0; then
            echo "🔧 Installing Clippy for Rust 1.71.0..."
            rustup component add clippy --toolchain 1.71.0
            run_fix "MSRV Clippy Auto-fix" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo clippy -p strict-path --lib --fix --allow-dirty --allow-staged --all-features"
            run_check_try "MSRV Check (Rust 1.71.0)" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo check -p strict-path --lib --locked --verbose" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo check -p strict-path --lib --locked --verbose"
            run_check_try "MSRV Clippy Lint" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo clippy --locked -p strict-path --lib --all-features -- -D warnings" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo clippy --locked -p strict-path --lib --all-features -- -D warnings"
            run_check_try "MSRV Test" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo test -p strict-path --lib --locked --verbose" "CARGO_TARGET_DIR=target/msrv rustup run 1.71.0 cargo test -p strict-path --lib --locked --verbose"
    else
        echo "❌ Failed to install Rust 1.71.0. Skipping MSRV check."
        echo "💡 To install manually: rustup toolchain install 1.71.0"
        fi
    fi
else
    echo "⚠️  rustup not found. Skipping MSRV check."
    echo "💡 MSRV check requires rustup to install Rust 1.71.0"
fi

echo "🎉 All CI checks passed!"
echo "💡 Remember to review and commit any auto-fixes made."
echo "Ready to push to remote."
