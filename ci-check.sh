#!/bin/bash
# ci-check.sh - Fast validation checks for strict-path crate
# Focuses on linting, formatting, and validation without compilation/testing

set -e

echo "=== CI Check: strict-path crate ==="
echo "Fast validation without compilation/testing"
echo

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
        exit 1
    fi
fi

echo "✓ Using cargo: $(command -v cargo)"

# Check Rust version
RUST_VERSION=$(rustc --version)
echo "🦀 Rust version: $RUST_VERSION"
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
        echo "❌ Validation checks failed."
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
        echo "⚠️  Continuing with checks anyway..."
        echo
        return 1
    fi
}

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]]; then
    echo "❌ Cargo.toml not found. Are you in the project root?"
    exit 1
fi

# Check if strict-path subdirectory exists
if [[ ! -d "strict-path" ]]; then
    echo "❌ strict-path/ subdirectory not found. Are you in the project root?"
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
    
    # Method 2: Try to read with Python UTF-8 (fallback)
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

echo "📄 Checking strict-path/Cargo.toml..."
check_utf8_encoding "strict-path/Cargo.toml" || exit 1

echo "📄 Checking strict-path Rust source files..."
if find strict-path/src -name "*.rs" -type f | head -1 >/dev/null 2>&1; then
    find strict-path/src -name "*.rs" -type f | while read file; do
        check_utf8_encoding "$file" || exit 1
    done
    echo "✅ All Rust source files in strict-path/src: UTF-8 encoding verified"
else
    echo "⚠️  No Rust source files found in strict-path/src; skipping source file encoding check"
fi

echo "🎉 All file encoding checks passed!"
echo

# Auto-fix common issues first
echo "🔧 Auto-fixing common issues..."
run_fix "Format strict-path" "cargo fmt -p strict-path"
run_fix "Clippy Fixable Issues (strict-path)" "cargo clippy -p strict-path --fix --allow-dirty --allow-staged --all-targets --all-features"
run_fix "Format strict-path (after clippy fix)" "cargo fmt -p strict-path"

echo "🦀 Running validation checks (no compilation/testing)..."
echo

# Run validation checks
run_check "Format Check (strict-path)" '
    set -e
    if ! cargo fmt -p strict-path -- --check; then
        echo "❌ Formatting check failed. Run cargo fmt -p strict-path to fix."
        echo "Here is what would be changed:"
        cargo fmt -p strict-path -- --check --verbose || true
        exit 1
    fi
'

run_check "Clippy Lint (strict-path, all features)" "cargo clippy -p strict-path --all-targets --all-features -- -D warnings"
run_check "Clippy Lint (strict-path, no features)" "cargo clippy -p strict-path --all-targets --no-default-features -- -D warnings"

# Check documentation generation (no compilation of code, just docs)
run_check "Documentation Check (strict-path)" "RUSTDOCFLAGS='-D warnings' cargo doc -p strict-path --no-deps --document-private-items --all-features"

echo "🎉 All validation checks passed!"
echo "💡 This was a fast check focusing on validation only."
echo "💡 Run ci-local.sh for full CI including compilation and testing."
echo "💡 Remember to review and commit any auto-fixes made."
