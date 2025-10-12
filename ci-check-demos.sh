#!/bin/bash
# ci-check-demos.sh - Fast validation checks for demos crate
# Focuses on linting, formatting, and validation without compilation/testing
# Supports selective testing of only changed demo files for faster development

set -e

# Parse command line arguments
FULL_TEST=false
DO_FIX=false
DO_FIX_CHANGED=false
DEMOS=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            FULL_TEST=true
            shift
            ;;
        --fix)
            DO_FIX=true
            shift
            ;;
        --fix-changed)
            DO_FIX_CHANGED=true
            shift
            ;;
        --demos)
            DEMOS="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--full] [--demos binary1,binary2,...]"
            exit 1
            ;;
    esac
done

echo "=== CI Check: demos crate ==="
if $FULL_TEST; then
    echo "Full validation mode (testing all demos)"
else
    echo "Smart validation mode (testing only changed demos)"
fi
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

# Function to detect changed demo files
get_changed_demo_files() {
    local force_full_test_var="$1"
    
    echo "🔍 Detecting changed files..." >&2
    
    # Check if we're in a git repository
    if [[ ! -d ".git" ]]; then
        echo "⚠️  Not in a git repository, running full test" >&2
        eval "$force_full_test_var=true"
        return
    fi
    
    # Get staged changes (ready to commit) and unstaged changes (working directory)
    local staged_changes=($(git diff --cached --name-only 2>/dev/null || true))
    local unstaged_changes=($(git diff --name-only 2>/dev/null || true))
    
    # Combine and deduplicate changes
    local all_changes=($(printf '%s\n' "${staged_changes[@]}" "${unstaged_changes[@]}" | sort -u))
    
    echo "📁 Found ${#all_changes[@]} changed files" >&2
    
    # Extract only actual demo files that changed - ignore core library changes
    local demo_changes=()
    for change in "${all_changes[@]}"; do
        if [[ "$change" =~ ^demos/src/bin/.*\.rs$ ]]; then
            demo_changes+=("$change")
        fi
    done
    
    if [[ ${#demo_changes[@]} -eq 0 ]]; then
        echo "✅ No demo files changed, nothing to validate." >&2
        return
    fi
    
    echo "🎯 Demo files changed:" >&2
    for change in "${demo_changes[@]}"; do
        echo "  - $change" >&2
    done
    
    printf '%s\n' "${demo_changes[@]}"
}

# Function to extract binary names from demo file paths
get_binary_names_from_paths() {
    local paths=("$@")
    local binary_names=()
    
    for path in "${paths[@]}"; do
        # Extract binary name from demos/src/bin/<category>/<binary_name>.rs
        if [[ "$path" =~ demos/src/bin/[^/]+/([^/]+)\.rs$ ]]; then
            binary_names+=("${BASH_REMATCH[1]}")
        fi
    done
    
    # Remove duplicates and sort
    printf '%s\n' "${binary_names[@]}" | sort -u
}

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]]; then
    echo "❌ Cargo.toml not found. Are you in the project root?"
    exit 1
fi

# Check if demos subdirectory exists
if [[ ! -d "demos" ]]; then
    echo "❌ demos/ subdirectory not found. Are you in the project root?"
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
echo "📄 Checking demos/Cargo.toml..."
check_utf8_encoding "demos/Cargo.toml" || exit 1

echo "📄 Checking demos/README.md..."
if [[ -f "demos/README.md" ]]; then
    check_utf8_encoding "demos/README.md" || exit 1
    check_no_bom "demos/README.md" || exit 1
else
    echo "ℹ️  demos/README.md not found, skipping"
fi

echo "📄 Checking demos Rust source files..."
if find demos/src -name "*.rs" -type f | head -1 >/dev/null 2>&1; then
    find demos/src -name "*.rs" -type f | while read file; do
        check_utf8_encoding "$file" || exit 1
    done
    echo "✅ All Rust source files in demos/src: UTF-8 encoding verified"
else
    echo "⚠️  No Rust source files found in demos/src; skipping source file encoding check"
fi

echo "🎉 All file encoding checks passed!"
echo

# Auto-fix is optional to avoid compilation in smart mode
if $FULL_TEST || $DO_FIX; then
    echo "🔧 Auto-fixing common issues..."
    run_fix "Format demos" "(cd demos && cargo fmt --all)"
    # Use safe features for auto-fix (avoid heavy dependencies like AWS that require cmake/nasm)
    run_fix "Clippy Fixable Issues (demos)" "(cd demos && cargo clippy --fix --allow-dirty --allow-staged --all-targets --features 'with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp,virtual-path')"
    run_fix "Format demos (after clippy fix)" "(cd demos && cargo fmt --all)"
else
    echo "⏭️  Skipping auto-fix (use --full, --fix or --fix-changed to enable)."
fi

echo "🦀 Running validation checks (no compilation/testing)..."
echo

# Run validation checks
if [[ "$FORCE_FULL_TEST" == "true" ]]; then
    # Full format check
    run_check "Format Check demos (ALL)" '
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
elif [[ ${#CHANGED_DEMO_FILES[@]} -gt 0 ]]; then
    # Fast format check - only changed files
    # Default behavior: auto-format changed files (no compilation)
    if ! $FULL_TEST && ! $DO_FIX && ! $DO_FIX_CHANGED; then
        run_fix "Format changed demo files" "rustfmt $(printf '%q ' \"${CHANGED_DEMO_FILES[@]}\")"
    fi
    run_check "Format Check demos (SELECTIVE: ${#CHANGED_DEMO_FILES[@]} files)" '
        set -e
        echo "🔍 Checking format for: $(IFS=","'" "'; echo "${CHANGED_DEMO_FILES[*]}")"
        
        # Use rustfmt directly on the changed files
        if ! rustfmt --check "${CHANGED_DEMO_FILES[@]}"; then
            echo "❌ Format check failed for changed demo files."
            echo "Fix with: rustfmt $(printf '"'"'%s '"'"' "${CHANGED_DEMO_FILES[@]}")"
            exit 1
        fi
        echo "✅ All changed demo files are properly formatted"
    '
fi

# Optional selective auto-fix for changed demos only (no full compile)
if $DO_FIX_CHANGED && [[ ${#CHANGED_DEMO_FILES[@]} -gt 0 ]] && ! $FULL_TEST && ! $DO_FIX; then
    echo "🔧 Selective auto-fix for changed demos..."
    # 1) Format only changed files
    run_fix "Format changed demo files" "rustfmt $(printf '%q ' "${CHANGED_DEMO_FILES[@]}")"

    # 2) Run clippy --fix per affected binary with safe features
    mapfile -t CHANGED_BINS < <(get_binary_names_from_paths "${CHANGED_DEMO_FILES[@]}")
    if [[ ${#CHANGED_BINS[@]} -gt 0 ]]; then
        (
            cd demos
            for bin in "${CHANGED_BINS[@]}"; do
                echo "Clippy fix for demo bin: $bin"
                cargo clippy --fix --allow-dirty --allow-staged --bin "$bin" --features 'with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp,virtual-path'
            done
        )
    fi
    # 3) Format again to normalize
    run_fix "Format demos (after selective fix)" "(cd demos && cargo fmt --all)"
fi

# Determine what to test
FORCE_FULL_TEST=false
if $FULL_TEST; then
    echo "📋 Full test mode requested via --full flag"
    FORCE_FULL_TEST=true
elif [[ -n "$DEMOS" ]]; then
    echo "📋 Manual demo selection via --demos flag: $DEMOS"
    IFS=',' read -ra BINARIES_TO_TEST <<< "$DEMOS"
    # Trim whitespace
    for i in "${!BINARIES_TO_TEST[@]}"; do
        BINARIES_TO_TEST[i]=$(echo "${BINARIES_TO_TEST[i]}" | xargs)
    done
else
    mapfile -t CHANGED_DEMO_FILES < <(get_changed_demo_files FORCE_FULL_TEST)
    # Default behavior: auto-format changed files (no compilation)
    if [[ "$FORCE_FULL_TEST" != "true" ]] && [[ ${#CHANGED_DEMO_FILES[@]} -gt 0 ]] && ! $FULL_TEST && ! $DO_FIX && ! $DO_FIX_CHANGED; then
        run_fix "Format changed demo files" "rustfmt $(printf '%q ' \"${CHANGED_DEMO_FILES[@]}\")"
    fi
    if [[ "$FORCE_FULL_TEST" != "true" ]] && [[ ${#CHANGED_DEMO_FILES[@]} -gt 0 ]]; then
        mapfile -t BINARIES_TO_TEST < <(get_binary_names_from_paths "${CHANGED_DEMO_FILES[@]}")
        echo "📋 Changed demo files detected:"
        for file in "${CHANGED_DEMO_FILES[@]}"; do
            echo "  - $file"
        done
        echo "🎯 Will test binaries: $(IFS=','; echo "${BINARIES_TO_TEST[*]}")"
    elif [[ "$FORCE_FULL_TEST" != "true" ]]; then
        echo "✅ No demo changes detected, skipping clippy tests"
        echo "💡 Use --full flag to force full testing"
        echo
        echo "🎉 No demo validation needed!"
        echo "💡 This was a smart check - no demo changes detected."
        echo "💡 Run with --full flag for complete validation."
        exit 0
    fi
fi

# Lint demos - fast validation without dependencies
if [[ "$FORCE_FULL_TEST" == "true" ]]; then
    # Full clippy with feature matrix (slow but thorough)
    run_check "Clippy Demos (all features - ALL)" '
        # Run in a subshell to avoid leaking directory changes
        (
            set -e
            cd demos
            
            # Check for heavy toolchain deps
            if command -v cmake >/dev/null 2>&1 && command -v nasm >/dev/null 2>&1; then
                ALL_FEATURES="with-zip,with-app-path,with-dirs,with-tempfile,with-aws,with-rmcp,virtual-path"
            else
                echo "⚠️  WARNING: Skipping '\''with-aws'\'' feature: cmake and/or nasm not found on PATH"
                ALL_FEATURES="with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp,virtual-path"
            fi
            
            # Single combined test: compile once with all available features
            echo "==> Clippy demos with features: $ALL_FEATURES"
            cargo clippy --all-targets --features "$ALL_FEATURES" -- -D warnings
        )
    '
elif [[ ${#BINARIES_TO_TEST[@]} -gt 0 ]]; then
    # Ultra-fast validation - file-level checks only (no compilation/builds)
    run_check "Ultra-Fast Demos (SELECTIVE: $(IFS=','; echo "${BINARIES_TO_TEST[*]}"))" '
        echo "🚀 Ultra-fast validation (no builds, no dependency downloads)..."
        
        # Format check on changed files only
        echo "==> Format check on changed demo files..."
        if ! rustfmt --check "${CHANGED_DEMO_FILES[@]}"; then
            echo "❌ Format check failed. Run rustfmt on the above files to fix."
            exit 1
        fi
        echo "✅ Format check passed for changed demo files"
        
        echo "💡 Selective validation complete - only checked changed files for formatting."
        echo "💡 For full lint/syntax checks, use --full flag or run ci-local.sh"
    '
fi

echo "🎉 All validation checks passed!"
if [[ "$FORCE_FULL_TEST" == "true" ]]; then
    echo "💡 Full validation completed for all demos."
elif [[ ${#BINARIES_TO_TEST[@]} -gt 0 ]]; then
    echo "💡 Selective validation completed for: $(IFS=','; echo "${BINARIES_TO_TEST[*]}")"
fi
echo "💡 This was a fast check focusing on validation only."
echo "💡 Run ci-local.sh for full CI including compilation and testing."
echo "💡 Use --full flag to force testing all demos."
echo "💡 Remember to review and commit any auto-fixes made."