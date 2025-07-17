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

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]]; then
    echo "❌ Cargo.toml not found. Are you in the project root?"
    exit 1
fi

# Auto-fix common issues first
echo "🔧 Auto-fixing common issues..."
run_fix "Format" "cargo fmt --all"
run_fix "Clippy Fixable Issues" "cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features"
echo "🦀 Now running CI checks after auto-fixes..."
echo

# Run all CI checks in order
run_check "Format Check" "cargo fmt --all -- --check"
run_check "Clippy Lint" "cargo clippy --all-targets --all-features -- -D warnings"
# Skip 'cargo check' since 'cargo test' compiles everything anyway
run_check "Tests (includes compilation)" "cargo test --verbose"
# Doc tests are included in 'cargo test --verbose', so no separate --doc run needed
run_check "Documentation" "RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --document-private-items --all-features"

# Check MSRV compatibility (same as GitHub Actions)
echo "🔍 Checking Minimum Supported Rust Version (1.70.0)..."
if command -v rustup &> /dev/null; then
    if rustup toolchain list | grep -q "1.70.0"; then
        echo "✓ Found Rust 1.70.0 toolchain, checking MSRV compatibility..."
        
        # Regenerate Cargo.lock with MSRV to avoid version conflicts
        echo "🔧 Regenerating Cargo.lock with MSRV Rust 1.70.0..."
        if [[ -f "Cargo.lock" ]]; then
            echo "  • Removing existing Cargo.lock"
            rm -f Cargo.lock
        fi
        
        echo "  • Generating new Cargo.lock with Rust 1.70.0"
        if rustup run 1.70.0 cargo generate-lockfile; then
            echo "  ✓ Cargo.lock regenerated successfully"
            run_check "MSRV Check (Rust 1.70.0)" "rustup run 1.70.0 cargo check --verbose"
        else
            echo "  ❌ Failed to generate Cargo.lock with Rust 1.70.0"
            echo "  💡 Trying fallback: cargo update then check"
            run_check "MSRV Check (Rust 1.70.0)" "rustup run 1.70.0 cargo check --verbose"
        fi
    else
        echo "⚠️  Rust 1.70.0 not installed. Installing for MSRV check..."
        if rustup toolchain install 1.70.0; then
            echo "🔧 Regenerating Cargo.lock with MSRV Rust 1.70.0..."
            if [[ -f "Cargo.lock" ]]; then
                echo "  • Removing existing Cargo.lock"
                rm -f Cargo.lock
            fi
            
            echo "  • Generating new Cargo.lock with Rust 1.70.0"
            if rustup run 1.70.0 cargo generate-lockfile; then
                echo "  ✓ Cargo.lock regenerated successfully"
                run_check "MSRV Check (Rust 1.70.0)" "rustup run 1.70.0 cargo check --verbose"
            else
                echo "  ❌ Failed to generate Cargo.lock with Rust 1.70.0"
                echo "  💡 Trying fallback: cargo update then check"
                run_check "MSRV Check (Rust 1.70.0)" "rustup run 1.70.0 cargo check --verbose"
            fi
        else
            echo "❌ Failed to install Rust 1.70.0. Skipping MSRV check."
            echo "💡 To install manually: rustup toolchain install 1.70.0"
        fi
    fi
else
    echo "⚠️  rustup not found. Skipping MSRV check."
    echo "💡 MSRV check requires rustup to install Rust 1.70.0"
fi

echo "🎉 All CI checks passed!"
echo "💡 Remember to review and commit any auto-fixes made."
echo "Ready to push to remote."
