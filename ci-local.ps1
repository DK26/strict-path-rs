# ci-local.ps1 - Cross-platform CI Test Runner for PowerShell
# Run all CI checks locally before pushing

$ErrorActionPreference = "Stop"

Write-Host "=== CI Local Test Runner ===" -ForegroundColor Cyan

# Check if cargo is available
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: cargo not found. Make sure Rust is installed." -ForegroundColor Red
    Write-Host "Install Rust from https://rustup.rs/" -ForegroundColor Yellow
    exit 1
}

# Check if we're in the right directory
if (-not (Test-Path "Cargo.toml")) {
    Write-Host "ERROR: Cargo.toml not found. Are you in the project root?" -ForegroundColor Red
    exit 1
}

# Show Rust version
$rustVersion = & rustc --version
Write-Host "Rust version: $rustVersion" -ForegroundColor Magenta

if ($rustVersion -match "nightly") {
    Write-Host "WARNING: Using nightly Rust, but GitHub Actions uses stable!" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Auto-fixing common issues..." -ForegroundColor Cyan

# Auto-fix formatting
Write-Host "Running: cargo fmt --all" -ForegroundColor Blue
try {
    & cargo fmt --all
    Write-Host "SUCCESS: Format auto-fix completed" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Format auto-fix failed, continuing..." -ForegroundColor Yellow
}

# Auto-fix clippy issues
Write-Host "Running: cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features" -ForegroundColor Blue
try {
    & cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features
    Write-Host "SUCCESS: Clippy auto-fix completed" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Clippy auto-fix failed, continuing..." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Running CI checks..." -ForegroundColor Cyan

# Format check
Write-Host "Running: cargo fmt --all -- --check" -ForegroundColor Blue
& cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: Format check failed" -ForegroundColor Red
    exit 1
}
Write-Host "SUCCESS: Format check passed" -ForegroundColor Green

# Clippy check
Write-Host "Running: cargo clippy --all-targets --all-features -- -D warnings" -ForegroundColor Blue
& cargo clippy --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: Clippy check failed" -ForegroundColor Red
    exit 1
}
Write-Host "SUCCESS: Clippy check passed" -ForegroundColor Green

# Tests
Write-Host "Running: cargo test --verbose" -ForegroundColor Blue
& cargo test --verbose
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: Tests failed" -ForegroundColor Red
    exit 1
}
Write-Host "SUCCESS: Tests passed" -ForegroundColor Green

# Documentation
Write-Host "Running: cargo doc --no-deps --document-private-items --all-features" -ForegroundColor Blue
$env:RUSTDOCFLAGS = "-D warnings"
& cargo doc --no-deps --document-private-items --all-features
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED: Documentation check failed" -ForegroundColor Red
    exit 1
}
Write-Host "SUCCESS: Documentation check passed" -ForegroundColor Green

# MSRV check
Write-Host "Checking MSRV (Rust 1.70.0)..." -ForegroundColor Blue
if (Get-Command rustup -ErrorAction SilentlyContinue) {
    $toolchains = & rustup toolchain list
    if ($toolchains -match "1\.70\.0") {
        Write-Host "Found Rust 1.70.0, running MSRV checks..." -ForegroundColor Blue
        
        # MSRV check
        & rustup run 1.70.0 cargo check --verbose
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED: MSRV check failed" -ForegroundColor Red
            exit 1
        }
        Write-Host "SUCCESS: MSRV check passed" -ForegroundColor Green
        
        # MSRV clippy
        & rustup run 1.70.0 cargo clippy --all-targets --all-features -- -D warnings
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED: MSRV Clippy check failed" -ForegroundColor Red
            exit 1
        }
        Write-Host "SUCCESS: MSRV Clippy check passed" -ForegroundColor Green
    } else {
        Write-Host "WARNING: Rust 1.70.0 not installed. Skipping MSRV check." -ForegroundColor Yellow
        Write-Host "To install: rustup toolchain install 1.70.0" -ForegroundColor Yellow
    }
} else {
    Write-Host "WARNING: rustup not found. Skipping MSRV check." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "All CI checks passed!" -ForegroundColor Green
Write-Host "Remember to review and commit any auto-fixes made." -ForegroundColor Blue
Write-Host "Ready to push to remote." -ForegroundColor Green
