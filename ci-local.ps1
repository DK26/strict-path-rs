# ci-local.ps1 - Cross-platform CI Test Runner for PowerShell
# Run all CI checks locally before pushing

$ErrorActionPreference = "Stop"

Write-Host "=== CI Local Test Runner ===" -ForegroundColor Cyan

# Try to find cargo in common locations  
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    # Try common cargo locations across platforms
    $cargoPaths = @(
        "$env:USERPROFILE\.cargo\bin\cargo.exe",
        "$env:HOME\.cargo\bin\cargo.exe",
        "$env:HOME\.cargo\bin\cargo",
        "C:\Users\$env:USERNAME\.cargo\bin\cargo.exe"
    )
    
    $cargoFound = $false
    foreach ($cargoPath in $cargoPaths) {
        if (Test-Path $cargoPath) {
            $env:PATH = "$(Split-Path $cargoPath);$env:PATH"
            Write-Host "* Found cargo at: $cargoPath" -ForegroundColor Green
            $cargoFound = $true
            break
        }
    }
    
    # Final check
    if (-not $cargoFound -and -not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: cargo not found. Make sure Rust is installed." -ForegroundColor Red
        Write-Host "" 
        Write-Host "To run CI tests:" -ForegroundColor Yellow
        Write-Host "  * Make sure 'cargo --version' works in your terminal" -ForegroundColor Yellow
        Write-Host "  * Or install Rust from https://rustup.rs/" -ForegroundColor Yellow
        exit 1
    }
}

Write-Host "* Using cargo: $(Get-Command cargo | Select-Object -ExpandProperty Source)" -ForegroundColor Green

# Check Rust version and warn about nightly vs stable differences
$rustVersion = & rustc --version
Write-Host "Rust version: $rustVersion" -ForegroundColor Magenta

if ($rustVersion -match "nightly") {
    Write-Host "WARNING: You're using nightly Rust, but GitHub Actions uses stable!" -ForegroundColor Yellow
    Write-Host "   Some nightly-only APIs might work locally but fail in CI." -ForegroundColor Yellow
    Write-Host "   Consider testing with: rustup default stable" -ForegroundColor Yellow
} elseif ($rustVersion -match "1\.(8[8-9]|9[0-9]|\d{3})") {
    Write-Host "WARNING: You're using a newer Rust version than GitHub Actions stable!" -ForegroundColor Yellow
    Write-Host "   GitHub Actions uses the latest stable release." -ForegroundColor Yellow
}
Write-Host ""

Write-Host "Auto-fixing common issues before CI checks" -ForegroundColor Cyan
Write-Host ""

function Run-Check {
    param(
        [string]$Name,
        [string]$Command
    )
    
    Write-Host "Running: $Name" -ForegroundColor Blue
    Write-Host "Command: $Command" -ForegroundColor Gray
    
    $startTime = Get-Date
    
    try {
        Invoke-Expression $Command
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code $LASTEXITCODE"
        }
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        Write-Host "SUCCESS: $Name completed in $([math]::Round($duration))s" -ForegroundColor Green
        Write-Host ""
        return
    } catch {
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        Write-Host "FAILED: $Name failed after $([math]::Round($duration))s" -ForegroundColor Red
        Write-Host "ERROR: CI checks failed. Fix issues before pushing." -ForegroundColor Red
        exit 1
    }
}

# Execute a scriptblock as a CI check (avoids quoting/interpolation pitfalls)
function Run-Check-Block {
    param(
        [string]$Name,
        [scriptblock]$Block
    )

    Write-Host "Running: $Name" -ForegroundColor Blue
    $startTime = Get-Date
    try {
        & $Block
        if ($LASTEXITCODE -ne 0) {
            throw "Block failed with exit code $LASTEXITCODE"
        }
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        Write-Host "SUCCESS: $Name completed in $([math]::Round($duration))s" -ForegroundColor Green
        Write-Host ""
        return
    } catch {
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        Write-Host "FAILED: $Name failed after $([math]::Round($duration))s" -ForegroundColor Red
        Write-Host "ERROR: CI checks failed. Fix issues before pushing." -ForegroundColor Red
        exit 1
    }
}

function Run-Fix {
    param(
        [string]$Name,
        [string]$Command
    )
    
    Write-Host "Auto-fixing: $Name" -ForegroundColor Blue
    Write-Host "Command: $Command" -ForegroundColor Gray
    
    $startTime = Get-Date
    
    try {
        Invoke-Expression $Command
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code $LASTEXITCODE"
        }
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        Write-Host "SUCCESS: $Name auto-fix completed in $([math]::Round($duration))s" -ForegroundColor Green
        Write-Host ""
        return $true
    } catch {
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        Write-Host "WARNING: $Name auto-fix failed after $([math]::Round($duration))s" -ForegroundColor Yellow
        Write-Host "WARNING: Continuing with CI checks anyway..." -ForegroundColor Yellow
        Write-Host ""
        return
    }
}

# Try primary MSRV command then fallback to manifest-scoped command if it fails
function Run-Check-Try {
    param(
        [string]$Name,
        [string]$Primary,
        [string]$Fallback
    )

    Write-Host "Running (try primary then fallback): $Name" -ForegroundColor Blue
    Write-Host "Primary: $Primary" -ForegroundColor Gray
    $start = Get-Date
    try {
        Invoke-Expression $Primary
        if ($LASTEXITCODE -eq 0) {
            $end = Get-Date
            $dur = ($end - $start).TotalSeconds
            Write-Host "SUCCESS: Primary succeeded in $([math]::Round($dur))s" -ForegroundColor Green
            Write-Host ""
            return
        } else {
            throw "Primary failed"
        }
    } catch {
        Write-Host "WARNING: Primary MSRV command failed; attempting fallback..." -ForegroundColor Yellow
        Write-Host "Fallback: $Fallback" -ForegroundColor Gray
        $start2 = Get-Date
        try {
            Invoke-Expression $Fallback
            if ($LASTEXITCODE -eq 0) {
                $end2 = Get-Date
                $dur2 = ($end2 - $start2).TotalSeconds
                Write-Host "SUCCESS: Fallback succeeded in $([math]::Round($dur2))s" -ForegroundColor Green
                Write-Host ""
                return
            } else {
                throw "Fallback failed"
            }
        } catch {
            Write-Host "ERROR: Both primary and fallback failed for: $Name" -ForegroundColor Red
            exit 1
        }
    }
}

# Check if we're in the right directory
if (-not (Test-Path "Cargo.toml")) {
    Write-Host "ERROR: Cargo.toml not found. Are you in the project root?" -ForegroundColor Red
    exit 1
}

# Validate file encodings first (critical for Cargo publish)
Write-Host "Validating UTF-8 encoding for critical files..." -ForegroundColor Cyan

function Test-Utf8Encoding {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Host "ERROR: File not found: $FilePath" -ForegroundColor Red
        return $false
    }
    
    try {
        # Try to read the file as UTF-8
        $content = Get-Content $FilePath -Encoding UTF8 -ErrorAction Stop
        
        # Check for UTF-8 BOM (which should not be present)
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            Write-Host "ERROR: $FilePath contains UTF-8 BOM (should be UTF-8 without BOM)" -ForegroundColor Red
            Write-Host "   This can cause issues with Cargo publish and GitHub Actions" -ForegroundColor Yellow
            Write-Host "   Fix with: Get-Content '$FilePath' -Encoding UTF8 | Set-Content '$FilePath' -Encoding UTF8NoBOM" -ForegroundColor Yellow
            return $false
        }
        
        Write-Host "SUCCESS: $FilePath - UTF-8 encoding verified, no BOM" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "ERROR: $FilePath - Not valid UTF-8 - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Check critical files for encoding issues
Write-Host "Checking README.md..." -ForegroundColor Blue
if (-not (Test-Utf8Encoding "README.md")) { exit 1 }

Write-Host "Checking Cargo.toml..." -ForegroundColor Blue
if (-not (Test-Utf8Encoding "Cargo.toml")) { exit 1 }

Write-Host "Checking Rust source files..." -ForegroundColor Blue
if (Test-Path "strict-path\src") {
    $rustFiles = Get-ChildItem -Path "strict-path\src" -Filter "*.rs" -Recurse
    if ($rustFiles.Count -gt 0) {
        foreach ($file in $rustFiles) {
            if (-not (Test-Utf8Encoding $file.FullName)) { exit 1 }
        }
        Write-Host "SUCCESS: All Rust source files in strict-path/src - UTF-8 encoding verified" -ForegroundColor Green
    } else {
        Write-Host "WARNING: No Rust source files found in strict-path/src" -ForegroundColor Yellow
    }
} elseif (Test-Path "src") {
    $rustFiles = Get-ChildItem -Path "src" -Filter "*.rs" -Recurse
    if ($rustFiles.Count -gt 0) {
        foreach ($file in $rustFiles) {
            if (-not (Test-Utf8Encoding $file.FullName)) { exit 1 }
        }
        Write-Host "SUCCESS: All Rust source files in src/ - UTF-8 encoding verified" -ForegroundColor Green
    } else {
        Write-Host "WARNING: No Rust source files found in src/" -ForegroundColor Yellow
    }
} elseif (Test-Path "demos\src") {
    $rustFiles = Get-ChildItem -Path "demos\src" -Filter "*.rs" -Recurse
    if ($rustFiles.Count -gt 0) {
        foreach ($file in $rustFiles) {
            if (-not (Test-Utf8Encoding $file.FullName)) { exit 1 }
        }
        Write-Host "SUCCESS: All Rust source files in demos/src - UTF-8 encoding verified" -ForegroundColor Green
    } else {
        Write-Host "WARNING: No Rust source files found in demos/src" -ForegroundColor Yellow
    }
} else {
    Write-Host "WARNING: No Rust source directories found (strict-path/src, src, demos/src) - skipping source file encoding check" -ForegroundColor Yellow
}

Write-Host "SUCCESS: All file encoding checks passed!" -ForegroundColor Green
Write-Host ""

# Auto-fix common issues first
Write-Host "Auto-fixing common issues..." -ForegroundColor Cyan
Run-Fix "Format" "cargo fmt --all"
Run-Fix "Format demos" "Push-Location demos; cargo fmt --all; Pop-Location"
Run-Fix "Clippy Fixable Issues" "cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features"
Run-Fix "Format (after clippy fix)" "cargo fmt --all"
Run-Fix "Format demos (after clippy fix)" "Push-Location demos; cargo fmt --all; Pop-Location"
Write-Host "Now running CI checks (same as GitHub Actions)..." -ForegroundColor Cyan
Write-Host ""

# Run all CI checks in order
Run-Check-Block "Format Check" {
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Formatting check failed. Run 'cargo fmt --all' to fix." -ForegroundColor Red
        Write-Host "Here's what would be changed:" -ForegroundColor Gray
        cargo fmt --all -- --check --verbose | Out-String | Write-Host
        exit 1
    }
}

Run-Check-Block "Format Check (demos)" {
    Push-Location demos
    try {
        cargo fmt --all -- --check
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Demos formatting check failed. Run 'cd demos; cargo fmt --all' to fix." -ForegroundColor Red
            Write-Host "Here's what would be changed:" -ForegroundColor Gray
            cargo fmt --all -- --check --verbose | Out-String | Write-Host
            exit 1
        }
    } finally {
        Pop-Location
    }
}
# Lint and tests on the latest installed Rust toolchain
Run-Check "Clippy Lint" "cargo clippy --all-targets --all-features -- -D warnings"
# Build library examples to ensure examples compile
Run-Check "Build library examples" "cargo build -p strict-path --examples --all-features"

# Lint demos across feature matrix (demos are not workspace members). We do not build/run demos in CI.
Run-Check-Block "Clippy Demos (feature matrix)" {
    Push-Location demos
    try {
        $hasCmake = [bool](Get-Command cmake -ErrorAction SilentlyContinue)
        $hasNasm  = [bool](Get-Command nasm -ErrorAction SilentlyContinue)
        $includeAws = $hasCmake -and $hasNasm
        if (-not $includeAws) {
            Write-Host "WARNING: Skipping 'with-aws' demos: cmake and/or nasm not found on PATH" -ForegroundColor Yellow
        }

        $featureSets = New-Object System.Collections.Generic.List[string]
        $featureSets.Add('') | Out-Null
        $featureSets.Add('with-zip') | Out-Null
        $featureSets.Add('with-app-path') | Out-Null
        $featureSets.Add('with-dirs') | Out-Null
        $featureSets.Add('with-tempfile') | Out-Null
        $featureSets.Add('with-rmcp') | Out-Null
        if ($includeAws) { $featureSets.Add('with-aws') | Out-Null }
        if ($includeAws) { $featureSets.Add('with-zip,with-app-path,with-dirs,with-tempfile,with-aws,with-rmcp') | Out-Null } else { $featureSets.Add('with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp') | Out-Null }

        foreach ($feats in $featureSets) {
            if ([string]::IsNullOrEmpty($feats)) {
                Write-Host "==> Clippy demos with features: <none>"
                cargo clippy --all-targets -- -D warnings
                if ($LASTEXITCODE -ne 0) { throw "clippy failed" }
            } else {
                Write-Host "==> Clippy demos with features: $feats"
                cargo clippy --all-targets --features $feats -- -D warnings
                if ($LASTEXITCODE -ne 0) { throw "clippy failed" }
            }
        }
    } finally {
        Pop-Location
    }
}
# Run workspace tests for the library only
Run-Check "Tests (library all features)" "cargo test -p strict-path --all-features --verbose"

# Doc tests are included in 'cargo test --workspace', so no separate --doc run needed
$env:RUSTDOCFLAGS = "-D warnings"
Run-Check "Documentation" "cargo doc --no-deps --document-private-items --all-features"

# Build mdbook documentation
Write-Host "Building mdbook documentation..." -ForegroundColor Cyan
if (Get-Command mdbook -ErrorAction SilentlyContinue) {
    Run-Check "Build mdbook docs" "Push-Location docs_src; mdbook build; Pop-Location"
} else {
    Write-Host "WARNING: mdbook not found. Installing..." -ForegroundColor Yellow
    try {
        & cargo install mdbook --locked
        if ($LASTEXITCODE -eq 0) {
            Write-Host "SUCCESS: mdbook installed successfully" -ForegroundColor Green
            Run-Check "Build mdbook docs" "Push-Location docs_src; mdbook build; Pop-Location"
        } else {
            throw "mdbook installation failed"
        }
    } catch {
        Write-Host "ERROR: Failed to install mdbook. Skipping documentation build." -ForegroundColor Red
        Write-Host "INFO: To install manually: cargo install mdbook" -ForegroundColor Yellow
        Write-Host "INFO: Then run: cd docs_src && mdbook build" -ForegroundColor Yellow
    }
}

# Security audit (same as GitHub Actions)
Write-Host "Running security audit..." -ForegroundColor Cyan
if (Get-Command cargo-audit -ErrorAction SilentlyContinue) {
    Run-Check "Security Audit" "cargo audit"
} else {
    Write-Host "WARNING: cargo-audit not found. Installing..." -ForegroundColor Yellow
    try {
        & cargo install cargo-audit --locked
        if ($LASTEXITCODE -eq 0) {
            Write-Host "SUCCESS: cargo-audit installed successfully" -ForegroundColor Green
            Run-Check "Security Audit" "cargo audit"
        } else {
            throw "cargo-audit installation failed"
        }
    } catch {
        Write-Host "ERROR: Failed to install cargo-audit. Skipping security audit." -ForegroundColor Red
        Write-Host "INFO: To install manually: cargo install cargo-audit" -ForegroundColor Yellow
    }
}

# Check MSRV compatibility (same as GitHub Actions)
Write-Host "Checking Minimum Supported Rust Version (1.71.0)..." -ForegroundColor Cyan
if (Get-Command rustup -ErrorAction SilentlyContinue) {
    $toolchains = & rustup toolchain list
    if ($toolchains -match "1\.71\.0") {
        Write-Host "SUCCESS: Found Rust 1.71.0 toolchain, checking MSRV compatibility..." -ForegroundColor Green

        # Ensure Clippy is installed for MSRV
        if (-not (& rustup component list --toolchain 1.71.0 | Select-String "clippy.*(installed)")) {
            Write-Host "Installing Clippy for Rust 1.71.0..." -ForegroundColor Blue
            & rustup component add clippy --toolchain 1.71.0
        }

        Write-Host "Running MSRV checks against library package (no demos)..." -ForegroundColor Blue
    Run-Fix "MSRV Clippy Auto-fix" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo clippy -p strict-path --lib --fix --allow-dirty --allow-staged --all-features" | Out-Null
    Run-Check-Try "MSRV Check (Rust 1.71.0)" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo check --locked -p strict-path --lib --verbose" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo check --locked -p strict-path --lib --verbose"
    Run-Check-Try "MSRV Clippy Lint" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo clippy --locked -p strict-path --lib --all-features -- -D warnings" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo clippy --locked -p strict-path --lib --all-features -- -D warnings"
    Run-Check-Try "MSRV Test" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo test --locked -p strict-path --lib --verbose" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo test --locked -p strict-path --lib --verbose"
    } else {
        Write-Host "WARNING: Rust 1.71.0 not installed. Installing for MSRV check..." -ForegroundColor Yellow
        try {
            & rustup toolchain install 1.71.0
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Installing Clippy for Rust 1.71.0..." -ForegroundColor Blue
                & rustup component add clippy --toolchain 1.71.0
                Run-Fix "MSRV Clippy Auto-fix" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo clippy -p strict-path --lib --fix --allow-dirty --allow-staged --all-features" | Out-Null
                Run-Check-Try "MSRV Check (Rust 1.71.0)" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo check --locked -p strict-path --lib --verbose" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo check --locked -p strict-path --lib --verbose"
                Run-Check-Try "MSRV Clippy Lint" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo clippy --locked -p strict-path --lib --all-features -- -D warnings" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo clippy --locked -p strict-path --lib --all-features -- -D warnings"
                Run-Check-Try "MSRV Test" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo test --locked -p strict-path --lib --verbose" "`$env:CARGO_TARGET_DIR='target/msrv'; rustup run 1.71.0 cargo test --locked -p strict-path --lib --verbose"
            } else {
                throw "toolchain install failed"
            }
        } catch {
            Write-Host "ERROR: Failed to install Rust 1.71.0. Skipping MSRV check." -ForegroundColor Red
            Write-Host "INFO: To install manually: rustup toolchain install 1.71.0" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "WARNING: rustup not found. Skipping MSRV check." -ForegroundColor Yellow
    Write-Host "INFO: MSRV check requires rustup to install Rust 1.71.0" -ForegroundColor Yellow
}

Write-Host "SUCCESS: All CI checks passed!" -ForegroundColor Green
Write-Host "INFO: Remember to review and commit any auto-fixes made." -ForegroundColor Blue
Write-Host "Ready to push to remote." -ForegroundColor Green
