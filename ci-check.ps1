# ci-check.ps1 - Fast validation checks for strict-path crate
# Focuses on linting, formatting, and validation without compilation/testing

$ErrorActionPreference = "Stop"

Write-Host "=== CI Check: strict-path crate ===" -ForegroundColor Cyan
Write-Host "Fast validation without compilation/testing" -ForegroundColor Gray
Write-Host ""

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
        exit 1
    }
}

Write-Host "* Using cargo: $(Get-Command cargo | Select-Object -ExpandProperty Source)" -ForegroundColor Green

# Check Rust version
$rustVersion = & rustc --version
Write-Host "Rust version: $rustVersion" -ForegroundColor Magenta
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
        Write-Host "ERROR: Validation checks failed." -ForegroundColor Red
        exit 1
    }
}

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
        Write-Host "ERROR: Validation checks failed." -ForegroundColor Red
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
        Write-Host "WARNING: Continuing with checks anyway..." -ForegroundColor Yellow
        Write-Host ""
        return
    }
}

# Check if we're in the right directory
if (-not (Test-Path "Cargo.toml")) {
    Write-Host "ERROR: Cargo.toml not found. Are you in the project root?" -ForegroundColor Red
    exit 1
}

# Check if strict-path subdirectory exists
if (-not (Test-Path "strict-path")) {
    Write-Host "ERROR: strict-path/ subdirectory not found. Are you in the project root?" -ForegroundColor Red
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

Write-Host "Checking strict-path/Cargo.toml..." -ForegroundColor Blue
if (-not (Test-Utf8Encoding "strict-path\Cargo.toml")) { exit 1 }

Write-Host "Checking strict-path Rust source files..." -ForegroundColor Blue
$rustFiles = Get-ChildItem -Path "strict-path\src" -Filter "*.rs" -Recurse
if ($rustFiles.Count -gt 0) {
    foreach ($file in $rustFiles) {
        if (-not (Test-Utf8Encoding $file.FullName)) { exit 1 }
    }
    Write-Host "SUCCESS: All Rust source files in strict-path/src - UTF-8 encoding verified" -ForegroundColor Green
} else {
    Write-Host "WARNING: No Rust source files found in strict-path/src" -ForegroundColor Yellow
}

Write-Host "SUCCESS: All file encoding checks passed!" -ForegroundColor Green
Write-Host ""

# Auto-fix common issues first
Write-Host "Auto-fixing common issues..." -ForegroundColor Cyan
Run-Fix "Format strict-path" "cargo fmt -p strict-path"
Run-Fix "Clippy Fixable Issues (strict-path)" "cargo clippy -p strict-path --fix --allow-dirty --allow-staged --all-targets --all-features"
Run-Fix "Format strict-path (after clippy fix)" "cargo fmt -p strict-path"

Write-Host "Running validation checks (no compilation/testing)..." -ForegroundColor Cyan
Write-Host ""

# Run validation checks
Run-Check-Block "Format Check (strict-path)" {
    cargo fmt -p strict-path -- --check
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Formatting check failed. Run 'cargo fmt -p strict-path' to fix." -ForegroundColor Red
        Write-Host "Here's what would be changed:" -ForegroundColor Gray
        cargo fmt -p strict-path -- --check --verbose | Out-String | Write-Host
        exit 1
    }
}

Run-Check "Clippy Lint (strict-path, all features)" "cargo clippy -p strict-path --all-targets --all-features -- -D warnings"
Run-Check "Clippy Lint (strict-path, no features)" "cargo clippy -p strict-path --all-targets --no-default-features -- -D warnings"

# Check documentation generation (no compilation of code, just docs)
$env:RUSTDOCFLAGS = "-D warnings"
Run-Check "Documentation Check (strict-path)" "cargo doc -p strict-path --no-deps --document-private-items --all-features"

Write-Host "SUCCESS: All validation checks passed!" -ForegroundColor Green
Write-Host "INFO: This was a fast check focusing on validation only." -ForegroundColor Blue
Write-Host "INFO: Run ci-local.ps1 for full CI including compilation and testing." -ForegroundColor Blue
Write-Host "INFO: Remember to review and commit any auto-fixes made." -ForegroundColor Blue
