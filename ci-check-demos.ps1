# ci-check-demos.ps1 - Fast validation checks for demos crate
# Focuses on linting, formatting, and validation without compilation/testing
# Supports selective testing of only changed demo files for faster development

param(
    [switch]$Full,
    [switch]$Fix,
    [switch]$FixChanged,
    [string]$Demos = ""
)

$ErrorActionPreference = "Stop"

Write-Host "=== CI Check: demos crate ===" -ForegroundColor Cyan
if ($Full) {
    Write-Host "Full validation mode (testing all demos)" -ForegroundColor Gray
} else {
    Write-Host "Smart validation mode (testing only changed demos)" -ForegroundColor Gray
}
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

# Function to detect changed demo files
function Get-ChangedDemoFiles {
    param([ref]$ForceFullTest)
    
    Write-Host "Detecting changed files..." -ForegroundColor Blue
    
    # Check if we're in a git repository
    if (-not (Test-Path ".git")) {
        Write-Host "WARNING: Not in a git repository, running full test" -ForegroundColor Yellow
        $ForceFullTest.Value = $true
        return @()
    }
    
    try {
        # Get staged changes (ready to commit) and unstaged changes (working directory)
        $stagedChanges = & git diff --cached --name-only 2>$null
        $unstagedChanges = & git diff --name-only 2>$null
        
        $allChanges = @($stagedChanges; $unstagedChanges) | Where-Object { $_ } | Sort-Object -Unique
        
        Write-Host "Found $($allChanges.Count) changed files" -ForegroundColor Gray
        
        # Extract only actual demo files that changed - ignore core library changes
        $demoChanges = $allChanges | Where-Object { $_ -match "^demos/src/bin/.*\.rs$" }
        
        if ($demoChanges.Count -eq 0) {
            Write-Host "✅ No demo files changed, nothing to validate." -ForegroundColor Green
            return @()
        }
        
        Write-Host "🎯 Demo files changed:" -ForegroundColor Cyan
        foreach ($change in $demoChanges) {
            Write-Host "  - $change" -ForegroundColor Gray
        }
        
        return $demoChanges
        
    } catch {
        Write-Host "WARNING: Git command failed, running full test" -ForegroundColor Yellow
        $ForceFullTest.Value = $true
        return @()
    }
}

# Function to extract binary names from demo file paths
function Get-BinaryNamesFromPaths {
    param([string[]]$FilePaths)
    
    $binaryNames = @()
    foreach ($path in $FilePaths) {
        # Extract binary name from demos/src/bin/<category>/<binary_name>.rs
        if ($path -match "demos[/\\]src[/\\]bin[/\\][^/\\]+[/\\]([^/\\]+)\.rs$") {
            $binaryNames += $matches[1]
        }
    }
    
    return $binaryNames | Sort-Object -Unique
}

# Check if we're in the right directory
if (-not (Test-Path "Cargo.toml")) {
    Write-Host "ERROR: Cargo.toml not found. Are you in the project root?" -ForegroundColor Red
    exit 1
}

# Check if demos subdirectory exists
if (-not (Test-Path "demos")) {
    Write-Host "ERROR: demos/ subdirectory not found. Are you in the project root?" -ForegroundColor Red
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
Write-Host "Checking demos/Cargo.toml..." -ForegroundColor Blue
if (-not (Test-Utf8Encoding "demos\Cargo.toml")) { exit 1 }

Write-Host "Checking demos/README.md..." -ForegroundColor Blue
if (Test-Path "demos\README.md") {
    if (-not (Test-Utf8Encoding "demos\README.md")) { exit 1 }
} else {
    Write-Host "INFO: demos/README.md not found, skipping" -ForegroundColor Gray
}

Write-Host "Checking demos Rust source files..." -ForegroundColor Blue
$rustFiles = Get-ChildItem -Path "demos\src" -Filter "*.rs" -Recurse
if ($rustFiles.Count -gt 0) {
    foreach ($file in $rustFiles) {
        if (-not (Test-Utf8Encoding $file.FullName)) { exit 1 }
    }
    Write-Host "SUCCESS: All Rust source files in demos/src - UTF-8 encoding verified" -ForegroundColor Green
} else {
    Write-Host "WARNING: No Rust source files found in demos/src" -ForegroundColor Yellow
}

Write-Host "SUCCESS: All file encoding checks passed!" -ForegroundColor Green
Write-Host ""

# Preflight: ensure library lints cleanly with no features
Run-Check "Library Clippy Lint (no features)" "cargo clippy -p strict-path --all-targets --no-default-features -- -D warnings"

# Auto-fix is optional to avoid compilation in smart mode
if ($Full -or $Fix) {
    Write-Host "Auto-fixing common issues..." -ForegroundColor Cyan
    Run-Fix "Format demos" "Push-Location demos; cargo fmt --all; Pop-Location"
    # Use safe features for auto-fix (avoid heavy dependencies like AWS that require cmake/nasm)
    Run-Fix "Clippy Fixable Issues (demos)" "Push-Location demos; cargo clippy --fix --allow-dirty --allow-staged --all-targets --features 'with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp,virtual-path'; Pop-Location"
    Run-Fix "Format demos (after clippy fix)" "Push-Location demos; cargo fmt --all; Pop-Location"
} else {
    Write-Host "Skipping auto-fix (use -Full, -Fix or -FixChanged to enable)." -ForegroundColor Yellow
}

Write-Host "Running validation checks (no compilation/testing)..." -ForegroundColor Cyan
Write-Host ""

# Run validation checks
if ($forceFullTest) {
    # Full format check
    Run-Check-Block "Format Check (demos - ALL)" {
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
} elseif ($changedDemoFiles.Count -gt 0) {
    # Fast format check - only changed files
    Run-Check-Block "Format Check (demos - SELECTIVE: $($changedDemoFiles.Count) files)" {
        $fileArgs = $changedDemoFiles -join " "
        Write-Host "Checking format for: $($changedDemoFiles -join ', ')" -ForegroundColor Gray
        
        # Use rustfmt directly on the changed files
        $result = & rustfmt --check $changedDemoFiles 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Format check failed for changed demo files." -ForegroundColor Red
            Write-Host "Files that need formatting:" -ForegroundColor Gray
            Write-Host $result -ForegroundColor Gray
            Write-Host "Fix with: rustfmt $fileArgs" -ForegroundColor Yellow
            exit 1
        }
        Write-Host "✅ All changed demo files are properly formatted" -ForegroundColor Green
    }
}

# Determine what to test
$forceFullTest = $false
$changedDemoFiles = @()
$binariesToTest = @()

if ($Full) {
    Write-Host "Full test mode requested via --Full flag" -ForegroundColor Blue
    $forceFullTest = $true
} elseif ($Demos) {
    Write-Host "Manual demo selection via --Demos flag: $Demos" -ForegroundColor Blue
    $binariesToTest = $Demos -split "," | ForEach-Object { $_.Trim() }
} else {
    $changedDemoFiles = Get-ChangedDemoFiles -ForceFullTest ([ref]$forceFullTest)
    if (-not $forceFullTest -and $changedDemoFiles.Count -gt 0) {
        $binariesToTest = Get-BinaryNamesFromPaths -FilePaths $changedDemoFiles
        Write-Host "Changed demo files detected:" -ForegroundColor Blue
        foreach ($file in $changedDemoFiles) {
            Write-Host "  - $file" -ForegroundColor Gray
        }
        Write-Host "Will test binaries: $($binariesToTest -join ', ')" -ForegroundColor Blue

            # Default behavior: auto-format changed files (no compilation)
            if (-not $Full -and -not $Fix -and -not $FixChanged) {
                Run-Fix "Format changed demo files" "rustfmt $($changedDemoFiles -join ' ')"
            }
    } elseif (-not $forceFullTest) {
        Write-Host "No demo changes detected, skipping clippy tests" -ForegroundColor Green
        Write-Host "Use --Full flag to force full testing" -ForegroundColor Gray
        Write-Host ""
        Write-Host "SUCCESS: No demo validation needed!" -ForegroundColor Green
        Write-Host "INFO: This was a smart check - no demo changes detected." -ForegroundColor Blue
        Write-Host "INFO: Run with --Full flag for complete validation." -ForegroundColor Blue
        exit 0
    }
}

# Lint demos - fast validation without dependencies
if ($FixChanged -and -not $Full -and -not $Fix) {
    if ($changedDemoFiles.Count -gt 0) {
        Write-Host "Selective auto-fix for changed demos..." -ForegroundColor Cyan
        # 1) Format only the changed files
        Run-Fix "Format changed demo files" "rustfmt $($changedDemoFiles -join ' ')"

        # 2) Run clippy --fix per affected binary with safe features
        $bins = Get-BinaryNamesFromPaths -FilePaths $changedDemoFiles
        if ($bins.Count -gt 0) {
            Push-Location demos
            try {
                foreach ($bin in $bins) {
                    Write-Host "Clippy fix for demo bin: $bin" -ForegroundColor Blue
                    $cmd = "cargo clippy --fix --allow-dirty --allow-staged --bin $bin --features 'with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp,virtual-path'"
                    Invoke-Expression $cmd
                    if ($LASTEXITCODE -ne 0) { throw "clippy --fix failed for $bin" }
                }
            } finally {
                Pop-Location
            }
        }
        # 3) Format again to normalize
        Run-Fix "Format demos (after selective fix)" "Push-Location demos; cargo fmt --all; Pop-Location"
    }
}

## Continue with lint-only validation below
if ($forceFullTest) {
    # Full clippy with all features at once (fast, fail fast)
    Run-Check-Block "Clippy Demos (all features - ALL)" {
        Push-Location demos
        try {
            $hasCmake = [bool](Get-Command cmake -ErrorAction SilentlyContinue)
            $hasNasm  = [bool](Get-Command nasm -ErrorAction SilentlyContinue)
            $includeAws = $hasCmake -and $hasNasm
            if (-not $includeAws) {
                Write-Host "WARNING: Skipping 'with-aws' feature: cmake and/or nasm not found on PATH" -ForegroundColor Yellow
            }

            # Single combined test: compile once with all available features
            $allFeatures = if ($includeAws) {
                "with-zip,with-app-path,with-dirs,with-tempfile,with-aws,with-rmcp,virtual-path"
            } else {
                "with-zip,with-app-path,with-dirs,with-tempfile,with-rmcp,virtual-path"
            }

            Write-Host "==> Clippy demos with features: $allFeatures"
            cargo clippy --all-targets --features $allFeatures -- -D warnings
            if ($LASTEXITCODE -ne 0) { throw "clippy failed" }
        } finally {
            Pop-Location
        }
    }
} elseif ($binariesToTest.Count -gt 0) {
    # Ultra-fast validation - file-level checks only (no compilation/builds)
    Run-Check-Block "Ultra-Fast Demos (SELECTIVE: $($binariesToTest -join ', '))" {
        Write-Host "🚀 Ultra-fast validation (no builds, no dependency downloads)..." -ForegroundColor Cyan
        
        # Format check on changed files only
        Write-Host "==> Format check on changed demo files..." -ForegroundColor Blue
        $rustfmtArgs = @('--check') + $changedDemoFiles
        rustfmt @rustfmtArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Format check failed. Run rustfmt on the above files to fix."
        }
        Write-Host "✅ Format check passed for changed demo files" -ForegroundColor Green
        
        Write-Host "💡 Selective validation complete - only checked changed files for formatting." -ForegroundColor Blue
        Write-Host "💡 For full lint/syntax checks, use -Full flag or run ci-local.ps1" -ForegroundColor Blue
    }
}

Write-Host "SUCCESS: All validation checks passed!" -ForegroundColor Green
if ($forceFullTest) {
    Write-Host "INFO: Full validation completed for all demos." -ForegroundColor Blue
} elseif ($binariesToTest.Count -gt 0) {
    Write-Host "INFO: Selective validation completed for: $($binariesToTest -join ', ')" -ForegroundColor Blue
}
Write-Host "INFO: This was a fast check focusing on validation only." -ForegroundColor Blue
Write-Host "INFO: Run ci-local.ps1 for full CI including compilation and testing." -ForegroundColor Blue
Write-Host "INFO: Use --Full flag to force testing all demos." -ForegroundColor Blue
Write-Host "INFO: Remember to review and commit any auto-fixes made." -ForegroundColor Blue
