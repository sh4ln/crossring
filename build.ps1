# CROSSRING v1.0.23 - Windows Build Script
# Run this script in PowerShell as Administrator

param(
    [switch]$Clean,
    [switch]$Build,
    [switch]$Package,
    [switch]$All
)

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
if (-not $projectRoot) { $projectRoot = Get-Location }

Write-Host "`n" -NoNewline
Write-Host "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•" -ForegroundColor Cyan
Write-Host "  CROSSRING v1.0.23 - Build Automation Script" -ForegroundColor Green
Write-Host "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•" -ForegroundColor Cyan
Write-Host "`n"

#region Pre-Build Checks

function Test-Prerequisites {
    Write-Host "[1/4] Checking prerequisites..." -ForegroundColor Yellow
    
    # Check solution file
    if (-not (Test-Path "$projectRoot\CROSSRING.sln")) {
        throw "CROSSRING.sln not found in $projectRoot"
    }
    Write-Host "  âœ… Solution file found" -ForegroundColor Green
    
    # Check project files
    $projects = @(
        "CrossringService\CrossringService.vcxproj",
        "CrossringUI\CrossringUI.csproj"
    )
    foreach ($proj in $projects) {
        if (-not (Test-Path "$projectRoot\$proj")) {
            throw "Project file missing: $proj"
        }
        Write-Host "  âœ… Found: $proj" -ForegroundColor Green
    }
    
    # Find MSBuild
    $script:msbuild = $null
    $vsLocations = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    )
    
    foreach ($loc in $vsLocations) {
        if (Test-Path $loc) {
            $script:msbuild = $loc
            break
        }
    }
    
    if (-not $script:msbuild) {
        # Try vswhere
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path $vswhere) {
            $script:msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
        }
    }
    
    if (-not $script:msbuild) {
        throw "Visual Studio 2022 not found. Please install Visual Studio 2022 with C++ and .NET workloads"
    }
    Write-Host "  âœ… MSBuild found: $script:msbuild" -ForegroundColor Green
    
    # Check .NET SDK
    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $dotnet) {
        throw ".NET SDK not found. Please install .NET 8.0 SDK"
    }
    Write-Host "  âœ… .NET SDK found" -ForegroundColor Green
    
    Write-Host "[1/4] Prerequisites OK`n" -ForegroundColor Green
}

#endregion

#region Clean

function Invoke-Clean {
    Write-Host "[2/4] Cleaning previous builds..." -ForegroundColor Yellow
    
    $foldersToClean = @(
        "x64\Release",
        "x64\Debug",
        "CrossringService\x64",
        "CrossringUI\bin",
        "CrossringUI\obj",
        "releases"
    )
    
    foreach ($folder in $foldersToClean) {
        $path = "$projectRoot\$folder"
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  ðŸ—‘ï¸ Removed: $folder" -ForegroundColor Gray
        }
    }
    
    Write-Host "[2/4] Clean complete`n" -ForegroundColor Green
}

#endregion

#region Build

function Invoke-Build {
    Write-Host "[3/4] Building solution (Release x64)..." -ForegroundColor Yellow
    
    # Restore NuGet packages
    Write-Host "  ðŸ“¦ Restoring NuGet packages..." -ForegroundColor Gray
    & nuget restore "$projectRoot\CROSSRING.sln" -Verbosity quiet
    if ($LASTEXITCODE -ne 0) {
        throw "NuGet restore failed"
    }
    
    # Build C++ service
    Write-Host "  ðŸ”¨ Building CrossringService (C++)..." -ForegroundColor Gray
    & $script:msbuild "$projectRoot\CrossringService\CrossringService.vcxproj" `
        /p:Configuration=Release `
        /p:Platform=x64 `
        /p:DebugType=None `
        /p:DebugSymbols=false `
        /m `
        /verbosity:minimal
    
    if ($LASTEXITCODE -ne 0) {
        throw "CrossringService build failed"
    }
    Write-Host "  âœ… CrossringService built" -ForegroundColor Green
    
    # Build .NET GUI
    Write-Host "  ðŸ”¨ Building CrossringUI (.NET)..." -ForegroundColor Gray
    Push-Location "$projectRoot\CrossringUI"
    & dotnet publish -c Release -r win-x64 --self-contained false -o "$projectRoot\CrossringUI\bin\Release\net8.0-windows" -v minimal
    Pop-Location
    
    if ($LASTEXITCODE -ne 0) {
        throw "CrossringUI build failed"
    }
    Write-Host "  âœ… CrossringUI built" -ForegroundColor Green
    
    # Verify outputs
    $requiredFiles = @(
        "x64\Release\CrossringService.exe",
        "CrossringUI\bin\Release\net8.0-windows\CrossringUI.exe"
    )
    
    foreach ($file in $requiredFiles) {
        $path = "$projectRoot\$file"
        if (-not (Test-Path $path)) {
            throw "Build output missing: $file"
        }
        $size = [math]::Round((Get-Item $path).Length / 1KB, 2)
        Write-Host "  âœ… Built: $file ($size KB)" -ForegroundColor Green
    }
    
    Write-Host "[3/4] Build complete`n" -ForegroundColor Green
}

#endregion

#region Package

function Invoke-Package {
    Write-Host "[4/4] Creating release package..." -ForegroundColor Yellow
    
    $releaseDir = "$projectRoot\releases\v1.0.23-Windows"
    $zipPath = "$projectRoot\releases\CROSSRING-v1.0.23-Windows-x64.zip"
    
    # Create directories
    New-Item -Path "$releaseDir\x64" -ItemType Directory -Force | Out-Null
    
    # Copy binaries
    Write-Host "  ðŸ“‚ Copying binaries..." -ForegroundColor Gray
    Copy-Item -Path "$projectRoot\x64\Release\CrossringService.exe" -Destination "$releaseDir\x64\" -Force
    Copy-Item -Path "$projectRoot\CrossringUI\bin\Release\net8.0-windows\*" -Destination "$releaseDir\" -Recurse -Force
    
    # Copy documentation
    Write-Host "  ðŸ“„ Copying documentation..." -ForegroundColor Gray
    if (Test-Path "$projectRoot\README.md") {
        Copy-Item -Path "$projectRoot\README.md" -Destination "$releaseDir\" -Force
    }
    if (Test-Path "$projectRoot\LICENSE.txt") {
        Copy-Item -Path "$projectRoot\LICENSE.txt" -Destination "$releaseDir\" -Force
    }
    
    # Copy install files
    if (Test-Path "$projectRoot\releases\INSTALL.txt") {
        Copy-Item -Path "$projectRoot\releases\INSTALL.txt" -Destination "$releaseDir\" -Force
    }
    if (Test-Path "$projectRoot\releases\QUICKSTART.txt") {
        Copy-Item -Path "$projectRoot\releases\QUICKSTART.txt" -Destination "$releaseDir\" -Force
    }
    
    # Create ZIP
    Write-Host "  ðŸ“¦ Creating ZIP archive..." -ForegroundColor Gray
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
    Compress-Archive -Path "$releaseDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
    
    $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-Host "  âœ… Created: $zipPath ($zipSize MB)" -ForegroundColor Green
    
    Write-Host "[4/4] Package complete`n" -ForegroundColor Green
}

#endregion

#region Main

try {
    if ($All) {
        $Clean = $true
        $Build = $true
        $Package = $true
    }
    
    Test-Prerequisites
    
    if ($Clean) { Invoke-Clean }
    if ($Build) { Invoke-Build }
    if ($Package) { Invoke-Package }
    
    Write-Host "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•" -ForegroundColor Cyan
    Write-Host "  ðŸŽ‰ Build completed successfully!" -ForegroundColor Green
    Write-Host "â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•" -ForegroundColor Cyan
    Write-Host "`n"
    
    if ($Package) {
        Write-Host "Release package: releases\CROSSRING-v1.0.23-Windows-x64.zip" -ForegroundColor Cyan
    }
}
catch {
    Write-Host "`nâŒ ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

#endregion
