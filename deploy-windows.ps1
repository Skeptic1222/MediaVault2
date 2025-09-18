# SecureGallery Pro Windows Deployment Script
# Run this script as Administrator in PowerShell

param(
    [string]$SitePath = "C:\inetpub\wwwroot\SecureGalleryPro",
    [string]$SiteName = "SecureGalleryPro",
    [string]$NodePort = "3000",
    [string]$DatabaseName = "SecureGalleryPro",
    [switch]$SkipIISSetup,
    [switch]$SkipDatabaseSetup,
    [switch]$SkipDependencies
)

Write-Host "=== SecureGallery Pro Windows Deployment Script ===" -ForegroundColor Green
Write-Host "Deploying to: $SitePath" -ForegroundColor Yellow
Write-Host "Site Name: $SiteName" -ForegroundColor Yellow
Write-Host "Node.js Port: $NodePort" -ForegroundColor Yellow

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Function to check if a Windows feature is enabled
function Test-WindowsFeature {
    param([string]$FeatureName)
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
    return $feature -and $feature.State -eq "Enabled"
}

# Step 1: Install required Windows features and IIS modules
if (-not $SkipIISSetup) {
    Write-Host "`n1. Setting up IIS and required modules..." -ForegroundColor Cyan
    
    # Enable IIS
    if (!(Test-WindowsFeature "IIS-WebServerRole")) {
        Write-Host "Enabling IIS..." -ForegroundColor Yellow
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -All -NoRestart
    }
    
    # Enable required IIS features
    $requiredFeatures = @(
        "IIS-HttpRedirect",
        "IIS-HttpCompressionDynamic",
        "IIS-HttpCompressionStatic",
        "IIS-ASPNET45",
        "IIS-NetFxExtensibility45",
        "IIS-ISAPIExtensions",
        "IIS-ISAPIFilter"
    )
    
    foreach ($feature in $requiredFeatures) {
        if (!(Test-WindowsFeature $feature)) {
            Write-Host "Enabling $feature..." -ForegroundColor Yellow
            Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
        }
    }
    
    # Check for URL Rewrite module
    $urlRewriteRegPath = "HKLM:\SOFTWARE\Microsoft\IIS Extensions\URL Rewrite"
    if (!(Test-Path $urlRewriteRegPath)) {
        Write-Warning "URL Rewrite module not found. Please download and install from:"
        Write-Host "https://www.iis.net/downloads/microsoft/url-rewrite" -ForegroundColor Blue
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue -ne "y") { exit 1 }
    }
    
    # Check for Application Request Routing (ARR)
    $arrRegPath = "HKLM:\SOFTWARE\Microsoft\IIS Extensions\Application Request Routing"
    if (!(Test-Path $arrRegPath)) {
        Write-Warning "Application Request Routing (ARR) module not found. Please download and install from:"
        Write-Host "https://www.iis.net/downloads/microsoft/application-request-routing" -ForegroundColor Blue
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue -ne "y") { exit 1 }
    }
}

# Step 2: Check Node.js installation
if (-not $SkipDependencies) {
    Write-Host "`n2. Checking Node.js installation..." -ForegroundColor Cyan
    try {
        $nodeVersion = node --version 2>$null
        if ($nodeVersion) {
            Write-Host "Node.js found: $nodeVersion" -ForegroundColor Green
        } else {
            throw "Node.js not found"
        }
    } catch {
        Write-Error "Node.js is not installed or not in PATH. Please install Node.js LTS from https://nodejs.org/"
        exit 1
    }
    
    # Check npm
    try {
        $npmVersion = npm --version 2>$null
        if ($npmVersion) {
            Write-Host "npm found: $npmVersion" -ForegroundColor Green
        }
    } catch {
        Write-Error "npm is not available. Please ensure Node.js is properly installed."
        exit 1
    }
}

# Step 3: Setup SQL Server Express database
if (-not $SkipDatabaseSetup) {
    Write-Host "`n3. Setting up SQL Server Express database..." -ForegroundColor Cyan
    
    # Check if SQL Server Express is installed
    $sqlServerInstance = Get-Service -Name "MSSQL`$SQLEXPRESS" -ErrorAction SilentlyContinue
    if (!$sqlServerInstance) {
        Write-Warning "SQL Server Express not found. Please install SQL Server Express from:"
        Write-Host "https://www.microsoft.com/en-us/sql-server/sql-server-downloads" -ForegroundColor Blue
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue -ne "y") { exit 1 }
    } else {
        Write-Host "SQL Server Express found and running" -ForegroundColor Green
        
        # Create database if it doesn't exist
        try {
            Write-Host "Creating database $DatabaseName..." -ForegroundColor Yellow
            $createDbScript = @"
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = '$DatabaseName')
BEGIN
    CREATE DATABASE [$DatabaseName]
    PRINT 'Database $DatabaseName created successfully'
END
ELSE
BEGIN
    PRINT 'Database $DatabaseName already exists'
END
"@
            
            sqlcmd -S "localhost\SQLEXPRESS" -E -Q $createDbScript
            Write-Host "Database setup completed" -ForegroundColor Green
        } catch {
            Write-Warning "Could not create database automatically. You may need to create it manually."
            Write-Host "SQL Command: CREATE DATABASE [$DatabaseName]" -ForegroundColor Blue
        }
    }
}

# Step 4: Create application directory and copy files
Write-Host "`n4. Setting up application files..." -ForegroundColor Cyan

if (Test-Path $SitePath) {
    Write-Host "Directory $SitePath already exists" -ForegroundColor Yellow
} else {
    Write-Host "Creating directory $SitePath..." -ForegroundColor Yellow
    New-Item -Path $SitePath -ItemType Directory -Force | Out-Null
}

# Create subdirectories
$subDirs = @("logs", "uploads", "temp", "backups")
foreach ($dir in $subDirs) {
    $fullPath = Join-Path $SitePath $dir
    if (!(Test-Path $fullPath)) {
        New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
        Write-Host "Created directory: $fullPath" -ForegroundColor Yellow
    }
}

# Copy application files (assumes script is run from project root)
if (Test-Path "package.json") {
    Write-Host "Copying application files..." -ForegroundColor Yellow
    
    # Copy files (excluding development-only files)
    $excludePatterns = @("node_modules", ".git", "*.log", ".env", ".env.*", "deploy-windows.ps1")
    
    Get-ChildItem -Path "." -Recurse | Where-Object {
        $relativePath = $_.FullName.Substring((Get-Location).Path.Length + 1)
        $exclude = $false
        foreach ($pattern in $excludePatterns) {
            if ($relativePath -like $pattern) {
                $exclude = $true
                break
            }
        }
        !$exclude
    } | Copy-Item -Destination { 
        $relativePath = $_.FullName.Substring((Get-Location).Path.Length + 1)
        $destPath = Join-Path $SitePath $relativePath
        $destDir = Split-Path $destPath -Parent
        if (!(Test-Path $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }
        $destPath
    } -Force
    
    Write-Host "Application files copied successfully" -ForegroundColor Green
} else {
    Write-Warning "package.json not found. Make sure to run this script from the project root directory."
}

# Step 5: Install Node.js dependencies
Write-Host "`n5. Installing Node.js dependencies..." -ForegroundColor Cyan
Push-Location $SitePath

try {
    # Copy Windows environment template
    if (Test-Path ".env.windows") {
        Copy-Item ".env.windows" ".env" -Force
        Write-Host "Environment template copied to .env - please configure your database settings" -ForegroundColor Yellow
    }
    
    Write-Host "Running npm install..." -ForegroundColor Yellow
    npm install --production
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Dependencies installed successfully" -ForegroundColor Green
    } else {
        Write-Warning "npm install completed with warnings. Check the output above."
    }
    
    # Build the application
    Write-Host "Building application..." -ForegroundColor Yellow
    npm run build
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Application built successfully" -ForegroundColor Green
    } else {
        Write-Error "Build failed. Please check the error messages above."
        Pop-Location
        exit 1
    }
} catch {
    Write-Error "Failed to install dependencies or build application: $_"
    Pop-Location
    exit 1
} finally {
    Pop-Location
}

# Step 6: Setup IIS website
if (-not $SkipIISSetup) {
    Write-Host "`n6. Setting up IIS website..." -ForegroundColor Cyan
    
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    
    # Remove existing site if it exists
    if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) {
        Write-Host "Removing existing website $SiteName..." -ForegroundColor Yellow
        Remove-Website -Name $SiteName
    }
    
    # Create new website
    Write-Host "Creating IIS website $SiteName..." -ForegroundColor Yellow
    New-Website -Name $SiteName -PhysicalPath $SitePath -Port 80
    
    # Set application pool settings
    $appPoolName = $SiteName + "AppPool"
    if (Get-IISAppPool -Name $appPoolName -ErrorAction SilentlyContinue) {
        Remove-WebAppPool -Name $appPoolName
    }
    
    New-WebAppPool -Name $appPoolName
    Set-ItemProperty -Path "IIS:\AppPools\$appPoolName" -Name processModel.identityType -Value ApplicationPoolIdentity
    Set-ItemProperty -Path "IIS:\AppPools\$appPoolName" -Name recycling.periodicRestart.time -Value "00:00:00"
    Set-ItemProperty -Path "IIS:\AppPools\$appPoolName" -Name processModel.idleTimeout -Value "00:00:00"
    
    # Assign app pool to website
    Set-ItemProperty -Path "IIS:\Sites\$SiteName" -Name applicationPool -Value $appPoolName
    
    Write-Host "IIS website created successfully" -ForegroundColor Green
}

# Step 7: Setup Windows Service for Node.js app
Write-Host "`n7. Setting up Node.js service..." -ForegroundColor Cyan

$serviceName = "SecureGalleryPro"
$nodeExePath = (Get-Command node).Source
$appMainFile = Join-Path $SitePath "dist\index.js"

# Check if NSSM is available
$nssmPath = Get-Command nssm -ErrorAction SilentlyContinue
if (!$nssmPath) {
    Write-Host "Installing PM2 for process management..." -ForegroundColor Yellow
    npm install -g pm2
    npm install -g pm2-windows-service
    
    # Configure PM2
    Push-Location $SitePath
    $pm2ConfigContent = @"
{
  "name": "$serviceName",
  "script": "dist/index.js",
  "instances": 1,
  "exec_mode": "fork",
  "env": {
    "NODE_ENV": "production",
    "PORT": "$NodePort"
  },
  "log_file": "./logs/app.log",
  "error_file": "./logs/error.log",
  "out_file": "./logs/out.log",
  "pid_file": "./logs/app.pid"
}
"@
    $pm2ConfigContent | Out-File -FilePath "ecosystem.config.json" -Encoding UTF8
    
    # Install PM2 as Windows service
    pm2-service-install
    Pop-Location
    
    Write-Host "PM2 service installed. Use 'pm2 start ecosystem.config.json' to start the application." -ForegroundColor Green
} else {
    Write-Host "NSSM found, using NSSM for service management..." -ForegroundColor Yellow
    
    # Remove existing service if it exists
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Host "Removing existing service..." -ForegroundColor Yellow
        & nssm stop $serviceName
        & nssm remove $serviceName confirm
    }
    
    # Install new service
    & nssm install $serviceName $nodeExePath $appMainFile
    & nssm set $serviceName AppDirectory $SitePath
    & nssm set $serviceName AppEnvironmentExtra "NODE_ENV=production" "PORT=$NodePort"
    & nssm set $serviceName DisplayName "SecureGallery Pro"
    & nssm set $serviceName Description "SecureGallery Pro Enterprise File Management System"
    & nssm set $serviceName Start SERVICE_AUTO_START
    
    Write-Host "Windows service '$serviceName' installed successfully" -ForegroundColor Green
}

# Step 8: Set file permissions
Write-Host "`n8. Setting file permissions..." -ForegroundColor Cyan

try {
    # Give IIS_IUSRS read access to application files
    icacls $SitePath /grant "IIS_IUSRS:(OI)(CI)R" /T
    
    # Give full control to logs and uploads directories
    icacls (Join-Path $SitePath "logs") /grant "IIS_IUSRS:(OI)(CI)F" /T
    icacls (Join-Path $SitePath "uploads") /grant "IIS_IUSRS:(OI)(CI)F" /T
    icacls (Join-Path $SitePath "temp") /grant "IIS_IUSRS:(OI)(CI)F" /T
    
    Write-Host "File permissions set successfully" -ForegroundColor Green
} catch {
    Write-Warning "Could not set all file permissions automatically. You may need to set them manually."
}

# Step 9: Final instructions
Write-Host "`n=== Deployment Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Configure your database connection in: $SitePath\.env" -ForegroundColor White
Write-Host "2. Update the session secret and encryption keys in .env" -ForegroundColor White
Write-Host "3. Start the Node.js service:" -ForegroundColor White
if ($nssmPath) {
    Write-Host "   nssm start $serviceName" -ForegroundColor Cyan
} else {
    Write-Host "   cd $SitePath && pm2 start ecosystem.config.json" -ForegroundColor Cyan
}
Write-Host "4. Your application should be accessible at: http://localhost" -ForegroundColor White
Write-Host "5. Check logs in: $SitePath\logs\" -ForegroundColor White
Write-Host ""
Write-Host "Troubleshooting:" -ForegroundColor Yellow
Write-Host "- Verify SQL Server Express is running: services.msc" -ForegroundColor White
Write-Host "- Check IIS Manager for website status" -ForegroundColor White
Write-Host "- Review application logs for any errors" -ForegroundColor White
Write-Host "- Ensure Windows Firewall allows HTTP traffic on port 80" -ForegroundColor White

Write-Host "`nDeployment script completed successfully!" -ForegroundColor Green