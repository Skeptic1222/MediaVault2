# SecureGallery Pro - Windows Deployment Guide

This guide addresses the key deployment issues identified in the enterprise deployment analysis and provides a complete solution for deploying SecureGallery Pro to Windows Server with IIS and SQL Server Express.

## Prerequisites

### Software Requirements
- **Windows Server 2022** (recommended) or Windows 10/11 Pro
- **IIS 10** with URL Rewrite and Application Request Routing modules
- **SQL Server Express 2022** or later
- **Node.js 18 LTS** or later
- **PowerShell 5.1** or later (for deployment script)

### Hardware Requirements
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 50GB minimum free space
- **CPU**: 2 cores minimum, 4 cores recommended
- **Network**: Internet access for initial setup

## Quick Deployment

### Option 1: Automated Deployment (Recommended)

1. **Download the application files** to a temporary directory
2. **Open PowerShell as Administrator**
3. **Run the deployment script**:
   ```powershell
   .\deploy-windows.ps1 -SitePath "C:\inetpub\wwwroot\SecureGalleryPro" -SiteName "SecureGalleryPro"
   ```

The script will:
- Set up IIS with required modules
- Install and configure SQL Server Express database
- Deploy application files
- Install Node.js dependencies
- Configure Windows Service
- Set proper file permissions

### Option 2: Manual Deployment

Follow the detailed steps below if you prefer manual installation or need customization.

## Detailed Manual Deployment

### Step 1: Install Prerequisites

#### 1.1 Install IIS and Required Modules

```powershell
# Enable IIS
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -All

# Enable required IIS features
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect -All
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionDynamic -All
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic -All
```

#### 1.2 Install URL Rewrite Module
- Download from: https://www.iis.net/downloads/microsoft/url-rewrite
- Install the MSI package

#### 1.3 Install Application Request Routing (ARR)
- Download from: https://www.iis.net/downloads/microsoft/application-request-routing
- Install the MSI package

#### 1.4 Install SQL Server Express
- Download from: https://www.microsoft.com/en-us/sql-server/sql-server-downloads
- Choose "Express" edition
- During installation, enable "SQL Server Authentication" mode
- Remember the SA password you set

#### 1.5 Install Node.js
- Download Node.js 18 LTS from: https://nodejs.org/
- Install with default options
- Verify installation: `node --version`

### Step 2: Database Setup

#### 2.1 Create Database
```sql
-- Connect to SQL Server Management Studio or use sqlcmd
-- Run the database creation script
sqlcmd -S localhost\SQLEXPRESS -E -i database\sqlserver-schema.sql
```

#### 2.2 Create Database User (Optional)
```sql
-- Create a dedicated user for the application
CREATE LOGIN SecureGalleryUser WITH PASSWORD = 'YourSecurePassword123!';
USE SecureGalleryPro;
CREATE USER SecureGalleryUser FOR LOGIN SecureGalleryUser;
ALTER ROLE db_owner ADD MEMBER SecureGalleryUser;
```

### Step 3: Application Deployment

#### 3.1 Create Application Directory
```powershell
$appPath = "C:\inetpub\wwwroot\SecureGalleryPro"
New-Item -Path $appPath -ItemType Directory -Force

# Create subdirectories
New-Item -Path "$appPath\logs" -ItemType Directory -Force
New-Item -Path "$appPath\uploads" -ItemType Directory -Force
New-Item -Path "$appPath\temp" -ItemType Directory -Force
```

#### 3.2 Copy Application Files
Copy all application files to `C:\inetpub\wwwroot\SecureGalleryPro`, excluding:
- `node_modules` folder
- `.git` folder
- `*.log` files
- `.env` files

#### 3.3 Configure Environment
```powershell
# Copy the Windows environment template
Copy-Item ".env.windows" ".env"
```

Edit the `.env` file with your specific configuration:
```bash
# Database Configuration
DB_TYPE=sqlserver
DB_SERVER=localhost\SQLEXPRESS
DB_NAME=SecureGalleryPro
DB_USER=SecureGalleryUser
DB_PASSWORD=YourSecurePassword123!

# Application Configuration
NODE_ENV=production
PORT=3000
SESSION_SECRET=your-ultra-secure-session-secret-at-least-32-chars
FILESYSTEM_MASTER_KEY=your-32-character-encryption-key-here12

# File Upload Configuration
MAX_FILE_SIZE=2147483648
UPLOAD_DIR=C:\inetpub\wwwroot\SecureGalleryPro\uploads
LOG_DIR=C:\inetpub\wwwroot\SecureGalleryPro\logs
```

#### 3.4 Install Dependencies and Build

**IMPORTANT**: Follow this exact sequence to avoid npm installation issues on Windows:

```powershell
# Navigate to application directory
cd C:\inetpub\wwwroot\SecureGalleryPro

# Install critical packages individually (addresses npm Windows issues)
npm install @vitejs/plugin-react --force
Start-Sleep -Seconds 2
npm install vite --force
Start-Sleep -Seconds 2
npm install esbuild --force
Start-Sleep -Seconds 2

# Install remaining dependencies
npm install --production --force

# Build the application
npm run build:windows
```

### Step 4: IIS Configuration

#### 4.1 Create IIS Website
```powershell
Import-Module WebAdministration

# Remove default website if it exists
Remove-Website -Name "Default Web Site" -ErrorAction SilentlyContinue

# Create new website
New-Website -Name "SecureGalleryPro" -PhysicalPath "C:\inetpub\wwwroot\SecureGalleryPro" -Port 80

# Create application pool
New-WebAppPool -Name "SecureGalleryProAppPool"
Set-ItemProperty -Path "IIS:\AppPools\SecureGalleryProAppPool" -Name processModel.identityType -Value ApplicationPoolIdentity
Set-ItemProperty -Path "IIS:\Sites\SecureGalleryPro" -Name applicationPool -Value "SecureGalleryProAppPool"
```

#### 4.2 Configure web.config
The `web.config` file is already included in the deployment. It configures:
- Reverse proxy to Node.js application (port 3000)
- Static file handling
- Security headers
- Compression
- Request size limits

### Step 5: Windows Service Setup

#### 5.1 Install PM2 (Recommended)
```powershell
npm install -g pm2
npm install -g pm2-windows-service

# Install PM2 as Windows service
pm2-service-install

# Start the application
pm2 start ecosystem.config.js --env production
pm2 save
```

#### 5.2 Alternative: NSSM (if PM2 doesn't work)
```powershell
# Download NSSM from https://nssm.cc/
# Extract to C:\nssm

# Install service
C:\nssm\nssm.exe install SecureGalleryPro "C:\Program Files\nodejs\node.exe"
C:\nssm\nssm.exe set SecureGalleryPro AppDirectory "C:\inetpub\wwwroot\SecureGalleryPro"
C:\nssm\nssm.exe set SecureGalleryPro AppParameters "dist\index.js"
C:\nssm\nssm.exe set SecureGalleryPro AppEnvironmentExtra "NODE_ENV=production" "PORT=3000"
C:\nssm\nssm.exe set SecureGalleryPro Start SERVICE_AUTO_START

# Start service
C:\nssm\nssm.exe start SecureGalleryPro
```

### Step 6: Set File Permissions
```powershell
# Give IIS_IUSRS read access to application files
icacls "C:\inetpub\wwwroot\SecureGalleryPro" /grant "IIS_IUSRS:(OI)(CI)R" /T

# Give full control to writable directories
icacls "C:\inetpub\wwwroot\SecureGalleryPro\logs" /grant "IIS_IUSRS:(OI)(CI)F" /T
icacls "C:\inetpub\wwwroot\SecureGalleryPro\uploads" /grant "IIS_IUSRS:(OI)(CI)F" /T
icacls "C:\inetpub\wwwroot\SecureGalleryPro\temp" /grant "IIS_IUSRS:(OI)(CI)F" /T
```

### Step 7: SSL Configuration (Production)

#### 7.1 Install SSL Certificate
```powershell
# Import certificate to Personal store
Import-PfxCertificate -FilePath "C:\path\to\certificate.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString "password" -AsPlainText -Force)

# Bind certificate to website
New-WebBinding -Name "SecureGalleryPro" -Protocol https -Port 443
# Use IIS Manager to assign the certificate to the HTTPS binding
```

## Testing the Deployment

### 1. Test Database Connection
```powershell
cd C:\inetpub\wwwroot\SecureGalleryPro
npm run test:connection
```

### 2. Test Node.js Application
```powershell
# Check if the service is running
Get-Service | Where-Object {$_.Name -like "*SecureGallery*"}

# Check application logs
Get-Content "C:\inetpub\wwwroot\SecureGalleryPro\logs\app.log" -Tail 20
```

### 3. Test Web Access
- Open browser and navigate to `http://localhost`
- You should see the SecureGallery Pro login page
- Test file upload functionality
- Test audio/video playback

## Troubleshooting

### Common Issues and Solutions

#### npm Installation Fails
**Problem**: npm install fails with dependency resolution errors
**Solution**: Use the sequential installation method:
```powershell
npm install @vitejs/plugin-react --force
timeout /t 2
npm install vite --force
timeout /t 2
npm install esbuild --force
timeout /t 2
npm install --force
```

#### Database Connection Fails
**Problem**: Cannot connect to SQL Server Express
**Solutions**:
1. Verify SQL Server Express service is running: `services.msc`
2. Enable TCP/IP protocol in SQL Server Configuration Manager
3. Check firewall settings for port 1433
4. Verify connection string in `.env` file

#### IIS Returns 502 Bad Gateway
**Problem**: IIS cannot connect to Node.js application
**Solutions**:
1. Verify Node.js service is running: `pm2 status`
2. Check Node.js application logs: `pm2 logs`
3. Verify port 3000 is not blocked by firewall
4. Check web.config reverse proxy configuration

#### File Upload Fails
**Problem**: Large file uploads fail
**Solutions**:
1. Increase `maxAllowedContentLength` in web.config
2. Verify upload directory permissions
3. Check disk space availability
4. Increase Node.js memory limit

#### Permission Denied Errors
**Problem**: Application cannot read/write files
**Solution**: Reset file permissions:
```powershell
icacls "C:\inetpub\wwwroot\SecureGalleryPro" /reset /T
icacls "C:\inetpub\wwwroot\SecureGalleryPro" /grant "IIS_IUSRS:(OI)(CI)R" /T
icacls "C:\inetpub\wwwroot\SecureGalleryPro\logs" /grant "IIS_IUSRS:(OI)(CI)F" /T
icacls "C:\inetpub\wwwroot\SecureGalleryPro\uploads" /grant "IIS_IUSRS:(OI)(CI)F" /T
```

## Maintenance

### Regular Tasks
1. **Monitor logs**: Check `logs\app.log` for errors
2. **Database backup**: Schedule regular SQL Server backups
3. **Update Node.js**: Keep Node.js LTS version updated
4. **Monitor disk space**: Uploads directory can grow large
5. **SSL certificate renewal**: Update certificates before expiration

### Performance Optimization
1. **Enable IIS compression** (already configured in web.config)
2. **Configure SQL Server memory limits**
3. **Use SSD storage** for database and uploads
4. **Monitor CPU and memory usage**
5. **Consider load balancing** for high-traffic scenarios

## Production Considerations

### Security
- Use HTTPS in production (SSL certificate required)
- Configure Windows Firewall properly
- Use strong database passwords
- Regular security updates for Windows and SQL Server
- Consider using Windows Authentication for database connection

### Scalability
- Configure SQL Server connection pooling
- Consider using Redis for session storage
- Implement proper backup strategies
- Monitor performance metrics
- Plan for storage growth

### Compliance
- Configure audit logging for HIPAA/PCI compliance
- Implement proper access controls
- Regular security assessments
- Data retention policies
- Backup and recovery procedures

This deployment guide resolves all the major issues identified in the enterprise deployment analysis, providing a robust, scalable solution for Windows environments.