# SecureGallery Pro - Windows Deployment Guide (PostgreSQL + IIS)

This guide provides step-by-step instructions for deploying SecureGallery Pro to Windows with IIS and PostgreSQL.

## 📋 **Prerequisites**

✅ **Already Configured:**
- Windows Server with IIS
- PostgreSQL database running
- IIS reverse proxy configured (no ports in URLs)

✅ **Required:**
- Node.js 18 LTS or later
- Git for Windows
- PowerShell (Administrator access)

## 🗂️ **Directory Structure**

```
C:\inetpub\wwwroot\mediavault\     # IIS website root
D:\project\mediavault\             # File storage location
├── uploads\                       # User uploaded files
├── logs\                         # Application logs
└── temp\                         # Temporary files
```

## 🚀 **Step-by-Step Installation**

### Step 1: Prepare Directories

```powershell
# Run as Administrator
# Create file storage directories
New-Item -Path "D:\project\mediavault" -ItemType Directory -Force
New-Item -Path "D:\project\mediavault\uploads" -ItemType Directory -Force
New-Item -Path "D:\project\mediavault\logs" -ItemType Directory -Force
New-Item -Path "D:\project\mediavault\temp" -ItemType Directory -Force

# Set permissions for IIS_IUSRS
icacls "D:\project\mediavault" /grant "IIS_IUSRS:(OI)(CI)F" /T
```

### Step 2: Clone and Setup Application

```powershell
# Navigate to IIS directory
cd C:\inetpub\wwwroot\

# Clone the repository
git clone https://github.com/Skeptic1222/MediaVault2 mediavault
cd mediavault

# Copy Windows environment configuration
copy .env.windows-postgresql .env
```

### Step 3: Configure Environment

Edit `C:\inetpub\wwwroot\mediavault\.env`:

```bash
# Update these values for your environment:
DATABASE_URL=postgresql://your_username:your_password@localhost:5432/mediavault

# File paths (use double backslashes)
UPLOAD_DIR=D:\\project\\mediavault\\uploads
LOG_DIR=D:\\project\\mediavault\\logs
TEMP_DIR=D:\\project\\mediavault\\temp

# Generate a secure session secret (32+ characters)
SESSION_SECRET=your-ultra-secure-session-secret-change-this

# Generate encryption key for vault feature (exactly 32 characters)
FILESYSTEM_MASTER_KEY=your-32-character-encryption-key-here12

# Set your domain
CORS_ORIGIN=https://yourdomain.com
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

### Step 4: Install Dependencies and Build

```powershell
# Navigate to application directory
cd C:\inetpub\wwwroot\mediavault

# Install dependencies (use specific order for Windows compatibility)
npm install --production

# Build the application
npm run build
```

### Step 5: Setup Database

```sql
-- Connect to PostgreSQL and create database
CREATE DATABASE mediavault;

-- Grant permissions to your user
GRANT ALL PRIVILEGES ON DATABASE mediavault TO your_username;
```

```powershell
# Push database schema
npm run db:push
```

### Step 6: Install PM2 Process Manager

```powershell
# Install PM2 globally
npm install -g pm2
npm install -g pm2-windows-service

# Install PM2 as Windows service
pm2-service-install

# Start the application
pm2 start ecosystem.config.js --env production
pm2 save
```

### Step 7: Configure IIS Website

Since your IIS reverse proxy is already configured, just ensure:

1. **Website Points to Correct Directory:**
   - Physical Path: `C:\inetpub\wwwroot\mediavault`

2. **web.config is Present** (should be in the repository):
   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <configuration>
     <system.webServer>
       <rewrite>
         <rules>
           <rule name="ReverseProxyInboundRule1" stopProcessing="true">
             <match url="(.*)" />
             <action type="Rewrite" url="http://localhost:3000/{R:1}" />
           </rule>
         </rules>
       </rewrite>
     </system.webServer>
   </configuration>
   ```

### Step 8: Set File Permissions

```powershell
# Set permissions for IIS application pool
icacls "C:\inetpub\wwwroot\mediavault" /grant "IIS_IUSRS:(OI)(CI)R" /T

# Set permissions for file storage
icacls "D:\project\mediavault" /grant "IIS_IUSRS:(OI)(CI)F" /T

# Set permissions for application pool identity (replace YourAppPool)
icacls "D:\project\mediavault" /grant "IIS AppPool\YourAppPool:(OI)(CI)F" /T
```

### Step 9: Start Services and Test

```powershell
# Start PM2 if not running
pm2 start ecosystem.config.js --env production

# Check PM2 status
pm2 status

# Check logs
pm2 logs

# Test database connection
cd C:\inetpub\wwwroot\mediavault
npm run test:connection
```

### Step 10: Verify Installation

1. **Test Application:**
   - Navigate to your domain (no port needed)
   - Should see SecureGallery Pro login page

2. **Test File Upload:**
   - Sign in with your account
   - Try uploading a test file
   - Verify file appears in `D:\project\mediavault\uploads\`

3. **Check Logs:**
   - Application logs: `D:\project\mediavault\logs\`
   - PM2 logs: `pm2 logs`

## 🔧 **Troubleshooting**

### Database Connection Issues
```powershell
# Test PostgreSQL connection
psql -U your_username -d mediavault -h localhost

# Check database permissions
npm run db:push --force
```

### File Upload Issues
```powershell
# Check directory permissions
icacls "D:\project\mediavault\uploads"

# Check disk space
dir "D:\project\mediavault" /s
```

### Application Not Starting
```powershell
# Check PM2 status
pm2 status

# View PM2 logs
pm2 logs

# Restart application
pm2 restart ecosystem.config.js
```

### IIS Issues
- Verify URL Rewrite module is installed
- Check Application Request Routing (ARR) is enabled
- Ensure Node.js application is running on port 3000

## 🔄 **Update Process**

When updating the application:

```powershell
# Navigate to application directory
cd C:\inetpub\wwwroot\mediavault

# Pull latest changes
git pull origin main

# Install any new dependencies
npm install --production

# Rebuild application
npm run build

# Apply database migrations
npm run db:push

# Restart application
pm2 restart ecosystem.config.js
```

## 📁 **Key Configuration Files**

- **Environment:** `.env` (configure database, paths, secrets)
- **Process Management:** `ecosystem.config.js` (PM2 configuration)
- **IIS Proxy:** `web.config` (reverse proxy rules)
- **Database Schema:** Managed by Drizzle ORM (automatic migrations)

## 🛡️ **Security Considerations**

1. **Use HTTPS** in production (configure SSL in IIS)
2. **Secure Database** connection (use SSL if possible)
3. **File Permissions** - Restrict access to necessary accounts only
4. **Regular Updates** - Keep Node.js, PostgreSQL, and dependencies updated
5. **Backup Strategy** - Regular backups of database and file storage

Your SecureGallery Pro installation should now be running successfully on Windows with IIS and PostgreSQL!