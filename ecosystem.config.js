// PM2 Configuration for SecureGallery Pro Windows Deployment
// This file configures PM2 process manager for running the Node.js application as a Windows service

module.exports = {
  apps: [{
    name: 'SecureGalleryPro',
    script: './dist/index.js',
    instances: 1, // Single instance for SQL Server connection pooling
    exec_mode: 'fork', // Fork mode for better SQL Server compatibility
    
    // Environment variables
    env: {
      NODE_ENV: 'production',
      PORT: 3000,
      DB_TYPE: 'sqlserver'
    },
    
    // Logging configuration
    log_file: './logs/app.log',
    error_file: './logs/error.log',
    out_file: './logs/out.log',
    pid_file: './logs/app.pid',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    
    // Restart configuration
    watch: false, // Disable watch in production
    ignore_watch: ['node_modules', 'logs', 'uploads', 'temp'],
    restart_delay: 4000, // Delay between restarts
    max_restarts: 10, // Maximum restarts within min_uptime
    min_uptime: '10s', // Minimum uptime before considering successful
    
    // Memory and performance
    max_memory_restart: '1G', // Restart if memory usage exceeds 1GB
    node_args: '--max-old-space-size=1024', // Node.js memory limit
    
    // Windows specific settings
    windowsHide: true, // Hide console window on Windows
    
    // Health monitoring
    kill_timeout: 5000, // Time to wait before force killing
    listen_timeout: 8000, // Time to wait for app to be ready
    
    // Source map support for better error reporting
    source_map_support: true,
    
    // Merge logs for easier debugging
    merge_logs: true,
    
    // Automatic restart on file changes (disabled in production)
    autorestart: true,
    
    // Additional settings for Windows deployment
    interpreter: 'node', // Explicitly use node interpreter
    interpreter_args: [], // No additional node arguments
    
    // Graceful shutdown
    kill_timeout: 5000,
    shutdown_with_message: true,
    
    // Error handling
    max_memory_restart: '1G',
    exponential_backoff_restart_delay: 100,
    
    // Environment-specific configurations
    env_development: {
      NODE_ENV: 'development',
      PORT: 3000,
      DB_TYPE: 'postgresql',
      LOG_LEVEL: 'debug'
    },
    
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
      DB_TYPE: 'sqlserver',
      LOG_LEVEL: 'info'
    },
    
    env_staging: {
      NODE_ENV: 'staging',
      PORT: 3000,
      DB_TYPE: 'sqlserver',
      LOG_LEVEL: 'info'
    }
  }],
  
  // Deployment configuration
  deploy: {
    production: {
      user: 'Administrator',
      host: 'localhost',
      ref: 'origin/main',
      repo: 'https://github.com/yourusername/securegallery-pro.git',
      path: 'C:\\inetpub\\wwwroot\\SecureGalleryPro',
      'post-deploy': 'npm install --production && npm run build && pm2 reload ecosystem.config.js --env production'
    }
  }
};