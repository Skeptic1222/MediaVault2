/**
 * Centralized file size constants to prevent configuration drift
 * All sizes are in bytes
 */

// Database storage limits
export const FILE_SIZE_LIMITS = {
  // Maximum size for uploading files to database storage (50MB)
  // Files larger than this should use filesystem or chunked storage
  MAX_DATABASE_UPLOAD: 50 * 1024 * 1024,
  
  // Hard limit for files stored in database (100MB)
  // Files exceeding this cause Node.js memory issues and should be migrated to filesystem
  MAX_DATABASE_FILE: 100 * 1024 * 1024,
  
  // Streaming thresholds for content delivery
  // Encrypted files up to 50MB can use full-content loading (streaming decryption not supported)
  MAX_ENCRYPTED_STREAMING: 50 * 1024 * 1024,
  
  // Unencrypted files over 5MB should use streaming to prevent buffer overflow
  MAX_UNENCRYPTED_FULL_LOAD: 5 * 1024 * 1024,
  
  // Chunked encryption threshold (10MB)
  // Files larger than this use chunked encryption for better memory management
  CHUNKED_ENCRYPTION_THRESHOLD: 10 * 1024 * 1024,
  
  // Multer upload limit (5GB)
  // Maximum file size accepted by the upload middleware
  MAX_UPLOAD_SIZE: 5 * 1024 * 1024 * 1024,
  
  // Field size limit for form data (1MB)
  MAX_FIELD_SIZE: 1024 * 1024,
} as const;

// Helper functions for readable size comparisons
export const formatFileSize = (bytes: number): string => {
  if (bytes >= 1024 * 1024 * 1024) {
    return `${Math.round(bytes / (1024 * 1024 * 1024))}GB`;
  } else if (bytes >= 1024 * 1024) {
    return `${Math.round(bytes / (1024 * 1024))}MB`;
  } else if (bytes >= 1024) {
    return `${Math.round(bytes / 1024)}KB`;
  } else {
    return `${bytes}B`;
  }
};

export const createFileSizeError = (actualSize: number, limit: number, context: string): string => {
  return `File too large for ${context} (${formatFileSize(actualSize)} > ${formatFileSize(limit)})`;
};