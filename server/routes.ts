import type { Express } from "express";
import { createServer, type Server } from "http";
import multer from "multer";
import path from "path";
import fs from "fs";
import { promises as fsPromises } from "fs";
import crypto from "crypto";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./replitAuth";
import { mediaService } from "./services/mediaService";
import { streamingHybridMediaService } from "./services/streamingHybridMediaService";
import { cryptoService } from "./services/cryptoService";
import { folderImportService } from "./services/folderImportService";
import { insertCategorySchema, insertMediaFileSchema } from "@shared/schema";
import { FILE_SIZE_LIMITS } from "@shared/constants";
import { z } from "zod";

// In-memory store for vault access tokens (in production, use Redis or similar)
const vaultTokenStore = new Map<string, { userId: string; passphrase: string; expiresAt: number }>();

// In-memory store for media access tokens (in production, use Redis or similar)
const mediaTokenStore = new Map<string, { userId: string; fileId: string; expiresAt: number }>();

// Clean up expired tokens every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of Array.from(vaultTokenStore.entries())) {
    if (now > data.expiresAt) {
      vaultTokenStore.delete(token);
    }
  }
  for (const [token, data] of Array.from(mediaTokenStore.entries())) {
    if (now > data.expiresAt) {
      mediaTokenStore.delete(token);
    }
  }
}, 5 * 60 * 1000);

// Upload request validation schema
const uploadRequestSchema = z.object({
  categoryId: z.string().uuid("Invalid category ID format").optional(),
  encryptContent: z.enum(['true', 'false']).default('false'),
  preserveDirectoryStructure: z.enum(['true', 'false']).default('false'),
  createCategories: z.enum(['true', 'false']).default('false'),
}).catchall(z.string()); // Allow relativePath_N parameters

// UUID validation helper
function isValidUUID(str: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(str);
}

// SECURITY: Filename sanitization to prevent path traversal attacks
function sanitizeFilename(originalname: string): string {
  // First, use path.basename to remove any directory traversal attempts
  let filename = path.basename(originalname);
  
  // Remove any remaining path separators and dangerous characters
  filename = filename.replace(/[\\\/:*?"<>|]/g, '_');
  
  // Remove leading dots to prevent hidden files
  filename = filename.replace(/^\.+/, '');
  
  // Ensure filename is not empty and has reasonable length
  if (!filename || filename.length === 0) {
    filename = 'unnamed_file';
  }
  
  // Truncate if too long (keep extension)
  if (filename.length > 100) {
    const ext = path.extname(filename);
    const name = path.basename(filename, ext);
    filename = name.substring(0, 100 - ext.length) + ext;
  }
  
  return filename;
}

// Helper function to extract vault token from header or query param
function extractVaultToken(req: any): string | null {
  // Try header first
  const vaultToken = req.get('X-Vault-Token');
  if (vaultToken) return vaultToken;
  
  // Fall back to query parameter for video elements
  const queryToken = req.query.vt || req.query.vaultToken;
  return queryToken || null;
}

// Helper function to get vault passphrase from token with user binding validation
function getVaultPassphrase(token: string, requestingUserId: string): string | null {
  const tokenData = vaultTokenStore.get(token);
  if (!tokenData || Date.now() > tokenData.expiresAt) {
    if (tokenData) vaultTokenStore.delete(token);
    return null;
  }
  
  // SECURITY: Verify the token belongs to the requesting user
  if (tokenData.userId !== requestingUserId) {
    throw new Error('Vault token does not belong to the requesting user');
  }
  
  return tokenData.passphrase;
}

// Configure multer for file uploads with disk storage to prevent memory exhaustion
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const uploadDir = path.join(process.cwd(), 'uploads', 'temp');
      fs.mkdirSync(uploadDir, { recursive: true });
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      // SECURITY: Sanitize filename to prevent path traversal attacks
      const sanitizedName = sanitizeFilename(file.originalname);
      const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}-${sanitizedName}`;
      cb(null, uniqueName);
    }
  }),
  limits: {
    fileSize: FILE_SIZE_LIMITS.MAX_UPLOAD_SIZE, // 5GB limit for streaming support (1GB+ files)
    files: 1000, // Allow up to 1000 files for bulk uploads
    fieldSize: FILE_SIZE_LIMITS.MAX_FIELD_SIZE, // 1MB field size limit
  },
  fileFilter: (req, file, cb) => {
    // Allow all file types - the file manager should handle all types of files
    cb(null, true);
  },
});

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth middleware
  await setupAuth(app);

  // Generate temporary access token for media files
  app.post('/api/media/:id/access-token', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id: fileId } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(fileId)) {
        return res.status(404).json({ message: 'File not found' });
      }

      // Verify file exists and user has access
      const file = await storage.getFile(fileId);
      if (!file) {
        // Try media_files table for backward compatibility
        const mediaFile = await mediaService.getMediaMetadata(fileId, userId).catch(() => null);
        if (!mediaFile) {
          return res.status(404).json({ message: 'File not found' });
        }
      } else if (file.userId !== userId || file.isDeleted) {
        return res.status(403).json({ message: 'Access denied' });
      }

      // Generate temporary access token (valid for 1 hour)
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + (60 * 60 * 1000); // 1 hour
      
      mediaTokenStore.set(token, {
        userId,
        fileId,
        expiresAt
      });

      res.json({ 
        token,
        expiresAt: new Date(expiresAt).toISOString()
      });
    } catch (error) {
      const err = error as Error;
      console.error("Error generating media access token:", err);
      res.status(500).json({ message: "Failed to generate access token" });
    }
  });

  // Auth routes
  app.get('/api/auth/user', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      res.json(user);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching user:", err);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Media file routes
  app.get('/api/media', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const {
        categoryId,
        isVault = 'false',
        limit = '20',
        offset = '0',
        search,
        sortBy = 'created_at',
        sortOrder = 'desc',
        mimeType
      } = req.query;

      // Validate categoryId if provided
      if (categoryId && !isValidUUID(categoryId as string)) {
        return res.status(400).json({ message: 'Invalid category ID format' });
      }

      const options = {
        categoryId: categoryId as string,
        isVault: isVault === 'true',
        userId,
        limit: parseInt(limit as string),
        offset: parseInt(offset as string),
        search: search as string,
        sortBy: sortBy as 'created_at' | 'filename' | 'file_size',
        sortOrder: sortOrder as 'asc' | 'desc',
        mimeType: mimeType as 'images' | 'videos' | undefined,
      };

      const result = await storage.getMediaFiles(options);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'VIEW_MEDIA',
        resource: 'media_files',
        metadata: { query: req.query },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json(result);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching media files:", err);
      res.status(500).json({ message: "Failed to fetch media files" });
    }
  });

  app.get('/api/media/:id', async (req: any, res) => {
    try {
      let userId: string;
      let isTokenAuth = false;

      // Check for temporary access token first
      const accessToken = req.query.token as string;
      if (accessToken) {
        const tokenData = mediaTokenStore.get(accessToken);
        if (!tokenData) {
          return res.status(401).json({ message: 'Invalid or expired access token' });
        }
        if (tokenData.expiresAt < Date.now()) {
          mediaTokenStore.delete(accessToken);
          return res.status(401).json({ message: 'Access token expired' });
        }
        if (tokenData.fileId !== req.params.id) {
          return res.status(403).json({ message: 'Access token not valid for this file' });
        }
        userId = tokenData.userId;
        isTokenAuth = true;
      } else {
        // Fall back to session authentication
        if (!req.isAuthenticated() || !req.user?.claims?.sub) {
          return res.status(401).json({ message: 'Authentication required' });
        }
        userId = req.user.claims.sub;
      }
      const { id } = req.params;
      const { decrypt = 'false' } = req.query;

      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Media file not found' });
      }

      // Get vault passphrase from Authorization header if decryption is requested
      let vaultPassphrase: string | null = null;
      if (decrypt === 'true') {
        const vaultToken = extractVaultToken(req);
        if (!vaultToken) {
          return res.status(401).json({ message: 'Vault authorization token required for encrypted content' });
        }
        
        vaultPassphrase = getVaultPassphrase(vaultToken, userId);
        if (!vaultPassphrase) {
          return res.status(401).json({ message: 'Invalid or expired vault token' });
        }
      }

      // First try to get from media_files table (for backward compatibility)
      let metadata = await mediaService.getMediaMetadata(id, userId).catch(() => null);
      
      // If not found in media_files, try files table
      let isFromFilesTable = false;
      if (!metadata) {
        const file = await storage.getFile(id);
        if (!file || file.userId !== userId || file.isDeleted) {
          return res.status(404).json({ message: 'Media file not found' });
        }
        
        // Convert file to metadata format
        metadata = {
          fileSize: file.fileSize,
          mimeType: file.mimeType,
          filename: file.filename || file.originalName || 'download',
          isEncrypted: file.isEncrypted || false
        } as any;
        isFromFilesTable = true;
      }
      
      if (!metadata) {
        return res.status(404).json({ message: 'Media file not found' });
      }

      // Check if this is an encrypted file that needs decryption
      if (metadata.isEncrypted && decrypt !== 'true') {
        return res.status(403).json({ message: 'Content is encrypted and requires decryption' });
      }

      const fileSize = metadata.fileSize;
      const range = req.get('range');

      // Parse range header if present
      let start = 0;
      let end = fileSize - 1;
      let isRangeRequest = false;

      if (range) {
        isRangeRequest = true;
        const parts = range.replace(/bytes=/, "").split("-");
        start = parseInt(parts[0], 10) || 0;
        end = parseInt(parts[1], 10) || fileSize - 1;
        
        // Ensure valid range
        if (start >= fileSize || end >= fileSize || start > end) {
          res.status(416).set({
            'Content-Range': `bytes */${fileSize}`,
            'Accept-Ranges': 'bytes'
          });
          return res.end();
        }
      }

      // Use different thresholds for encrypted vs unencrypted files
      // Encrypted files up to 50MB can use full-content loading (streaming decryption not supported)
      // Unencrypted files over 5MB should use streaming to prevent buffer overflow
      const isLargeFile = metadata.isEncrypted 
        ? fileSize > 50 * 1024 * 1024 // 50MB threshold for encrypted files
        : fileSize > 5 * 1024 * 1024; // 5MB threshold for unencrypted files

      // For large files, always use chunked streaming
      if (isLargeFile || isRangeRequest) {
        try {
          // If from files table, serve directly
          if (isFromFilesTable) {
            const fileData = await storage.getFileBinaryData(id);
            if (!fileData || !fileData.binaryData) {
              return res.status(404).json({ message: 'File content not found' });
            }
            
            const buffer = Buffer.from(fileData.binaryData);
            const chunkSize = end - start + 1;
            const chunk = buffer.slice(start, end + 1);
            
            res.status(206).set({
              'Content-Type': metadata.mimeType,
              'Content-Disposition': metadata.mimeType?.includes('pdf') 
                ? `inline; filename="${metadata.filename}"`
                : `inline; filename="${metadata.filename}"`,
              'Content-Length': chunkSize.toString(),
              'Accept-Ranges': 'bytes',
              'Content-Range': `bytes ${start}-${end}/${fileSize}`,
              'Cache-Control': 'public, max-age=3600',
              'X-Content-Type-Options': 'nosniff'
            });
            
            return res.send(chunk);
          }
          
          const chunkResult = await streamingHybridMediaService.getMediaChunk(
            id,
            userId,
            start,
            end,
            decrypt === 'true',
            vaultPassphrase || undefined
          );

          if (!chunkResult) {
            return res.status(404).json({ message: 'Media file not found' });
          }

          const chunkSize = end - start + 1;

          // Log activity for chunked access
          await storage.logActivity({
            userId,
            action: 'DOWNLOAD_MEDIA',
            resource: 'media_files',
            resourceId: id,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
          });

          // Always return 206 for range requests, or for large files
          const statusCode = isRangeRequest ? 206 : (isLargeFile ? 206 : 200);
          
          res.status(statusCode).set({
            'Content-Type': chunkResult.mimeType,
            'Content-Disposition': `inline; filename="${chunkResult.filename}"`,
            'Content-Length': chunkSize.toString(),
            'Accept-Ranges': 'bytes',
            ...(statusCode === 206 && {
              'Content-Range': `bytes ${start}-${end}/${chunkResult.totalSize}`
            })
          });

          return res.send(chunkResult.buffer);

        } catch (error) {
          const err = error as Error;
          if (err.message.includes('Streaming decryption not yet supported')) {
            return res.status(501).json({ message: 'Streaming not supported for encrypted large files' });
          }
          throw error;
        }
      }

      // For smaller files, use traditional full-content loading
      let content;
      
      // If from files table, serve directly
      if (isFromFilesTable) {
        const fileData = await storage.getFileBinaryData(id);
        if (!fileData || !fileData.binaryData) {
          return res.status(404).json({ message: 'File content not found' });
        }
        
        content = {
          buffer: Buffer.from(fileData.binaryData),
          mimeType: metadata.mimeType,
          filename: metadata.filename
        };
      } else {
        content = await streamingHybridMediaService.getMediaContent(
          id,
          userId,
          decrypt === 'true',
          vaultPassphrase || undefined
        );
      }

      if (!content) {
        return res.status(404).json({ message: 'Media file not found' });
      }

      // Log activity
      await storage.logActivity({
        userId,
        action: 'DOWNLOAD_MEDIA',
        resource: 'media_files',
        resourceId: id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Handle range requests for small files 
      if (isRangeRequest) {
        const chunkSize = end - start + 1;
        const chunk = content.buffer.slice(start, end + 1);

        res.status(206).set({
          'Content-Range': `bytes ${start}-${end}/${fileSize}`,
          'Accept-Ranges': 'bytes',
          'Content-Length': chunkSize.toString(),
          'Content-Type': content.mimeType,
          'Content-Disposition': `inline; filename="${content.filename}"`,
        });

        return res.send(chunk);
      }

      // Regular full-content response for small files
      res.set({
        'Content-Type': content.mimeType,
        'Content-Disposition': content.mimeType?.includes('pdf') 
          ? `inline; filename="${content.filename}"`
          : `inline; filename="${content.filename}"`,
        'Content-Length': content.buffer.length.toString(),
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'public, max-age=3600',
        'X-Content-Type-Options': 'nosniff'
      });

      res.send(content.buffer);
    } catch (error) {
      const err = error as Error;
      console.error("Error serving media file:", err);
      if (err.message.includes('Access denied')) {
        res.status(403).json({ message: err.message });
      } else if (err.message.includes('Vault token does not belong')) {
        res.status(403).json({ message: err.message });
      } else if (err.message.includes('decryption')) {
        res.status(403).json({ message: err.message });
      } else if (err.message.includes('File too large')) {
        res.status(413).json({ message: 'File too large - use range requests' });
      } else if (err.message.includes('invalid input syntax for type uuid')) {
        res.status(404).json({ message: 'Media file not found' });
      } else {
        res.status(500).json({ message: "Failed to serve media file" });
      }
    }
  });

  app.get('/api/media/:id/thumbnail', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const { decrypt = 'false', format = 'auto' } = req.query;
      const acceptHeader = req.get('Accept');

      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Thumbnail not found' });
      }

      // Get vault passphrase from Authorization header if decryption is requested
      let vaultPassphrase: string | null = null;
      if (decrypt === 'true') {
        const vaultToken = extractVaultToken(req);
        if (!vaultToken) {
          return res.status(401).json({ message: 'Vault authorization token required for encrypted content' });
        }
        
        vaultPassphrase = getVaultPassphrase(vaultToken, userId);
        if (!vaultPassphrase) {
          return res.status(401).json({ message: 'Invalid or expired vault token' });
        }
      }

      const thumbnailResult = await mediaService.getThumbnailWithFormat(
        id,
        userId,
        {
          format: format as 'auto' | 'jpeg' | 'webp' | 'avif',
          acceptHeader,
          decrypt: decrypt === 'true',
          vaultPassphrase: vaultPassphrase || undefined
        }
      );

      if (!thumbnailResult) {
        return res.status(404).json({ message: 'Thumbnail not found' });
      }

      res.set({
        'Content-Type': thumbnailResult.mimeType,
        'Cache-Control': 'public, max-age=86400', // Cache for 24 hours
        'Vary': 'Accept', // Enable proper caching with content negotiation
      });

      res.send(thumbnailResult.buffer);
    } catch (error) {
      const err = error as Error;
      console.error("Error serving thumbnail:", err);
      if (err.message.includes('Access denied')) {
        res.status(403).json({ message: err.message });
      } else if (err.message.includes('Vault token does not belong')) {
        res.status(403).json({ message: err.message });
      } else if (err.message.includes('decryption')) {
        res.status(403).json({ message: err.message });
      } else if (err.message.includes('invalid input syntax for type uuid')) {
        res.status(404).json({ message: 'Thumbnail not found' });
      } else {
        res.status(500).json({ message: "Failed to serve thumbnail" });
      }
    }
  });

  // Admin data migration endpoints
  app.post('/api/admin/sync-media-to-files', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      
      // Check if user is admin
      const user = await storage.getUser(userId);
      if (!user || user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }

      // Sync media files to files table
      const result = await storage.syncMediaFilesToFilesTable();
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'ADMIN_SYNC_MEDIA',
        resource: 'admin',
        metadata: { result },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json({
        success: true,
        message: `Successfully synced ${result.synced} media files to files table`,
        details: result
      });
    } catch (error) {
      const err = error as Error;
      console.error("Error syncing media to files:", err);
      res.status(500).json({ message: "Failed to sync media to files: " + err.message });
    }
  });

  app.get('/api/admin/cleanup-duplicate-categories', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      
      // Check if user is admin
      const user = await storage.getUser(userId);
      if (!user || user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }

      // Clean up duplicate categories
      const result = await storage.cleanupDuplicateCategories();
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'ADMIN_CLEANUP_CATEGORIES',
        resource: 'admin',
        metadata: { result },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json({
        success: true,
        message: `Successfully cleaned up ${result.removed} duplicate categories`,
        details: result
      });
    } catch (error) {
      const err = error as Error;
      console.error("Error cleaning up categories:", err);
      res.status(500).json({ message: "Failed to cleanup categories: " + err.message });
    }
  });

  // User management admin routes
  app.get('/api/admin/users', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      
      // Check if user is admin
      const user = await storage.getUser(userId);
      if (!user || user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }

      // Get all users with their basic info
      const result = await storage.getAllUsers();
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'ADMIN_VIEW_USERS',
        resource: 'admin',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json(result);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching users:", err);
      res.status(500).json({ message: "Failed to fetch users: " + err.message });
    }
  });

  app.get('/api/admin/users/:id/stats', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const targetUserId = req.params.id;
      
      // Check if user is admin
      const user = await storage.getUser(userId);
      if (!user || user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }

      // Get user stats
      const stats = await storage.getUserStats(targetUserId);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'ADMIN_VIEW_USER_STATS',
        resource: 'users',
        resourceId: targetUserId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json(stats);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching user stats:", err);
      res.status(500).json({ message: "Failed to fetch user stats: " + err.message });
    }
  });

  app.put('/api/admin/users/:id/role', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const targetUserId = req.params.id;
      const { role } = req.body;
      
      // Check if user is admin
      const user = await storage.getUser(userId);
      if (!user || user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }

      // Prevent admin from removing their own admin role
      if (userId === targetUserId && role !== 'admin') {
        return res.status(400).json({ message: "Cannot remove your own admin privileges" });
      }

      // Update user role
      const updatedUser = await storage.updateUserRole(targetUserId, role);
      
      if (!updatedUser) {
        return res.status(404).json({ message: "User not found" });
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'ADMIN_UPDATE_USER_ROLE',
        resource: 'users',
        resourceId: targetUserId,
        metadata: { newRole: role },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json(updatedUser);
    } catch (error) {
      const err = error as Error;
      console.error("Error updating user role:", err);
      res.status(500).json({ message: "Failed to update user role: " + err.message });
    }
  });

  app.delete('/api/admin/users/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const targetUserId = req.params.id;
      
      // Check if user is admin
      const user = await storage.getUser(userId);
      if (!user || user.role !== 'admin') {
        return res.status(403).json({ message: "Admin access required" });
      }

      // Prevent admin from deleting themselves
      if (userId === targetUserId) {
        return res.status(400).json({ message: "Cannot delete your own account" });
      }

      // Delete user and their data
      const result = await storage.deleteUser(targetUserId);
      
      if (!result.success) {
        return res.status(500).json({ message: "Failed to delete user" });
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'ADMIN_DELETE_USER',
        resource: 'users',
        resourceId: targetUserId,
        metadata: { filesDeleted: result.filesDeleted, foldersDeleted: result.foldersDeleted },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json({
        success: true,
        message: "User and all associated data deleted successfully",
        details: result
      });
    } catch (error) {
      const err = error as Error;
      console.error("Error deleting user:", err);
      res.status(500).json({ message: "Failed to delete user: " + err.message });
    }
  });

  app.post('/api/media/upload', isAuthenticated, (req: any, res: any, next: any) => {
    upload.array('files')(req, res, async (err: any) => {
      // Handle multer errors
      if (err) {
        console.error('Upload error:', err);
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).json({ message: 'File too large. Maximum size is 5GB per file.' });
        }
        if (err.code === 'LIMIT_FILE_COUNT') {
          return res.status(400).json({ message: 'Too many files. Maximum 1000 files per upload.' });
        }
        if (err.code === 'LIMIT_UNEXPECTED_FILE') {
          return res.status(400).json({ message: 'Unexpected field in upload.' });
        }
        return res.status(500).json({ message: err.message || 'Upload failed' });
      }

      // Proceed with normal upload handling
      try {
        const userId = req.user.claims.sub;
        const files = req.files as Express.Multer.File[];

      if (!files || files.length === 0) {
        return res.status(400).json({ message: 'No files provided' });
      }

      // Validate request body with Zod schema  
      const validationResult = uploadRequestSchema.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({ 
          message: "Invalid request data", 
          errors: validationResult.error.errors 
        });
      }

      const { categoryId, encryptContent, preserveDirectoryStructure, createCategories } = validationResult.data;

      // Get vault passphrase and auto-generate encryption key if encrypting content
      let vaultPassphrase: string | null = null;
      let encryptionKey: string | undefined;
      
      if (encryptContent === 'true') {
        const vaultToken = extractVaultToken(req);
        if (!vaultToken) {
          return res.status(401).json({ message: 'Vault authorization token required for encrypted uploads' });
        }
        
        vaultPassphrase = getVaultPassphrase(vaultToken, userId);
        if (!vaultPassphrase) {
          return res.status(401).json({ message: 'Invalid or expired vault token' });
        }
        
        // Auto-generate encryption key for this upload session
        encryptionKey = crypto.randomBytes(32).toString('hex');
      }

      const tempFilesToCleanup: string[] = [];

      try {
        // Add all temp files to cleanup list
        for (const file of files) {
          tempFilesToCleanup.push(file.path);
        }

        // Check if this is a directory upload with preserved structure
        if (preserveDirectoryStructure === 'true') {
          // Extract relative paths from request body
          const filesWithPaths = files.map((file, index) => {
            const relativePath = validationResult.data[`relativePath_${index}`] || file.originalname;
            return {
              file,
              relativePath
            };
          });

          // Use the secure folder import service to handle directory structure
          const result = await folderImportService.processUploadedFolderStructure(
            filesWithPaths,
            userId,
            {
              createCategories: createCategories === 'true',
              isVault: encryptContent === 'true',
              parentCategoryId: categoryId,
              vaultPassphrase: vaultPassphrase || undefined,
            }
          );

          // Log activity
          await storage.logActivity({
            userId,
            action: 'DIRECTORY_UPLOAD',
            resource: 'import_batches',
            resourceId: result.importBatchId,
            metadata: {
              totalFiles: result.totalFiles,
              processedFiles: result.processedFiles,
              duplicatesFound: result.duplicatesFound,
              success: result.success,
              createCategories: createCategories === 'true',
              encrypted: encryptContent === 'true'
            },
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
          });

          return res.json(result);
        } else {
          // Handle individual file uploads (existing behavior)
          const results = [];

          for (const file of files) {
            try {
              // Use streaming approach with temp file path (no memory loading)
              const result = await streamingHybridMediaService.processAndStoreFile(
                file.path, // Pass temp file path directly instead of buffer
                file.originalname,
                file.mimetype,
                userId,
                {
                  encryptContent: encryptContent === 'true',
                  encryptionKey: encryptionKey || undefined,
                  vaultPassphrase: vaultPassphrase || undefined,
                  categoryId: categoryId || undefined,
                  generateThumbnail: true
                }
              );

              results.push(result);
              
              // Temporary file will be cleaned up in finally block
            } catch (error) {
              const err = error as Error;
              console.error(`Error processing file ${file.originalname}:`, err);
              results.push({
                originalName: file.originalname,
                error: err.message,
              });
              
              // Temporary file will be cleaned up in finally block
            }
          }

          // Log activity
          await storage.logActivity({
            userId,
            action: 'UPLOAD_MEDIA',
            resource: 'media_files',
            metadata: { 
              fileCount: files.length,
              totalSize: files.reduce((sum, f) => sum + f.size, 0),
              categoryId,
              encrypted: encryptContent === 'true'
            },
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
          });

          return res.json({ results });
        }
      } finally {
        // SECURITY: Always cleanup temporary files to prevent disk space exhaustion
        for (const tempFile of tempFilesToCleanup) {
          try {
            await fsPromises.unlink(tempFile);
          } catch (cleanupError) {
            console.error(`Failed to cleanup temp file ${tempFile}:`, cleanupError);
          }
        }
      }
    } catch (error) {
      const err = error as Error;
      console.error("Error uploading media files:", err);
      
      // Cleanup any uploaded files in case of error
      if (req.files) {
        const files = req.files as Express.Multer.File[];
        for (const file of files) {
          try {
            if (file.path) {
              await fsPromises.unlink(file.path);
            }
          } catch (cleanupError) {
            console.error(`Failed to cleanup temp file ${file.path}:`, cleanupError);
          }
        }
      }
      
      res.status(500).json({ message: "Failed to upload media files" });
      }
    });
  });


  app.patch('/api/media/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const updates = req.body;

      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Media file not found' });
      }

      // Validate the media file belongs to user or user is admin
      const mediaFile = await storage.getMediaFile(id);
      if (!mediaFile) {
        return res.status(404).json({ message: 'Media file not found' });
      }

      const user = await storage.getUser(userId);
      if (mediaFile.uploadedBy !== userId && user?.role !== 'admin') {
        return res.status(403).json({ message: 'Unauthorized to modify this file' });
      }

      const updated = await storage.updateMediaFile(id, updates);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'UPDATE_MEDIA',
        resource: 'media_files',
        resourceId: id,
        metadata: { updates },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json(updated);
    } catch (error) {
      const err = error as Error;
      console.error("Error updating media file:", err);
      res.status(500).json({ message: "Failed to update media file" });
    }
  });

  app.delete('/api/media/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;

      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Media file not found' });
      }

      // Validate the media file belongs to user or user is admin
      const mediaFile = await storage.getMediaFile(id);
      if (!mediaFile) {
        return res.status(404).json({ message: 'Media file not found' });
      }

      const user = await storage.getUser(userId);
      if (mediaFile.uploadedBy !== userId && user?.role !== 'admin') {
        return res.status(403).json({ message: 'Unauthorized to delete this file' });
      }

      const deleted = await storage.deleteMediaFile(id);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'DELETE_MEDIA',
        resource: 'media_files',
        resourceId: id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json({ success: deleted });
    } catch (error) {
      const err = error as Error;
      console.error("Error deleting media file:", err);
      res.status(500).json({ message: "Failed to delete media file" });
    }
  });

  // Download media file route
  app.get('/api/media/:id/download', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;

      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Media file not found' });
      }

      // Validate the media file belongs to user or user is admin
      const mediaFile = await storage.getMediaFile(id);
      if (!mediaFile) {
        return res.status(404).json({ message: 'Media file not found' });
      }

      const user = await storage.getUser(userId);
      if (mediaFile.uploadedBy !== userId && user?.role !== 'admin') {
        return res.status(403).json({ message: 'Unauthorized to download this file' });
      }

      // Get file content
      const fileData = await mediaService.getMediaContent(id, userId);
      
      if (!fileData) {
        return res.status(404).json({ message: 'File content not found' });
      }

      // Set headers for download
      res.set({
        'Content-Type': mediaFile.mimeType || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${encodeURIComponent(mediaFile.originalName)}"`,
        'Content-Length': mediaFile.fileSize.toString(),
      });

      // Log activity
      await storage.logActivity({
        userId,
        action: 'DOWNLOAD_MEDIA',
        resource: 'media_files',
        resourceId: id,
        metadata: { filename: mediaFile.originalName },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // Send file content
      res.send(fileData);
    } catch (error) {
      const err = error as Error;
      console.error("Error downloading media file:", err);
      res.status(500).json({ message: "Failed to download media file" });
    }
  });

  // Category routes
  app.get('/api/categories', isAuthenticated, async (req: any, res) => {
    try {
      const categories = await storage.getCategoryTree();
      res.json(categories);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching categories:", err);
      res.status(500).json({ message: "Failed to fetch categories" });
    }
  });

  app.post('/api/categories', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      
      if (user?.role !== 'admin') {
        return res.status(403).json({ message: 'Only administrators can create categories' });
      }

      const categoryData = insertCategorySchema.parse(req.body);
      const category = await storage.createCategory(categoryData);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'CREATE_CATEGORY',
        resource: 'categories',
        resourceId: category.id,
        metadata: categoryData,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json(category);
    } catch (error) {
      const err = error as Error;
      console.error("Error creating category:", err);
      if (err instanceof z.ZodError) {
        res.status(400).json({ message: "Invalid category data", errors: err.errors });
      } else {
        res.status(500).json({ message: "Failed to create category" });
      }
    }
  });

  app.put('/api/categories/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const { id } = req.params;
      
      if (user?.role !== 'admin') {
        return res.status(403).json({ message: 'Only administrators can update categories' });
      }

      // Parse and validate the update data
      const updateData = req.body;
      const category = await storage.updateCategory(id, updateData);
      
      if (!category) {
        return res.status(404).json({ message: 'Category not found' });
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'UPDATE_CATEGORY',
        resource: 'categories',
        resourceId: id,
        metadata: updateData,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json(category);
    } catch (error) {
      const err = error as Error;
      console.error("Error updating category:", err);
      res.status(500).json({ message: "Failed to update category" });
    }
  });

  app.delete('/api/categories/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const { id } = req.params;
      
      if (user?.role !== 'admin') {
        return res.status(403).json({ message: 'Only administrators can delete categories' });
      }

      // Check if category has any media files
      const mediaFiles = await storage.getMediaFiles({ categoryId: id, limit: 1 });
      if (mediaFiles.total > 0) {
        return res.status(400).json({ 
          message: 'Cannot delete category with files. Please move or delete all files first.',
          fileCount: mediaFiles.total
        });
      }

      const deleted = await storage.deleteCategory(id);
      
      if (!deleted) {
        return res.status(404).json({ message: 'Category not found' });
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'DELETE_CATEGORY',
        resource: 'categories',
        resourceId: id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json({ success: true, message: 'Category deleted successfully' });
    } catch (error) {
      const err = error as Error;
      console.error("Error deleting category:", err);
      res.status(500).json({ message: "Failed to delete category" });
    }
  });

  // Folder API routes
  app.get('/api/folders', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { parentId } = req.query;
      
      const folders = await storage.getFolders(userId, parentId as string | undefined);
      
      res.json(folders);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching folders:", err);
      res.status(500).json({ message: "Failed to fetch folders" });
    }
  });

  app.get('/api/folders/tree', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const folderTree = await storage.getFolderTree(userId);
      
      res.json(folderTree);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching folder tree:", err);
      res.status(500).json({ message: "Failed to fetch folder tree" });
    }
  });

  app.get('/api/folders/:id', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Folder not found' });
      }
      
      const folder = await storage.getFolders(req.user.claims.sub, id);
      
      if (!folder || folder.length === 0) {
        return res.status(404).json({ message: 'Folder not found' });
      }
      
      res.json(folder[0]);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching folder:", err);
      res.status(500).json({ message: "Failed to fetch folder" });
    }
  });

  app.post('/api/folders', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const folderData = req.body;
      
      // Validate folder data
      if (!folderData.name) {
        return res.status(400).json({ message: 'Folder name is required' });
      }
      
      const folder = await storage.createFolder({
        ...folderData,
        userId
      });
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'CREATE_FOLDER',
        resource: 'folders',
        resourceId: folder.id,
        metadata: { folderName: folder.name },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(201).json(folder);
    } catch (error) {
      const err = error as Error;
      console.error("Error creating folder:", err);
      res.status(500).json({ message: "Failed to create folder" });
    }
  });

  app.patch('/api/folders/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const updates = req.body;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Folder not found' });
      }
      
      const folder = await storage.updateFolder(id, updates);
      
      if (!folder) {
        return res.status(404).json({ message: 'Folder not found' });
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'UPDATE_FOLDER',
        resource: 'folders',
        resourceId: id,
        metadata: { updates },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.json(folder);
    } catch (error) {
      const err = error as Error;
      console.error("Error updating folder:", err);
      res.status(500).json({ message: "Failed to update folder" });
    }
  });

  app.delete('/api/folders/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Folder not found' });
      }
      
      const deleted = await storage.deleteFolder(id);
      
      if (!deleted) {
        return res.status(404).json({ message: 'Folder not found' });
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'DELETE_FOLDER',
        resource: 'folders',
        resourceId: id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(204).send();
    } catch (error) {
      const err = error as Error;
      console.error("Error deleting folder:", err);
      res.status(500).json({ message: err.message || "Failed to delete folder" });
    }
  });

  app.put('/api/folders/:id/move', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const { parentId } = req.body;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Folder not found' });
      }
      
      if (parentId && !isValidUUID(parentId)) {
        return res.status(400).json({ message: 'Invalid parent folder ID' });
      }
      
      const moved = await storage.moveFolderToFolder(id, parentId);
      
      if (!moved) {
        return res.status(404).json({ message: 'Folder not found' });
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'MOVE_FOLDER',
        resource: 'folders',
        resourceId: id,
        metadata: { newParentId: parentId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.json({ success: true });
    } catch (error) {
      const err = error as Error;
      console.error("Error moving folder:", err);
      res.status(500).json({ message: err.message || "Failed to move folder" });
    }
  });

  // File API routes
  app.get('/api/files', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const {
        folderId,
        fileType,
        limit = '20',
        offset = '0',
        search,
        tags,
        sortBy = 'created_at',
        sortOrder = 'desc'
      } = req.query;
      
      // Validate folderId if provided
      if (folderId && !isValidUUID(folderId as string)) {
        return res.status(400).json({ message: 'Invalid folder ID format' });
      }
      
      const currentFolderId = folderId === 'null' ? null : folderId as string;
      
      // Fetch folders for current directory
      const folders = await storage.getFolders(userId, currentFolderId);
      
      // Fetch files for current directory
      const options = {
        userId,
        folderId: currentFolderId,
        fileType: fileType as string,
        limit: parseInt(limit as string),
        offset: parseInt(offset as string),
        search: search as string,
        tags: tags ? (Array.isArray(tags) ? tags : [tags]) : undefined,
        sortBy: sortBy as 'created_at' | 'filename' | 'file_size',
        sortOrder: sortOrder as 'asc' | 'desc'
      };
      
      const filesResult = await storage.getFiles(options);
      
      // Convert folders and files to FileItem format
      const folderItems = folders.map((folder: any) => ({
        id: folder.id,
        name: folder.name,
        type: 'folder' as const,
        size: 0,
        mimeType: 'folder',
        createdAt: folder.createdAt,
        updatedAt: folder.updatedAt,
        parentId: folder.parentId,
        path: folder.path || `/${folder.name}`,
        isEncrypted: false,
        childrenCount: 0
      }));
      
      const fileItems = (filesResult.files || []).map((file: any) => ({
        id: file.id,
        name: file.originalName || file.filename,
        type: 'file' as const,
        size: file.fileSize,
        mimeType: file.mimeType,
        createdAt: file.createdAt,
        updatedAt: file.updatedAt,
        parentId: file.folderId,
        path: file.filePath || `/${file.filename}`,
        // Use /api/media/:id/thumbnail for media files (those without folderId), /api/files/:id/thumbnail for regular files
        thumbnailUrl: file.thumbnailData ? 
          (file.folderId === null && (file.mimeType?.startsWith('image/') || file.mimeType?.startsWith('video/')) ? 
            `/api/media/${file.id}/thumbnail` : 
            `/api/files/${file.id}/thumbnail`) 
          : undefined,
        isEncrypted: file.isEncrypted || false,
        tags: file.tags || []
      }));
      
      // Combine and sort the items
      let combinedItems = [...folderItems, ...fileItems];
      
      // Apply search filter if provided
      if (search) {
        const searchLower = search.toLowerCase();
        combinedItems = combinedItems.filter(item => 
          item.name.toLowerCase().includes(searchLower)
        );
      }
      
      // Apply sorting
      combinedItems.sort((a, b) => {
        // Folders first, then files
        if (a.type !== b.type) {
          return a.type === 'folder' ? -1 : 1;
        }
        
        // Then sort by specified field
        if (sortBy === 'filename' || sortBy === 'name') {
          return sortOrder === 'asc' 
            ? a.name.localeCompare(b.name)
            : b.name.localeCompare(a.name);
        } else if (sortBy === 'file_size' || sortBy === 'size') {
          return sortOrder === 'asc' 
            ? (a.size || 0) - (b.size || 0)
            : (b.size || 0) - (a.size || 0);
        } else { // created_at or date
          const aDate = new Date(a.createdAt).getTime();
          const bDate = new Date(b.createdAt).getTime();
          return sortOrder === 'asc' ? aDate - bDate : bDate - aDate;
        }
      });
      
      // Return as a flat array
      res.json(combinedItems);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching files:", err);
      res.status(500).json({ message: "Failed to fetch files" });
    }
  });

  app.get('/api/files/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const { decrypt = 'false' } = req.query;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Get vault passphrase if decryption is requested
      let vaultPassphrase: string | null = null;
      if (decrypt === 'true') {
        const vaultToken = extractVaultToken(req);
        if (!vaultToken) {
          return res.status(401).json({ message: 'Vault authorization token required for encrypted content' });
        }
        
        vaultPassphrase = getVaultPassphrase(vaultToken, userId);
        if (!vaultPassphrase) {
          return res.status(401).json({ message: 'Invalid or expired vault token' });
        }
      }
      
      const file = await storage.getFile(id);
      
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Check ownership
      if (file.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      res.json(file);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching file:", err);
      res.status(500).json({ message: "Failed to fetch file" });
    }
  });

  app.get('/api/files/:id/thumbnail', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const { decrypt = 'false', format = 'auto' } = req.query;
      const acceptHeader = req.get('Accept');

      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Thumbnail not found' });
      }

      // First check if it's a regular file
      const file = await storage.getFile(id);
      
      if (file) {
        // Check ownership
        if (file.userId !== userId) {
          return res.status(403).json({ message: 'Access denied' });
        }
        
        // For regular files from the files table
        const thumbnailResult = await storage.getFileThumbnail(id);
        
        if (!thumbnailResult || !thumbnailResult.thumbnailData) {
          return res.status(404).json({ message: 'Thumbnail not found' });
        }
        
        res.set({
          'Content-Type': thumbnailResult.mimeType,
          'Cache-Control': 'public, max-age=86400',
        });
        
        return res.send(thumbnailResult.thumbnailData);
      }
      
      // If not found in files table, check mediaFiles table
      // Get vault passphrase from Authorization header if decryption is requested
      let vaultPassphrase: string | null = null;
      if (decrypt === 'true') {
        const vaultToken = extractVaultToken(req);
        if (!vaultToken) {
          return res.status(401).json({ message: 'Vault authorization token required for encrypted content' });
        }
        
        vaultPassphrase = getVaultPassphrase(vaultToken, userId);
        if (!vaultPassphrase) {
          return res.status(401).json({ message: 'Invalid or expired vault token' });
        }
      }

      // Use mediaService for media files
      const thumbnailResult = await mediaService.getThumbnailWithFormat(
        id,
        userId,
        {
          format: format as 'auto' | 'jpeg' | 'webp' | 'avif',
          acceptHeader,
          decrypt: decrypt === 'true',
          vaultPassphrase: vaultPassphrase || undefined
        }
      );

      if (!thumbnailResult) {
        return res.status(404).json({ message: 'Thumbnail not found' });
      }

      res.set({
        'Content-Type': thumbnailResult.mimeType,
        'Cache-Control': 'public, max-age=86400',
        'Vary': 'Accept',
      });

      res.send(thumbnailResult.buffer);
    } catch (error) {
      const err = error as Error;
      console.error("Error serving file thumbnail:", err);
      if (err.message.includes('Access denied')) {
        res.status(403).json({ message: err.message });
      } else if (err.message.includes('Vault token does not belong')) {
        res.status(403).json({ message: err.message });
      } else if (err.message.includes('invalid input syntax for type uuid')) {
        res.status(404).json({ message: 'Thumbnail not found' });
      } else {
        res.status(500).json({ message: "Failed to serve thumbnail" });
      }
    }
  });

  app.patch('/api/files/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const updates = req.body;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Verify ownership
      const file = await storage.getFile(id);
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      if (file.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const updated = await storage.updateFile(id, updates);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'UPDATE_FILE',
        resource: 'files',
        resourceId: id,
        metadata: { updates },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.json(updated);
    } catch (error) {
      const err = error as Error;
      console.error("Error updating file:", err);
      res.status(500).json({ message: "Failed to update file" });
    }
  });

  app.delete('/api/files/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Verify ownership
      const file = await storage.getFile(id);
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      if (file.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const deleted = await storage.deleteFile(id);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'DELETE_FILE',
        resource: 'files',
        resourceId: id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(204).send();
    } catch (error) {
      const err = error as Error;
      console.error("Error deleting file:", err);
      res.status(500).json({ message: "Failed to delete file" });
    }
  });

  app.put('/api/files/:id/move', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const { folderId } = req.body;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      if (folderId && !isValidUUID(folderId)) {
        return res.status(400).json({ message: 'Invalid folder ID' });
      }
      
      // Verify ownership
      const file = await storage.getFile(id);
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      if (file.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const moved = await storage.moveFileToFolder(id, folderId);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'MOVE_FILE',
        resource: 'files',
        resourceId: id,
        metadata: { newFolderId: folderId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.json({ success: moved });
    } catch (error) {
      const err = error as Error;
      console.error("Error moving file:", err);
      res.status(500).json({ message: "Failed to move file" });
    }
  });

  app.post('/api/files/:id/copy', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const { folderId } = req.body;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      if (folderId && !isValidUUID(folderId)) {
        return res.status(400).json({ message: 'Invalid folder ID' });
      }
      
      // Verify ownership
      const file = await storage.getFile(id);
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      if (file.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const copiedFile = await storage.copyFile(id, folderId);
      
      if (!copiedFile) {
        return res.status(500).json({ message: 'Failed to copy file' });
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'COPY_FILE',
        resource: 'files',
        resourceId: id,
        metadata: { targetFolderId: folderId, newFileId: copiedFile.id },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(201).json(copiedFile);
    } catch (error) {
      const err = error as Error;
      console.error("Error copying file:", err);
      res.status(500).json({ message: "Failed to copy file" });
    }
  });

  // Keep the generic bulk endpoint for backward compatibility
  app.post('/api/files/bulk', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { operation, fileIds, options } = req.body;
      
      // Validate operation
      if (!['delete', 'move', 'copy', 'tag'].includes(operation)) {
        return res.status(400).json({ message: 'Invalid operation' });
      }
      
      // Validate fileIds
      if (!Array.isArray(fileIds) || fileIds.length === 0) {
        return res.status(400).json({ message: 'File IDs are required' });
      }
      
      // Validate all file IDs are UUIDs and belong to user
      for (const fileId of fileIds) {
        if (!isValidUUID(fileId)) {
          return res.status(400).json({ message: 'Invalid file ID format' });
        }
        
        const file = await storage.getFile(fileId);
        if (!file || file.userId !== userId) {
          return res.status(403).json({ message: 'Access denied to one or more files' });
        }
      }
      
      const result = await storage.bulkOperation(operation, fileIds, options);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: `BULK_${operation.toUpperCase()}`,
        resource: 'files',
        metadata: { fileIds, options, result },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.json(result);
    } catch (error) {
      const err = error as Error;
      console.error("Error performing bulk operation:", err);
      res.status(500).json({ message: "Failed to perform bulk operation" });
    }
  });
  
  // Specific bulk delete endpoint for frontend compatibility
  app.delete('/api/files/bulk-delete', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { ids } = req.body;
      
      // Validate IDs
      if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: 'IDs are required' });
      }
      
      let deletedFiles = 0;
      let deletedFolders = 0;
      const errors: string[] = [];
      
      // Process each ID - could be file or folder
      for (const id of ids) {
        if (!isValidUUID(id)) {
          errors.push(`Invalid ID format: ${id}`);
          continue;
        }
        
        try {
          // Try to delete as file first
          const file = await storage.getFile(id);
          if (file) {
            if (file.userId !== userId) {
              errors.push(`Access denied to file: ${id}`);
              continue;
            }
            const deleted = await storage.deleteFile(id);
            if (deleted) deletedFiles++;
          } else {
            // Try to delete as folder
            const folders = await storage.getFolders(userId, undefined);
            const folder = folders.find((f: any) => f.id === id);
            if (folder) {
              const deleted = await storage.deleteFolder(id);
              if (deleted) deletedFolders++;
            } else {
              errors.push(`Item not found: ${id}`);
            }
          }
        } catch (err) {
          errors.push(`Failed to delete ${id}: ${(err as Error).message}`);
        }
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'BULK_DELETE',
        resource: 'files',
        metadata: { ids, deletedFiles, deletedFolders, errors },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.json({ 
        success: deletedFiles + deletedFolders,
        failed: errors.length,
        errors: errors.length > 0 ? errors : undefined
      });
    } catch (error) {
      const err = error as Error;
      console.error("Error performing bulk delete:", err);
      res.status(500).json({ message: "Failed to perform bulk delete" });
    }
  });
  
  // Specific bulk move endpoint for frontend compatibility
  app.post('/api/files/bulk-move', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { itemIds, targetFolderId } = req.body;
      
      // Validate itemIds
      if (!Array.isArray(itemIds) || itemIds.length === 0) {
        return res.status(400).json({ message: 'Item IDs are required' });
      }
      
      // Validate targetFolderId if provided
      if (targetFolderId && !isValidUUID(targetFolderId)) {
        return res.status(400).json({ message: 'Invalid target folder ID format' });
      }
      
      let movedFiles = 0;
      let movedFolders = 0;
      const errors: string[] = [];
      
      // Process each item ID - could be file or folder
      for (const itemId of itemIds) {
        if (!isValidUUID(itemId)) {
          errors.push(`Invalid ID format: ${itemId}`);
          continue;
        }
        
        try {
          // Try as file first
          const file = await storage.getFile(itemId);
          if (file) {
            if (file.userId !== userId) {
              errors.push(`Access denied to file: ${itemId}`);
              continue;
            }
            const moved = await storage.moveFileToFolder(itemId, targetFolderId);
            if (moved) movedFiles++;
          } else {
            // Try as folder
            const folders = await storage.getFolders(userId, undefined);
            const folder = folders.find((f: any) => f.id === itemId);
            if (folder) {
              const moved = await storage.moveFolderToFolder(itemId, targetFolderId);
              if (moved) movedFolders++;
            } else {
              errors.push(`Item not found: ${itemId}`);
            }
          }
        } catch (err) {
          errors.push(`Failed to move ${itemId}: ${(err as Error).message}`);
        }
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'BULK_MOVE',
        resource: 'files',
        metadata: { itemIds, targetFolderId, movedFiles, movedFolders, errors },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.json({ 
        success: movedFiles + movedFolders,
        failed: errors.length,
        errors: errors.length > 0 ? errors : undefined
      });
    } catch (error) {
      const err = error as Error;
      console.error("Error performing bulk move:", err);
      res.status(500).json({ message: "Failed to perform bulk move" });
    }
  });

  // Album API routes
  app.get('/api/albums', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const albums = await storage.getAlbums(userId);
      
      res.json(albums);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching albums:", err);
      res.status(500).json({ message: "Failed to fetch albums" });
    }
  });

  app.get('/api/albums/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Album not found' });
      }
      
      const album = await storage.getAlbum(id);
      
      if (!album) {
        return res.status(404).json({ message: 'Album not found' });
      }
      
      // Check ownership
      if (album.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      res.json(album);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching album:", err);
      res.status(500).json({ message: "Failed to fetch album" });
    }
  });

  app.get('/api/albums/:id/files', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Album not found' });
      }
      
      const album = await storage.getAlbum(id);
      
      if (!album) {
        return res.status(404).json({ message: 'Album not found' });
      }
      
      // Check ownership
      if (album.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const albumFiles = await storage.getAlbumFiles(id);
      
      res.json(albumFiles);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching album files:", err);
      res.status(500).json({ message: "Failed to fetch album files" });
    }
  });

  app.post('/api/albums', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const albumData = req.body;
      
      // Validate album data
      if (!albumData.name) {
        return res.status(400).json({ message: 'Album name is required' });
      }
      
      const album = await storage.createAlbum({
        ...albumData,
        userId
      });
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'CREATE_ALBUM',
        resource: 'albums',
        resourceId: album.id,
        metadata: { albumName: album.name },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(201).json(album);
    } catch (error) {
      const err = error as Error;
      console.error("Error creating album:", err);
      res.status(500).json({ message: "Failed to create album" });
    }
  });

  app.patch('/api/albums/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const updates = req.body;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Album not found' });
      }
      
      // Verify ownership
      const album = await storage.getAlbum(id);
      if (!album) {
        return res.status(404).json({ message: 'Album not found' });
      }
      
      if (album.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const updated = await storage.updateAlbum(id, updates);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'UPDATE_ALBUM',
        resource: 'albums',
        resourceId: id,
        metadata: { updates },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.json(updated);
    } catch (error) {
      const err = error as Error;
      console.error("Error updating album:", err);
      res.status(500).json({ message: "Failed to update album" });
    }
  });

  app.delete('/api/albums/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Album not found' });
      }
      
      // Verify ownership
      const album = await storage.getAlbum(id);
      if (!album) {
        return res.status(404).json({ message: 'Album not found' });
      }
      
      if (album.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const deleted = await storage.deleteAlbum(id);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'DELETE_ALBUM',
        resource: 'albums',
        resourceId: id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(204).send();
    } catch (error) {
      const err = error as Error;
      console.error("Error deleting album:", err);
      res.status(500).json({ message: "Failed to delete album" });
    }
  });

  app.post('/api/albums/:id/files', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const { fileId, sortOrder } = req.body;
      
      // Validate UUID format
      if (!isValidUUID(id) || !isValidUUID(fileId)) {
        return res.status(400).json({ message: 'Invalid ID format' });
      }
      
      // Verify album ownership
      const album = await storage.getAlbum(id);
      if (!album) {
        return res.status(404).json({ message: 'Album not found' });
      }
      
      if (album.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      // Verify file ownership
      const file = await storage.getFile(fileId);
      if (!file || file.userId !== userId) {
        return res.status(403).json({ message: 'File not found or access denied' });
      }
      
      const albumFile = await storage.addFileToAlbum(id, fileId, sortOrder);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'ADD_FILE_TO_ALBUM',
        resource: 'albums',
        resourceId: id,
        metadata: { fileId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(201).json(albumFile);
    } catch (error) {
      const err = error as Error;
      console.error("Error adding file to album:", err);
      res.status(500).json({ message: "Failed to add file to album" });
    }
  });

  app.delete('/api/albums/:id/files/:fileId', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id, fileId } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id) || !isValidUUID(fileId)) {
        return res.status(400).json({ message: 'Invalid ID format' });
      }
      
      // Verify album ownership
      const album = await storage.getAlbum(id);
      if (!album) {
        return res.status(404).json({ message: 'Album not found' });
      }
      
      if (album.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const removed = await storage.removeFileFromAlbum(id, fileId);
      
      if (!removed) {
        return res.status(404).json({ message: 'File not found in album' });
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'REMOVE_FILE_FROM_ALBUM',
        resource: 'albums',
        resourceId: id,
        metadata: { fileId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(204).send();
    } catch (error) {
      const err = error as Error;
      console.error("Error removing file from album:", err);
      res.status(500).json({ message: "Failed to remove file from album" });
    }
  });

  // Tag API routes
  app.get('/api/tags', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const tags = await storage.getTags(userId);
      
      res.json(tags);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching tags:", err);
      res.status(500).json({ message: "Failed to fetch tags" });
    }
  });

  app.post('/api/tags', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const tagData = req.body;
      
      // Validate tag data
      if (!tagData.name) {
        return res.status(400).json({ message: 'Tag name is required' });
      }
      
      const tag = await storage.createTag({
        ...tagData,
        userId
      });
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'CREATE_TAG',
        resource: 'tags',
        resourceId: tag.id,
        metadata: { tagName: tag.name },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(201).json(tag);
    } catch (error) {
      const err = error as Error;
      console.error("Error creating tag:", err);
      res.status(500).json({ message: "Failed to create tag" });
    }
  });

  app.patch('/api/tags/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const updates = req.body;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Tag not found' });
      }
      
      // Verify ownership
      const tag = await storage.getTag(id);
      if (!tag) {
        return res.status(404).json({ message: 'Tag not found' });
      }
      
      if (tag.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const updated = await storage.updateTag(id, updates);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'UPDATE_TAG',
        resource: 'tags',
        resourceId: id,
        metadata: { updates },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.json(updated);
    } catch (error) {
      const err = error as Error;
      console.error("Error updating tag:", err);
      res.status(500).json({ message: "Failed to update tag" });
    }
  });

  app.delete('/api/tags/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Tag not found' });
      }
      
      // Verify ownership
      const tag = await storage.getTag(id);
      if (!tag) {
        return res.status(404).json({ message: 'Tag not found' });
      }
      
      if (tag.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const deleted = await storage.deleteTag(id);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'DELETE_TAG',
        resource: 'tags',
        resourceId: id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(204).send();
    } catch (error) {
      const err = error as Error;
      console.error("Error deleting tag:", err);
      res.status(500).json({ message: "Failed to delete tag" });
    }
  });

  app.post('/api/files/:id/tags', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const { tagId } = req.body;
      
      // Validate UUID format
      if (!isValidUUID(id) || !isValidUUID(tagId)) {
        return res.status(400).json({ message: 'Invalid ID format' });
      }
      
      // Verify file ownership
      const file = await storage.getFile(id);
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      if (file.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      // Verify tag ownership
      const tag = await storage.getTag(tagId);
      if (!tag || tag.userId !== userId) {
        return res.status(403).json({ message: 'Tag not found or access denied' });
      }
      
      const fileTag = await storage.tagFile(id, tagId);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'TAG_FILE',
        resource: 'files',
        resourceId: id,
        metadata: { tagId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(201).json(fileTag);
    } catch (error) {
      const err = error as Error;
      console.error("Error tagging file:", err);
      res.status(500).json({ message: "Failed to tag file" });
    }
  });

  app.delete('/api/files/:id/tags/:tagId', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id, tagId } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id) || !isValidUUID(tagId)) {
        return res.status(400).json({ message: 'Invalid ID format' });
      }
      
      // Verify file ownership
      const file = await storage.getFile(id);
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      if (file.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const removed = await storage.untagFile(id, tagId);
      
      if (!removed) {
        return res.status(404).json({ message: 'Tag not found on file' });
      }
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'UNTAG_FILE',
        resource: 'files',
        resourceId: id,
        metadata: { tagId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });
      
      res.status(204).send();
    } catch (error) {
      const err = error as Error;
      console.error("Error removing tag from file:", err);
      res.status(500).json({ message: "Failed to remove tag from file" });
    }
  });

  app.get('/api/files/:id/tags', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      // Verify file ownership
      const file = await storage.getFile(id);
      if (!file) {
        return res.status(404).json({ message: 'File not found' });
      }
      
      if (file.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const tags = await storage.getFileTags(id);
      
      res.json(tags);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching file tags:", err);
      res.status(500).json({ message: "Failed to fetch file tags" });
    }
  });

  app.get('/api/tags/:id/files', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      
      // Validate UUID format
      if (!isValidUUID(id)) {
        return res.status(404).json({ message: 'Tag not found' });
      }
      
      // Verify tag ownership
      const tag = await storage.getTag(id);
      if (!tag) {
        return res.status(404).json({ message: 'Tag not found' });
      }
      
      if (tag.userId !== userId) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const files = await storage.getFilesByTag(id, userId);
      
      res.json(files);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching files by tag:", err);
      res.status(500).json({ message: "Failed to fetch files by tag" });
    }
  });

  // Documents routes
  app.get('/api/documents', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { search, type, category, sortBy = 'updatedAt', sortOrder = 'desc' } = req.query;
      
      // Fetch files that are documents (PDFs, Word docs, spreadsheets, etc.)
      const documentMimeTypes = [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'text/plain',
        'text/markdown',
        'text/csv',
        'application/json',
        'application/xml',
        'text/xml'
      ];
      
      const result = await storage.getFiles({
        userId,
        search: search as string
      });
      
      // Filter for document types
      const documents = result.files.filter((file: any) => {
        const mimeType = file.mimeType?.toLowerCase() || '';
        const ext = file.filename?.split('.').pop()?.toLowerCase() || '';
        
        // Check by MIME type
        if (documentMimeTypes.some(mime => mimeType.includes(mime))) {
          return true;
        }
        
        // Check by extension
        const documentExtensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'md', 'csv', 'json', 'xml', 'log', 'rtf', 'odt', 'ods', 'odp'];
        if (documentExtensions.includes(ext)) {
          return true;
        }
        
        return false;
      });
      
      // Map the fields to match the frontend expectations
      const mappedDocuments = documents.map((file: any) => ({
        id: file.id,
        name: file.filename || file.originalName || 'Untitled',
        type: file.fileType || 'document',
        size: file.fileSize || 0,
        mimeType: file.mimeType,
        createdAt: file.createdAt,
        updatedAt: file.updatedAt,
        category: file.category,
        tags: file.tags
      }));
      
      res.json(mappedDocuments);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching documents:", err);
      res.status(500).json({ message: "Failed to fetch documents" });
    }
  });

  app.get('/api/document-categories', isAuthenticated, async (req: any, res) => {
    try {
      // For now, return empty array as documents don't have separate categories
      // They can use tags or folders instead
      res.json([]);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching document categories:", err);
      res.status(500).json({ message: "Failed to fetch document categories" });
    }
  });

  // Statistics route
  app.get('/api/stats', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      
      // Admin gets global stats, users get their own stats
      const stats = await storage.getMediaStats(user?.role === 'admin' ? undefined : userId);
      res.json(stats);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching stats:", err);
      res.status(500).json({ message: "Failed to fetch statistics" });
    }
  });

  // Category statistics route
  app.get('/api/stats/categories', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      
      // Admin gets global category stats, users get their own category stats
      const categoryStats = await storage.getCategoryStats(user?.role === 'admin' ? undefined : userId);
      res.json(categoryStats);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching category stats:", err);
      res.status(500).json({ message: "Failed to fetch category statistics" });
    }
  });

  // Vault authentication route
  app.post('/api/vault/authenticate', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { passphrase } = req.body;

      if (!passphrase) {
        return res.status(400).json({ message: 'Passphrase is required' });
      }

      const user = await storage.getUser(userId);
      if (!user?.vaultPassphrase) {
        return res.status(404).json({ message: 'No vault configured for this user' });
      }

      // Verify passphrase
      const isValid = cryptoService.verifyPassword(passphrase, user.vaultPassphrase);
      
      // Log activity
      await storage.logActivity({
        userId,
        action: isValid ? 'VAULT_ACCESS_SUCCESS' : 'VAULT_ACCESS_FAILED',
        resource: 'vault',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      if (!isValid) {
        return res.status(401).json({ message: 'Invalid vault passphrase' });
      }

      // Generate temporary access token and store raw passphrase securely
      const accessToken = cryptoService.generateUUID();
      const expiresAt = Date.now() + 30 * 60 * 1000; // 30 minutes
      
      // Store raw passphrase with token for encryption/decryption operations
      vaultTokenStore.set(accessToken, {
        userId,
        passphrase, // Store raw passphrase, not the hash!
        expiresAt
      });
      
      res.json({ 
        success: true, 
        accessToken,
        expiresAt: new Date(expiresAt)
      });
    } catch (error) {
      const err = error as Error;
      console.error("Error authenticating vault access:", err);
      res.status(500).json({ message: "Failed to authenticate vault access" });
    }
  });

  // Set vault passphrase
  app.post('/api/vault/setup', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { passphrase } = req.body;

      if (!passphrase || passphrase.length < 8) {
        return res.status(400).json({ message: 'Passphrase must be at least 8 characters long' });
      }

      const hashedPassphrase = cryptoService.hashPassword(passphrase);
      await storage.upsertUser({ id: userId, vaultPassphrase: hashedPassphrase });
      
      // Log activity
      await storage.logActivity({
        userId,
        action: 'VAULT_SETUP',
        resource: 'vault',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
      });

      res.json({ success: true });
    } catch (error) {
      const err = error as Error;
      console.error("Error setting up vault:", err);
      res.status(500).json({ message: "Failed to setup vault" });
    }
  });

  // Activity logs route - for users and admins
  app.get('/api/activity', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { 
        limit = '50',
        offset = '0',
        search,
        action,
        targetUserId,
        dateFrom,
        dateTo,
        adminView = 'false'
      } = req.query;

      // Check if user is admin
      const user = await storage.getUser(userId);
      const isAdmin = user?.role === 'admin';

      // If adminView requested but user is not admin, return only their logs
      const viewAsAdmin = adminView === 'true' && isAdmin;

      const result = await storage.getActivityLogs(
        viewAsAdmin ? undefined : userId,
        {
          limit: parseInt(limit as string),
          offset: parseInt(offset as string),
          search: search as string,
          action: action as string,
          targetUserId: targetUserId as string,
          dateFrom: dateFrom as string,
          dateTo: dateTo as string,
        }
      );

      res.json(result);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching activity logs:", err);
      res.status(500).json({ message: "Failed to fetch activity logs" });
    }
  });

  // Playlist routes
  app.post('/api/playlists', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { name, description, isPublic } = req.body;
      
      if (!name || name.trim().length === 0) {
        return res.status(400).json({ message: 'Playlist name is required' });
      }
      
      const playlist = await storage.createPlaylist({
        userId,
        name: name.trim(),
        description: description?.trim(),
        coverImage: null,
        isPublic: isPublic || false,
      });
      
      res.json(playlist);
    } catch (error) {
      const err = error as Error;
      console.error("Error creating playlist:", err);
      res.status(500).json({ message: "Failed to create playlist" });
    }
  });

  app.get('/api/playlists', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const playlists = await storage.getPlaylists(userId);
      res.json(playlists);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching playlists:", err);
      res.status(500).json({ message: "Failed to fetch playlists" });
    }
  });

  app.get('/api/playlists/:id', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.claims.sub;
      
      const playlist = await storage.getPlaylist(id);
      if (!playlist) {
        return res.status(404).json({ message: 'Playlist not found' });
      }
      
      // Check if user has access to playlist
      if (playlist.userId !== userId && !playlist.isPublic) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      res.json(playlist);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching playlist:", err);
      res.status(500).json({ message: "Failed to fetch playlist" });
    }
  });

  app.get('/api/playlists/:id/tracks', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.claims.sub;
      
      const playlist = await storage.getPlaylist(id);
      if (!playlist) {
        return res.status(404).json({ message: 'Playlist not found' });
      }
      
      // Check if user has access to playlist
      if (playlist.userId !== userId && !playlist.isPublic) {
        return res.status(403).json({ message: 'Access denied' });
      }
      
      const result = await storage.getPlaylistTracks(id);
      res.json(result);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching playlist tracks:", err);
      res.status(500).json({ message: "Failed to fetch playlist tracks" });
    }
  });

  app.put('/api/playlists/:id', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.claims.sub;
      const updates = req.body;
      
      const playlist = await storage.getPlaylist(id);
      if (!playlist) {
        return res.status(404).json({ message: 'Playlist not found' });
      }
      
      // Check ownership
      if (playlist.userId !== userId) {
        return res.status(403).json({ message: 'Only the owner can update this playlist' });
      }
      
      const updated = await storage.updatePlaylist(id, updates);
      res.json(updated);
    } catch (error) {
      const err = error as Error;
      console.error("Error updating playlist:", err);
      res.status(500).json({ message: "Failed to update playlist" });
    }
  });

  app.delete('/api/playlists/:id', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.claims.sub;
      
      const playlist = await storage.getPlaylist(id);
      if (!playlist) {
        return res.status(404).json({ message: 'Playlist not found' });
      }
      
      // Check ownership
      if (playlist.userId !== userId) {
        return res.status(403).json({ message: 'Only the owner can delete this playlist' });
      }
      
      await storage.deletePlaylist(id);
      res.json({ success: true });
    } catch (error) {
      const err = error as Error;
      console.error("Error deleting playlist:", err);
      res.status(500).json({ message: "Failed to delete playlist" });
    }
  });

  app.post('/api/playlists/:id/tracks', isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.claims.sub;
      const { fileId, position } = req.body;
      
      if (!fileId) {
        return res.status(400).json({ message: 'File ID is required' });
      }
      
      const playlist = await storage.getPlaylist(id);
      if (!playlist) {
        return res.status(404).json({ message: 'Playlist not found' });
      }
      
      // Check ownership
      if (playlist.userId !== userId) {
        return res.status(403).json({ message: 'Only the owner can add tracks to this playlist' });
      }
      
      const track = await storage.addTrackToPlaylist(id, fileId, position, userId);
      res.json(track);
    } catch (error) {
      const err = error as Error;
      console.error("Error adding track to playlist:", err);
      res.status(500).json({ message: "Failed to add track to playlist" });
    }
  });

  app.delete('/api/playlists/:id/tracks/:fileId', isAuthenticated, async (req: any, res) => {
    try {
      const { id, fileId } = req.params;
      const userId = req.user.claims.sub;
      
      const playlist = await storage.getPlaylist(id);
      if (!playlist) {
        return res.status(404).json({ message: 'Playlist not found' });
      }
      
      // Check ownership
      if (playlist.userId !== userId) {
        return res.status(403).json({ message: 'Only the owner can remove tracks from this playlist' });
      }
      
      await storage.removeTrackFromPlaylist(id, fileId);
      res.json({ success: true });
    } catch (error) {
      const err = error as Error;
      console.error("Error removing track from playlist:", err);
      res.status(500).json({ message: "Failed to remove track from playlist" });
    }
  });

  app.put('/api/playlists/:id/tracks/:trackId/position', isAuthenticated, async (req: any, res) => {
    try {
      const { id, trackId } = req.params;
      const userId = req.user.claims.sub;
      const { position } = req.body;
      
      if (typeof position !== 'number') {
        return res.status(400).json({ message: 'Position must be a number' });
      }
      
      const playlist = await storage.getPlaylist(id);
      if (!playlist) {
        return res.status(404).json({ message: 'Playlist not found' });
      }
      
      // Check ownership
      if (playlist.userId !== userId) {
        return res.status(403).json({ message: 'Only the owner can reorder tracks in this playlist' });
      }
      
      await storage.reorderPlaylistTracks(id, trackId, position);
      res.json({ success: true });
    } catch (error) {
      const err = error as Error;
      console.error("Error reordering playlist tracks:", err);
      res.status(500).json({ message: "Failed to reorder playlist tracks" });
    }
  });

  // Play history routes
  app.post('/api/play-history', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { fileId, playlistId, duration, completed } = req.body;
      
      if (!fileId) {
        return res.status(400).json({ message: 'File ID is required' });
      }
      
      const history = await storage.recordPlay({
        userId,
        fileId,
        playlistId,
        duration,
        completed: completed || false,
      });
      
      res.json(history);
    } catch (error) {
      const err = error as Error;
      console.error("Error recording play history:", err);
      res.status(500).json({ message: "Failed to record play history" });
    }
  });

  app.get('/api/recently-played', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const limit = parseInt(req.query.limit as string) || 20;
      
      const files = await storage.getRecentlyPlayed(userId, limit);
      res.json(files);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching recently played:", err);
      res.status(500).json({ message: "Failed to fetch recently played" });
    }
  });

  app.get('/api/most-played', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const limit = parseInt(req.query.limit as string) || 20;
      
      const files = await storage.getMostPlayed(userId, limit);
      res.json(files);
    } catch (error) {
      const err = error as Error;
      console.error("Error fetching most played:", err);
      res.status(500).json({ message: "Failed to fetch most played" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
