import { MediaFile, InsertFile } from "@shared/schema";
import { storage } from "../storage";
import { encryptedFilesystemService } from "./encryptedFilesystemService";
import { mediaService } from "./mediaService";
import * as crypto from 'crypto';

export interface HybridMediaUploadOptions {
  generateThumbnail?: boolean;
  thumbnailSize?: number;
  thumbnailFormats?: ('jpeg' | 'webp' | 'avif')[];
  encryptContent?: boolean;
  encryptionKey?: string;
  vaultPassphrase?: string;
  categoryId?: string;
  useFilesystemThreshold?: number; // Files larger than this go to filesystem
}

export interface HybridMediaResult {
  id: string;
  sha256Hash: string;
  isDuplicate: boolean;
  thumbnailGenerated: boolean;
  storageType: 'database' | 'filesystem';
}

export class HybridMediaService {
  private readonly filesystemThreshold: number;
  
  constructor() {
    // Files larger than 50MB go to encrypted filesystem storage
    this.filesystemThreshold = 50 * 1024 * 1024;
  }

  /**
   * Process and store media file using hybrid storage approach
   */
  async processAndStoreFile(
    buffer: Buffer,
    originalName: string,
    mimeType: string,
    uploadedBy: string,
    options: HybridMediaUploadOptions = {}
  ): Promise<HybridMediaResult> {
    const {
      generateThumbnail = true,
      thumbnailSize = 300,
      thumbnailFormats = ['jpeg', 'webp'],
      encryptContent = false,
      encryptionKey,
      vaultPassphrase,
      categoryId,
      useFilesystemThreshold = this.filesystemThreshold
    } = options;

    // Generate SHA-256 hash for duplicate detection
    const sha256Hash = crypto.createHash('sha256').update(buffer).digest('hex');

    // Check for duplicates (scoped to user)
    // Check files table first (new)
    const existingFile = await storage.getFileByHash(sha256Hash, uploadedBy);
    if (existingFile) {
      return {
        id: existingFile.id,
        sha256Hash,
        isDuplicate: true,
        thumbnailGenerated: false,
        storageType: existingFile.storageType as 'database' | 'filesystem',
      };
    }
    
    // Also check media_files for backward compatibility
    const existingMediaFile = await storage.getMediaFileByHash(sha256Hash, uploadedBy);
    if (existingMediaFile) {
      return {
        id: existingMediaFile.id,
        sha256Hash,
        isDuplicate: true,
        thumbnailGenerated: false,
        storageType: existingMediaFile.storageType as 'database' | 'filesystem',
      };
    }

    const fileSize = buffer.length;
    const useFilesystem = fileSize > useFilesystemThreshold;

    if (useFilesystem) {
      return await this.storeInFilesystem(
        buffer,
        originalName,
        mimeType,
        uploadedBy,
        sha256Hash,
        {
          generateThumbnail,
          thumbnailSize,
          thumbnailFormats,
          encryptContent,
          encryptionKey,
          vaultPassphrase,
          categoryId,
        }
      );
    } else {
      // Use existing mediaService for database storage
      const result = await mediaService.processFile(
        buffer,
        originalName,
        mimeType,
        uploadedBy,
        {
          generateThumbnail,
          thumbnailSize,
          thumbnailFormats,
          encryptContent,
          encryptionKey,
          vaultPassphrase,
          categoryId,
        }
      );

      return {
        ...result,
        storageType: 'database',
      };
    }
  }

  /**
   * Store large files in encrypted filesystem
   */
  private async storeInFilesystem(
    buffer: Buffer,
    originalName: string,
    mimeType: string,
    uploadedBy: string,
    sha256Hash: string,
    options: Omit<HybridMediaUploadOptions, 'useFilesystemThreshold'>
  ): Promise<HybridMediaResult> {
    const {
      generateThumbnail = true,
      thumbnailSize = 300,
      thumbnailFormats = ['jpeg', 'webp'],
      encryptContent = false,
      categoryId,
    } = options;

    let thumbnailData: Buffer | undefined;
    let thumbnailWebp: Buffer | undefined;
    let thumbnailAvif: Buffer | undefined;
    let width: number | undefined;
    let height: number | undefined;
    let duration: number | undefined;

    // Generate thumbnails using existing mediaService logic
    if (mimeType.startsWith('image/') && generateThumbnail) {
      const Sharp = require('sharp');
      const image = Sharp(buffer);
      const metadata = await image.metadata();
      width = metadata.width;
      height = metadata.height;

      // Generate thumbnails
      const thumbnails = await mediaService.generateThumbnails(buffer, thumbnailSize, thumbnailFormats);
      thumbnailData = thumbnails.jpeg;
      thumbnailWebp = thumbnails.webp;
      thumbnailAvif = thumbnails.avif;
    } else if (mimeType.startsWith('video/') && generateThumbnail) {
      // Process video metadata and thumbnails
      const ffmpegAvailable = await mediaService.checkFFmpegAvailability();
      if (ffmpegAvailable) {
        try {
          const videoResult = await mediaService.processVideo(buffer, generateThumbnail, thumbnailSize, thumbnailFormats);
          duration = videoResult.duration;
          width = videoResult.width;
          height = videoResult.height;
          thumbnailData = videoResult.thumbnail?.jpeg;
          thumbnailWebp = videoResult.thumbnail?.webp;
          thumbnailAvif = videoResult.thumbnail?.avif;
        } catch (error) {
          console.warn('Video processing failed for filesystem storage:', error);
        }
      }
    }

    // Store encrypted file on filesystem
    const encryptedFileResult = await encryptedFilesystemService.storeEncryptedFile(
      buffer,
      originalName,
      uploadedBy
    );

    // Determine file type based on MIME type
    let fileType: string | undefined;
    if (mimeType.startsWith('image/')) {
      fileType = 'image';
    } else if (mimeType.startsWith('video/')) {
      fileType = 'video';
    } else if (mimeType.startsWith('audio/')) {
      fileType = 'audio';
    } else if (mimeType.startsWith('application/pdf') || mimeType.startsWith('text/') || 
               mimeType.includes('document') || mimeType.includes('sheet') || 
               mimeType.includes('presentation')) {
      fileType = 'document';
    } else if (mimeType.includes('zip') || mimeType.includes('tar') || mimeType.includes('rar') ||
               mimeType.includes('7z') || mimeType.includes('gz')) {
      fileType = 'archive';
    } else {
      fileType = 'other';
    }

    // Store metadata in files table
    const fileData: InsertFile = {
      filename: `fs_${encryptedFileResult.filePath}`,
      originalName,
      mimeType,
      fileType,
      fileSize: buffer.length,
      sha256Hash,
      binaryData: null, // No binary data for filesystem storage
      storageType: 'filesystem',
      filePath: encryptedFileResult.filePath,
      width,
      height,
      duration,
      thumbnailData: thumbnailData || thumbnailWebp || thumbnailAvif,  // Use any available thumbnail
      isEncrypted: encryptContent,
      encryptionKey: options.encryptionKey,
      folderId: null,
      userId: uploadedBy,
      tags: [],
    };
    
    const newFile = await storage.createFile(fileData);
    
    // Also create in media_files for backward compatibility
    try {
      await storage.createMediaFile({
        filename: `fs_${encryptedFileResult.filePath}`,
        originalName,
        mimeType,
        fileSize: buffer.length,
        sha256Hash,
        binaryData: null,
        storageType: 'filesystem',
        filePath: encryptedFileResult.filePath,
        fileEncryptionKey: encryptedFileResult.encryptionKey,
        width,
        height,
        duration,
        thumbnailData,
        thumbnailWebp,
        thumbnailAvif,
        isEncrypted: encryptContent,
        encryptionKey: options.encryptionKey,
        categoryId,
        uploadedBy,
        tags: [],
      });
    } catch (legacyError) {
      console.log('Could not create legacy media file, continuing with new file system');
    }

    return {
      id: newFile.id,
      sha256Hash,
      isDuplicate: false,
      thumbnailGenerated: !!thumbnailData,
      storageType: 'filesystem',
    };
  }

  /**
   * Get media content from hybrid storage
   */
  async getMediaContent(
    id: string,
    requestingUserId: string,
    decrypt = false,
    vaultPassphrase?: string
  ): Promise<{
    buffer: Buffer;
    mimeType: string;
    filename: string;
  } | null> {
    const mediaFile = await storage.getMediaFile(id);
    if (!mediaFile) return null;

    // Security check
    if (mediaFile.uploadedBy !== requestingUserId) {
      throw new Error('Access denied: You do not own this media file');
    }

    if (mediaFile.storageType === 'filesystem') {
      // Get from encrypted filesystem
      if (!mediaFile.filePath || !mediaFile.fileEncryptionKey) {
        throw new Error('Filesystem storage metadata missing');
      }

      const buffer = await encryptedFilesystemService.getDecryptedFileChunk(
        mediaFile.filePath,
        mediaFile.fileEncryptionKey,
        requestingUserId,
        0,
        Number.MAX_SAFE_INTEGER
      );

      return {
        buffer,
        mimeType: mediaFile.mimeType,
        filename: mediaFile.originalName,
      };
    } else {
      // Use existing mediaService for database storage
      return await mediaService.getMediaContent(id, requestingUserId, decrypt, vaultPassphrase);
    }
  }

  /**
   * Get media chunk from hybrid storage
   */
  async getMediaChunk(
    id: string,
    requestingUserId: string,
    start: number,
    end: number,
    decrypt = false,
    vaultPassphrase?: string
  ): Promise<{
    buffer: Buffer;
    mimeType: string;
    filename: string;
    totalSize: number;
  } | null> {
    const mediaFile = await storage.getMediaFile(id);
    if (!mediaFile) return null;

    // Security check
    if (mediaFile.uploadedBy !== requestingUserId) {
      throw new Error('Access denied: You do not own this media file');
    }

    if (mediaFile.storageType === 'filesystem') {
      // Get chunk from encrypted filesystem
      if (!mediaFile.filePath || !mediaFile.fileEncryptionKey) {
        throw new Error('Filesystem storage metadata missing');
      }

      const buffer = await encryptedFilesystemService.getDecryptedFileChunk(
        mediaFile.filePath,
        mediaFile.fileEncryptionKey,
        requestingUserId,
        start,
        end
      );

      return {
        buffer,
        mimeType: mediaFile.mimeType,
        filename: mediaFile.originalName,
        totalSize: mediaFile.fileSize,
      };
    } else {
      // Use existing mediaService for database storage
      const result = await mediaService.getMediaChunk(id, requestingUserId, start, end, decrypt, vaultPassphrase);
      return result;
    }
  }

  /**
   * Check if file should use filesystem storage
   */
  shouldUseFilesystem(fileSize: number, mimeType: string): boolean {
    // Always use filesystem for large files
    if (fileSize > this.filesystemThreshold) {
      return true;
    }
    
    // Could add additional logic here (e.g., always use filesystem for videos)
    return false;
  }
}

export const hybridMediaService = new HybridMediaService();