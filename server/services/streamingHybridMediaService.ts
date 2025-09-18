import { MediaFile, InsertFile } from "@shared/schema";
import { storage } from "../storage";
import { chunkedEncryptedFilesystemService } from "./chunkedEncryptedFilesystem";
import { mediaService } from "./mediaService";
import * as crypto from 'crypto';
import * as fs from 'fs';
import { promises as fsPromises } from 'fs';
import * as path from 'path';

export interface StreamingMediaUploadOptions {
  generateThumbnail?: boolean;
  thumbnailSize?: number;
  thumbnailFormats?: ('jpeg' | 'webp' | 'avif')[];
  encryptContent?: boolean;
  encryptionKey?: string;
  vaultPassphrase?: string;
  categoryId?: string;
  useChunkedThreshold?: number; // Files larger than this use chunked encryption
}

export interface StreamingMediaResult {
  id: string;
  sha256Hash: string;
  isDuplicate: boolean;
  thumbnailGenerated: boolean;
  storageType: 'database' | 'chunked';
}

export class StreamingHybridMediaService {
  private readonly chunkedThreshold: number;
  
  constructor() {
    // Files larger than 10MB use chunked encryption for streaming support
    this.chunkedThreshold = 10 * 1024 * 1024;
  }

  /**
   * Process and store media file using streaming approach for large files
   */
  async processAndStoreFile(
    tempFilePath: string, // Use temp file path instead of buffer
    originalName: string,
    mimeType: string,
    uploadedBy: string,
    options: StreamingMediaUploadOptions = {}
  ): Promise<StreamingMediaResult> {
    const {
      generateThumbnail = true,
      thumbnailSize = 300,
      thumbnailFormats = ['jpeg', 'webp'],
      encryptContent = false,
      encryptionKey,
      vaultPassphrase,
      categoryId,
      useChunkedThreshold = this.chunkedThreshold
    } = options;

    // Get file size without loading into memory
    const fileStats = await fsPromises.stat(tempFilePath);
    const fileSize = fileStats.size;

    // Calculate SHA-256 hash from file stream
    const sha256Hash = await this.calculateFileHash(tempFilePath);

    // Check for duplicates (scoped to user)
    // Check files table first (new)
    const existingFile = await storage.getFileByHash(sha256Hash, uploadedBy);
    if (existingFile) {
      // Clean up temp file
      await fsPromises.unlink(tempFilePath).catch(() => {});
      
      return {
        id: existingFile.id,
        sha256Hash,
        isDuplicate: true,
        thumbnailGenerated: false,
        storageType: existingFile.storageType as 'database' | 'chunked',
      };
    }
    
    // Also check media_files for backward compatibility
    const existingMediaFile = await storage.getMediaFileByHash(sha256Hash, uploadedBy);
    if (existingMediaFile) {
      // Clean up temp file
      await fsPromises.unlink(tempFilePath).catch(() => {});
      
      return {
        id: existingMediaFile.id,
        sha256Hash,
        isDuplicate: true,
        thumbnailGenerated: false,
        storageType: existingMediaFile.storageType as 'database' | 'chunked',
      };
    }

    const useChunked = fileSize > useChunkedThreshold;

    if (useChunked) {
      return await this.storeUsingChunkedEncryption(
        tempFilePath,
        originalName,
        mimeType,
        uploadedBy,
        sha256Hash,
        fileSize,
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
      // For smaller files, still use database storage with buffer approach
      const fileBuffer = await fsPromises.readFile(tempFilePath);
      
      // Clean up temp file after reading
      await fsPromises.unlink(tempFilePath).catch(() => {});
      
      const result = await mediaService.processFile(
        fileBuffer,
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
   * Calculate SHA-256 hash from file stream
   */
  private async calculateFileHash(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      const stream = fs.createReadStream(filePath);
      
      stream.on('data', (data) => {
        hash.update(data);
      });
      
      stream.on('end', () => {
        resolve(hash.digest('hex'));
      });
      
      stream.on('error', reject);
    });
  }

  /**
   * Store large files using chunked encryption
   */
  private async storeUsingChunkedEncryption(
    tempFilePath: string,
    originalName: string,
    mimeType: string,
    uploadedBy: string,
    sha256Hash: string,
    fileSize: number,
    options: Omit<StreamingMediaUploadOptions, 'useChunkedThreshold'>
  ): Promise<StreamingMediaResult> {
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

    // Generate thumbnails using file path instead of buffer
    if (mimeType.startsWith('image/') && generateThumbnail) {
      try {
        const Sharp = require('sharp');
        const image = Sharp(tempFilePath);
        const metadata = await image.metadata();
        width = metadata.width;
        height = metadata.height;

        // Generate thumbnails from file path
        const thumbnails = await this.generateThumbnailsFromPath(tempFilePath, thumbnailSize, thumbnailFormats);
        thumbnailData = thumbnails.jpeg;
        thumbnailWebp = thumbnails.webp;
        thumbnailAvif = thumbnails.avif;
      } catch (error) {
        console.warn('Image processing failed for chunked storage:', error);
      }
    } else if (mimeType.startsWith('video/') && generateThumbnail) {
      // Process video metadata and thumbnails from file path
      const ffmpegAvailable = await mediaService.checkFFmpegAvailability();
      if (ffmpegAvailable) {
        try {
          const videoResult = await this.processVideoFromPath(tempFilePath, generateThumbnail, thumbnailSize, thumbnailFormats);
          duration = videoResult.duration;
          width = videoResult.width;
          height = videoResult.height;
          thumbnailData = videoResult.thumbnail?.jpeg;
          thumbnailWebp = videoResult.thumbnail?.webp;
          thumbnailAvif = videoResult.thumbnail?.avif;
        } catch (error) {
          console.warn('Video processing failed for chunked storage:', error);
        }
      }
    }

    // Store encrypted file using chunked encryption
    const chunkedResult = await chunkedEncryptedFilesystemService.storeEncryptedFile(
      tempFilePath,
      originalName,
      uploadedBy
    );

    // Clean up temp file after successful encryption
    await fsPromises.unlink(tempFilePath).catch(() => {});

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
      filename: `chunked_${chunkedResult.metadata.encryptedFilename}`,
      originalName,
      mimeType,
      fileType,
      fileSize,
      sha256Hash,
      binaryData: null, // No binary data for chunked storage
      storageType: 'chunked',
      filePath: chunkedResult.filePath,
      width,
      height,
      duration,
      thumbnailData: thumbnailData || thumbnailWebp || thumbnailAvif, // Use any available thumbnail
      isEncrypted: true, // Always true for chunked storage as files are always encrypted
      encryptionKey: options.encryptionKey,
      folderId: null,
      userId: uploadedBy,
      tags: [],
    };
    
    const newFile = await storage.createFile(fileData);
    
    // Also create in media_files for backward compatibility
    try {
      await storage.createMediaFile({
        filename: `chunked_${chunkedResult.metadata.encryptedFilename}`,
        originalName,
        mimeType,
        fileSize,
        sha256Hash,
        binaryData: null,
        storageType: 'chunked',
        filePath: chunkedResult.filePath,
        fileEncryptionKey: chunkedResult.encryptionKey,
        filenameKeyWrapped: chunkedResult.metadata.filenameKeyWrapped,
        encryptedFilename: chunkedResult.metadata.encryptedFilename,
        chunkMetadata: chunkedResult.metadata,
        width,
        height,
        duration,
        thumbnailData,
        thumbnailWebp,
        thumbnailAvif,
        isEncrypted: true,
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
      storageType: 'chunked',
    };
  }

  /**
   * Generate thumbnails from file path
   */
  private async generateThumbnailsFromPath(
    filePath: string,
    size: number,
    formats: ('jpeg' | 'webp' | 'avif')[]
  ): Promise<{ jpeg?: Buffer; webp?: Buffer; avif?: Buffer }> {
    const Sharp = require('sharp');
    const thumbnails: { jpeg?: Buffer; webp?: Buffer; avif?: Buffer } = {};

    const baseImage = Sharp(filePath)
      .resize(size, size, { 
        fit: 'cover',
        withoutEnlargement: true 
      });

    // Generate JPEG thumbnail (primary format)
    if (formats.includes('jpeg')) {
      try {
        thumbnails.jpeg = await baseImage
          .jpeg({ quality: 85 })
          .toBuffer();
      } catch (error) {
        console.warn('JPEG thumbnail generation failed:', error);
      }
    }

    // Generate WebP thumbnail
    if (formats.includes('webp')) {
      try {
        thumbnails.webp = await baseImage
          .webp({ quality: 80, effort: 4 })
          .toBuffer();
      } catch (error) {
        console.warn('WebP thumbnail generation failed:', error);
      }
    }

    // Generate AVIF thumbnail
    if (formats.includes('avif')) {
      try {
        thumbnails.avif = await baseImage
          .avif({ quality: 60, effort: 4 })
          .toBuffer();
      } catch (error) {
        console.warn('AVIF thumbnail generation failed:', error);
      }
    }

    return thumbnails;
  }

  /**
   * Process video from file path
   */
  private async processVideoFromPath(
    filePath: string,
    generateThumbnail: boolean,
    thumbnailSize: number,
    thumbnailFormats: ('jpeg' | 'webp' | 'avif')[]
  ): Promise<{
    duration?: number;
    width?: number;
    height?: number;
    thumbnail?: { jpeg?: Buffer; webp?: Buffer; avif?: Buffer };
  }> {
    const ffmpeg = require('fluent-ffmpeg');
    
    return new Promise((resolve, reject) => {
      let duration: number | undefined;
      let width: number | undefined;
      let height: number | undefined;

      // Get video metadata
      ffmpeg.ffprobe(filePath, async (err: any, metadata: any) => {
        if (err) {
          reject(err);
          return;
        }

        // Extract duration and dimensions
        if (metadata.format && metadata.format.duration) {
          duration = Math.floor(metadata.format.duration);
        }

        if (metadata.streams) {
          const videoStream = metadata.streams.find((stream: any) => stream.codec_type === 'video');
          if (videoStream) {
            width = videoStream.width;
            height = videoStream.height;
          }
        }

        let thumbnail: { jpeg?: Buffer; webp?: Buffer; avif?: Buffer } | undefined;

        if (generateThumbnail) {
          try {
            // Generate video thumbnail at 10% of duration
            const thumbnailTime = duration ? Math.max(1, Math.floor(duration * 0.1)) : 1;
            
            // Create temp thumbnail path
            const tempThumbnailPath = path.join(path.dirname(filePath), `thumb_${Date.now()}.jpg`);
            
            ffmpeg(filePath)
              .screenshots({
                timestamps: [thumbnailTime],
                filename: path.basename(tempThumbnailPath),
                folder: path.dirname(tempThumbnailPath),
                size: `${thumbnailSize}x${thumbnailSize}`
              })
              .on('end', async () => {
                try {
                  // Generate multiple formats from the extracted frame
                  thumbnail = await this.generateThumbnailsFromPath(tempThumbnailPath, thumbnailSize, thumbnailFormats);
                  
                  // Clean up temp thumbnail
                  await fsPromises.unlink(tempThumbnailPath).catch(() => {});
                  
                  resolve({ duration, width, height, thumbnail });
                } catch (error) {
                  console.warn('Thumbnail format conversion failed:', error);
                  resolve({ duration, width, height });
                }
              })
              .on('error', (error: any) => {
                console.warn('Thumbnail generation failed:', error);
                resolve({ duration, width, height });
              });
          } catch (error) {
            console.warn('Video thumbnail processing failed:', error);
            resolve({ duration, width, height });
          }
        } else {
          resolve({ duration, width, height });
        }
      });
    });
  }

  /**
   * Get media content from hybrid storage with streaming support
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

    if (mediaFile.storageType === 'chunked') {
      // For chunked files, this should only be used for small range requests
      // Large files should use streaming endpoints
      if (mediaFile.fileSize > 100 * 1024 * 1024) { // 100MB limit
        throw new Error('File too large for full content loading - use streaming endpoint');
      }

      if (!mediaFile.filePath || !mediaFile.fileEncryptionKey) {
        throw new Error('Chunked storage metadata missing');
      }

      const buffer = await chunkedEncryptedFilesystemService.getDecryptedFileChunk(
        mediaFile.filePath,
        mediaFile.fileEncryptionKey,
        requestingUserId,
        0,
        mediaFile.fileSize - 1
      );

      // Get original filename
      const metadata = await chunkedEncryptedFilesystemService.getFileMetadata(
        mediaFile.filePath,
        mediaFile.filenameKeyWrapped!,
        requestingUserId
      );

      return {
        buffer,
        mimeType: mediaFile.mimeType,
        filename: metadata.originalFilename,
      };
    } else {
      // Use existing mediaService for database storage
      return await mediaService.getMediaContent(id, requestingUserId, decrypt, vaultPassphrase);
    }
  }

  /**
   * Get media chunk from hybrid storage with true streaming for large files
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

    if (mediaFile.storageType === 'chunked') {
      // Get chunk from chunked encrypted filesystem
      if (!mediaFile.filePath || !mediaFile.fileEncryptionKey) {
        throw new Error('Chunked storage metadata missing');
      }

      const buffer = await chunkedEncryptedFilesystemService.getDecryptedFileChunk(
        mediaFile.filePath,
        mediaFile.fileEncryptionKey,
        requestingUserId,
        start,
        end
      );

      // Get original filename
      const metadata = await chunkedEncryptedFilesystemService.getFileMetadata(
        mediaFile.filePath,
        mediaFile.filenameKeyWrapped!,
        requestingUserId
      );

      return {
        buffer,
        mimeType: mediaFile.mimeType,
        filename: metadata.originalFilename,
        totalSize: mediaFile.fileSize,
      };
    } else {
      // Use existing mediaService for database storage
      return await mediaService.getMediaChunk(id, requestingUserId, start, end, decrypt, vaultPassphrase);
    }
  }

  /**
   * Check if file should use chunked storage
   */
  shouldUseChunkedStorage(fileSize: number, mimeType: string): boolean {
    // Always use chunked storage for large files
    if (fileSize > this.chunkedThreshold) {
      return true;
    }
    
    // Could add additional logic here (e.g., always use chunked for videos)
    return false;
  }
}

export const streamingHybridMediaService = new StreamingHybridMediaService();