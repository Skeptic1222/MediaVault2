import sharp from 'sharp';
import crypto from 'crypto';
import ffmpeg from 'fluent-ffmpeg';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { spawn } from 'child_process';
import { storage } from '../storage';
import { cryptoService } from './cryptoService';
import type { InsertMediaFile, InsertFile } from '@shared/schema';
import { FILE_SIZE_LIMITS, createFileSizeError, formatFileSize } from '@shared/constants';

export interface MediaProcessingOptions {
  generateThumbnail?: boolean;
  thumbnailSize?: number;
  thumbnailFormats?: ('jpeg' | 'webp' | 'avif')[];
  encryptContent?: boolean;
  encryptionKey?: string;
  vaultPassphrase?: string;
  categoryId?: string;
}

export interface ThumbnailData {
  webp?: Buffer;
  avif?: Buffer;
  jpeg: Buffer; // Always generate JPEG as fallback
}

export interface MediaUploadResult {
  id: string;
  sha256Hash: string;
  isDuplicate: boolean;
  thumbnailGenerated: boolean;
}

export class MediaService {
  private ffmpegAvailable: boolean | null = null;

  public async checkFFmpegAvailability(): Promise<boolean> {
    if (this.ffmpegAvailable !== null) {
      return this.ffmpegAvailable;
    }

    try {
      // Test both ffmpeg and ffprobe binaries
      await Promise.all([
        this.testBinary('ffmpeg'),
        this.testBinary('ffprobe')
      ]);
      
      console.log('FFmpeg and FFprobe are available and working');
      this.ffmpegAvailable = true;
      return true;
    } catch (error) {
      console.warn('FFmpeg/FFprobe not available:', error);
      this.ffmpegAvailable = false;
      return false;
    }
  }

  private async testBinary(binaryName: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const process = spawn(binaryName, ['-version'], {
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let outputReceived = false;

      process.stdout.on('data', () => {
        outputReceived = true;
      });

      process.stderr.on('data', () => {
        outputReceived = true;
      });

      process.on('close', (code) => {
        if (code === 0 && outputReceived) {
          resolve();
        } else {
          reject(new Error(`${binaryName} process exited with code ${code} or no output received`));
        }
      });

      process.on('error', (error) => {
        reject(new Error(`Failed to spawn ${binaryName}: ${error.message}`));
      });

      // Timeout after 5 seconds
      setTimeout(() => {
        process.kill();
        reject(new Error(`${binaryName} version check timed out`));
      }, 5000);
    });
  }
  async processFile(
    buffer: Buffer,
    originalName: string,
    mimeType: string,
    uploadedBy: string,
    options: MediaProcessingOptions = {}
  ): Promise<MediaUploadResult> {
    const {
      generateThumbnail = true,
      thumbnailSize = 300,
      thumbnailFormats = ['jpeg', 'webp'],
      encryptContent = false,
      encryptionKey,
      vaultPassphrase,
      categoryId
    } = options;

    // CRITICAL: Prevent database storage of oversized files to avoid Node.js string length errors
    const fileSize = buffer.length;
    
    if (fileSize > FILE_SIZE_LIMITS.MAX_DATABASE_UPLOAD) {
      throw new Error(
        createFileSizeError(fileSize, FILE_SIZE_LIMITS.MAX_DATABASE_UPLOAD, "database storage") + ". " +
        "Large files should use filesystem or chunked storage to prevent system crashes."
      );
    }

    // Generate SHA-256 hash for duplicate detection
    const sha256Hash = crypto.createHash('sha256').update(buffer).digest('hex');

    // Check for duplicates (scoped to user to prevent cross-tenant access)
    // First check files table (new)
    const existingFile = await storage.getFileByHash(sha256Hash, uploadedBy);
    if (existingFile) {
      return {
        id: existingFile.id,
        sha256Hash,
        isDuplicate: true,
        thumbnailGenerated: false,
      };
    }
    
    // Also check old media_files table for backward compatibility
    const existingMediaFile = await storage.getMediaFileByHash(sha256Hash, uploadedBy);
    if (existingMediaFile) {
      return {
        id: existingMediaFile.id,
        sha256Hash,
        isDuplicate: true,
        thumbnailGenerated: false,
      };
    }

    let processedBuffer = buffer;
    let thumbnailData: Buffer | undefined;
    let thumbnailWebp: Buffer | undefined;
    let thumbnailAvif: Buffer | undefined;
    let width: number | undefined;
    let height: number | undefined;
    let duration: number | undefined;

    // Process based on media type
    if (mimeType.startsWith('image/')) {
      const image = sharp(buffer);
      const metadata = await image.metadata();
      width = metadata.width;
      height = metadata.height;

      // Generate enhanced thumbnails with multiple formats
      if (generateThumbnail) {
        const thumbnails = await this.generateThumbnails(buffer, thumbnailSize, thumbnailFormats);
        thumbnailData = thumbnails.jpeg; // Primary thumbnail (backward compatibility)
        thumbnailWebp = thumbnails.webp; // WebP thumbnail for better compression
        thumbnailAvif = thumbnails.avif; // AVIF thumbnail for modern browsers
      }
    } else if (mimeType.startsWith('video/')) {
      // Process video using ffmpeg with graceful fallback
      const ffmpegAvailable = await this.checkFFmpegAvailability();
      if (ffmpegAvailable) {
        try {
          const videoResult = await this.processVideo(buffer, generateThumbnail, thumbnailSize, thumbnailFormats);
          duration = videoResult.duration;
          width = videoResult.width;
          height = videoResult.height;
          thumbnailData = videoResult.thumbnail?.jpeg;
          thumbnailWebp = videoResult.thumbnail?.webp;
          thumbnailAvif = videoResult.thumbnail?.avif;
        } catch (error) {
          console.warn('Video processing failed, proceeding without metadata:', error);
          // Fallback: proceed without video metadata or thumbnail
        }
      } else {
        console.warn('FFmpeg not available, proceeding without video processing');
        // Fallback: proceed without video metadata or thumbnail
      }
    }

    // Encrypt content if requested
    let encryptedKey: string | undefined;
    if (encryptContent && encryptionKey && vaultPassphrase) {
      // Validate that vault is set up
      const user = await storage.getUser(uploadedBy);
      if (!user?.vaultPassphrase) {
        throw new Error('User vault must be set up before encrypting content');
      }

      processedBuffer = cryptoService.encryptBuffer(buffer, encryptionKey);
      
      // CRITICAL FIX: Use the raw vault passphrase (not the stored hash) for key wrapping
      // This fixes the severe security flaw where the hash was used for encryption
      encryptedKey = cryptoService.encryptString(encryptionKey, vaultPassphrase);
      
      if (thumbnailData) {
        thumbnailData = cryptoService.encryptBuffer(thumbnailData, encryptionKey);
      }
      if (thumbnailWebp) {
        thumbnailWebp = cryptoService.encryptBuffer(thumbnailWebp, encryptionKey);
      }
      if (thumbnailAvif) {
        thumbnailAvif = cryptoService.encryptBuffer(thumbnailAvif, encryptionKey);
      }
    } else if (encryptContent && !vaultPassphrase) {
      throw new Error('Vault passphrase is required for encrypted content');
    }

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

    // Create file record for the new files table
    const fileData: InsertFile = {
      filename: this.generateUniqueFilename(originalName),
      originalName,
      mimeType,
      fileType,
      fileSize: buffer.length,
      sha256Hash,
      binaryData: processedBuffer,
      storageType: 'database',
      width,
      height,
      duration,
      thumbnailData: thumbnailData || thumbnailWebp || thumbnailAvif, // Use any available thumbnail
      isEncrypted: encryptContent,
      encryptionKey: encryptedKey,
      folderId: null, // No folder for backward compatibility
      userId: uploadedBy,
      tags: [],
    };

    // Also create media file record for backward compatibility
    const mediaFileData: Omit<InsertMediaFile, 'uploadedBy'> & { uploadedBy: string } = {
      filename: fileData.filename,
      originalName,
      mimeType,
      fileSize: buffer.length,
      sha256Hash,
      binaryData: processedBuffer,
      width,
      height,
      duration,
      thumbnailData,
      thumbnailWebp,
      thumbnailAvif,
      isEncrypted: encryptContent,
      encryptionKey: encryptedKey,
      categoryId,
      uploadedBy,
    };

    let newFile;
    try {
      // Create in files table (primary storage)
      newFile = await storage.createFile(fileData);
      
      // Also create in media_files table for backward compatibility
      // We'll ignore errors here as it's just for legacy support
      try {
        await storage.createMediaFile(mediaFileData);
      } catch (legacyError) {
        console.log('Could not create legacy media file, continuing with new file system');
      }
    } catch (error) {
      const err = error as Error;
      // Handle race condition where another concurrent upload created the same file
      if (err.message.includes('unique_violation') || err.message.includes('duplicate key') || err.message.includes('UNIQUE constraint')) {
        // Re-fetch the existing file by hash
        const existingFile = await storage.getFileByHash(sha256Hash, uploadedBy);
        if (existingFile) {
          return {
            id: existingFile.id,
            sha256Hash,
            isDuplicate: true,
            thumbnailGenerated: false,
          };
        }
      }
      // Re-throw other errors
      throw error;
    }

    return {
      id: newFile.id,
      sha256Hash,
      isDuplicate: false,
      thumbnailGenerated: !!thumbnailData,
    };
  }

  async getMediaContent(id: string, requestingUserId: string, decrypt = false, vaultPassphrase?: string): Promise<{
    buffer: Buffer;
    mimeType: string;
    filename: string;
  } | null> {
    const mediaFile = await storage.getMediaFile(id);
    if (!mediaFile) return null;

    // SECURITY: Verify ownership to prevent IDOR/BOLA attacks
    if (mediaFile.uploadedBy !== requestingUserId) {
      throw new Error('Access denied: You do not own this media file');
    }

    // CRITICAL: Prevent memory crashes from oversized database files
    // Files over 100MB stored in database can cause Node.js string length errors
    if (mediaFile.storageType === 'database' && mediaFile.fileSize > FILE_SIZE_LIMITS.MAX_DATABASE_FILE) {
      throw new Error(`Database file too large (${formatFileSize(mediaFile.fileSize)} > ${formatFileSize(FILE_SIZE_LIMITS.MAX_DATABASE_FILE)}) - exceeds Node.js memory limits. File should be migrated to filesystem storage.`);
    }

    // Use different thresholds for encrypted vs unencrypted files
    // Encrypted files up to 50MB can use full-content loading (streaming decryption not supported)
    // Unencrypted files over 5MB should use streaming to prevent buffer overflow
    const sizeLimit = mediaFile.isEncrypted ? FILE_SIZE_LIMITS.MAX_ENCRYPTED_STREAMING : FILE_SIZE_LIMITS.MAX_UNENCRYPTED_FULL_LOAD;
    if (mediaFile.fileSize > sizeLimit) {
      throw new Error('File too large - use streaming endpoint instead');
    }

    // Get binary data separately to avoid buffer overflow
    const binaryData = await storage.getMediaFileBinaryData(id);
    if (!binaryData) return null;

    if (!binaryData.binaryData) {
      // File is stored on filesystem, not in database
      throw new Error('File stored on filesystem - use filesystem service instead');
    }
    
    let buffer = Buffer.from(binaryData.binaryData);

    // Decrypt if necessary
    if (mediaFile.isEncrypted && decrypt && vaultPassphrase) {
      try {
        // Unwrap the encryption key using the vault passphrase
        if (!mediaFile.encryptionKey) {
          throw new Error('Encrypted content missing encryption key');
        }
        
        const unwrappedKey = cryptoService.decryptString(mediaFile.encryptionKey, vaultPassphrase);
        buffer = cryptoService.decryptBuffer(buffer, unwrappedKey);
      } catch (error) {
        throw new Error('Invalid vault passphrase or corrupted encryption data');
      }
    } else if (mediaFile.isEncrypted && !decrypt) {
      throw new Error('Content is encrypted and requires decryption');
    }

    return {
      buffer,
      mimeType: mediaFile.mimeType,
      filename: mediaFile.originalName,
    };
  }

  async getMediaMetadata(id: string, requestingUserId: string): Promise<{
    mimeType: string;
    filename: string;
    fileSize: number;
    isEncrypted: boolean;
  } | null> {
    const mediaFile = await storage.getMediaFile(id);
    if (!mediaFile) return null;

    // SECURITY: Verify ownership to prevent IDOR/BOLA attacks
    if (mediaFile.uploadedBy !== requestingUserId) {
      throw new Error('Access denied: You do not own this media file');
    }

    return {
      mimeType: mediaFile.mimeType,
      filename: mediaFile.originalName,
      fileSize: mediaFile.fileSize,
      isEncrypted: mediaFile.isEncrypted || false,
    };
  }

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

    // SECURITY: Verify ownership to prevent IDOR/BOLA attacks
    if (mediaFile.uploadedBy !== requestingUserId) {
      throw new Error('Access denied: You do not own this media file');
    }

    // CRITICAL: Prevent memory crashes from oversized database files
    const MAX_DATABASE_FILE_SIZE = 100 * 1024 * 1024; // 100MB hard limit for database files
    if (mediaFile.storageType === 'database' && mediaFile.fileSize > MAX_DATABASE_FILE_SIZE) {
      throw new Error('Database file too large - exceeds Node.js memory limits. File should be migrated to filesystem storage.');
    }

    // Check encryption status
    if (mediaFile.isEncrypted && !decrypt) {
      throw new Error('Content is encrypted and requires decryption');
    }

    // For encrypted files, currently not supported with streaming
    // TODO: Implement offset-capable decryption (AES-CTR with known IV)
    if (mediaFile.isEncrypted && decrypt) {
      throw new Error('Streaming decryption not yet supported for large encrypted files');
    }

    // Get the chunk from storage
    const chunkResult = await storage.getMediaFileChunk(id, start, end);
    if (!chunkResult) return null;

    return {
      buffer: chunkResult.chunkData,
      mimeType: chunkResult.mimeType,
      filename: mediaFile.originalName,
      totalSize: chunkResult.totalSize,
    };
  }

  async getThumbnail(id: string, requestingUserId: string, decrypt = false, vaultPassphrase?: string): Promise<Buffer | null> {
    // Legacy method - returns JPEG thumbnail for backward compatibility
    const result = await this.getThumbnailWithFormat(id, requestingUserId, { format: 'jpeg', decrypt, vaultPassphrase });
    return result?.buffer || null;
  }

  async getThumbnailWithFormat(
    id: string, 
    requestingUserId: string, 
    options: {
      format?: 'auto' | 'jpeg' | 'webp' | 'avif';
      acceptHeader?: string;
      decrypt?: boolean;
      vaultPassphrase?: string;
    } = {}
  ): Promise<{ buffer: Buffer; mimeType: string; format: string } | null> {
    const { format = 'auto', acceptHeader, decrypt = false, vaultPassphrase } = options;
    
    const mediaFile = await storage.getMediaFile(id);
    if (!mediaFile) return null;

    // SECURITY: Verify ownership to prevent IDOR/BOLA attacks
    if (mediaFile.uploadedBy !== requestingUserId) {
      throw new Error('Access denied: You do not own this media file');
    }

    // Get all thumbnail data
    const thumbnailData = await storage.getMediaFileThumbnail(id);
    if (!thumbnailData) return null;

    // Content negotiation: determine best format to serve
    let selectedFormat: string = 'jpeg';
    let selectedBuffer: Buffer | null = null;
    let selectedMimeType: string = 'image/jpeg';

    if (format === 'auto') {
      // Auto-negotiation based on Accept header
      if (acceptHeader?.includes('image/avif') && thumbnailData.thumbnailAvif) {
        selectedFormat = 'avif';
        selectedBuffer = Buffer.from(thumbnailData.thumbnailAvif);
        selectedMimeType = 'image/avif';
      } else if (acceptHeader?.includes('image/webp') && thumbnailData.thumbnailWebp) {
        selectedFormat = 'webp';
        selectedBuffer = Buffer.from(thumbnailData.thumbnailWebp);
        selectedMimeType = 'image/webp';
      } else if (thumbnailData.thumbnailData) {
        selectedFormat = 'jpeg';
        selectedBuffer = Buffer.from(thumbnailData.thumbnailData);
        selectedMimeType = 'image/jpeg';
      }
    } else {
      // Specific format requested
      switch (format) {
        case 'avif':
          if (thumbnailData.thumbnailAvif) {
            selectedFormat = 'avif';
            selectedBuffer = Buffer.from(thumbnailData.thumbnailAvif);
            selectedMimeType = 'image/avif';
          }
          break;
        case 'webp':
          if (thumbnailData.thumbnailWebp) {
            selectedFormat = 'webp';
            selectedBuffer = Buffer.from(thumbnailData.thumbnailWebp);
            selectedMimeType = 'image/webp';
          }
          break;
        case 'jpeg':
        default:
          if (thumbnailData.thumbnailData) {
            selectedFormat = 'jpeg';
            selectedBuffer = Buffer.from(thumbnailData.thumbnailData);
            selectedMimeType = 'image/jpeg';
          }
          break;
      }
    }

    // Fallback to JPEG if selected format not available
    if (!selectedBuffer && thumbnailData.thumbnailData) {
      selectedFormat = 'jpeg';
      selectedBuffer = Buffer.from(thumbnailData.thumbnailData);
      selectedMimeType = 'image/jpeg';
    }

    if (!selectedBuffer) return null;

    // Handle encryption
    if (mediaFile.isEncrypted && decrypt && vaultPassphrase) {
      try {
        if (!mediaFile.encryptionKey) {
          throw new Error('Encrypted content missing encryption key');
        }
        
        const unwrappedKey = cryptoService.decryptString(mediaFile.encryptionKey, vaultPassphrase);
        selectedBuffer = cryptoService.decryptBuffer(selectedBuffer, unwrappedKey);
      } catch (error) {
        throw new Error('Invalid vault passphrase for thumbnail decryption');
      }
    } else if (mediaFile.isEncrypted && !decrypt) {
      // Return placeholder for encrypted content
      const placeholderBuffer = await sharp({
        create: {
          width: 300,
          height: 300,
          channels: 3,
          background: { r: 50, g: 50, b: 50 }
        }
      }).jpeg().toBuffer();
      
      return {
        buffer: placeholderBuffer,
        mimeType: 'image/jpeg',
        format: 'jpeg'
      };
    }

    return {
      buffer: selectedBuffer,
      mimeType: selectedMimeType,
      format: selectedFormat
    };
  }

  async moveToCategory(fileId: string, categoryId: string): Promise<boolean> {
    const updated = await storage.updateMediaFile(fileId, { categoryId });
    return !!updated;
  }

  async addTags(fileId: string, tags: string[]): Promise<boolean> {
    const mediaFile = await storage.getMediaFile(fileId);
    if (!mediaFile) return false;

    const existingTags = mediaFile.tags || [];
    const newTags = Array.from(new Set([...existingTags, ...tags]));
    
    const updated = await storage.updateMediaFile(fileId, { tags: newTags });
    return !!updated;
  }

  async removeTags(fileId: string, tags: string[]): Promise<boolean> {
    const mediaFile = await storage.getMediaFile(fileId);
    if (!mediaFile) return false;

    const existingTags = mediaFile.tags || [];
    const newTags = existingTags.filter(tag => !tags.includes(tag));
    
    const updated = await storage.updateMediaFile(fileId, { tags: newTags });
    return !!updated;
  }

  async toggleFavorite(fileId: string): Promise<boolean> {
    const mediaFile = await storage.getMediaFile(fileId);
    if (!mediaFile) return false;

    const updated = await storage.updateMediaFile(fileId, { 
      isFavorite: !mediaFile.isFavorite 
    });
    return !!updated;
  }

  public async processVideo(
    buffer: Buffer, 
    generateThumbnail: boolean, 
    thumbnailSize: number,
    thumbnailFormats: ('jpeg' | 'webp' | 'avif')[] = ['jpeg', 'webp']
  ): Promise<{
    duration?: number;
    width?: number;
    height?: number;
    thumbnail?: ThumbnailData;
  }> {
    // Create temporary file for ffmpeg processing
    const tempDir = os.tmpdir();
    const tempVideoPath = path.join(tempDir, `video_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.tmp`);
    const tempThumbnailPath = path.join(tempDir, `thumb_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.jpg`);

    try {
      // Write buffer to temporary file
      await fs.writeFile(tempVideoPath, buffer);

      // Extract video metadata and generate thumbnail
      return await new Promise((resolve, reject) => {
        const command = ffmpeg(tempVideoPath);
        
        let duration: number | undefined;
        let width: number | undefined;
        let height: number | undefined;

        // Get video metadata
        command.ffprobe((err, metadata) => {
          if (err) {
            console.error('FFprobe error:', err);
            return reject(err);
          }

          try {
            // Extract duration and dimensions
            const videoStream = metadata.streams.find(stream => stream.codec_type === 'video');
            if (videoStream) {
              // Handle duration parsing with proper fallback for "N/A" values
              let parsedDuration = videoStream.duration ? Number(videoStream.duration) : NaN;
              if (!Number.isFinite(parsedDuration)) {
                // Fallback to format duration if stream duration is invalid
                parsedDuration = metadata.format?.duration ? Number(metadata.format.duration) : NaN;
              }
              duration = Number.isFinite(parsedDuration) ? Math.round(parsedDuration) : undefined;
              
              width = videoStream.width;
              height = videoStream.height;
            }

            if (!generateThumbnail) {
              return resolve({ duration, width, height });
            }

            // Generate thumbnail at 1 second mark
            command
              .seekInput(1) // Seek to 1 second
              .frames(1) // Extract 1 frame
              .size(`${thumbnailSize}x${thumbnailSize}`)
              .aspect('1:1')
              .output(tempThumbnailPath)
              .on('end', async () => {
                try {
                  // Read thumbnail and process with enhanced thumbnail generation
                  const thumbnailBuffer = await fs.readFile(tempThumbnailPath);
                  const processedThumbnail = await this.generateThumbnails(thumbnailBuffer, thumbnailSize, thumbnailFormats);

                  resolve({
                    duration,
                    width,
                    height,
                    thumbnail: processedThumbnail,
                  });
                } catch (thumbnailError) {
                  console.error('Thumbnail processing error:', thumbnailError);
                  resolve({ duration, width, height });
                } finally {
                  // Cleanup thumbnail file
                  try {
                    await fs.unlink(tempThumbnailPath);
                  } catch {}
                }
              })
              .on('error', (thumbnailError) => {
                console.error('FFmpeg thumbnail generation error:', thumbnailError);
                // Return metadata without thumbnail if thumbnail generation fails
                resolve({ duration, width, height });
              })
              .run();
          } catch (metadataError) {
            console.error('Metadata processing error:', metadataError);
            reject(metadataError);
          }
        });
      });
    } catch (error) {
      console.error('Video processing error:', error);
      throw error;
    } finally {
      // Cleanup temporary video file
      try {
        await fs.unlink(tempVideoPath);
      } catch {}
    }
  }

  public async generateThumbnails(
    imageBuffer: Buffer, 
    size: number = 300, 
    formats: ('jpeg' | 'webp' | 'avif')[] = ['jpeg', 'webp']
  ): Promise<ThumbnailData> {
    const baseImage = sharp(imageBuffer)
      .resize(size, size, { 
        fit: 'cover',
        withoutEnlargement: true 
      });

    const thumbnails: Partial<ThumbnailData> = {};

    // Always generate JPEG as fallback
    thumbnails.jpeg = await baseImage
      .jpeg({ quality: 85, mozjpeg: true })
      .toBuffer();

    // Generate WebP if requested
    if (formats.includes('webp')) {
      try {
        thumbnails.webp = await baseImage
          .webp({ quality: 80, effort: 4 })
          .toBuffer();
      } catch (error) {
        console.warn('WebP generation failed, skipping:', error);
      }
    }

    // Generate AVIF if requested
    if (formats.includes('avif')) {
      try {
        thumbnails.avif = await baseImage
          .avif({ quality: 60, effort: 4 })
          .toBuffer();
      } catch (error) {
        console.warn('AVIF generation failed, skipping:', error);
      }
    }

    return thumbnails as ThumbnailData;
  }

  private generateUniqueFilename(originalName: string): string {
    const timestamp = Date.now();
    const random = crypto.randomBytes(8).toString('hex');
    const ext = originalName.split('.').pop();
    return `${timestamp}_${random}.${ext}`;
  }

  async validateHashIntegrity(fileId: string): Promise<boolean> {
    const mediaFile = await storage.getMediaFile(fileId);
    if (!mediaFile) return false;

    // Get binary data separately
    const binaryData = await storage.getMediaFileBinaryData(fileId);
    if (!binaryData) return false;

    if (!binaryData.binaryData) {
      // File is stored on filesystem, not in database
      return false;
    }
    
    const buffer = Buffer.from(binaryData.binaryData);
    const currentHash = crypto.createHash('sha256').update(buffer).digest('hex');
    
    return currentHash === mediaFile.sha256Hash;
  }

  async regenerateThumbnail(fileId: string): Promise<boolean> {
    const mediaFile = await storage.getMediaFile(fileId);
    if (!mediaFile || !mediaFile.mimeType.startsWith('image/')) return false;

    try {
      // Get binary data separately
      const binaryData = await storage.getMediaFileBinaryData(fileId);
      if (!binaryData) return false;

      if (!binaryData.binaryData) {
        // File is stored on filesystem, not in database
        return false;
      }
      
      const buffer = Buffer.from(binaryData.binaryData);
      let imageBuffer = buffer;

      // Decrypt if necessary (would need decryption key)
      if (mediaFile.isEncrypted) {
        throw new Error('Cannot regenerate thumbnail for encrypted content without decryption key');
      }

      const thumbnailData = await sharp(imageBuffer)
        .resize(300, 300, { 
          fit: 'cover',
          withoutEnlargement: true 
        })
        .jpeg({ quality: 85 })
        .toBuffer();

      const updated = await storage.updateMediaFile(fileId, { thumbnailData });
      return !!updated;
    } catch (error) {
      console.error('Error regenerating thumbnail:', error);
      return false;
    }
  }
}

export const mediaService = new MediaService();
