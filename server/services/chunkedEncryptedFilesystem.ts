import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { promises as fsPromises } from 'fs';
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';
import { Transform } from 'stream';

/**
 * Chunked Encrypted Filesystem Service
 * 
 * Handles large file storage (1GB+) with streaming encryption/decryption.
 * Files are broken into 2MB chunks, each encrypted independently with AES-256-GCM.
 * Supports range requests for video streaming without loading entire files into memory.
 */

export interface ChunkedFileMetadata {
  originalFilename: string;
  encryptedFilename: string;
  chunkSize: number;
  totalChunks: number;
  totalSize: number;
  sha256Hash: string;
  encryptionKeyWrapped: string; // Wrapped with master key
  filenameKeyWrapped: string;   // Separate key for filename encryption
  chunks: ChunkMetadata[];
}

export interface ChunkMetadata {
  index: number;
  iv: string;           // Base64 encoded IV for this chunk
  authTag: string;      // Base64 encoded auth tag for this chunk
  size: number;         // Encrypted chunk size
  originalSize: number; // Original chunk size before encryption
}

export interface StorageResult {
  filePath: string;
  encryptionKey: string;
  metadata: ChunkedFileMetadata;
}

export class ChunkedEncryptedFilesystemService {
  private readonly baseDir: string;
  private readonly chunkSize: number;
  private readonly maxRangeWindow: number; // Maximum range size to prevent OOM
  private masterKey: Buffer;

  constructor() {
    this.baseDir = path.join(process.cwd(), 'encrypted_media');
    this.chunkSize = 2 * 1024 * 1024; // 2MB chunks for optimal streaming
    this.maxRangeWindow = 8 * 1024 * 1024; // 8MB max range to prevent OOM attacks

    // Initialize master key
    this.masterKey = this.initializeMasterKey();
    
    // Ensure storage directory exists
    this.ensureStorageDirectory();
  }

  private initializeMasterKey(): Buffer {
    const envKey = process.env.FILESYSTEM_MASTER_KEY;
    if (envKey) {
      return Buffer.from(envKey, 'hex');
    }
    
    // CRITICAL: In production, master key is mandatory to prevent data loss
    const nodeEnv = process.env.NODE_ENV || 'development';
    if (nodeEnv === 'production') {
      throw new Error(
        'FILESYSTEM_MASTER_KEY environment variable is required in production. ' +
        'Without this key, all encrypted files will become permanently inaccessible after restart. ' +
        'Generate a secure key with: openssl rand -hex 32'
      );
    }
    
    // Generate session-only master key for development only
    console.warn(
      '⚠️  DEVELOPMENT MODE: No FILESYSTEM_MASTER_KEY found, using session-only master key. ' +
      'Files encrypted with this key will be LOST on restart. ' +
      'Set FILESYSTEM_MASTER_KEY environment variable for persistent encryption.'
    );
    return crypto.randomBytes(32);
  }

  private async ensureStorageDirectory(): Promise<void> {
    try {
      await fsPromises.mkdir(this.baseDir, { recursive: true });
    } catch (error) {
      console.error('Failed to create storage directory:', error);
      throw new Error('Storage initialization failed');
    }
  }

  /**
   * Encrypt a filename using AES-256-GCM
   */
  private encryptFilename(filename: string, key: Buffer): string {
    const iv = crypto.randomBytes(12); // GCM standard IV size
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(filename, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    // Return: iv + authTag + encrypted (all hex encoded)
    return iv.toString('hex') + authTag.toString('hex') + encrypted;
  }

  /**
   * Decrypt a filename using AES-256-GCM
   */
  private decryptFilename(encryptedFilename: string, key: Buffer): string {
    const ivHex = encryptedFilename.slice(0, 24);    // 12 bytes = 24 hex chars
    const tagHex = encryptedFilename.slice(24, 56);   // 16 bytes = 32 hex chars
    const encrypted = encryptedFilename.slice(56);
    
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(tagHex, 'hex');
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Wrap encryption key with master key
   */
  private wrapKey(key: Buffer, userId: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);
    cipher.setAAD(Buffer.from(userId, 'utf8'));
    
    let wrapped = cipher.update(key);
    wrapped = Buffer.concat([wrapped, cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    // Return: iv + authTag + wrapped (all base64)
    const result = Buffer.concat([iv, authTag, wrapped]);
    return result.toString('base64');
  }

  /**
   * Unwrap encryption key with master key
   */
  private unwrapKey(wrappedKey: string, userId: string): Buffer {
    const combined = Buffer.from(wrappedKey, 'base64');
    const iv = combined.subarray(0, 12);
    const authTag = combined.subarray(12, 28);
    const wrapped = combined.subarray(28);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterKey, iv);
    decipher.setAAD(Buffer.from(userId, 'utf8'));
    decipher.setAuthTag(authTag);
    
    let key = decipher.update(wrapped);
    key = Buffer.concat([key, decipher.final()]);
    
    return key;
  }

  /**
   * Store file using chunked encryption with streaming
   */
  async storeEncryptedFile(
    filePath: string, 
    originalFilename: string, 
    userId: string
  ): Promise<StorageResult> {
    // Generate encryption keys
    const fileKey = crypto.randomBytes(32);
    const filenameKey = crypto.randomBytes(32);
    
    // Encrypt filename
    const encryptedFilename = this.encryptFilename(originalFilename, filenameKey);
    
    // Create storage path
    const storageId = crypto.randomBytes(16).toString('hex');
    const storagePath = path.join(this.baseDir, userId, storageId);
    
    await fsPromises.mkdir(path.dirname(storagePath), { recursive: true });
    
    // Calculate SHA-256 hash while streaming
    const hasher = crypto.createHash('sha256');
    let totalSize = 0;
    let chunkIndex = 0;
    const chunks: ChunkMetadata[] = [];
    
    const fileStream = createReadStream(filePath, { highWaterMark: this.chunkSize });
    
    // Process file in chunks
    for await (const chunk of fileStream) {
      totalSize += chunk.length;
      hasher.update(chunk);
      
      // Encrypt this chunk
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', fileKey, iv);
      cipher.setAAD(Buffer.from(`${userId}:${chunkIndex}`, 'utf8'));
      
      let encryptedChunk = cipher.update(chunk);
      encryptedChunk = Buffer.concat([encryptedChunk, cipher.final()]);
      const authTag = cipher.getAuthTag();
      
      // Write encrypted chunk to disk
      const chunkPath = `${storagePath}.chunk.${chunkIndex}`;
      await fsPromises.writeFile(chunkPath, encryptedChunk);
      
      // Store chunk metadata
      chunks.push({
        index: chunkIndex,
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        size: encryptedChunk.length,
        originalSize: chunk.length
      });
      
      chunkIndex++;
    }
    
    const sha256Hash = hasher.digest('hex');
    
    // Create metadata
    const metadata: ChunkedFileMetadata = {
      originalFilename,
      encryptedFilename,
      chunkSize: this.chunkSize,
      totalChunks: chunks.length,
      totalSize,
      sha256Hash,
      encryptionKeyWrapped: this.wrapKey(fileKey, userId),
      filenameKeyWrapped: this.wrapKey(filenameKey, userId),
      chunks
    };
    
    // Write metadata file
    await fsPromises.writeFile(
      `${storagePath}.metadata.json`, 
      JSON.stringify(metadata, null, 2)
    );
    
    return {
      filePath: path.relative(this.baseDir, storagePath),
      encryptionKey: this.wrapKey(fileKey, userId),
      metadata
    };
  }

  /**
   * Get decrypted file chunk for range requests with bounded window protection
   */
  async getDecryptedFileChunk(
    filePath: string,
    wrappedKey: string,
    userId: string,
    start: number,
    end: number
  ): Promise<Buffer> {
    const fullPath = path.join(this.baseDir, filePath);
    const metadataPath = `${fullPath}.metadata.json`;
    
    // Load metadata
    const metadataContent = await fsPromises.readFile(metadataPath, 'utf8');
    const metadata: ChunkedFileMetadata = JSON.parse(metadataContent);
    
    // SECURITY: Validate range bounds to prevent OOM attacks
    const totalSize = metadata.totalSize;
    const clampedStart = Math.max(0, Math.min(start, totalSize - 1));
    const clampedEnd = Math.max(clampedStart, Math.min(end, totalSize - 1));
    
    // CRITICAL: Enforce maximum range window to prevent Buffer exhaustion
    const requestedSize = clampedEnd - clampedStart + 1;
    let actualEnd = clampedEnd;
    
    if (requestedSize > this.maxRangeWindow) {
      actualEnd = clampedStart + this.maxRangeWindow - 1;
      console.warn(
        `Range request clamped for safety: ${clampedStart}-${clampedEnd} (${requestedSize} bytes) ` +
        `reduced to ${clampedStart}-${actualEnd} (${this.maxRangeWindow} bytes) for user ${userId}`
      );
    }
    
    // Unwrap encryption key
    const fileKey = this.unwrapKey(wrappedKey, userId);
    
    // Calculate which chunks we need with bounds-checked values
    const startChunk = Math.floor(clampedStart / this.chunkSize);
    const endChunk = Math.floor(actualEnd / this.chunkSize);
    
    const resultChunks: Buffer[] = [];
    let currentPos = 0;
    
    for (let chunkIndex = startChunk; chunkIndex <= endChunk; chunkIndex++) {
      if (chunkIndex >= metadata.chunks.length) break;
      
      const chunkMeta = metadata.chunks[chunkIndex];
      const chunkPath = `${fullPath}.chunk.${chunkIndex}`;
      
      // Read and decrypt chunk
      const encryptedChunk = await fsPromises.readFile(chunkPath);
      
      const iv = Buffer.from(chunkMeta.iv, 'base64');
      const authTag = Buffer.from(chunkMeta.authTag, 'base64');
      
      const decipher = crypto.createDecipheriv('aes-256-gcm', fileKey, iv);
      decipher.setAAD(Buffer.from(`${userId}:${chunkIndex}`, 'utf8'));
      decipher.setAuthTag(authTag);
      
      let decryptedChunk = decipher.update(encryptedChunk);
      decryptedChunk = Buffer.concat([decryptedChunk, decipher.final()]);
      
      // Calculate slice boundaries for this chunk using bounds-checked values
      const chunkStart = chunkIndex * this.chunkSize;
      const chunkEnd = chunkStart + decryptedChunk.length - 1;
      
      let sliceStart = 0;
      let sliceEnd = decryptedChunk.length;
      
      if (clampedStart > chunkStart) {
        sliceStart = clampedStart - chunkStart;
      }
      
      if (actualEnd < chunkEnd) {
        sliceEnd = actualEnd - chunkStart + 1;
      }
      
      const slicedChunk = decryptedChunk.subarray(sliceStart, sliceEnd);
      resultChunks.push(slicedChunk);
    }
    
    return Buffer.concat(resultChunks);
  }

  /**
   * Create streaming decryption transform for large files
   */
  createDecryptedStream(
    filePath: string,
    wrappedKey: string,
    userId: string,
    start = 0,
    end?: number
  ): Promise<NodeJS.ReadableStream> {
    return new Promise(async (resolve, reject) => {
      try {
        const fullPath = path.join(this.baseDir, filePath);
        const metadataPath = `${fullPath}.metadata.json`;
        
        // Load metadata
        const metadataContent = await fsPromises.readFile(metadataPath, 'utf8');
        const metadata: ChunkedFileMetadata = JSON.parse(metadataContent);
        
        // Unwrap encryption key
        const fileKey = this.unwrapKey(wrappedKey, userId);
        
        const totalSize = metadata.totalSize;
        const actualEnd = end ?? totalSize - 1;
        
        // Calculate chunk range
        const startChunk = Math.floor(start / this.chunkSize);
        const endChunk = Math.floor(actualEnd / this.chunkSize);
        
        let currentChunk = startChunk;
        let bytesRead = 0;
        let streamStarted = false;
        
        const transform = new Transform({
          transform(chunk, encoding, callback) {
            callback(null, chunk);
          }
        });
        
        const processNextChunk = async () => {
          if (currentChunk > endChunk || currentChunk >= metadata.chunks.length) {
            transform.end();
            return;
          }
          
          try {
            const chunkMeta = metadata.chunks[currentChunk];
            const chunkPath = `${fullPath}.chunk.${currentChunk}`;
            
            // Read and decrypt chunk
            const encryptedChunk = await fsPromises.readFile(chunkPath);
            
            const iv = Buffer.from(chunkMeta.iv, 'base64');
            const authTag = Buffer.from(chunkMeta.authTag, 'base64');
            
            const decipher = crypto.createDecipheriv('aes-256-gcm', fileKey, iv);
            decipher.setAAD(Buffer.from(`${userId}:${currentChunk}`, 'utf8'));
            decipher.setAuthTag(authTag);
            
            let decryptedChunk = decipher.update(encryptedChunk);
            decryptedChunk = Buffer.concat([decryptedChunk, decipher.final()]);
            
            // Calculate slice boundaries
            const chunkStart = currentChunk * this.chunkSize;
            const chunkEnd = chunkStart + decryptedChunk.length - 1;
            
            let sliceStart = 0;
            let sliceEnd = decryptedChunk.length;
            
            if (start > chunkStart) {
              sliceStart = start - chunkStart;
            }
            
            if (actualEnd < chunkEnd) {
              sliceEnd = actualEnd - chunkStart + 1;
            }
            
            const slicedChunk = decryptedChunk.subarray(sliceStart, sliceEnd);
            
            if (slicedChunk.length > 0) {
              transform.write(slicedChunk);
            }
            
            currentChunk++;
            
            // Continue with next chunk
            setImmediate(processNextChunk);
            
          } catch (error) {
            transform.destroy(error as Error);
          }
        };
        
        // Start processing
        resolve(transform);
        setImmediate(processNextChunk);
        
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Delete encrypted file and all its chunks
   */
  async deleteEncryptedFile(filePath: string): Promise<void> {
    const fullPath = path.join(this.baseDir, filePath);
    const metadataPath = `${fullPath}.metadata.json`;
    
    try {
      // Load metadata to know how many chunks to delete
      const metadataContent = await fsPromises.readFile(metadataPath, 'utf8');
      const metadata: ChunkedFileMetadata = JSON.parse(metadataContent);
      
      // Delete all chunks
      for (let i = 0; i < metadata.totalChunks; i++) {
        const chunkPath = `${fullPath}.chunk.${i}`;
        try {
          await fsPromises.unlink(chunkPath);
        } catch (error) {
          console.warn(`Failed to delete chunk ${i}:`, error);
        }
      }
      
      // Delete metadata
      await fsPromises.unlink(metadataPath);
      
    } catch (error) {
      console.error(`Failed to delete encrypted file ${filePath}:`, error);
      throw error;
    }
  }

  /**
   * Get file metadata without decrypting content
   */
  async getFileMetadata(filePath: string, filenameKeyWrapped: string, userId: string): Promise<{
    originalFilename: string;
    totalSize: number;
    sha256Hash: string;
  }> {
    const fullPath = path.join(this.baseDir, filePath);
    const metadataPath = `${fullPath}.metadata.json`;
    
    const metadataContent = await fsPromises.readFile(metadataPath, 'utf8');
    const metadata: ChunkedFileMetadata = JSON.parse(metadataContent);
    
    // Decrypt filename
    const filenameKey = this.unwrapKey(filenameKeyWrapped, userId);
    const originalFilename = this.decryptFilename(metadata.encryptedFilename, filenameKey);
    
    return {
      originalFilename,
      totalSize: metadata.totalSize,
      sha256Hash: metadata.sha256Hash
    };
  }
}

export const chunkedEncryptedFilesystemService = new ChunkedEncryptedFilesystemService();