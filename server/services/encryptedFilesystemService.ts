import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';

export interface EncryptedFileResult {
  filePath: string;
  encryptionKey: string;
  fileSize: number;
}

export interface DecryptedStreamResult {
  stream: NodeJS.ReadableStream;
  mimeType: string;
  fileSize: number;
}

export class EncryptedFilesystemService {
  private readonly baseStoragePath: string;
  private readonly masterKey: Buffer;
  
  constructor() {
    // Store encrypted files in a dedicated directory
    this.baseStoragePath = path.join(process.cwd(), 'encrypted_media');
    this.ensureStorageDirectory();
    
    // Initialize master key from environment or generate one
    const masterKeyHex = process.env.FILESYSTEM_MASTER_KEY;
    if (masterKeyHex) {
      this.masterKey = Buffer.from(masterKeyHex, 'hex');
    } else {
      // Generate and store master key for this session
      this.masterKey = crypto.randomBytes(32);
      console.warn('No FILESYSTEM_MASTER_KEY found, using session-only master key. Set FILESYSTEM_MASTER_KEY environment variable for persistent encryption.');
    }
  }

  private async ensureStorageDirectory(): Promise<void> {
    try {
      await fs.access(this.baseStoragePath);
    } catch {
      await fs.mkdir(this.baseStoragePath, { recursive: true });
    }
  }

  /**
   * Wrap (encrypt) a file encryption key for secure database storage
   */
  private wrapFileEncryptionKey(fileKey: Buffer, userId: string): string {
    // Use GCM mode with 12-byte IV for key wrapping
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);
    cipher.setAAD(Buffer.from(userId)); // Bind to user ID
    
    const encryptedKey = Buffer.concat([
      cipher.update(fileKey),
      cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    
    // Store: IV (12 bytes) + encrypted key + auth tag (16 bytes)
    const wrappedKey = Buffer.concat([iv, encryptedKey, authTag]);
    return wrappedKey.toString('base64');
  }

  /**
   * Unwrap (decrypt) a file encryption key from database storage
   */
  private unwrapFileEncryptionKey(wrappedKey: string, userId: string): Buffer {
    const wrappedBuffer = Buffer.from(wrappedKey, 'base64');
    
    // Extract IV (12 bytes), encrypted key, and auth tag (16 bytes)
    const iv = wrappedBuffer.subarray(0, 12);
    const authTag = wrappedBuffer.subarray(wrappedBuffer.length - 16);
    const encryptedKey = wrappedBuffer.subarray(12, wrappedBuffer.length - 16);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterKey, iv);
    decipher.setAAD(Buffer.from(userId));
    decipher.setAuthTag(authTag);
    
    return Buffer.concat([
      decipher.update(encryptedKey),
      decipher.final()
    ]);
  }

  /**
   * Store a buffer as an encrypted file on the filesystem
   */
  async storeEncryptedFile(
    buffer: Buffer,
    originalFilename: string,
    userId: string
  ): Promise<EncryptedFileResult> {
    // Generate unique encryption key for this file
    const encryptionKey = crypto.randomBytes(32);
    
    // Generate unique filename to prevent conflicts and hide original names
    const fileId = crypto.randomUUID();
    const encryptedFilename = `${fileId}.enc`;
    const filePath = path.join(this.baseStoragePath, encryptedFilename);
    
    // Generate IV for GCM mode (12 bytes recommended for GCM)
    const iv = crypto.randomBytes(12);
    
    // Create cipher with proper GCM mode
    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
    cipher.setAAD(Buffer.from(userId)); // Authenticated encryption with user ID
    
    // Encrypt data
    const encryptedContent = Buffer.concat([
      cipher.update(buffer),
      cipher.final()
    ]);
    
    // Get authentication tag after encryption
    const authTag = cipher.getAuthTag();
    
    // Store: IV (12 bytes) + encrypted content + auth tag (16 bytes)
    const encryptedData = Buffer.concat([
      iv,
      encryptedContent,
      authTag
    ]);
    
    // Write encrypted data to filesystem
    await fs.writeFile(filePath, encryptedData);
    
    // Wrap the encryption key for secure database storage
    const wrappedKey = this.wrapFileEncryptionKey(encryptionKey, userId);
    
    return {
      filePath: encryptedFilename, // Store relative path only
      encryptionKey: wrappedKey, // Return wrapped key for secure database storage
      fileSize: buffer.length, // Original unencrypted size
    };
  }

  /**
   * Retrieve and decrypt a file chunk from the filesystem
   */
  async getDecryptedFileChunk(
    filePath: string,
    wrappedEncryptionKey: string,
    userId: string,
    start: number,
    end: number
  ): Promise<Buffer> {
    const fullPath = path.join(this.baseStoragePath, filePath);
    
    // Read the encrypted file
    const encryptedData = await fs.readFile(fullPath);
    
    // Extract IV (12 bytes), encrypted content, and auth tag (16 bytes)
    const iv = encryptedData.subarray(0, 12);
    const authTag = encryptedData.subarray(encryptedData.length - 16);
    const encryptedContent = encryptedData.subarray(12, encryptedData.length - 16);
    
    // Unwrap the encryption key from secure storage
    const keyBuffer = this.unwrapFileEncryptionKey(wrappedEncryptionKey, userId);
    
    // Decrypt with proper GCM mode
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
    decipher.setAAD(Buffer.from(userId));
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(encryptedContent),
      decipher.final()
    ]);
    
    // Return requested chunk
    const actualEnd = Math.min(end, decrypted.length - 1);
    const actualStart = Math.min(start, actualEnd);
    
    return decrypted.subarray(actualStart, actualEnd + 1);
  }

  /**
   * Create a streaming decryption for large files
   * Note: Due to GCM authentication requirements, we still need to decrypt the entire file
   * For true streaming, consider switching to a different encryption mode (e.g., CTR with HMAC)
   */
  async createDecryptedStream(
    filePath: string,
    wrappedEncryptionKey: string,
    userId: string,
    start: number = 0,
    end?: number
  ): Promise<NodeJS.ReadableStream> {
    // Get file stats to determine actual size
    const fullPath = path.join(this.baseStoragePath, filePath);
    const stats = await fs.stat(fullPath);
    const encryptedFileSize = stats.size;
    
    // For very large files, we should consider a streaming approach
    // but GCM mode requires full file for authentication
    if (encryptedFileSize > 500 * 1024 * 1024) { // 500MB threshold
      console.warn(`Large file detected (${encryptedFileSize} bytes). Consider implementing chunked encryption for better memory efficiency.`);
    }
    
    try {
      // Decrypt the file content (still need full file for GCM)
      const decryptedBuffer = await this.getDecryptedFileChunk(
        filePath,
        wrappedEncryptionKey, 
        userId,
        0,
        Number.MAX_SAFE_INTEGER
      );
      
      // Create stream from the requested portion
      const actualEnd = end ? Math.min(end, decryptedBuffer.length - 1) : decryptedBuffer.length - 1;
      const actualStart = Math.max(0, start);
      const chunk = decryptedBuffer.subarray(actualStart, actualEnd + 1);
      
      const { Readable } = require('stream');
      return Readable.from(chunk);
    } catch (error) {
      console.error('Failed to create decrypted stream:', error);
      throw new Error('Failed to decrypt file for streaming');
    }
  }

  /**
   * Delete an encrypted file from filesystem
   */
  async deleteEncryptedFile(filePath: string): Promise<boolean> {
    try {
      const fullPath = path.join(this.baseStoragePath, filePath);
      await fs.unlink(fullPath);
      return true;
    } catch (error) {
      console.error('Error deleting encrypted file:', error);
      return false;
    }
  }

  /**
   * Check if a file exists on the filesystem
   */
  async fileExists(filePath: string): Promise<boolean> {
    try {
      const fullPath = path.join(this.baseStoragePath, filePath);
      await fs.access(fullPath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get the size of an encrypted file (encrypted size, not original)
   */
  async getEncryptedFileSize(filePath: string): Promise<number> {
    try {
      const fullPath = path.join(this.baseStoragePath, filePath);
      const stats = await fs.stat(fullPath);
      return stats.size;
    } catch {
      return 0;
    }
  }
}

export const encryptedFilesystemService = new EncryptedFilesystemService();