import crypto from 'crypto';

export class CryptoService {
  private algorithm = 'aes-256-gcm';
  private keyLength = 32; // 256 bits
  private ivLength = 16; // 128 bits
  private tagLength = 16; // 128 bits

  /**
   * Derives a key from a passphrase using PBKDF2
   */
  deriveKey(passphrase: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(passphrase, salt, 15000, this.keyLength, 'sha256');
  }

  /**
   * Generates a random salt
   */
  generateSalt(): Buffer {
    return crypto.randomBytes(32);
  }

  /**
   * Encrypts a buffer using AES-256-GCM
   */
  encryptBuffer(buffer: Buffer, passphrase: string): Buffer {
    const salt = this.generateSalt();
    const key = this.deriveKey(passphrase, salt);
    const iv = crypto.randomBytes(this.ivLength);
    
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    const tag = cipher.getAuthTag();
    
    // Structure: salt (32) + iv (16) + tag (16) + encrypted data
    return Buffer.concat([salt, iv, tag, encrypted]);
  }

  /**
   * Decrypts a buffer using AES-256-GCM
   */
  decryptBuffer(encryptedBuffer: Buffer, passphrase: string): Buffer {
    if (encryptedBuffer.length < this.keyLength + this.ivLength + this.tagLength) {
      throw new Error('Invalid encrypted buffer length');
    }

    const salt = encryptedBuffer.subarray(0, 32);
    const iv = encryptedBuffer.subarray(32, 32 + this.ivLength);
    const tag = encryptedBuffer.subarray(32 + this.ivLength, 32 + this.ivLength + this.tagLength);
    const encrypted = encryptedBuffer.subarray(32 + this.ivLength + this.tagLength);
    
    const key = this.deriveKey(passphrase, salt);
    
    const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
    decipher.setAuthTag(tag);
    
    try {
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      return decrypted;
    } catch (error) {
      throw new Error('Decryption failed: Invalid passphrase or corrupted data');
    }
  }

  /**
   * Encrypts a string
   */
  encryptString(text: string, passphrase: string): string {
    const buffer = Buffer.from(text, 'utf8');
    const encrypted = this.encryptBuffer(buffer, passphrase);
    return encrypted.toString('base64');
  }

  /**
   * Decrypts a string
   */
  decryptString(encryptedText: string, passphrase: string): string {
    const encrypted = Buffer.from(encryptedText, 'base64');
    const decrypted = this.decryptBuffer(encrypted, passphrase);
    return decrypted.toString('utf8');
  }

  /**
   * Generates a secure random password
   */
  generateSecurePassword(length: number = 32): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = crypto.randomInt(0, charset.length);
      password += charset[randomIndex];
    }
    
    return password;
  }

  /**
   * Hashes a password using bcrypt-like method with crypto
   */
  hashPassword(password: string): string {
    const salt = crypto.randomBytes(16);
    const hash = crypto.pbkdf2Sync(password, salt, 15000, 64, 'sha256');
    return `${salt.toString('hex')}:${hash.toString('hex')}`;
  }

  /**
   * Verifies a password against a hash
   */
  verifyPassword(password: string, hashedPassword: string): boolean {
    const [saltHex, hashHex] = hashedPassword.split(':');
    const salt = Buffer.from(saltHex, 'hex');
    const hash = crypto.pbkdf2Sync(password, salt, 15000, 64, 'sha256');
    return hash.toString('hex') === hashHex;
  }

  /**
   * Generates SHA-256 hash of a buffer
   */
  generateSHA256(buffer: Buffer): string {
    return crypto.createHash('sha256').update(buffer).digest('hex');
  }

  /**
   * Generates a UUID v4
   */
  generateUUID(): string {
    return crypto.randomUUID();
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   */
  constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    
    return result === 0;
  }
}

export const cryptoService = new CryptoService();
