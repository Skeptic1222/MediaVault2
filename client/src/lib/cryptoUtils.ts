/**
 * Client-side cryptographic utilities for SecureGallery Pro
 * Provides AES-256-GCM encryption, key derivation, and secure random generation
 */

export class CryptoUtils {
  private static readonly ALGORITHM = 'AES-GCM';
  private static readonly KEY_LENGTH = 256;
  private static readonly IV_LENGTH = 12; // 96 bits for GCM
  private static readonly TAG_LENGTH = 16; // 128 bits
  private static readonly SALT_LENGTH = 32; // 256 bits
  private static readonly ITERATIONS = 100000; // PBKDF2 iterations

  /**
   * Derives a cryptographic key from a passphrase using PBKDF2
   */
  static async deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passphraseKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: this.ITERATIONS,
        hash: 'SHA-256',
      },
      passphraseKey,
      { name: this.ALGORITHM, length: this.KEY_LENGTH },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Generates a cryptographically secure random array
   */
  static generateRandomBytes(length: number): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  /**
   * Generates a random salt for key derivation
   */
  static generateSalt(): Uint8Array {
    return this.generateRandomBytes(this.SALT_LENGTH);
  }

  /**
   * Encrypts data using AES-256-GCM
   */
  static async encrypt(data: Uint8Array, passphrase: string): Promise<Uint8Array> {
    const salt = this.generateSalt();
    const iv = this.generateRandomBytes(this.IV_LENGTH);
    const key = await this.deriveKey(passphrase, salt);

    const encrypted = await crypto.subtle.encrypt(
      {
        name: this.ALGORITHM,
        iv: iv,
      },
      key,
      data
    );

    // Combine salt + iv + encrypted data
    const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(encrypted), salt.length + iv.length);

    return result;
  }

  /**
   * Decrypts data using AES-256-GCM
   */
  static async decrypt(encryptedData: Uint8Array, passphrase: string): Promise<Uint8Array> {
    if (encryptedData.length < this.SALT_LENGTH + this.IV_LENGTH + this.TAG_LENGTH) {
      throw new Error('Invalid encrypted data length');
    }

    const salt = encryptedData.slice(0, this.SALT_LENGTH);
    const iv = encryptedData.slice(this.SALT_LENGTH, this.SALT_LENGTH + this.IV_LENGTH);
    const encrypted = encryptedData.slice(this.SALT_LENGTH + this.IV_LENGTH);

    const key = await this.deriveKey(passphrase, salt);

    try {
      const decrypted = await crypto.subtle.decrypt(
        {
          name: this.ALGORITHM,
          iv: iv,
        },
        key,
        encrypted
      );

      return new Uint8Array(decrypted);
    } catch (error) {
      throw new Error('Decryption failed: Invalid passphrase or corrupted data');
    }
  }

  /**
   * Encrypts a string and returns base64 encoded result
   */
  static async encryptString(text: string, passphrase: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const encrypted = await this.encrypt(data, passphrase);
    return this.arrayBufferToBase64(encrypted);
  }

  /**
   * Decrypts a base64 encoded string
   */
  static async decryptString(encryptedBase64: string, passphrase: string): Promise<string> {
    const encrypted = this.base64ToArrayBuffer(encryptedBase64);
    const decrypted = await this.decrypt(new Uint8Array(encrypted), passphrase);
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  /**
   * Encrypts a File object
   */
  static async encryptFile(file: File, passphrase: string): Promise<Uint8Array> {
    const arrayBuffer = await file.arrayBuffer();
    return this.encrypt(new Uint8Array(arrayBuffer), passphrase);
  }

  /**
   * Generates SHA-256 hash of data
   */
  static async generateHash(data: Uint8Array): Promise<string> {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Generates SHA-256 hash of a string
   */
  static async generateStringHash(text: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    return this.generateHash(data);
  }

  /**
   * Generates SHA-256 hash of a File
   */
  static async generateFileHash(file: File): Promise<string> {
    const arrayBuffer = await file.arrayBuffer();
    return this.generateHash(new Uint8Array(arrayBuffer));
  }

  /**
   * Generates a secure random password
   */
  static generateSecurePassword(length: number = 32): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    const randomValues = this.generateRandomBytes(length);
    let password = '';
    
    for (let i = 0; i < length; i++) {
      password += charset[randomValues[i] % charset.length];
    }
    
    return password;
  }

  /**
   * Validates password strength
   */
  static validatePasswordStrength(password: string): {
    isValid: boolean;
    score: number;
    feedback: string[];
  } {
    const feedback: string[] = [];
    let score = 0;

    if (password.length < 8) {
      feedback.push('Password must be at least 8 characters long');
    } else {
      score += 1;
    }

    if (password.length >= 12) {
      score += 1;
    }

    if (/[a-z]/.test(password)) {
      score += 1;
    } else {
      feedback.push('Add lowercase letters');
    }

    if (/[A-Z]/.test(password)) {
      score += 1;
    } else {
      feedback.push('Add uppercase letters');
    }

    if (/\d/.test(password)) {
      score += 1;
    } else {
      feedback.push('Add numbers');
    }

    if (/[^a-zA-Z\d]/.test(password)) {
      score += 1;
    } else {
      feedback.push('Add special characters');
    }

    return {
      isValid: score >= 4 && password.length >= 8,
      score,
      feedback,
    };
  }

  /**
   * Generates a UUID v4
   */
  static generateUUID(): string {
    return crypto.randomUUID();
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   */
  static constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    
    return result === 0;
  }

  /**
   * Converts ArrayBuffer to base64 string
   */
  private static arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const uint8Array = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < uint8Array.byteLength; i++) {
      binary += String.fromCharCode(uint8Array[i]);
    }
    return btoa(binary);
  }

  /**
   * Converts base64 string to ArrayBuffer
   */
  private static base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Securely wipes sensitive data from memory
   */
  static secureWipe(data: Uint8Array): void {
    // Fill with random data first, then zeros
    crypto.getRandomValues(data);
    data.fill(0);
  }
}

/**
 * Key derivation function for vault access
 */
export async function deriveVaultKey(passphrase: string): Promise<string> {
  const salt = new TextEncoder().encode('SecureGallery-Vault-Salt-v1');
  const key = await CryptoUtils.deriveKey(passphrase, salt);
  const exported = await crypto.subtle.exportKey('raw', key);
  return CryptoUtils.arrayBufferToBase64(exported);
}

/**
 * Client-side file encryption for vault uploads
 */
export async function encryptFileForVault(file: File, vaultKey: string): Promise<{
  encryptedData: Uint8Array;
  hash: string;
  metadata: {
    originalName: string;
    mimeType: string;
    size: number;
    encryptedAt: string;
  };
}> {
  const hash = await CryptoUtils.generateFileHash(file);
  const encryptedData = await CryptoUtils.encryptFile(file, vaultKey);

  return {
    encryptedData,
    hash,
    metadata: {
      originalName: file.name,
      mimeType: file.type,
      size: file.size,
      encryptedAt: new Date().toISOString(),
    },
  };
}

/**
 * Validates vault passphrase strength
 */
export function validateVaultPassphrase(passphrase: string): {
  isValid: boolean;
  strength: 'weak' | 'fair' | 'good' | 'strong' | 'excellent';
  feedback: string[];
} {
  const result = CryptoUtils.validatePasswordStrength(passphrase);
  
  let strength: 'weak' | 'fair' | 'good' | 'strong' | 'excellent';
  if (result.score <= 2) {
    strength = 'weak';
  } else if (result.score === 3) {
    strength = 'fair';
  } else if (result.score === 4) {
    strength = 'good';
  } else if (result.score === 5) {
    strength = 'strong';
  } else {
    strength = 'excellent';
  }

  return {
    ...result,
    strength,
  };
}
