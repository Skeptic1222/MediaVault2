import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';
import { IStorage, storage } from '../storage';
import { mediaService } from './mediaService';
import { InsertCategory, InsertImportBatch } from '@shared/schema';

export class FolderImportService {
  constructor(private storage: IStorage) {}

  /**
   * Processes uploaded files preserving folder structure as categories
   * SECURITY: Works only with uploaded file data, no server file system access
   */
  async processUploadedFolderStructure(
    files: Array<{
      file: Express.Multer.File;
      relativePath: string; // Path from webkitdirectory upload
    }>,
    userId: string,
    options: {
      createCategories: boolean;
      isVault: boolean;
      parentCategoryId?: string;
      vaultPassphrase?: string;
    } = {
      createCategories: true,
      isVault: false
    }
  ): Promise<{
    success: boolean;
    importBatchId: string;
    totalFiles: number;
    processedFiles: number;
    errors: string[];
    duplicatesFound: number;
  }> {
    
    // Create import batch to track progress
    const importBatch = await this.storage.createImportBatch({
      source: 'directory_upload',
      totalFiles: files.length,
      settings: {
        createCategories: options.createCategories,
        isVault: options.isVault,
        parentCategoryId: options.parentCategoryId
      },
      userId
    });

    const result = {
      success: false,
      importBatchId: importBatch.id,
      totalFiles: files.length,
      processedFiles: 0,
      errors: [] as string[],
      duplicatesFound: 0
    };

    try {
      // Update batch status to processing
      await this.storage.updateImportBatch(importBatch.id, {
        status: 'processing'
      });

      // Group files by their directory paths for category creation
      const folderGroups = this.groupUploadedFilesByFolder(files);

      // Create categories from folder structure if enabled
      const categoryMap = new Map<string, string>(); // folder path -> category ID
      if (options.createCategories) {
        await this.createCategoriesFromUploadedFolders(folderGroups, userId, options.isVault, categoryMap, options.parentCategoryId);
      }

      // Process each uploaded file
      for (const { file, relativePath } of files) {
        let tempFilePath: string | null = null;
        try {
          const directoryPath = path.dirname(relativePath);
          const normalizedPath = directoryPath === '.' ? '' : directoryPath;
          const categoryId = categoryMap.get(normalizedPath) || options.parentCategoryId;

          // Read file buffer from disk (critical fix: was passing file object instead of buffer)
          const fileBuffer = await fs.readFile(file.path);
          tempFilePath = file.path; // Track for cleanup

          // SECURITY: Generate encryption key for vault uploads to prevent plaintext storage
          let encryptionKey: string | undefined;
          if (options.isVault) {
            if (!options.vaultPassphrase) {
              throw new Error('Vault passphrase is required for encrypted uploads');
            }
            encryptionKey = crypto.randomBytes(32).toString('hex');
          }

          const processResult = await mediaService.processFile(
            fileBuffer,
            file.originalname,
            file.mimetype,
            userId,
            {
              categoryId,
              encryptContent: options.isVault,
              encryptionKey,
              vaultPassphrase: options.vaultPassphrase,
              generateThumbnail: true
            }
          );

          if (processResult.isDuplicate) {
            result.duplicatesFound++;
          }

          result.processedFiles++;

          // Update batch progress every 10 files
          if (result.processedFiles % 10 === 0) {
            await this.storage.updateImportBatch(importBatch.id, {
              processedFiles: result.processedFiles,
              duplicatesFound: result.duplicatesFound
            });
          }

        } catch (error) {
          const errorMsg = `Failed to process ${file.originalname}: ${(error as Error).message}`;
          result.errors.push(errorMsg);
          console.error(errorMsg, error);
        } finally {
          // SECURITY: Always clean up temp files to prevent disk accumulation
          if (tempFilePath) {
            try {
              await fs.unlink(tempFilePath);
            } catch (unlinkError) {
              console.warn(`Failed to clean up temp file ${tempFilePath}:`, unlinkError);
            }
          }
        }
      }

      // Final batch update
      await this.storage.updateImportBatch(importBatch.id, {
        status: 'completed',
        processedFiles: result.processedFiles,
        duplicatesFound: result.duplicatesFound,
        errors: result.errors.length > 0 ? result.errors : undefined
      });

      result.success = true;
      return result;

    } catch (error) {
      const errorMsg = `Import failed: ${(error as Error).message}`;
      result.errors.push(errorMsg);
      
      await this.storage.updateImportBatch(importBatch.id, {
        status: 'failed',
        errors: result.errors
      });

      console.error('Folder import failed:', error);
      return result;
    }
  }

  /**
   * Groups uploaded files by their directory paths
   * SECURITY: Works only with uploaded file data, no file system access
   */
  private groupUploadedFilesByFolder(files: Array<{
    file: Express.Multer.File;
    relativePath: string;
  }>): Map<string, Array<{ file: Express.Multer.File; relativePath: string }>> {
    const folderGroups = new Map<string, Array<{ file: Express.Multer.File; relativePath: string }>>();

    for (const fileData of files) {
      const directoryPath = path.dirname(fileData.relativePath);
      const normalizedPath = directoryPath === '.' ? '' : directoryPath;
      
      if (!folderGroups.has(normalizedPath)) {
        folderGroups.set(normalizedPath, []);
      }
      folderGroups.get(normalizedPath)!.push(fileData);
    }

    return folderGroups;
  }

  /**
   * Creates categories from uploaded folder structure
   * SECURITY: Works only with uploaded file data, no server file system access
   */
  private async createCategoriesFromUploadedFolders(
    folderGroups: Map<string, Array<{ file: Express.Multer.File; relativePath: string }>>,
    userId: string,
    isVault: boolean,
    categoryMap: Map<string, string>,
    parentCategoryId?: string
  ): Promise<void> {
    const folderPaths = Array.from(folderGroups.keys()).sort();

    for (const folderPath of folderPaths) {
      if (folderPath === '') {
        // Root level files - use parent category if provided
        if (parentCategoryId) {
          categoryMap.set('', parentCategoryId);
        }
        continue;
      }

      const pathParts = folderPath.split(path.sep);
      let currentPath = '';
      let currentParentId = parentCategoryId;

      // Create nested categories for each path segment
      for (let i = 0; i < pathParts.length; i++) {
        const pathSegment = pathParts[i];
        const segmentPath = i === 0 ? pathSegment : path.join(currentPath, pathSegment);
        
        if (!categoryMap.has(segmentPath)) {
          // Create category from folder name
          const categoryData: InsertCategory = {
            name: this.formatCategoryName(pathSegment),
            slug: this.generateSlug(segmentPath + '-' + Date.now()),
            description: `Imported from folder: ${segmentPath}`,
            parentId: currentParentId,
            isVault,
            folderPath: segmentPath,
            location: this.extractLocationFromFolderName(pathSegment),
            tags: this.extractTagsFromFolderName(pathSegment),
            color: this.assignCategoryColor(pathSegment),
            metadata: {
              importedAt: new Date().toISOString(),
              originalFolderName: pathSegment,
              folderDepth: i + 1
            }
          };

          try {
            const category = await this.storage.createCategory(categoryData);
            categoryMap.set(segmentPath, category.id);
            currentParentId = category.id;
          } catch (error) {
            console.error(`Failed to create category for ${segmentPath}:`, error);
          }
        } else {
          currentParentId = categoryMap.get(segmentPath)!;
        }

        currentPath = segmentPath;
      }

      // Map the final folder path to its category
      categoryMap.set(folderPath, currentParentId!);
    }
  }

  /**
   * Formats folder names into user-friendly category names
   */
  private formatCategoryName(folderName: string): string {
    return folderName
      .replace(/[-_]/g, ' ')
      .replace(/\b\w/g, l => l.toUpperCase())
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Generates a unique slug from folder path
   */
  private generateSlug(path: string): string {
    return path
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 250); // Ensure within varchar limit
  }

  /**
   * Attempts to extract location information from folder names
   */
  private extractLocationFromFolderName(folderName: string): string | undefined {
    const lowerName = folderName.toLowerCase();
    
    // Common location patterns
    if (lowerName.includes('germany')) return 'Germany';
    if (lowerName.includes('berlin')) return 'Berlin, Germany';
    if (lowerName.includes('paris')) return 'Paris, France';
    if (lowerName.includes('london')) return 'London, UK';
    if (lowerName.includes('vacation') || lowerName.includes('trip')) {
      // Try to extract location from vacation folder names
      const words = folderName.split(/[-_\s]+/);
      for (let i = 0; i < words.length; i++) {
        const word = words[i].toLowerCase();
        if (['in', 'to', 'at'].includes(word) && i + 1 < words.length) {
          return words[i + 1];
        }
      }
    }
    
    return undefined;
  }

  /**
   * Extracts tags from folder names
   */
  private extractTagsFromFolderName(folderName: string): string[] | undefined {
    const lowerName = folderName.toLowerCase();
    const tags: string[] = [];

    if (lowerName.includes('vacation') || lowerName.includes('holiday')) tags.push('vacation');
    if (lowerName.includes('family')) tags.push('family');
    if (lowerName.includes('wedding')) tags.push('wedding');
    if (lowerName.includes('birthday')) tags.push('birthday');
    if (lowerName.includes('christmas')) tags.push('christmas');
    if (lowerName.includes('summer')) tags.push('summer');
    if (lowerName.includes('winter')) tags.push('winter');
    if (lowerName.includes('work') || lowerName.includes('business')) tags.push('work');

    return tags.length > 0 ? tags : undefined;
  }

  /**
   * Assigns colors based on folder names for UI organization
   */
  private assignCategoryColor(folderName: string): string {
    const lowerName = folderName.toLowerCase();
    
    if (lowerName.includes('vacation') || lowerName.includes('holiday')) return '#10B981'; // green
    if (lowerName.includes('family')) return '#8B5CF6'; // purple
    if (lowerName.includes('work') || lowerName.includes('business')) return '#3B82F6'; // blue
    if (lowerName.includes('wedding')) return '#EC4899'; // pink
    if (lowerName.includes('christmas')) return '#DC2626'; // red
    if (lowerName.includes('birthday')) return '#F59E0B'; // amber
    
    return '#6B7280'; // default gray
  }

  /**
   * Gets MIME type from file extension
   */
  private getMimeTypeFromExtension(filename: string): string | null {
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes: { [key: string]: string } = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.bmp': 'image/bmp',
      '.webp': 'image/webp',
      '.tiff': 'image/tiff',
      '.tif': 'image/tiff',
      '.mp4': 'video/mp4',
      '.avi': 'video/x-msvideo',
      '.mov': 'video/quicktime',
      '.wmv': 'video/x-ms-wmv',
      '.flv': 'video/x-flv',
      '.webm': 'video/webm',
      '.mkv': 'video/x-matroska',
      '.m4v': 'video/x-m4v'
    };

    return mimeTypes[ext] || null;
  }
}

export const folderImportService = new FolderImportService(storage);