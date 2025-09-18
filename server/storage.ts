import {
  users,
  categories,
  mediaFiles,
  importBatches,
  activityLogs,
  folders,
  files,
  albums,
  albumFiles,
  tags,
  fileTags,
  permissions,
  shareLinks,
  smartFolders,
  systemSettings,
  playlists,
  playlistTracks,
  playHistory,
  type User,
  type UpsertUser,
  type Category,
  type InsertCategory,
  type MediaFile,
  type InsertMediaFile,
  type ImportBatch,
  type InsertImportBatch,
  type ActivityLog,
  type InsertActivityLog,
  type Folder,
  type InsertFolder,
  type File,
  type InsertFile,
  type Album,
  type InsertAlbum,
  type AlbumFile,
  type InsertAlbumFile,
  type Tag,
  type InsertTag,
  type FileTag,
  type InsertFileTag,
  type Permission,
  type InsertPermission,
  type ShareLink,
  type InsertShareLink,
  type SmartFolder,
  type InsertSmartFolder,
  type SystemSetting,
  type InsertSystemSetting,
  type Playlist,
  type InsertPlaylist,
  type PlaylistTrack,
  type InsertPlaylistTrack,
  type PlayHistory,
  type InsertPlayHistory,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, asc, like, and, or, isNull, sql, count, gte, lte, SQL } from "drizzle-orm";

// Interface for storage operations
export interface IStorage {
  // User operations (mandatory for Replit Auth)
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
  
  // Category operations
  getCategories(): Promise<Category[]>;
  getCategoryTree(): Promise<Category[]>;
  createCategory(category: InsertCategory): Promise<Category>;
  updateCategory(id: string, updates: Partial<Category>): Promise<Category | undefined>;
  deleteCategory(id: string): Promise<boolean>;
  
  // Media file operations
  getMediaFiles(options?: {
    categoryId?: string;
    isVault?: boolean;
    userId?: string;
    limit?: number;
    offset?: number;
    search?: string;
    sortBy?: 'created_at' | 'filename' | 'file_size';
    sortOrder?: 'asc' | 'desc';
  }): Promise<{ files: MediaFile[]; total: number }>;
  getMediaFile(id: string): Promise<MediaFile | undefined>;
  getMediaFileByHash(hash: string, userId: string): Promise<MediaFile | undefined>;
  getMediaFileBinaryData(id: string): Promise<{ binaryData: Buffer | null; mimeType: string } | undefined>;
  getMediaFileChunk(id: string, start: number, end: number): Promise<{ chunkData: Buffer; mimeType: string; totalSize: number } | undefined>;
  getMediaFileThumbnail(id: string): Promise<{ thumbnailData: Buffer | null; mimeType: string } | undefined>;
  createMediaFile(file: InsertMediaFile & { uploadedBy: string; sha256Hash: string }): Promise<MediaFile>;
  updateMediaFile(id: string, updates: Partial<MediaFile>): Promise<MediaFile | undefined>;
  deleteMediaFile(id: string): Promise<boolean>;
  getMediaStats(userId?: string): Promise<{
    totalItems: number;
    images: number;
    videos: number;
    vaultItems: number;
    storageUsed: number;
    duplicatesFound: number;
  }>;
  getCategoryStats(userId?: string): Promise<Record<string, number>>;
  
  // Import batch operations
  createImportBatch(batch: InsertImportBatch & { userId: string }): Promise<ImportBatch>;
  updateImportBatch(id: string, updates: Partial<ImportBatch>): Promise<ImportBatch | undefined>;
  getImportBatch(id: string): Promise<ImportBatch | undefined>;
  getImportBatches(userId: string): Promise<ImportBatch[]>;
  
  // Activity log operations
  logActivity(log: InsertActivityLog & { userId: string }): Promise<ActivityLog>;
  getActivityLogs(userId?: string, options?: {
    limit?: number;
    offset?: number;
    search?: string;
    action?: string;
    targetUserId?: string;
    dateFrom?: string;
    dateTo?: string;
  }): Promise<{ logs: ActivityLog[]; total: number }>;
  
  // Folder operations
  getFolders(userId: string, parentId?: string | null): Promise<Folder[]>;
  getFolderTree(userId: string): Promise<Folder[]>;
  createFolder(folder: InsertFolder): Promise<Folder>;
  updateFolder(id: string, updates: Partial<Folder>): Promise<Folder | undefined>;
  deleteFolder(id: string): Promise<boolean>;
  moveFolderToFolder(folderId: string, newParentId: string | null): Promise<boolean>;
  
  // File operations
  getFiles(options?: {
    userId?: string;
    folderId?: string | null;
    fileType?: string;
    limit?: number;
    offset?: number;
    search?: string;
    tags?: string[];
    sortBy?: 'created_at' | 'filename' | 'file_size';
    sortOrder?: 'asc' | 'desc';
  }): Promise<{ files: File[]; total: number }>;
  getFile(id: string): Promise<File | undefined>;
  getFileByHash(hash: string, userId: string): Promise<File | undefined>;
  getFileBinaryData(id: string): Promise<{ binaryData: Buffer | null; mimeType: string } | undefined>;
  getFileThumbnail(id: string): Promise<{ thumbnailData: Buffer | null; mimeType: string } | undefined>;
  createFile(file: InsertFile): Promise<File>;
  updateFile(id: string, updates: Partial<File>): Promise<File | undefined>;
  deleteFile(id: string): Promise<boolean>;
  moveFileToFolder(fileId: string, folderId: string | null): Promise<boolean>;
  copyFile(fileId: string, targetFolderId: string | null): Promise<File | undefined>;
  bulkOperation(operation: 'delete' | 'move' | 'copy' | 'tag', fileIds: string[], options?: any): Promise<{ success: number; failed: number }>;
  
  // Album operations
  getAlbums(userId: string): Promise<Album[]>;
  getAlbum(id: string): Promise<Album | undefined>;
  createAlbum(album: InsertAlbum): Promise<Album>;
  updateAlbum(id: string, updates: Partial<Album>): Promise<Album | undefined>;
  deleteAlbum(id: string): Promise<boolean>;
  addFileToAlbum(albumId: string, fileId: string, sortOrder?: number): Promise<AlbumFile>;
  removeFileFromAlbum(albumId: string, fileId: string): Promise<boolean>;
  getAlbumFiles(albumId: string): Promise<{ album: Album; files: File[] }>;
  
  // Tag operations
  getTags(userId: string): Promise<Tag[]>;
  getTag(id: string): Promise<Tag | undefined>;
  createTag(tag: InsertTag): Promise<Tag>;
  updateTag(id: string, updates: Partial<Tag>): Promise<Tag | undefined>;
  deleteTag(id: string): Promise<boolean>;
  tagFile(fileId: string, tagId: string): Promise<FileTag>;
  untagFile(fileId: string, tagId: string): Promise<boolean>;
  getFileTags(fileId: string): Promise<Tag[]>;
  getFilesByTag(tagId: string, userId: string): Promise<File[]>;
  
  // Permission operations
  getPermissions(userId: string, resourceType?: string, resourceId?: string): Promise<Permission[]>;
  grantPermission(permission: InsertPermission): Promise<Permission>;
  revokePermission(id: string): Promise<boolean>;
  checkPermission(userId: string, resourceType: string, resourceId: string, action: 'view' | 'edit' | 'delete' | 'share'): Promise<boolean>;
  
  // Playlist operations
  createPlaylist(playlist: InsertPlaylist): Promise<Playlist>;
  getPlaylists(userId: string): Promise<Playlist[]>;
  getPlaylist(id: string): Promise<Playlist | undefined>;
  updatePlaylist(id: string, updates: Partial<Playlist>): Promise<Playlist | undefined>;
  deletePlaylist(id: string): Promise<boolean>;
  addTrackToPlaylist(playlistId: string, fileId: string, position?: number, addedBy?: string): Promise<PlaylistTrack>;
  removeTrackFromPlaylist(playlistId: string, fileId: string): Promise<boolean>;
  reorderPlaylistTracks(playlistId: string, trackId: string, newPosition: number): Promise<boolean>;
  getPlaylistTracks(playlistId: string): Promise<{ playlist: Playlist; tracks: File[] }>;
  
  // Play history operations
  recordPlay(history: InsertPlayHistory): Promise<PlayHistory>;
  getRecentlyPlayed(userId: string, limit?: number): Promise<File[]>;
  getMostPlayed(userId: string, limit?: number): Promise<{ file: File; playCount: number }[]>;
  
  // Admin migration operations
  syncMediaFilesToFilesTable(): Promise<{ synced: number; skipped: number; total: number }>;
  cleanupDuplicateCategories(): Promise<{ removed: number; kept: number; updated: number }>;
  
  // User management operations (admin only)
  getAllUsers(): Promise<{ users: User[]; total: number }>;
  updateUserRole(userId: string, role: string): Promise<User | undefined>;
  deleteUser(userId: string): Promise<{ success: boolean; filesDeleted: number; foldersDeleted: number }>;
  getUserStats(userId: string): Promise<{
    storageUsed: number;
    storageQuota: number;
    totalFiles: number;
    totalMediaFiles: number;
    totalFolders: number;
    totalAlbums: number;
    totalPlaylists: number;
    lastActivity: Date | null;
    accountCreated: Date;
  }>;
}

export class DatabaseStorage implements IStorage {
  // User operations (mandatory for Replit Auth)
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(userData)
      .onConflictDoUpdate({
        target: users.id,
        set: {
          ...userData,
          updatedAt: new Date(),
        },
      })
      .returning();
    return user;
  }

  // Category validation helper
  private async validateCategoryData(categoryData: Partial<Category>, categoryId?: string): Promise<void> {
    // Check for self-parenting
    if (categoryData.parentId && categoryData.parentId === categoryId) {
      throw new Error("A category cannot be its own parent");
    }

    // Check if parent exists (if parentId is provided)
    if (categoryData.parentId) {
      const parent = await db.select().from(categories).where(eq(categories.id, categoryData.parentId));
      if (parent.length === 0) {
        throw new Error(`Parent category with id "${categoryData.parentId}" does not exist`);
      }
    }

    // Check for cycles if we're updating an existing category's parent
    if (categoryData.parentId && categoryId) {
      await this.checkForCycles(categoryId, categoryData.parentId);
    }
  }

  // Cycle detection helper
  private async checkForCycles(categoryId: string, newParentId: string): Promise<void> {
    const visited = new Set<string>();
    let currentId: string | null = newParentId;

    while (currentId) {
      if (visited.has(currentId)) {
        throw new Error("Circular reference detected: this parent assignment would create a cycle");
      }
      
      if (currentId === categoryId) {
        throw new Error("Circular reference detected: the proposed parent is a descendant of this category");
      }

      visited.add(currentId);

      // Get the parent of the current category
      const [parent] = await db.select({ parentId: categories.parentId })
        .from(categories)
        .where(eq(categories.id, currentId));
      
      currentId = parent?.parentId || null;
    }
  }

  // Category operations
  async getCategories(): Promise<Category[]> {
    return await db.select().from(categories).orderBy(asc(categories.sortOrder), asc(categories.name));
  }

  async getCategoryTree(): Promise<Category[]> {
    const allCategories = await this.getCategories();
    
    // Build tree structure
    const categoryMap = new Map<string, Category & { children?: Category[] }>();
    const rootCategories: (Category & { children?: Category[] })[] = [];
    
    // Initialize map
    allCategories.forEach(cat => {
      categoryMap.set(cat.id, { ...cat, children: [] });
    });
    
    // Build tree
    allCategories.forEach(cat => {
      const category = categoryMap.get(cat.id)!;
      if (cat.parentId) {
        const parent = categoryMap.get(cat.parentId);
        if (parent) {
          parent.children!.push(category);
        }
      } else {
        rootCategories.push(category);
      }
    });
    
    return rootCategories as Category[];
  }

  async createCategory(category: InsertCategory): Promise<Category> {
    // Validate the category data
    await this.validateCategoryData(category, undefined);
    
    const [newCategory] = await db.insert(categories).values(category).returning();
    return newCategory;
  }

  async updateCategory(id: string, updates: Partial<Category>): Promise<Category | undefined> {
    // Validate the update data
    await this.validateCategoryData(updates, id);
    
    const [updated] = await db
      .update(categories)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(categories.id, id))
      .returning();
    return updated;
  }

  async deleteCategory(id: string): Promise<boolean> {
    // Check if category has children
    const children = await db.select().from(categories).where(eq(categories.parentId, id));
    if (children.length > 0) {
      throw new Error(`Cannot delete category: it has ${children.length} child categories. Please move or delete child categories first.`);
    }
    
    // Check if category has media files
    const [mediaCount] = await db.select({ count: count() })
      .from(mediaFiles)
      .where(and(eq(mediaFiles.categoryId, id), eq(mediaFiles.isDeleted, false)));
    
    if (mediaCount.count > 0) {
      throw new Error(`Cannot delete category: it contains ${mediaCount.count} media files. Please move or delete the files first.`);
    }
    
    const result = await db.delete(categories).where(eq(categories.id, id));
    return result.rowCount! > 0;
  }

  // Media file operations
  async getMediaFiles(options: {
    categoryId?: string;
    isVault?: boolean;
    userId?: string;
    limit?: number;
    offset?: number;
    search?: string;
    sortBy?: 'created_at' | 'filename' | 'file_size';
    sortOrder?: 'asc' | 'desc';
    mimeType?: 'images' | 'videos';
  } = {}): Promise<{ files: MediaFile[]; total: number }> {
    const {
      categoryId,
      isVault = false,
      userId,
      limit = 20,
      offset = 0,
      search,
      sortBy = 'created_at',
      sortOrder = 'desc',
      mimeType
    } = options;

    // Filter for media types (images and videos) from the generic files table
    const conditions = [
      eq(files.isDeleted, false),
      or(
        sql`${files.mimeType} LIKE 'image/%'`,
        sql`${files.mimeType} LIKE 'video/%'`
      )!
    ];

    // Special handling for "Videos" category - show all videos regardless of category
    const videosCategory = await db
      .select({ id: categories.id })
      .from(categories)
      .where(eq(categories.slug, 'videos'))
      .limit(1);
    
    const isVideosCategory = videosCategory.length > 0 && categoryId === videosCategory[0].id;

    if (isVideosCategory) {
      // For Videos category, show only videos
      conditions.push(sql`${files.mimeType} LIKE 'video/%'`);
    } else if (categoryId) {
      // Since files table doesn't have categoryId, we'll skip category filtering
      // This could be handled with folder mapping or other logic if needed
    }

    if (isVault) {
      conditions.push(eq(files.isEncrypted, true));
    }

    if (userId) {
      conditions.push(eq(files.userId, userId));
    }

    if (search) {
      conditions.push(
        or(
          like(files.originalName, `%${search}%`),
          like(files.filename, `%${search}%`),
          sql`${files.tags} && ARRAY[${search}]`
        )!
      );
    }

    if (mimeType === 'images') {
      conditions.push(sql`${files.mimeType} LIKE 'image/%'`);
    } else if (mimeType === 'videos') {
      conditions.push(sql`${files.mimeType} LIKE 'video/%'`);
    }

    // Apply sorting
    const sortColumn = sortBy === 'created_at' ? files.createdAt 
                     : sortBy === 'filename' ? files.filename 
                     : files.fileSize;

    // EXCLUDE large binary fields to prevent buffer overflow
    const query = db.select({
      id: files.id,
      filename: files.filename,
      originalName: files.originalName,
      mimeType: files.mimeType,
      fileSize: files.fileSize,
      sha256Hash: files.sha256Hash,
      width: files.width,
      height: files.height,
      duration: files.duration,
      metadata: files.customMetadata,
      isEncrypted: files.isEncrypted,
      encryptionKey: files.encryptionKey,
      categoryId: sql<string | null>`null`,  // files table doesn't have categoryId
      uploadedBy: files.userId,  // Map userId to uploadedBy for compatibility
      importSource: sql<string | null>`null`,  // files table doesn't have importSource
      tags: files.tags,
      isFavorite: files.isFavorite,
      isDeleted: files.isDeleted,
      createdAt: files.createdAt,
      updatedAt: files.updatedAt,
      storageType: files.storageType,
      // Explicitly exclude: binaryData, thumbnailData
    })
      .from(files)
      .where(and(...conditions))
      .orderBy(sortOrder === 'asc' ? asc(sortColumn) : desc(sortColumn))
      .limit(limit)
      .offset(offset);
      
    const countQuery = db.select({ count: count() })
      .from(files)
      .where(and(...conditions));

    const [filesResult, [{ count: total }]] = await Promise.all([
      query,
      countQuery
    ]);

    return { files: filesResult as MediaFile[], total };
  }

  async getMediaFile(id: string): Promise<MediaFile | undefined> {
    // Get file metadata without binary data
    const [file] = await db.select({
      id: files.id,
      filename: files.filename,
      originalName: files.originalName,
      mimeType: files.mimeType,
      fileSize: files.fileSize,
      sha256Hash: files.sha256Hash,
      width: files.width,
      height: files.height,
      duration: files.duration,
      metadata: files.customMetadata,
      isEncrypted: files.isEncrypted,
      encryptionKey: files.encryptionKey,
      categoryId: sql<string | null>`null`,  // files table doesn't have categoryId
      uploadedBy: files.userId,  // Map userId to uploadedBy for compatibility
      importSource: sql<string | null>`null`,  // files table doesn't have importSource
      tags: files.tags,
      isFavorite: files.isFavorite,
      isDeleted: files.isDeleted,
      createdAt: files.createdAt,
      updatedAt: files.updatedAt,
      storageType: files.storageType,
      // Explicitly exclude: binaryData, thumbnailData
    }).from(files).where(
      and(
        eq(files.id, id),
        or(
          sql`${files.mimeType} LIKE 'image/%'`,
          sql`${files.mimeType} LIKE 'video/%'`
        )!
      )
    );
    return file as MediaFile;
  }

  // Get binary data for a specific media file
  async getMediaFileBinaryData(id: string): Promise<{ binaryData: Buffer | null; mimeType: string } | undefined> {
    const [file] = await db.select({
      binaryData: files.binaryData,
      mimeType: files.mimeType,
    }).from(files).where(
      and(
        eq(files.id, id),
        or(
          sql`${files.mimeType} LIKE 'image/%'`,
          sql`${files.mimeType} LIKE 'video/%'`
        )!
      )
    );
    return file;
  }

  async getMediaFileChunk(id: string, start: number, end: number): Promise<{ chunkData: Buffer; mimeType: string; totalSize: number } | undefined> {
    // Get file metadata first for total size
    const [metadata] = await db.select({
      fileSize: files.fileSize,
      mimeType: files.mimeType,
    }).from(files).where(
      and(
        eq(files.id, id),
        or(
          sql`${files.mimeType} LIKE 'image/%'`,
          sql`${files.mimeType} LIKE 'video/%'`
        )!
      )
    );
    
    if (!metadata) return undefined;

    // Validate range bounds
    if (start < 0 || end >= metadata.fileSize || start > end) {
      throw new Error(`Invalid byte range: ${start}-${end} for file size ${metadata.fileSize}`);
    }

    // Calculate chunk length for PostgreSQL substring (1-indexed)
    const chunkLength = end - start + 1;
    const postgresStart = start + 1; // PostgreSQL substring is 1-indexed

    // Use PostgreSQL substring to get only the requested bytes
    const [file] = await db.select({
      chunkData: sql<Buffer>`substring(${files.binaryData} FROM ${postgresStart} FOR ${chunkLength})`,
    }).from(files).where(
      and(
        eq(files.id, id),
        or(
          sql`${files.mimeType} LIKE 'image/%'`,
          sql`${files.mimeType} LIKE 'video/%'`
        )!
      )
    );

    if (!file) return undefined;

    return {
      chunkData: file.chunkData,
      mimeType: metadata.mimeType,
      totalSize: metadata.fileSize,
    };
  }

  // Get thumbnail data for a specific media file
  async getMediaFileThumbnail(id: string): Promise<{ 
    thumbnailData: Buffer | null; 
    thumbnailWebp: Buffer | null;
    thumbnailAvif: Buffer | null;
    mimeType: string;
  } | undefined> {
    const [file] = await db.select({
      thumbnailData: files.thumbnailData,
      thumbnailWebp: sql<Buffer | null>`null`,  // files table doesn't have thumbnailWebp
      thumbnailAvif: sql<Buffer | null>`null`,  // files table doesn't have thumbnailAvif
      mimeType: files.mimeType,
    }).from(files).where(
      and(
        eq(files.id, id),
        or(
          sql`${files.mimeType} LIKE 'image/%'`,
          sql`${files.mimeType} LIKE 'video/%'`
        )!
      )
    );
    return file;
  }

  async getMediaFileByHash(hash: string, userId: string): Promise<MediaFile | undefined> {
    // Get file metadata without binary data
    const [file] = await db.select({
      id: files.id,
      filename: files.filename,
      originalName: files.originalName,
      mimeType: files.mimeType,
      fileSize: files.fileSize,
      sha256Hash: files.sha256Hash,
      width: files.width,
      height: files.height,
      duration: files.duration,
      metadata: files.customMetadata,
      isEncrypted: files.isEncrypted,
      encryptionKey: files.encryptionKey,
      categoryId: sql<string | null>`null`,  // files table doesn't have categoryId
      uploadedBy: files.userId,  // Map userId to uploadedBy for compatibility
      importSource: sql<string | null>`null`,  // files table doesn't have importSource
      tags: files.tags,
      isFavorite: files.isFavorite,
      isDeleted: files.isDeleted,
      createdAt: files.createdAt,
      updatedAt: files.updatedAt,
      storageType: files.storageType,
      // Explicitly exclude: binaryData, thumbnailData
    }).from(files).where(
      and(
        eq(files.sha256Hash, hash),
        eq(files.userId, userId),
        eq(files.isDeleted, false),
        or(
          sql`${files.mimeType} LIKE 'image/%'`,
          sql`${files.mimeType} LIKE 'video/%'`
        )!
      )
    );
    return file as MediaFile;
  }

  async createMediaFile(file: InsertMediaFile & { uploadedBy: string; sha256Hash: string }): Promise<MediaFile> {
    const [newFile] = await db.insert(mediaFiles).values(file).returning();
    return newFile;
  }

  async updateMediaFile(id: string, updates: Partial<MediaFile>): Promise<MediaFile | undefined> {
    const [updated] = await db
      .update(mediaFiles)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(mediaFiles.id, id))
      .returning();
    return updated;
  }

  async deleteMediaFile(id: string): Promise<boolean> {
    const [updated] = await db
      .update(files)
      .set({ isDeleted: true, deletedAt: new Date(), updatedAt: new Date() })
      .where(
        and(
          eq(files.id, id),
          or(
            sql`${files.mimeType} LIKE 'image/%'`,
            sql`${files.mimeType} LIKE 'video/%'`
          )!
        )
      )
      .returning();
    return !!updated;
  }

  async getMediaStats(userId?: string): Promise<{
    totalItems: number;
    images: number;
    videos: number;
    vaultItems: number;
    storageUsed: number;
    duplicatesFound: number;
  }> {
    // Query from files table for media types
    const conditions = [
      eq(files.isDeleted, false),
      or(
        sql`${files.mimeType} LIKE 'image/%'`,
        sql`${files.mimeType} LIKE 'video/%'`
      )!
    ];
    
    if (userId) {
      conditions.push(eq(files.userId, userId));
    }

    const [
      totalResult,
      imageResult,
      videoResult,
      vaultResult,
      storageSumResult,
      duplicatesResult,
    ] = await Promise.all([
      db.select({ count: count() }).from(files).where(and(...conditions)),
      db.select({ count: count() }).from(files).where(and(...conditions, sql`${files.mimeType} LIKE 'image/%'`)),
      db.select({ count: count() }).from(files).where(and(...conditions, sql`${files.mimeType} LIKE 'video/%'`)),
      db.select({ count: count() }).from(files).where(and(...conditions, eq(files.isEncrypted, true))),
      db.select({ sum: sql<number>`sum(${files.fileSize})` }).from(files).where(and(...conditions)),
      db.select({ count: count() }).from(files)
        .where(and(...conditions))
        .groupBy(files.sha256Hash)
        .having(sql`count(*) > 1`)
    ]);

    return {
      totalItems: totalResult[0]?.count || 0,
      images: imageResult[0]?.count || 0,
      videos: videoResult[0]?.count || 0,
      vaultItems: vaultResult[0]?.count || 0,
      storageUsed: storageSumResult[0]?.sum || 0,
      duplicatesFound: duplicatesResult.length,
    };
  }

  async getCategoryStats(userId?: string): Promise<Record<string, number>> {
    // Since files table doesn't have categoryId, we'll handle special categories based on file types
    const conditions = [
      eq(files.isDeleted, false),
      or(
        sql`${files.mimeType} LIKE 'image/%'`,
        sql`${files.mimeType} LIKE 'video/%'`
      )!
    ];
    
    if (userId) {
      conditions.push(eq(files.userId, userId));
    }

    // Special handling for "Videos" category - count all videos
    const videosCategory = await db
      .select({ id: categories.id })
      .from(categories)
      .where(eq(categories.slug, 'videos'))
      .limit(1);
    
    const categoryStats: Record<string, number> = {};
    
    if (videosCategory.length > 0) {
      const videoConditions = [...conditions, sql`${files.mimeType} LIKE 'video/%'`];
      const videoCount = await db
        .select({ count: count() })
        .from(files)
        .where(and(...videoConditions));
      
      categoryStats[videosCategory[0].id] = Number(videoCount[0]?.count) || 0;
    }
    
    // Since files don't have categories anymore, we can only return counts for special categories
    // In the future, this could be mapped to folders or other organizational structures
    return categoryStats;
  }

  // Import batch operations
  async createImportBatch(batch: InsertImportBatch & { userId: string }): Promise<ImportBatch> {
    const [newBatch] = await db.insert(importBatches).values(batch).returning();
    return newBatch;
  }

  async updateImportBatch(id: string, updates: Partial<ImportBatch>): Promise<ImportBatch | undefined> {
    const [updated] = await db
      .update(importBatches)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(importBatches.id, id))
      .returning();
    return updated;
  }

  async getImportBatch(id: string): Promise<ImportBatch | undefined> {
    const [batch] = await db.select().from(importBatches).where(eq(importBatches.id, id));
    return batch;
  }

  async getImportBatches(userId: string): Promise<ImportBatch[]> {
    return await db
      .select()
      .from(importBatches)
      .where(eq(importBatches.userId, userId))
      .orderBy(desc(importBatches.createdAt));
  }

  // Activity log operations
  async logActivity(log: InsertActivityLog & { userId: string }): Promise<ActivityLog> {
    const [newLog] = await db.insert(activityLogs).values(log).returning();
    return newLog;
  }

  async getActivityLogs(
    userId?: string, 
    options: {
      limit?: number;
      offset?: number;
      search?: string;
      action?: string;
      targetUserId?: string;
      dateFrom?: string;
      dateTo?: string;
    } = {}
  ): Promise<{ logs: ActivityLog[]; total: number }> {
    const { 
      limit = 50, 
      offset = 0, 
      search, 
      action, 
      targetUserId, 
      dateFrom, 
      dateTo 
    } = options;

    const conditions: SQL[] = [];
    
    // Filter by userId if provided (for non-admin view)
    if (userId) {
      conditions.push(eq(activityLogs.userId, userId));
    }
    
    // Filter by targetUserId if provided
    if (targetUserId) {
      conditions.push(eq(activityLogs.userId, targetUserId));
    }
    
    // Filter by action type
    if (action) {
      conditions.push(eq(activityLogs.action, action));
    }
    
    // Search in resource and metadata
    if (search) {
      const searchCondition = or(
        sql`${activityLogs.resource} ILIKE ${`%${search}%`}`,
        sql`${activityLogs.resourceId} ILIKE ${`%${search}%`}`,
        sql`${activityLogs.metadata}::text ILIKE ${`%${search}%`}`
      );
      if (searchCondition) {
        conditions.push(searchCondition);
      }
    }
    
    // Date range filters
    if (dateFrom) {
      conditions.push(gte(activityLogs.createdAt, new Date(dateFrom)));
    }
    if (dateTo) {
      const endDate = new Date(dateTo);
      endDate.setHours(23, 59, 59, 999);
      conditions.push(lte(activityLogs.createdAt, endDate));
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    // Get total count for pagination
    const [countResult] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(activityLogs)
      .where(whereClause);

    // Get paginated results
    const logs = await db
      .select()
      .from(activityLogs)
      .where(whereClause)
      .orderBy(desc(activityLogs.createdAt))
      .limit(limit)
      .offset(offset);

    return { 
      logs, 
      total: countResult?.count || 0 
    };
  }

  // Folder operations
  async getFolders(userId: string, parentId?: string | null): Promise<Folder[]> {
    const conditions = [eq(folders.userId, userId)];
    if (parentId === null) {
      conditions.push(isNull(folders.parentId));
    } else if (parentId !== undefined) {
      conditions.push(eq(folders.parentId, parentId));
    }

    return await db
      .select()
      .from(folders)
      .where(and(...conditions))
      .orderBy(asc(folders.sortOrder), asc(folders.name));
  }

  async getFolderTree(userId: string): Promise<Folder[]> {
    const allFolders = await this.getFolders(userId);
    
    // Build tree structure
    const folderMap = new Map<string, Folder & { children?: Folder[] }>();
    const rootFolders: (Folder & { children?: Folder[] })[] = [];
    
    // Initialize map
    allFolders.forEach(folder => {
      folderMap.set(folder.id, { ...folder, children: [] });
    });
    
    // Build tree
    allFolders.forEach(folder => {
      const folderNode = folderMap.get(folder.id)!;
      if (folder.parentId) {
        const parent = folderMap.get(folder.parentId);
        if (parent) {
          parent.children!.push(folderNode);
        }
      } else {
        rootFolders.push(folderNode);
      }
    });
    
    return rootFolders as Folder[];
  }

  async createFolder(folder: InsertFolder): Promise<Folder> {
    // Generate path based on parent
    if (folder.parentId) {
      const parent = await this.getFolders(folder.userId, folder.parentId);
      if (parent.length > 0 && parent[0].path) {
        folder.path = `${parent[0].path}/${folder.name}`;
      }
    } else {
      folder.path = `/${folder.name}`;
    }
    
    const [newFolder] = await db.insert(folders).values(folder).returning();
    return newFolder;
  }

  async updateFolder(id: string, updates: Partial<Folder>): Promise<Folder | undefined> {
    const [updated] = await db
      .update(folders)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(folders.id, id))
      .returning();
    return updated;
  }

  async deleteFolder(id: string): Promise<boolean> {
    // Check if folder has children
    const children = await db.select().from(folders).where(eq(folders.parentId, id));
    if (children.length > 0) {
      throw new Error(`Cannot delete folder: it has ${children.length} child folders. Please delete child folders first.`);
    }
    
    // Check if folder has files
    const filesInFolder = await db.select({ count: count() })
      .from(files)
      .where(and(eq(files.folderId, id), eq(files.isDeleted, false)));
    
    if (filesInFolder[0].count > 0) {
      throw new Error(`Cannot delete folder: it contains ${filesInFolder[0].count} files. Please move or delete the files first.`);
    }
    
    const result = await db.delete(folders).where(eq(folders.id, id));
    return result.rowCount! > 0;
  }

  async moveFolderToFolder(folderId: string, newParentId: string | null): Promise<boolean> {
    // Prevent circular references
    if (newParentId) {
      let currentId: string | null = newParentId;
      while (currentId) {
        if (currentId === folderId) {
          throw new Error("Cannot move folder: this would create a circular reference");
        }
        const [parent] = await db.select({ parentId: folders.parentId })
          .from(folders)
          .where(eq(folders.id, currentId));
        currentId = parent?.parentId || null;
      }
    }
    
    const [updated] = await db
      .update(folders)
      .set({ parentId: newParentId, updatedAt: new Date() })
      .where(eq(folders.id, folderId))
      .returning();
    return !!updated;
  }

  // File operations
  async getFiles(options: {
    userId?: string;
    folderId?: string | null;
    fileType?: string;
    limit?: number;
    offset?: number;
    search?: string;
    tags?: string[];
    sortBy?: 'created_at' | 'filename' | 'file_size';
    sortOrder?: 'asc' | 'desc';
  } = {}): Promise<{ files: File[]; total: number }> {
    const {
      userId,
      folderId,
      fileType,
      limit = 20,
      offset = 0,
      search,
      tags: searchTags,
      sortBy = 'created_at',
      sortOrder = 'desc',
    } = options;

    // Query files table
    const filesConditions = [eq(files.isDeleted, false)];

    if (userId) {
      filesConditions.push(eq(files.userId, userId));
    }

    if (folderId === null) {
      filesConditions.push(isNull(files.folderId));
    } else if (folderId !== undefined) {
      filesConditions.push(eq(files.folderId, folderId));
    }

    if (fileType) {
      filesConditions.push(eq(files.fileType, fileType));
    }

    if (search) {
      filesConditions.push(
        or(
          like(files.originalName, `%${search}%`),
          like(files.filename, `%${search}%`),
          like(files.description, `%${search}%`)
        )!
      );
    }

    if (searchTags && searchTags.length > 0) {
      filesConditions.push(sql`${files.tags} && ARRAY[${searchTags.join(',')}]`);
    }

    // Query files table (exclude large binary fields)
    const filesQuery = db.select({
      id: files.id,
      filename: files.filename,
      originalName: files.originalName,
      mimeType: files.mimeType,
      fileType: files.fileType,
      fileSize: files.fileSize,
      sha256Hash: files.sha256Hash,
      folderId: files.folderId,
      userId: files.userId,
      storageType: files.storageType,
      filePath: files.filePath,
      description: files.description,
      notes: files.notes,
      customMetadata: files.customMetadata,
      exifData: files.exifData,
      width: files.width,
      height: files.height,
      duration: files.duration,
      pageCount: files.pageCount,
      wordCount: files.wordCount,
      isEncrypted: files.isEncrypted,
      encryptionKey: files.encryptionKey,
      tags: files.tags,
      isFavorite: files.isFavorite,
      isDeleted: files.isDeleted,
      deletedAt: files.deletedAt,
      version: files.version,
      previousVersionId: files.previousVersionId,
      createdAt: files.createdAt,
      updatedAt: files.updatedAt,
    })
      .from(files)
      .where(and(...filesConditions));

    // Query mediaFiles table and map to File structure
    const mediaFilesConditions = [eq(mediaFiles.isDeleted, false)];

    if (userId) {
      mediaFilesConditions.push(eq(mediaFiles.uploadedBy, userId));
    }

    // For mediaFiles, we only include them when viewing root folder (null) or all files (undefined)
    // Don't include them when viewing a specific folder (non-null string)
    const shouldIncludeMediaFiles = (folderId === null || folderId === undefined);
    
    if (!shouldIncludeMediaFiles) {
      // If we're looking for files in a specific folder, don't include media files
      // since they don't have folder support yet
      mediaFilesConditions.push(sql`false`); // Never match
    }
    // When folderId is null (root folder) or undefined (all files), include media files

    // Determine fileType based on mimeType for filtering
    if (fileType) {
      if (fileType === 'image') {
        mediaFilesConditions.push(like(mediaFiles.mimeType, 'image/%'));
      } else if (fileType === 'video') {
        mediaFilesConditions.push(like(mediaFiles.mimeType, 'video/%'));
      } else if (fileType === 'audio') {
        mediaFilesConditions.push(like(mediaFiles.mimeType, 'audio/%'));
      }
      // For other file types, don't include media files
    }

    if (search) {
      mediaFilesConditions.push(
        or(
          like(mediaFiles.originalName, `%${search}%`),
          like(mediaFiles.filename, `%${search}%`)
        )!
      );
    }

    if (searchTags && searchTags.length > 0) {
      mediaFilesConditions.push(sql`${mediaFiles.tags} && ARRAY[${searchTags.join(',')}]`);
    }

    // Query mediaFiles table (exclude large binary fields)
    const mediaFilesQuery = db.select({
      id: mediaFiles.id,
      filename: mediaFiles.filename,
      originalName: mediaFiles.originalName,
      mimeType: mediaFiles.mimeType,
      fileSize: mediaFiles.fileSize,
      sha256Hash: mediaFiles.sha256Hash,
      uploadedBy: mediaFiles.uploadedBy,
      storageType: mediaFiles.storageType,
      filePath: mediaFiles.filePath,
      fileEncryptionKey: mediaFiles.fileEncryptionKey,
      width: mediaFiles.width,
      height: mediaFiles.height,
      duration: mediaFiles.duration,
      metadata: mediaFiles.metadata,
      isEncrypted: mediaFiles.isEncrypted,
      encryptionKey: mediaFiles.encryptionKey,
      tags: mediaFiles.tags,
      isFavorite: mediaFiles.isFavorite,
      isDeleted: mediaFiles.isDeleted,
      createdAt: mediaFiles.createdAt,
      updatedAt: mediaFiles.updatedAt,
    })
      .from(mediaFiles)
      .where(and(...mediaFilesConditions));

    // Only fetch from files table (media files have been migrated)
    const fileResults = await filesQuery;

    // Use only files table results  
    let allFiles = fileResults as File[];

    // Apply sorting to combined results
    allFiles.sort((a, b) => {
      let compareValue = 0;
      if (sortBy === 'created_at') {
        const aTime = a.createdAt ? new Date(a.createdAt).getTime() : 0;
        const bTime = b.createdAt ? new Date(b.createdAt).getTime() : 0;
        compareValue = aTime - bTime;
      } else if (sortBy === 'filename') {
        compareValue = a.filename.localeCompare(b.filename);
      } else if (sortBy === 'file_size') {
        compareValue = a.fileSize - b.fileSize;
      }
      return sortOrder === 'asc' ? compareValue : -compareValue;
    });

    // Apply pagination to combined results
    const total = allFiles.length;
    const paginatedFiles = allFiles.slice(offset, offset + limit);

    return { files: paginatedFiles, total };
  }

  async getFile(id: string): Promise<File | undefined> {
    const [file] = await db.select().from(files).where(eq(files.id, id));
    return file;
  }

  async getFileByHash(hash: string, userId: string): Promise<File | undefined> {
    const [file] = await db.select()
      .from(files)
      .where(
        and(
          eq(files.sha256Hash, hash),
          eq(files.userId, userId),
          eq(files.isDeleted, false)
        )
      );
    return file;
  }

  async getFileBinaryData(id: string): Promise<{ binaryData: Buffer | null; mimeType: string } | undefined> {
    const [file] = await db.select({
      binaryData: files.binaryData,
      mimeType: files.mimeType,
    }).from(files).where(eq(files.id, id));
    return file;
  }

  async getFileThumbnail(id: string): Promise<{ thumbnailData: Buffer | null; mimeType: string } | undefined> {
    const [file] = await db.select({
      thumbnailData: files.thumbnailData,
      mimeType: files.mimeType,
    }).from(files).where(eq(files.id, id));
    return file;
  }

  async createFile(file: InsertFile): Promise<File> {
    const [newFile] = await db.insert(files).values(file).returning();
    return newFile;
  }

  async updateFile(id: string, updates: Partial<File>): Promise<File | undefined> {
    const [updated] = await db
      .update(files)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(files.id, id))
      .returning();
    return updated;
  }

  async deleteFile(id: string): Promise<boolean> {
    const [updated] = await db
      .update(files)
      .set({ isDeleted: true, deletedAt: new Date(), updatedAt: new Date() })
      .where(eq(files.id, id))
      .returning();
    return !!updated;
  }

  async moveFileToFolder(fileId: string, folderId: string | null): Promise<boolean> {
    const [updated] = await db
      .update(files)
      .set({ folderId, updatedAt: new Date() })
      .where(eq(files.id, fileId))
      .returning();
    return !!updated;
  }

  async copyFile(fileId: string, targetFolderId: string | null): Promise<File | undefined> {
    const original = await this.getFile(fileId);
    if (!original) return undefined;
    
    // Create a copy with a new name
    const copyName = `Copy of ${original.originalName}`;
    const newFile = {
      ...original,
      id: undefined, // Let DB generate new ID
      filename: `copy_${Date.now()}_${original.filename}`,
      originalName: copyName,
      folderId: targetFolderId,
      createdAt: undefined, // Let DB set new timestamp
      updatedAt: undefined, // Let DB set new timestamp
    };
    
    delete newFile.id;
    delete newFile.createdAt;
    delete newFile.updatedAt;
    
    return await this.createFile(newFile as InsertFile);
  }

  async bulkOperation(
    operation: 'delete' | 'move' | 'copy' | 'tag',
    fileIds: string[],
    options?: any
  ): Promise<{ success: number; failed: number }> {
    let success = 0;
    let failed = 0;
    
    for (const fileId of fileIds) {
      try {
        switch (operation) {
          case 'delete':
            if (await this.deleteFile(fileId)) success++;
            else failed++;
            break;
          case 'move':
            if (options?.targetFolderId !== undefined) {
              if (await this.moveFileToFolder(fileId, options.targetFolderId)) success++;
              else failed++;
            } else {
              failed++;
            }
            break;
          case 'copy':
            if (options?.targetFolderId !== undefined) {
              const copied = await this.copyFile(fileId, options.targetFolderId);
              if (copied) success++;
              else failed++;
            } else {
              failed++;
            }
            break;
          case 'tag':
            if (options?.tagIds) {
              for (const tagId of options.tagIds) {
                await this.tagFile(fileId, tagId);
              }
              success++;
            } else {
              failed++;
            }
            break;
          default:
            failed++;
        }
      } catch (error) {
        failed++;
      }
    }
    
    return { success, failed };
  }

  // Album operations
  async getAlbums(userId: string): Promise<Album[]> {
    return await db
      .select()
      .from(albums)
      .where(eq(albums.userId, userId))
      .orderBy(asc(albums.sortOrder), desc(albums.createdAt));
  }

  async getAlbum(id: string): Promise<Album | undefined> {
    const [album] = await db.select().from(albums).where(eq(albums.id, id));
    return album;
  }

  async createAlbum(album: InsertAlbum): Promise<Album> {
    const [newAlbum] = await db.insert(albums).values(album).returning();
    return newAlbum;
  }

  async updateAlbum(id: string, updates: Partial<Album>): Promise<Album | undefined> {
    const [updated] = await db
      .update(albums)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(albums.id, id))
      .returning();
    return updated;
  }

  async deleteAlbum(id: string): Promise<boolean> {
    // First delete all album-file relationships
    await db.delete(albumFiles).where(eq(albumFiles.albumId, id));
    
    // Then delete the album
    const result = await db.delete(albums).where(eq(albums.id, id));
    return result.rowCount! > 0;
  }

  async addFileToAlbum(albumId: string, fileId: string, sortOrder: number = 0): Promise<AlbumFile> {
    const [albumFile] = await db
      .insert(albumFiles)
      .values({ albumId, fileId, sortOrder })
      .returning();
    return albumFile;
  }

  async removeFileFromAlbum(albumId: string, fileId: string): Promise<boolean> {
    const result = await db
      .delete(albumFiles)
      .where(and(
        eq(albumFiles.albumId, albumId),
        eq(albumFiles.fileId, fileId)
      ));
    return result.rowCount! > 0;
  }

  async getAlbumFiles(albumId: string): Promise<{ album: Album; files: File[] }> {
    const album = await this.getAlbum(albumId);
    if (!album) {
      throw new Error(`Album with id ${albumId} not found`);
    }
    
    const albumFileRelations = await db
      .select({ fileId: albumFiles.fileId })
      .from(albumFiles)
      .where(eq(albumFiles.albumId, albumId))
      .orderBy(asc(albumFiles.sortOrder));
    
    const fileIds = albumFileRelations.map(af => af.fileId);
    
    const filesResult = fileIds.length > 0
      ? await db.select().from(files).where(sql`${files.id} = ANY(${fileIds})`)
      : [];
    
    return { album, files: filesResult };
  }

  // Tag operations
  async getTags(userId: string): Promise<Tag[]> {
    return await db
      .select()
      .from(tags)
      .where(eq(tags.userId, userId))
      .orderBy(desc(tags.usageCount), asc(tags.name));
  }

  async getTag(id: string): Promise<Tag | undefined> {
    const [tag] = await db.select().from(tags).where(eq(tags.id, id));
    return tag;
  }

  async createTag(tag: InsertTag): Promise<Tag> {
    const [newTag] = await db.insert(tags).values(tag).returning();
    return newTag;
  }

  async updateTag(id: string, updates: Partial<Tag>): Promise<Tag | undefined> {
    const [updated] = await db
      .update(tags)
      .set(updates)
      .where(eq(tags.id, id))
      .returning();
    return updated;
  }

  async deleteTag(id: string): Promise<boolean> {
    // First delete all file-tag relationships
    await db.delete(fileTags).where(eq(fileTags.tagId, id));
    
    // Then delete the tag
    const result = await db.delete(tags).where(eq(tags.id, id));
    return result.rowCount! > 0;
  }

  async tagFile(fileId: string, tagId: string): Promise<FileTag> {
    // Update tag usage count
    await db
      .update(tags)
      .set({ usageCount: sql`${tags.usageCount} + 1` })
      .where(eq(tags.id, tagId));
    
    const [fileTag] = await db
      .insert(fileTags)
      .values({ fileId, tagId })
      .onConflictDoNothing()
      .returning();
    return fileTag;
  }

  async untagFile(fileId: string, tagId: string): Promise<boolean> {
    const result = await db
      .delete(fileTags)
      .where(and(
        eq(fileTags.fileId, fileId),
        eq(fileTags.tagId, tagId)
      ));
    
    if (result.rowCount! > 0) {
      // Update tag usage count
      await db
        .update(tags)
        .set({ usageCount: sql`GREATEST(${tags.usageCount} - 1, 0)` })
        .where(eq(tags.id, tagId));
    }
    
    return result.rowCount! > 0;
  }

  async getFileTags(fileId: string): Promise<Tag[]> {
    const fileTagRelations = await db
      .select({ tagId: fileTags.tagId })
      .from(fileTags)
      .where(eq(fileTags.fileId, fileId));
    
    const tagIds = fileTagRelations.map(ft => ft.tagId);
    
    return tagIds.length > 0
      ? await db.select().from(tags).where(sql`${tags.id} = ANY(${tagIds})`)
      : [];
  }

  async getFilesByTag(tagId: string, userId: string): Promise<File[]> {
    const fileTagRelations = await db
      .select({ fileId: fileTags.fileId })
      .from(fileTags)
      .where(eq(fileTags.tagId, tagId));
    
    const fileIds = fileTagRelations.map(ft => ft.fileId);
    
    return fileIds.length > 0
      ? await db
          .select()
          .from(files)
          .where(and(
            sql`${files.id} = ANY(${fileIds})`,
            eq(files.userId, userId),
            eq(files.isDeleted, false)
          ))
      : [];
  }

  // Permission operations
  async getPermissions(userId: string, resourceType?: string, resourceId?: string): Promise<Permission[]> {
    const conditions = [eq(permissions.userId, userId)];
    
    if (resourceType) {
      conditions.push(eq(permissions.resourceType, resourceType));
    }
    
    if (resourceId) {
      conditions.push(eq(permissions.resourceId, resourceId));
    }
    
    return await db
      .select()
      .from(permissions)
      .where(and(...conditions));
  }

  async grantPermission(permission: InsertPermission): Promise<Permission> {
    const [newPermission] = await db
      .insert(permissions)
      .values(permission)
      .onConflictDoUpdate({
        target: [permissions.userId, permissions.resourceType, permissions.resourceId],
        set: {
          ...permission,
          createdAt: new Date(),
        },
      })
      .returning();
    return newPermission;
  }

  async revokePermission(id: string): Promise<boolean> {
    const result = await db.delete(permissions).where(eq(permissions.id, id));
    return result.rowCount! > 0;
  }

  async checkPermission(
    userId: string,
    resourceType: string,
    resourceId: string,
    action: 'view' | 'edit' | 'delete' | 'share'
  ): Promise<boolean> {
    const [permission] = await db
      .select()
      .from(permissions)
      .where(and(
        eq(permissions.userId, userId),
        eq(permissions.resourceType, resourceType),
        eq(permissions.resourceId, resourceId),
        or(
          isNull(permissions.expiresAt),
          sql`${permissions.expiresAt} > NOW()`
        )!
      ));
    
    if (!permission) return false;
    
    switch (action) {
      case 'view':
        return permission.canView ?? false;
      case 'edit':
        return permission.canEdit ?? false;
      case 'delete':
        return permission.canDelete ?? false;
      case 'share':
        return permission.canShare ?? false;
      default:
        return false;
    }
  }

  // Admin migration operations
  // Playlist operations
  async createPlaylist(playlist: InsertPlaylist): Promise<Playlist> {
    const [newPlaylist] = await db.insert(playlists).values(playlist).returning();
    return newPlaylist;
  }

  async getPlaylists(userId: string): Promise<Playlist[]> {
    return await db.select().from(playlists)
      .where(eq(playlists.userId, userId))
      .orderBy(desc(playlists.createdAt));
  }

  async getPlaylist(id: string): Promise<Playlist | undefined> {
    const [playlist] = await db.select().from(playlists).where(eq(playlists.id, id));
    return playlist;
  }

  async updatePlaylist(id: string, updates: Partial<Playlist>): Promise<Playlist | undefined> {
    const [updated] = await db
      .update(playlists)
      .set({ ...updates, updatedAt: new Date() })
      .where(eq(playlists.id, id))
      .returning();
    return updated;
  }

  async deletePlaylist(id: string): Promise<boolean> {
    // Delete all tracks from the playlist first
    await db.delete(playlistTracks).where(eq(playlistTracks.playlistId, id));
    
    // Delete the playlist
    const result = await db.delete(playlists).where(eq(playlists.id, id));
    return result.rowCount ? result.rowCount > 0 : false;
  }

  async addTrackToPlaylist(playlistId: string, fileId: string, position?: number, addedBy?: string): Promise<PlaylistTrack> {
    // Get the max position if not specified
    if (!position) {
      const [maxPos] = await db.select({ maxPosition: sql<number>`COALESCE(MAX(position), 0)` })
        .from(playlistTracks)
        .where(eq(playlistTracks.playlistId, playlistId));
      position = (maxPos?.maxPosition || 0) + 1;
    }
    
    const [track] = await db.insert(playlistTracks).values({
      playlistId,
      fileId,
      position,
      addedBy: addedBy || '',
    }).returning();
    
    // Update playlist total duration
    await this.updatePlaylistDuration(playlistId);
    
    return track;
  }

  async removeTrackFromPlaylist(playlistId: string, fileId: string): Promise<boolean> {
    const result = await db.delete(playlistTracks)
      .where(and(
        eq(playlistTracks.playlistId, playlistId),
        eq(playlistTracks.fileId, fileId)
      ));
    
    // Update playlist total duration
    await this.updatePlaylistDuration(playlistId);
    
    return result.rowCount ? result.rowCount > 0 : false;
  }

  async reorderPlaylistTracks(playlistId: string, trackId: string, newPosition: number): Promise<boolean> {
    // Get the current track
    const [track] = await db.select()
      .from(playlistTracks)
      .where(and(
        eq(playlistTracks.playlistId, playlistId),
        eq(playlistTracks.id, trackId)
      ));
    
    if (!track) return false;
    
    const oldPosition = track.position;
    
    // Update positions for affected tracks
    if (newPosition < oldPosition) {
      // Moving up - increment positions of tracks in between
      await db.update(playlistTracks)
        .set({ position: sql`position + 1` })
        .where(and(
          eq(playlistTracks.playlistId, playlistId),
          sql`position >= ${newPosition} AND position < ${oldPosition}`
        ));
    } else if (newPosition > oldPosition) {
      // Moving down - decrement positions of tracks in between
      await db.update(playlistTracks)
        .set({ position: sql`position - 1` })
        .where(and(
          eq(playlistTracks.playlistId, playlistId),
          sql`position > ${oldPosition} AND position <= ${newPosition}`
        ));
    }
    
    // Update the track's position
    await db.update(playlistTracks)
      .set({ position: newPosition })
      .where(eq(playlistTracks.id, trackId));
    
    return true;
  }

  async getPlaylistTracks(playlistId: string): Promise<{ playlist: Playlist; tracks: File[] }> {
    const playlist = await this.getPlaylist(playlistId);
    if (!playlist) {
      throw new Error('Playlist not found');
    }
    
    // Get tracks with file details
    const tracksWithFiles = await db.select({
      file: files,
      position: playlistTracks.position
    })
      .from(playlistTracks)
      .innerJoin(files, eq(playlistTracks.fileId, files.id))
      .where(eq(playlistTracks.playlistId, playlistId))
      .orderBy(asc(playlistTracks.position));
    
    const tracks = tracksWithFiles.map(t => t.file);
    
    return { playlist, tracks };
  }
  
  // Helper to update playlist duration
  private async updatePlaylistDuration(playlistId: string): Promise<void> {
    const [totalDuration] = await db.select({
      total: sql<number>`COALESCE(SUM(${files.duration}), 0)`
    })
      .from(playlistTracks)
      .innerJoin(files, eq(playlistTracks.fileId, files.id))
      .where(eq(playlistTracks.playlistId, playlistId));
    
    await db.update(playlists)
      .set({ totalDuration: totalDuration?.total || 0 })
      .where(eq(playlists.id, playlistId));
  }
  
  // Play history operations
  async recordPlay(history: InsertPlayHistory): Promise<PlayHistory> {
    const [record] = await db.insert(playHistory).values(history).returning();
    
    // Update playlist play count if playing from a playlist
    if (history.playlistId) {
      await db.update(playlists)
        .set({ playCount: sql`play_count + 1` })
        .where(eq(playlists.id, history.playlistId));
    }
    
    return record;
  }

  async getRecentlyPlayed(userId: string, limit: number = 20): Promise<File[]> {
    const recentlyPlayed = await db.selectDistinct({
      file: files,
      playedAt: playHistory.playedAt
    })
      .from(playHistory)
      .innerJoin(files, eq(playHistory.fileId, files.id))
      .where(eq(playHistory.userId, userId))
      .orderBy(desc(playHistory.playedAt))
      .limit(limit);
    
    return recentlyPlayed.map(r => r.file);
  }

  async getMostPlayed(userId: string, limit: number = 20): Promise<{ file: File; playCount: number }[]> {
    const mostPlayed = await db.select({
      file: files,
      playCount: sql<number>`COUNT(*)::int`
    })
      .from(playHistory)
      .innerJoin(files, eq(playHistory.fileId, files.id))
      .where(eq(playHistory.userId, userId))
      .groupBy(files.id)
      .orderBy(desc(sql`COUNT(*)`))
      .limit(limit);
    
    return mostPlayed;
  }

  async syncMediaFilesToFilesTable(): Promise<{ synced: number; skipped: number; total: number }> {
    try {
      // Fetch all media files
      const allMediaFiles = await db.select().from(mediaFiles).where(eq(mediaFiles.isDeleted, false));
      
      let synced = 0;
      let skipped = 0;
      
      for (const media of allMediaFiles) {
        // Check if file already exists in files table
        const existingFile = await db.select().from(files).where(eq(files.id, media.id)).limit(1);
        
        if (existingFile.length > 0) {
          skipped++;
          continue;
        }
        
        // Determine file type from mime type
        let fileType: string | undefined;
        if (media.mimeType.startsWith('image/')) {
          fileType = 'image';
        } else if (media.mimeType.startsWith('video/')) {
          fileType = 'video';
        } else if (media.mimeType.startsWith('audio/')) {
          fileType = 'audio';
        } else if (media.mimeType.startsWith('application/pdf')) {
          fileType = 'document';
        } else if (media.mimeType.includes('zip') || media.mimeType.includes('tar') || media.mimeType.includes('rar')) {
          fileType = 'archive';
        } else {
          fileType = 'other';
        }
        
        // Create file entry from media
        await db.insert(files).values({
          id: media.id, // Reuse the same ID
          filename: media.filename,
          originalName: media.originalName,
          mimeType: media.mimeType,
          fileType: fileType,
          fileSize: media.fileSize,
          sha256Hash: media.sha256Hash,
          folderId: null, // Root level
          userId: media.uploadedBy,
          storageType: media.storageType || 'database',
          binaryData: media.binaryData,
          filePath: media.filePath,
          description: null,
          notes: null,
          customMetadata: null,
          exifData: media.metadata, // Transfer EXIF data
          width: media.width,
          height: media.height,
          duration: media.duration,
          thumbnailData: media.thumbnailData || media.thumbnailWebp || media.thumbnailAvif, // Use any available thumbnail
          pageCount: null,
          wordCount: null,
          isEncrypted: media.isEncrypted,
          encryptionKey: media.encryptionKey,
          tags: media.tags,
          isFavorite: media.isFavorite,
          isDeleted: media.isDeleted,
          deletedAt: null,
          version: 1,
          previousVersionId: null,
          createdAt: media.createdAt,
          updatedAt: media.updatedAt,
        });
        
        synced++;
      }
      
      return {
        synced,
        skipped,
        total: allMediaFiles.length
      };
    } catch (error) {
      console.error('Error syncing media files to files table:', error);
      throw error;
    }
  }

  // User management operations (admin only)
  async getAllUsers(): Promise<{ users: User[]; total: number }> {
    try {
      const allUsers = await db.select().from(users)
        .orderBy(desc(users.lastLoginAt), asc(users.createdAt));
      
      return {
        users: allUsers,
        total: allUsers.length
      };
    } catch (error) {
      console.error('Error fetching all users:', error);
      throw error;
    }
  }

  async updateUserRole(userId: string, role: string): Promise<User | undefined> {
    try {
      // Validate role
      const validRoles = ['user', 'admin', 'moderator', 'viewer'];
      if (!validRoles.includes(role)) {
        throw new Error(`Invalid role: ${role}. Must be one of: ${validRoles.join(', ')}`);
      }

      const [updated] = await db
        .update(users)
        .set({ role, updatedAt: new Date() })
        .where(eq(users.id, userId))
        .returning();
      
      return updated;
    } catch (error) {
      console.error('Error updating user role:', error);
      throw error;
    }
  }

  async deleteUser(userId: string): Promise<{ success: boolean; filesDeleted: number; foldersDeleted: number }> {
    try {
      // Count and delete user's files
      const [fileCount] = await db.select({ count: count() })
        .from(files)
        .where(eq(files.userId, userId));
      
      const filesDeleted = Number(fileCount.count) || 0;
      
      if (filesDeleted > 0) {
        await db.delete(files).where(eq(files.userId, userId));
      }

      // Count and delete user's folders
      const [folderCount] = await db.select({ count: count() })
        .from(folders)
        .where(eq(folders.userId, userId));
      
      const foldersDeleted = Number(folderCount.count) || 0;
      
      if (foldersDeleted > 0) {
        await db.delete(folders).where(eq(folders.userId, userId));
      }

      // Delete user's albums
      await db.delete(albums).where(eq(albums.userId, userId));
      
      // Delete user's playlists
      await db.delete(playlists).where(eq(playlists.userId, userId));
      
      // Delete user's tags
      await db.delete(tags).where(eq(tags.userId, userId));
      
      // Delete user's media files
      await db.delete(mediaFiles).where(eq(mediaFiles.uploadedBy, userId));
      
      // Delete user's activity logs
      await db.delete(activityLogs).where(eq(activityLogs.userId, userId));
      
      // Finally, delete the user
      await db.delete(users).where(eq(users.id, userId));
      
      return {
        success: true,
        filesDeleted,
        foldersDeleted
      };
    } catch (error) {
      console.error('Error deleting user:', error);
      return {
        success: false,
        filesDeleted: 0,
        foldersDeleted: 0
      };
    }
  }

  async getUserStats(userId: string): Promise<{
    storageUsed: number;
    storageQuota: number;
    totalFiles: number;
    totalMediaFiles: number;
    totalFolders: number;
    totalAlbums: number;
    totalPlaylists: number;
    lastActivity: Date | null;
    accountCreated: Date;
  }> {
    try {
      // Get user data
      const user = await this.getUser(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Get file counts and storage used
      const [fileStats] = await db.select({
        count: count(),
        totalSize: sql<number>`COALESCE(SUM(${files.fileSize}), 0)`
      })
        .from(files)
        .where(eq(files.userId, userId));

      // Get media file count
      const [mediaStats] = await db.select({ count: count() })
        .from(mediaFiles)
        .where(eq(mediaFiles.uploadedBy, userId));

      // Get folder count
      const [folderStats] = await db.select({ count: count() })
        .from(folders)
        .where(eq(folders.userId, userId));

      // Get album count
      const [albumStats] = await db.select({ count: count() })
        .from(albums)
        .where(eq(albums.userId, userId));

      // Get playlist count
      const [playlistStats] = await db.select({ count: count() })
        .from(playlists)
        .where(eq(playlists.userId, userId));

      // Get last activity
      const [lastActivityLog] = await db.select()
        .from(activityLogs)
        .where(eq(activityLogs.userId, userId))
        .orderBy(desc(activityLogs.createdAt))
        .limit(1);

      return {
        storageUsed: user.storageUsed || Number(fileStats.totalSize) || 0,
        storageQuota: user.storageQuota || 2147483647,
        totalFiles: Number(fileStats.count) || 0,
        totalMediaFiles: Number(mediaStats.count) || 0,
        totalFolders: Number(folderStats.count) || 0,
        totalAlbums: Number(albumStats.count) || 0,
        totalPlaylists: Number(playlistStats.count) || 0,
        lastActivity: lastActivityLog?.createdAt || user.lastLoginAt || null,
        accountCreated: user.createdAt || new Date()
      };
    } catch (error) {
      console.error('Error getting user stats:', error);
      throw error;
    }
  }

  async cleanupDuplicateCategories(): Promise<{ removed: number; kept: number; updated: number }> {
    try {
      // Get all categories grouped by name (case-insensitive)
      const allCategories = await db.select().from(categories).orderBy(asc(categories.createdAt));
      
      // Group categories by lowercase name
      const categoryGroups = new Map<string, Category[]>();
      for (const category of allCategories) {
        const key = category.name.toLowerCase().trim();
        if (!categoryGroups.has(key)) {
          categoryGroups.set(key, []);
        }
        categoryGroups.get(key)!.push(category);
      }
      
      let removed = 0;
      let kept = 0;
      let updated = 0;
      
      // Process each group of duplicates
      for (const [name, group] of Array.from(categoryGroups.entries())) {
        if (group.length <= 1) {
          kept++;
          continue; // No duplicates
        }
        
        // Keep the first (oldest) category
        const categoryToKeep = group[0];
        kept++;
        
        // Remove the rest and update references
        for (let i = 1; i < group.length; i++) {
          const categoryToRemove = group[i];
          
          // Update media files to reference the kept category
          const updateResult = await db
            .update(mediaFiles)
            .set({ categoryId: categoryToKeep.id })
            .where(eq(mediaFiles.categoryId, categoryToRemove.id));
          
          // Count how many media files were updated
          if (updateResult.rowCount && updateResult.rowCount > 0) {
            updated += updateResult.rowCount;
          }
          
          // Update child categories to reference the kept category
          await db
            .update(categories)
            .set({ parentId: categoryToKeep.id })
            .where(eq(categories.parentId, categoryToRemove.id));
          
          // Delete the duplicate category
          await db.delete(categories).where(eq(categories.id, categoryToRemove.id));
          removed++;
        }
      }
      
      return {
        removed,
        kept,
        updated
      };
    } catch (error) {
      console.error('Error cleaning up duplicate categories:', error);
      throw error;
    }
  }
}

export const storage = new DatabaseStorage();
