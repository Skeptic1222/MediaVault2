import { sql, relations } from 'drizzle-orm';
import {
  index,
  jsonb,
  pgTable,
  timestamp,
  varchar,
  text,
  integer,
  boolean,
  uuid,
  customType,
  unique,
} from "drizzle-orm/pg-core";

// Custom bytea type for binary data storage
const bytea = customType<{ data: Buffer; notNull: false; default: false }>({
  dataType() {
    return 'bytea';
  },
  toDriver(value: Buffer) {
    return value;
  },
  fromDriver(value: unknown) {
    return value as Buffer;
  },
});
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Session storage table (mandatory for Replit Auth)
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

// User storage table (mandatory for Replit Auth)
export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  role: varchar("role").default("user"), // user, admin, moderator, viewer
  vaultPassphrase: varchar("vault_passphrase"), // encrypted vault access
  storageQuota: integer("storage_quota").default(2147483647), // 2GB default (max integer)
  storageUsed: integer("storage_used").default(0),
  preferences: jsonb("preferences"), // User preferences (theme, view modes, etc.)
  isActive: boolean("is_active").default(true),
  lastLoginAt: timestamp("last_login_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Categories table for hierarchical organization
export const categories = pgTable("categories", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name", { length: 255 }).notNull(),
  slug: varchar("slug", { length: 255 }).unique().notNull(),
  description: text("description"),
  parentId: uuid("parent_id"),
  icon: varchar("icon", { length: 50 }),
  isVault: boolean("is_vault").default(false),
  sortOrder: integer("sort_order").default(0),
  // Enhanced metadata fields
  location: varchar("location", { length: 500 }), // e.g., "Germany", "Berlin, Germany"
  eventDate: timestamp("event_date"), // Date of the event/trip
  dateRange: varchar("date_range", { length: 100 }), // e.g., "July 2023" or "2023-07-01 to 2023-07-14"
  tags: text("tags").array(), // Additional tags like ["vacation", "family", "europe"]
  metadata: jsonb("metadata"), // Flexible JSON storage for additional details
  color: varchar("color", { length: 7 }).default("#6b7280"), // Hex color for UI organization
  folderPath: varchar("folder_path", { length: 1000 }), // Original folder path from import
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Media files table with binary storage
export const mediaFiles = pgTable("media_files", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  filename: varchar("filename", { length: 500 }).notNull(),
  originalName: varchar("original_name", { length: 500 }).notNull(),
  mimeType: varchar("mime_type", { length: 100 }).notNull(),
  fileSize: integer("file_size").notNull(),
  sha256Hash: varchar("sha256_hash", { length: 64 }).notNull(),
  binaryData: bytea("binary_data"), // nullable for filesystem storage
  // Filesystem storage fields
  storageType: varchar("storage_type", { length: 20 }).default("database"), // "database" | "filesystem" | "chunked"
  filePath: varchar("file_path", { length: 1000 }), // encrypted file path on disk
  fileEncryptionKey: varchar("file_encryption_key"), // AES key for filesystem encryption
  // Chunked encryption fields
  filenameKeyWrapped: varchar("filename_key_wrapped"), // Wrapped key for filename encryption
  encryptedFilename: varchar("encrypted_filename", { length: 1000 }), // Encrypted original filename
  chunkMetadata: jsonb("chunk_metadata"), // Metadata for chunked storage
  width: integer("width"),
  height: integer("height"),
  duration: integer("duration"), // for videos in seconds
  thumbnailData: bytea("thumbnail_data"), // JPEG thumbnail (backward compatibility)
  thumbnailWebp: bytea("thumbnail_webp"), // WebP thumbnail for better compression
  thumbnailAvif: bytea("thumbnail_avif"), // AVIF thumbnail for modern browsers
  metadata: jsonb("metadata"), // EXIF, location, etc.
  isEncrypted: boolean("is_encrypted").default(false),
  encryptionKey: varchar("encryption_key"), // encrypted with vault passphrase
  categoryId: uuid("category_id"),
  uploadedBy: varchar("uploaded_by").notNull(),
  importSource: varchar("import_source"), // google_photos, manual, etc.
  tags: text("tags").array(),
  isFavorite: boolean("is_favorite").default(false),
  isDeleted: boolean("is_deleted").default(false),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_media_files_sha256").on(table.sha256Hash),
  index("idx_media_files_category").on(table.categoryId),
  index("idx_media_files_uploaded_by").on(table.uploadedBy),
  index("idx_media_files_created_at").on(table.createdAt),
  unique("unique_media_files_sha256_uploaded_by").on(table.sha256Hash, table.uploadedBy),
]);

// Import batches for tracking Google Photos imports
export const importBatches = pgTable("import_batches", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  source: varchar("source", { length: 50 }).notNull(), // google_photos, manual
  status: varchar("status", { length: 20 }).default("pending"), // pending, processing, completed, failed
  totalFiles: integer("total_files").default(0),
  processedFiles: integer("processed_files").default(0),
  duplicatesFound: integer("duplicates_found").default(0),
  errors: jsonb("errors"),
  settings: jsonb("settings"), // import configuration
  userId: varchar("user_id").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// User activity logs for security auditing
export const activityLogs = pgTable("activity_logs", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  action: varchar("action", { length: 100 }).notNull(),
  resource: varchar("resource", { length: 100 }),
  resourceId: varchar("resource_id"),
  ipAddress: varchar("ip_address", { length: 45 }),
  userAgent: text("user_agent"),
  metadata: jsonb("metadata"),
  createdAt: timestamp("created_at").defaultNow(),
});

// Folders table for hierarchical file organization
export const folders = pgTable("folders", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name", { length: 255 }).notNull(),
  parentId: uuid("parent_id"),
  userId: varchar("user_id").notNull(),
  path: text("path"), // Full path like /root/folder1/subfolder
  description: text("description"),
  color: varchar("color", { length: 7 }),
  icon: varchar("icon", { length: 50 }),
  sortOrder: integer("sort_order").default(0),
  isShared: boolean("is_shared").default(false),
  shareSettings: jsonb("share_settings"), // Sharing permissions and settings
  metadata: jsonb("metadata"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_folders_user").on(table.userId),
  index("idx_folders_parent").on(table.parentId),
  index("idx_folders_path").on(table.path),
]);

// Generic files table (extends mediaFiles concept)
export const files = pgTable("files", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  filename: varchar("filename", { length: 500 }).notNull(),
  originalName: varchar("original_name", { length: 500 }).notNull(),
  mimeType: varchar("mime_type", { length: 100 }).notNull(),
  fileType: varchar("file_type", { length: 50 }), // image, video, document, audio, archive, etc.
  fileSize: integer("file_size").notNull(),
  sha256Hash: varchar("sha256_hash", { length: 64 }).notNull(),
  folderId: uuid("folder_id"),
  userId: varchar("user_id").notNull(),
  // Storage fields
  storageType: varchar("storage_type", { length: 20 }).default("database"),
  binaryData: bytea("binary_data"),
  filePath: varchar("file_path", { length: 1000 }),
  // Metadata
  description: text("description"),
  notes: text("notes"),
  customMetadata: jsonb("custom_metadata"), // User-defined metadata fields
  exifData: jsonb("exif_data"),
  // Media-specific fields
  width: integer("width"),
  height: integer("height"),
  duration: integer("duration"),
  thumbnailData: bytea("thumbnail_data"),
  // Document-specific fields
  pageCount: integer("page_count"),
  wordCount: integer("word_count"),
  // Security
  isEncrypted: boolean("is_encrypted").default(false),
  encryptionKey: varchar("encryption_key"),
  // Organization
  tags: text("tags").array(),
  isFavorite: boolean("is_favorite").default(false),
  isDeleted: boolean("is_deleted").default(false),
  deletedAt: timestamp("deleted_at"),
  // Versioning
  version: integer("version").default(1),
  previousVersionId: uuid("previous_version_id"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_files_folder").on(table.folderId),
  index("idx_files_user").on(table.userId),
  index("idx_files_hash").on(table.sha256Hash),
  index("idx_files_type").on(table.fileType),
  unique("unique_files_hash_user").on(table.sha256Hash, table.userId),
]);

// Albums/Collections for curated file groups
export const albums = pgTable("albums", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  userId: varchar("user_id").notNull(),
  coverImageId: uuid("cover_image_id"), // Reference to files table
  isPublic: boolean("is_public").default(false),
  shareLink: varchar("share_link", { length: 100 }).unique(),
  sortOrder: integer("sort_order").default(0),
  metadata: jsonb("metadata"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_albums_user").on(table.userId),
]);

// Album-file relationship
export const albumFiles = pgTable("album_files", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  albumId: uuid("album_id").notNull(),
  fileId: uuid("file_id").notNull(),
  sortOrder: integer("sort_order").default(0),
  addedAt: timestamp("added_at").defaultNow(),
}, (table) => [
  index("idx_album_files_album").on(table.albumId),
  index("idx_album_files_file").on(table.fileId),
  unique("unique_album_file").on(table.albumId, table.fileId),
]);

// Tags table for flexible tagging
export const tags = pgTable("tags", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name", { length: 100 }).notNull(),
  userId: varchar("user_id").notNull(),
  color: varchar("color", { length: 7 }),
  description: text("description"),
  usageCount: integer("usage_count").default(0),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_tags_user").on(table.userId),
  unique("unique_tag_name_user").on(table.name, table.userId),
]);

// File-tag relationship
export const fileTags = pgTable("file_tags", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  fileId: uuid("file_id").notNull(),
  tagId: uuid("tag_id").notNull(),
  addedAt: timestamp("added_at").defaultNow(),
}, (table) => [
  index("idx_file_tags_file").on(table.fileId),
  index("idx_file_tags_tag").on(table.tagId),
  unique("unique_file_tag").on(table.fileId, table.tagId),
]);

// Smart folders with auto-updating rules
export const smartFolders = pgTable("smart_folders", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  name: varchar("name", { length: 255 }).notNull(),
  userId: varchar("user_id").notNull(),
  rules: jsonb("rules").notNull(), // JSON rules for filtering
  icon: varchar("icon", { length: 50 }),
  color: varchar("color", { length: 7 }),
  description: text("description"),
  isActive: boolean("is_active").default(true),
  lastUpdated: timestamp("last_updated"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_smart_folders_user").on(table.userId),
]);

// User permissions for granular access control
export const permissions = pgTable("permissions", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  resourceType: varchar("resource_type", { length: 50 }).notNull(), // folder, file, album
  resourceId: uuid("resource_id").notNull(),
  canView: boolean("can_view").default(true),
  canEdit: boolean("can_edit").default(false),
  canDelete: boolean("can_delete").default(false),
  canShare: boolean("can_share").default(false),
  grantedBy: varchar("granted_by").notNull(),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_permissions_user").on(table.userId),
  index("idx_permissions_resource").on(table.resourceType, table.resourceId),
  unique("unique_user_resource_permission").on(table.userId, table.resourceType, table.resourceId),
]);

// System settings for admin configuration
export const systemSettings = pgTable("system_settings", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  key: varchar("key", { length: 100 }).unique().notNull(),
  value: jsonb("value").notNull(),
  description: text("description"),
  category: varchar("category", { length: 50 }), // branding, features, security, etc.
  isPublic: boolean("is_public").default(false), // Whether setting is visible to non-admins
  updatedBy: varchar("updated_by"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Share links for public/guest access
export const shareLinks = pgTable("share_links", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  code: varchar("code", { length: 100 }).unique().notNull(),
  resourceType: varchar("resource_type", { length: 50 }).notNull(), // folder, file, album
  resourceId: uuid("resource_id").notNull(),
  createdBy: varchar("created_by").notNull(),
  password: varchar("password"), // Optional password protection
  permissions: jsonb("permissions"), // What the link allows
  maxUses: integer("max_uses"),
  usageCount: integer("usage_count").default(0),
  expiresAt: timestamp("expires_at"),
  lastAccessedAt: timestamp("last_accessed_at"),
  createdAt: timestamp("created_at").defaultNow(),
}, (table) => [
  index("idx_share_links_resource").on(table.resourceType, table.resourceId),
  index("idx_share_links_creator").on(table.createdBy),
]);

// Playlists table for organizing audio files
export const playlists = pgTable("playlists", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  coverImage: bytea("cover_image"), // Thumbnail image for playlist
  isPublic: boolean("is_public").default(false),
  playCount: integer("play_count").default(0),
  totalDuration: integer("total_duration").default(0), // Total duration in seconds
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (table) => [
  index("idx_playlists_user").on(table.userId),
  index("idx_playlists_created").on(table.createdAt),
]);

// Playlist tracks junction table
export const playlistTracks = pgTable("playlist_tracks", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  playlistId: uuid("playlist_id").notNull(),
  fileId: uuid("file_id").notNull(),
  position: integer("position").notNull(),
  addedBy: varchar("added_by").notNull(),
  addedAt: timestamp("added_at").defaultNow(),
}, (table) => [
  index("idx_playlist_tracks_playlist").on(table.playlistId),
  index("idx_playlist_tracks_file").on(table.fileId),
  index("idx_playlist_tracks_position").on(table.playlistId, table.position),
  unique("unique_playlist_track").on(table.playlistId, table.fileId),
]);

// Play history for tracking listening history
export const playHistory = pgTable("play_history", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  fileId: uuid("file_id").notNull(),
  playlistId: uuid("playlist_id"), // Optional: track which playlist it was played from
  playedAt: timestamp("played_at").defaultNow(),
  duration: integer("duration"), // How long the user listened in seconds
  completed: boolean("completed").default(false), // Whether they finished the track
}, (table) => [
  index("idx_play_history_user").on(table.userId),
  index("idx_play_history_file").on(table.fileId),
  index("idx_play_history_played_at").on(table.playedAt),
]);

// Relations
export const usersRelations = relations(users, ({ many }) => ({
  mediaFiles: many(mediaFiles),
  files: many(files),
  folders: many(folders),
  albums: many(albums),
  tags: many(tags),
  smartFolders: many(smartFolders),
  importBatches: many(importBatches),
  activityLogs: many(activityLogs),
  permissions: many(permissions),
  shareLinks: many(shareLinks),
  playlists: many(playlists),
  playHistory: many(playHistory),
}));

export const categoriesRelations = relations(categories, ({ one, many }) => ({
  parent: one(categories, {
    fields: [categories.parentId],
    references: [categories.id],
  }),
  children: many(categories),
  mediaFiles: many(mediaFiles),
}));

export const mediaFilesRelations = relations(mediaFiles, ({ one }) => ({
  category: one(categories, {
    fields: [mediaFiles.categoryId],
    references: [categories.id],
  }),
  uploader: one(users, {
    fields: [mediaFiles.uploadedBy],
    references: [users.id],
  }),
}));

export const importBatchesRelations = relations(importBatches, ({ one }) => ({
  user: one(users, {
    fields: [importBatches.userId],
    references: [users.id],
  }),
}));

export const activityLogsRelations = relations(activityLogs, ({ one }) => ({
  user: one(users, {
    fields: [activityLogs.userId],
    references: [users.id],
  }),
}));

export const foldersRelations = relations(folders, ({ one, many }) => ({
  parent: one(folders, {
    fields: [folders.parentId],
    references: [folders.id],
  }),
  children: many(folders),
  files: many(files),
  owner: one(users, {
    fields: [folders.userId],
    references: [users.id],
  }),
}));

export const filesRelations = relations(files, ({ one, many }) => ({
  folder: one(folders, {
    fields: [files.folderId],
    references: [folders.id],
  }),
  owner: one(users, {
    fields: [files.userId],
    references: [users.id],
  }),
  albumFiles: many(albumFiles),
  fileTags: many(fileTags),
  previousVersion: one(files, {
    fields: [files.previousVersionId],
    references: [files.id],
  }),
}));

export const albumsRelations = relations(albums, ({ one, many }) => ({
  owner: one(users, {
    fields: [albums.userId],
    references: [users.id],
  }),
  coverImage: one(files, {
    fields: [albums.coverImageId],
    references: [files.id],
  }),
  albumFiles: many(albumFiles),
}));

export const albumFilesRelations = relations(albumFiles, ({ one }) => ({
  album: one(albums, {
    fields: [albumFiles.albumId],
    references: [albums.id],
  }),
  file: one(files, {
    fields: [albumFiles.fileId],
    references: [files.id],
  }),
}));

export const tagsRelations = relations(tags, ({ one, many }) => ({
  owner: one(users, {
    fields: [tags.userId],
    references: [users.id],
  }),
  fileTags: many(fileTags),
}));

export const fileTagsRelations = relations(fileTags, ({ one }) => ({
  file: one(files, {
    fields: [fileTags.fileId],
    references: [files.id],
  }),
  tag: one(tags, {
    fields: [fileTags.tagId],
    references: [tags.id],
  }),
}));

export const smartFoldersRelations = relations(smartFolders, ({ one }) => ({
  owner: one(users, {
    fields: [smartFolders.userId],
    references: [users.id],
  }),
}));

export const permissionsRelations = relations(permissions, ({ one }) => ({
  user: one(users, {
    fields: [permissions.userId],
    references: [users.id],
  }),
  grantor: one(users, {
    fields: [permissions.grantedBy],
    references: [users.id],
  }),
}));

export const shareLinksRelations = relations(shareLinks, ({ one }) => ({
  creator: one(users, {
    fields: [shareLinks.createdBy],
    references: [users.id],
  }),
}));

export const playlistsRelations = relations(playlists, ({ one, many }) => ({
  owner: one(users, {
    fields: [playlists.userId],
    references: [users.id],
  }),
  tracks: many(playlistTracks),
}));

export const playlistTracksRelations = relations(playlistTracks, ({ one }) => ({
  playlist: one(playlists, {
    fields: [playlistTracks.playlistId],
    references: [playlists.id],
  }),
  file: one(files, {
    fields: [playlistTracks.fileId],
    references: [files.id],
  }),
  addedBy: one(users, {
    fields: [playlistTracks.addedBy],
    references: [users.id],
  }),
}));

export const playHistoryRelations = relations(playHistory, ({ one }) => ({
  user: one(users, {
    fields: [playHistory.userId],
    references: [users.id],
  }),
  file: one(files, {
    fields: [playHistory.fileId],
    references: [files.id],
  }),
  playlist: one(playlists, {
    fields: [playHistory.playlistId],
    references: [playlists.id],
  }),
}));

// Zod schemas
export const insertUserSchema = createInsertSchema(users).pick({
  email: true,
  firstName: true,
  lastName: true,
  profileImageUrl: true,
  role: true,
  vaultPassphrase: true,
  storageQuota: true,
  preferences: true,
  isActive: true,
});

export const insertCategorySchema = createInsertSchema(categories).pick({
  name: true,
  slug: true,
  description: true,
  parentId: true,
  icon: true,
  isVault: true,
  sortOrder: true,
  location: true,
  eventDate: true,
  dateRange: true,
  tags: true,
  metadata: true,
  color: true,
  folderPath: true,
});

export const insertMediaFileSchema = createInsertSchema(mediaFiles).pick({
  filename: true,
  originalName: true,
  mimeType: true,
  fileSize: true,
  sha256Hash: true,
  binaryData: true,
  storageType: true,
  filePath: true,
  fileEncryptionKey: true,
  filenameKeyWrapped: true,
  encryptedFilename: true,
  chunkMetadata: true,
  width: true,
  height: true,
  duration: true,
  thumbnailData: true,
  thumbnailWebp: true,
  thumbnailAvif: true,
  metadata: true,
  isEncrypted: true,
  encryptionKey: true,
  categoryId: true,
  uploadedBy: true,
  importSource: true,
  tags: true,
});

export const insertImportBatchSchema = createInsertSchema(importBatches).pick({
  source: true,
  totalFiles: true,
  settings: true,
});

export const insertActivityLogSchema = createInsertSchema(activityLogs).pick({
  action: true,
  resource: true,
  resourceId: true,
  ipAddress: true,
  userAgent: true,
  metadata: true,
});

export const insertFolderSchema = createInsertSchema(folders).pick({
  name: true,
  parentId: true,
  userId: true,
  path: true,
  description: true,
  color: true,
  icon: true,
  sortOrder: true,
  isShared: true,
  shareSettings: true,
  metadata: true,
});

export const insertFileSchema = createInsertSchema(files).pick({
  filename: true,
  originalName: true,
  mimeType: true,
  fileType: true,
  fileSize: true,
  sha256Hash: true,
  folderId: true,
  userId: true,
  storageType: true,
  binaryData: true,
  filePath: true,
  description: true,
  notes: true,
  customMetadata: true,
  exifData: true,
  width: true,
  height: true,
  duration: true,
  thumbnailData: true,
  pageCount: true,
  wordCount: true,
  isEncrypted: true,
  encryptionKey: true,
  tags: true,
  isFavorite: true,
  version: true,
  previousVersionId: true,
});

export const insertAlbumSchema = createInsertSchema(albums).pick({
  name: true,
  description: true,
  userId: true,
  coverImageId: true,
  isPublic: true,
  shareLink: true,
  sortOrder: true,
  metadata: true,
});

export const insertAlbumFileSchema = createInsertSchema(albumFiles).pick({
  albumId: true,
  fileId: true,
  sortOrder: true,
});

export const insertTagSchema = createInsertSchema(tags).pick({
  name: true,
  userId: true,
  color: true,
  description: true,
});

export const insertFileTagSchema = createInsertSchema(fileTags).pick({
  fileId: true,
  tagId: true,
});

export const insertSmartFolderSchema = createInsertSchema(smartFolders).pick({
  name: true,
  userId: true,
  rules: true,
  icon: true,
  color: true,
  description: true,
  isActive: true,
});

export const insertPermissionSchema = createInsertSchema(permissions).pick({
  userId: true,
  resourceType: true,
  resourceId: true,
  canView: true,
  canEdit: true,
  canDelete: true,
  canShare: true,
  grantedBy: true,
  expiresAt: true,
});

export const insertSystemSettingSchema = createInsertSchema(systemSettings).pick({
  key: true,
  value: true,
  description: true,
  category: true,
  isPublic: true,
  updatedBy: true,
});

export const insertShareLinkSchema = createInsertSchema(shareLinks).pick({
  code: true,
  resourceType: true,
  resourceId: true,
  createdBy: true,
  password: true,
  permissions: true,
  maxUses: true,
  expiresAt: true,
});

export const insertPlaylistSchema = createInsertSchema(playlists).pick({
  userId: true,
  name: true,
  description: true,
  coverImage: true,
  isPublic: true,
});

export const insertPlaylistTrackSchema = createInsertSchema(playlistTracks).pick({
  playlistId: true,
  fileId: true,
  position: true,
  addedBy: true,
});

export const insertPlayHistorySchema = createInsertSchema(playHistory).pick({
  userId: true,
  fileId: true,
  playlistId: true,
  duration: true,
  completed: true,
});

// Types
export type UpsertUser = z.infer<typeof insertUserSchema> & { id: string };
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Category = typeof categories.$inferSelect;
export type InsertCategory = z.infer<typeof insertCategorySchema>;
export type MediaFile = typeof mediaFiles.$inferSelect;
export type InsertMediaFile = z.infer<typeof insertMediaFileSchema>;
export type ImportBatch = typeof importBatches.$inferSelect;
export type InsertImportBatch = z.infer<typeof insertImportBatchSchema>;
export type ActivityLog = typeof activityLogs.$inferSelect;
export type InsertActivityLog = z.infer<typeof insertActivityLogSchema>;
export type Folder = typeof folders.$inferSelect;
export type InsertFolder = z.infer<typeof insertFolderSchema>;
export type File = typeof files.$inferSelect;
export type InsertFile = z.infer<typeof insertFileSchema>;
export type Album = typeof albums.$inferSelect;
export type InsertAlbum = z.infer<typeof insertAlbumSchema>;
export type AlbumFile = typeof albumFiles.$inferSelect;
export type InsertAlbumFile = z.infer<typeof insertAlbumFileSchema>;
export type Tag = typeof tags.$inferSelect;
export type InsertTag = z.infer<typeof insertTagSchema>;
export type FileTag = typeof fileTags.$inferSelect;
export type InsertFileTag = z.infer<typeof insertFileTagSchema>;
export type SmartFolder = typeof smartFolders.$inferSelect;
export type InsertSmartFolder = z.infer<typeof insertSmartFolderSchema>;
export type Permission = typeof permissions.$inferSelect;
export type InsertPermission = z.infer<typeof insertPermissionSchema>;
export type SystemSetting = typeof systemSettings.$inferSelect;
export type InsertSystemSetting = z.infer<typeof insertSystemSettingSchema>;
export type ShareLink = typeof shareLinks.$inferSelect;
export type InsertShareLink = z.infer<typeof insertShareLinkSchema>;
export type Playlist = typeof playlists.$inferSelect;
export type InsertPlaylist = z.infer<typeof insertPlaylistSchema>;
export type PlaylistTrack = typeof playlistTracks.$inferSelect;
export type InsertPlaylistTrack = z.infer<typeof insertPlaylistTrackSchema>;
export type PlayHistory = typeof playHistory.$inferSelect;
export type InsertPlayHistory = z.infer<typeof insertPlayHistorySchema>;
