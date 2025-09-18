import { sql, relations } from 'drizzle-orm';
import {
  index,
  int,
  bigint,
  varchar,
  text,
  bit,
  uniqueIdentifier,
  datetime2,
  varbinary,
  decimal,
} from "drizzle-orm/mssql-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// SQL Server compatible schema definitions

// Session storage table (mandatory for authentication)
export const sessions = {
  sid: varchar("sid", { length: 255 }).primaryKey(),
  sess: text("sess").notNull(), // JSON as text in SQL Server
  expire: datetime2("expire").notNull(),
};

// User storage table
export const users = {
  id: varchar("id", { length: 36 }).primaryKey().default(sql`NEWID()`),
  email: varchar("email", { length: 255 }),
  firstName: varchar("first_name", { length: 255 }),
  lastName: varchar("last_name", { length: 255 }),
  profileImageUrl: varchar("profile_image_url", { length: 500 }),
  role: varchar("role", { length: 50 }).default("user"),
  vaultPassphrase: varchar("vault_passphrase", { length: 500 }),
  storageQuota: bigint("storage_quota", { mode: "number" }).default(2147483647),
  storageUsed: bigint("storage_used", { mode: "number" }).default(0),
  preferences: text("preferences"), // JSON as text
  isActive: bit("is_active").default(1),
  lastLoginAt: datetime2("last_login_at"),
  createdAt: datetime2("created_at").default(sql`GETDATE()`),
  updatedAt: datetime2("updated_at").default(sql`GETDATE()`),
};

// Categories table
export const categories = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  name: varchar("name", { length: 255 }).notNull(),
  slug: varchar("slug", { length: 255 }).notNull(),
  description: text("description"),
  parentId: uniqueIdentifier("parent_id"),
  icon: varchar("icon", { length: 50 }),
  isVault: bit("is_vault").default(0),
  sortOrder: int("sort_order").default(0),
  location: varchar("location", { length: 500 }),
  eventDate: datetime2("event_date"),
  dateRange: varchar("date_range", { length: 100 }),
  tags: text("tags"), // JSON array as text
  metadata: text("metadata"), // JSON as text
  color: varchar("color", { length: 7 }).default("#6b7280"),
  folderPath: varchar("folder_path", { length: 1000 }),
  createdAt: datetime2("created_at").default(sql`GETDATE()`),
  updatedAt: datetime2("updated_at").default(sql`GETDATE()`),
};

// Files table (unified media and documents)
export const files = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  filename: varchar("filename", { length: 500 }).notNull(),
  originalName: varchar("original_name", { length: 500 }).notNull(),
  mimeType: varchar("mime_type", { length: 100 }).notNull(),
  fileSize: bigint("file_size", { mode: "number" }).notNull(),
  sha256Hash: varchar("sha256_hash", { length: 64 }).notNull(),
  binaryData: varbinary("binary_data"), // VARBINARY(MAX) for binary data
  storageType: varchar("storage_type", { length: 20 }).default("database"),
  filePath: varchar("file_path", { length: 1000 }),
  fileEncryptionKey: varchar("file_encryption_key", { length: 500 }),
  width: int("width"),
  height: int("height"),
  duration: int("duration"),
  thumbnailData: varbinary("thumbnail_data"),
  thumbnailWebp: varbinary("thumbnail_webp"),
  thumbnailAvif: varbinary("thumbnail_avif"),
  metadata: text("metadata"), // JSON as text
  isEncrypted: bit("is_encrypted").default(0),
  encryptionKey: varchar("encryption_key", { length: 500 }),
  folderId: uniqueIdentifier("folder_id"),
  uploadedBy: varchar("uploaded_by", { length: 36 }).notNull(),
  importSource: varchar("import_source", { length: 100 }),
  tags: text("tags"), // JSON array as text
  isFavorite: bit("is_favorite").default(0),
  isDeleted: bit("is_deleted").default(0),
  createdAt: datetime2("created_at").default(sql`GETDATE()`),
  updatedAt: datetime2("updated_at").default(sql`GETDATE()`),
};

// Folders table
export const folders = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  name: varchar("name", { length: 255 }).notNull(),
  parentId: uniqueIdentifier("parent_id"),
  path: varchar("path", { length: 1000 }).notNull(),
  description: text("description"),
  color: varchar("color", { length: 7 }),
  icon: varchar("icon", { length: 50 }),
  isEncrypted: bit("is_encrypted").default(0),
  encryptionKey: varchar("encryption_key", { length: 500 }),
  tags: text("tags"), // JSON array as text
  metadata: text("metadata"), // JSON as text
  createdBy: varchar("created_by", { length: 36 }).notNull(),
  isDeleted: bit("is_deleted").default(0),
  createdAt: datetime2("created_at").default(sql`GETDATE()`),
  updatedAt: datetime2("updated_at").default(sql`GETDATE()`),
};

// Albums table
export const albums = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  coverImageId: uniqueIdentifier("cover_image_id"),
  isPublic: bit("is_public").default(0),
  tags: text("tags"), // JSON array as text
  metadata: text("metadata"), // JSON as text
  createdBy: varchar("created_by", { length: 36 }).notNull(),
  createdAt: datetime2("created_at").default(sql`GETDATE()`),
  updatedAt: datetime2("updated_at").default(sql`GETDATE()`),
};

// Album files junction table
export const albumFiles = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  albumId: uniqueIdentifier("album_id").notNull(),
  fileId: uniqueIdentifier("file_id").notNull(),
  sortOrder: int("sort_order").default(0),
  addedAt: datetime2("added_at").default(sql`GETDATE()`),
};

// Tags table
export const tags = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  name: varchar("name", { length: 100 }).notNull(),
  color: varchar("color", { length: 7 }),
  description: text("description"),
  createdBy: varchar("created_by", { length: 36 }).notNull(),
  createdAt: datetime2("created_at").default(sql`GETDATE()`),
};

// File tags junction table
export const fileTags = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  fileId: uniqueIdentifier("file_id").notNull(),
  tagId: uniqueIdentifier("tag_id").notNull(),
  addedAt: datetime2("added_at").default(sql`GETDATE()`),
};

// Playlists table
export const playlists = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  isPublic: bit("is_public").default(0),
  coverImageId: uniqueIdentifier("cover_image_id"),
  createdBy: varchar("created_by", { length: 36 }).notNull(),
  createdAt: datetime2("created_at").default(sql`GETDATE()`),
  updatedAt: datetime2("updated_at").default(sql`GETDATE()`),
};

// Playlist tracks junction table
export const playlistTracks = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  playlistId: uniqueIdentifier("playlist_id").notNull(),
  fileId: uniqueIdentifier("file_id").notNull(),
  sortOrder: int("sort_order").default(0),
  addedAt: datetime2("added_at").default(sql`GETDATE()`),
};

// Play history table
export const playHistory = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  fileId: uniqueIdentifier("file_id").notNull(),
  userId: varchar("user_id", { length: 36 }).notNull(),
  playlistId: uniqueIdentifier("playlist_id"),
  duration: int("duration").notNull(),
  completed: bit("completed").default(0),
  playedAt: datetime2("played_at").default(sql`GETDATE()`),
};

// Activity logs table
export const activityLogs = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  userId: varchar("user_id", { length: 36 }).notNull(),
  action: varchar("action", { length: 100 }).notNull(),
  resourceType: varchar("resource_type", { length: 50 }),
  resourceId: varchar("resource_id", { length: 36 }),
  details: text("details"), // JSON as text
  ipAddress: varchar("ip_address", { length: 45 }),
  userAgent: varchar("user_agent", { length: 500 }),
  createdAt: datetime2("created_at").default(sql`GETDATE()`),
};

// System settings table
export const systemSettings = {
  id: uniqueIdentifier("id").primaryKey().default(sql`NEWID()`),
  key: varchar("key", { length: 100 }).notNull(),
  value: text("value"),
  description: text("description"),
  isPublic: bit("is_public").default(0),
  updatedBy: varchar("updated_by", { length: 36 }),
  updatedAt: datetime2("updated_at").default(sql`GETDATE()`),
};

// Type definitions for SQL Server schema
export type SqlServerUser = typeof users;
export type SqlServerCategory = typeof categories;
export type SqlServerFile = typeof files;
export type SqlServerFolder = typeof folders;
export type SqlServerAlbum = typeof albums;
export type SqlServerAlbumFile = typeof albumFiles;
export type SqlServerTag = typeof tags;
export type SqlServerFileTag = typeof fileTags;
export type SqlServerPlaylist = typeof playlists;
export type SqlServerPlaylistTrack = typeof playlistTracks;
export type SqlServerPlayHistory = typeof playHistory;
export type SqlServerActivityLog = typeof activityLogs;
export type SqlServerSystemSetting = typeof systemSettings;

// Zod schemas for validation
export const insertUserSchema = createInsertSchema(users as any);
export const insertCategorySchema = createInsertSchema(categories as any);
export const insertFileSchema = createInsertSchema(files as any);
export const insertFolderSchema = createInsertSchema(folders as any);
export const insertAlbumSchema = createInsertSchema(albums as any);
export const insertTagSchema = createInsertSchema(tags as any);
export const insertPlaylistSchema = createInsertSchema(playlists as any);

export type InsertUser = z.infer<typeof insertUserSchema>;
export type InsertCategory = z.infer<typeof insertCategorySchema>;
export type InsertFile = z.infer<typeof insertFileSchema>;
export type InsertFolder = z.infer<typeof insertFolderSchema>;
export type InsertAlbum = z.infer<typeof insertAlbumSchema>;
export type InsertTag = z.infer<typeof insertTagSchema>;
export type InsertPlaylist = z.infer<typeof insertPlaylistSchema>;