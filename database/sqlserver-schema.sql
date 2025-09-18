-- SecureGallery Pro SQL Server Express Database Schema
-- Run this script to create the database and tables

USE master;
GO

-- Create database if it doesn't exist
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'SecureGalleryPro')
BEGIN
    CREATE DATABASE [SecureGalleryPro];
    PRINT 'Database SecureGalleryPro created successfully';
END
ELSE
BEGIN
    PRINT 'Database SecureGalleryPro already exists';
END
GO

USE [SecureGalleryPro];
GO

-- Enable full-text search if available
IF EXISTS (SELECT * FROM sys.fulltext_catalogs WHERE name = 'SecureGalleryFTCatalog')
    DROP FULLTEXT CATALOG SecureGalleryFTCatalog;
GO

CREATE FULLTEXT CATALOG SecureGalleryFTCatalog AS DEFAULT;
GO

-- Sessions table (for session storage)
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='sessions' AND xtype='U')
BEGIN
    CREATE TABLE [sessions] (
        [sid] NVARCHAR(255) NOT NULL PRIMARY KEY,
        [sess] NVARCHAR(MAX) NOT NULL, -- JSON session data
        [expire] DATETIME2 NOT NULL
    );
    
    CREATE INDEX [IDX_session_expire] ON [sessions] ([expire]);
    PRINT 'Sessions table created';
END
GO

-- Users table
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='users' AND xtype='U')
BEGIN
    CREATE TABLE [users] (
        [id] NVARCHAR(36) NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [email] NVARCHAR(255) UNIQUE,
        [first_name] NVARCHAR(255),
        [last_name] NVARCHAR(255),
        [profile_image_url] NVARCHAR(500),
        [role] NVARCHAR(50) DEFAULT 'user', -- user, admin, moderator, viewer
        [vault_passphrase] NVARCHAR(500), -- encrypted vault access
        [storage_quota] BIGINT DEFAULT 2147483647, -- 2GB default
        [storage_used] BIGINT DEFAULT 0,
        [preferences] NVARCHAR(MAX), -- JSON user preferences
        [is_active] BIT DEFAULT 1,
        [last_login_at] DATETIME2,
        [created_at] DATETIME2 DEFAULT GETDATE(),
        [updated_at] DATETIME2 DEFAULT GETDATE()
    );
    PRINT 'Users table created';
END
GO

-- Categories table for hierarchical organization
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='categories' AND xtype='U')
BEGIN
    CREATE TABLE [categories] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [name] NVARCHAR(255) NOT NULL,
        [slug] NVARCHAR(255) NOT NULL UNIQUE,
        [description] NVARCHAR(MAX),
        [parent_id] UNIQUEIDENTIFIER,
        [icon] NVARCHAR(50),
        [is_vault] BIT DEFAULT 0,
        [sort_order] INT DEFAULT 0,
        [location] NVARCHAR(500), -- e.g., "Germany", "Berlin, Germany"
        [event_date] DATETIME2, -- Date of the event/trip
        [date_range] NVARCHAR(100), -- e.g., "July 2023"
        [tags] NVARCHAR(MAX), -- JSON array of tags
        [metadata] NVARCHAR(MAX), -- JSON metadata
        [color] NVARCHAR(7) DEFAULT '#6b7280', -- Hex color
        [folder_path] NVARCHAR(1000), -- Original folder path
        [created_at] DATETIME2 DEFAULT GETDATE(),
        [updated_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([parent_id]) REFERENCES [categories]([id])
    );
    
    CREATE INDEX [idx_categories_parent] ON [categories] ([parent_id]);
    CREATE INDEX [idx_categories_slug] ON [categories] ([slug]);
    PRINT 'Categories table created';
END
GO

-- Folders table for hierarchical file organization
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='folders' AND xtype='U')
BEGIN
    CREATE TABLE [folders] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [name] NVARCHAR(255) NOT NULL,
        [parent_id] UNIQUEIDENTIFIER,
        [path] NVARCHAR(1000) NOT NULL,
        [description] NVARCHAR(MAX),
        [color] NVARCHAR(7),
        [icon] NVARCHAR(50),
        [is_encrypted] BIT DEFAULT 0,
        [encryption_key] NVARCHAR(500),
        [tags] NVARCHAR(MAX), -- JSON array
        [metadata] NVARCHAR(MAX), -- JSON metadata
        [created_by] NVARCHAR(36) NOT NULL,
        [is_deleted] BIT DEFAULT 0,
        [created_at] DATETIME2 DEFAULT GETDATE(),
        [updated_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([parent_id]) REFERENCES [folders]([id]),
        FOREIGN KEY ([created_by]) REFERENCES [users]([id])
    );
    
    CREATE INDEX [idx_folders_parent] ON [folders] ([parent_id]);
    CREATE INDEX [idx_folders_path] ON [folders] ([path]);
    CREATE INDEX [idx_folders_created_by] ON [folders] ([created_by]);
    PRINT 'Folders table created';
END
GO

-- Files table (unified media and documents)
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='files' AND xtype='U')
BEGIN
    CREATE TABLE [files] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [filename] NVARCHAR(500) NOT NULL,
        [original_name] NVARCHAR(500) NOT NULL,
        [mime_type] NVARCHAR(100) NOT NULL,
        [file_size] BIGINT NOT NULL,
        [sha256_hash] NVARCHAR(64) NOT NULL,
        [binary_data] VARBINARY(MAX), -- Binary file content
        [storage_type] NVARCHAR(20) DEFAULT 'database', -- "database" | "filesystem"
        [file_path] NVARCHAR(1000), -- Path on filesystem
        [file_encryption_key] NVARCHAR(500), -- AES key for file encryption
        [width] INT, -- Image/video width
        [height] INT, -- Image/video height
        [duration] INT, -- Video/audio duration in seconds
        [thumbnail_data] VARBINARY(MAX), -- JPEG thumbnail
        [thumbnail_webp] VARBINARY(MAX), -- WebP thumbnail
        [thumbnail_avif] VARBINARY(MAX), -- AVIF thumbnail
        [metadata] NVARCHAR(MAX), -- JSON metadata (EXIF, etc.)
        [is_encrypted] BIT DEFAULT 0,
        [encryption_key] NVARCHAR(500),
        [folder_id] UNIQUEIDENTIFIER,
        [uploaded_by] NVARCHAR(36) NOT NULL,
        [import_source] NVARCHAR(100), -- google_photos, manual, etc.
        [tags] NVARCHAR(MAX), -- JSON array of tags
        [is_favorite] BIT DEFAULT 0,
        [is_deleted] BIT DEFAULT 0,
        [created_at] DATETIME2 DEFAULT GETDATE(),
        [updated_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([folder_id]) REFERENCES [folders]([id]),
        FOREIGN KEY ([uploaded_by]) REFERENCES [users]([id])
    );
    
    CREATE INDEX [idx_files_sha256] ON [files] ([sha256_hash]);
    CREATE INDEX [idx_files_folder] ON [files] ([folder_id]);
    CREATE INDEX [idx_files_uploaded_by] ON [files] ([uploaded_by]);
    CREATE INDEX [idx_files_created_at] ON [files] ([created_at]);
    CREATE UNIQUE INDEX [idx_files_unique_hash_user] ON [files] ([sha256_hash], [uploaded_by]);
    PRINT 'Files table created';
END
GO

-- Albums table
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='albums' AND xtype='U')
BEGIN
    CREATE TABLE [albums] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [name] NVARCHAR(255) NOT NULL,
        [description] NVARCHAR(MAX),
        [cover_image_id] UNIQUEIDENTIFIER,
        [is_public] BIT DEFAULT 0,
        [tags] NVARCHAR(MAX), -- JSON array
        [metadata] NVARCHAR(MAX), -- JSON metadata
        [created_by] NVARCHAR(36) NOT NULL,
        [created_at] DATETIME2 DEFAULT GETDATE(),
        [updated_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([cover_image_id]) REFERENCES [files]([id]),
        FOREIGN KEY ([created_by]) REFERENCES [users]([id])
    );
    
    CREATE INDEX [idx_albums_created_by] ON [albums] ([created_by]);
    PRINT 'Albums table created';
END
GO

-- Album files junction table
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='album_files' AND xtype='U')
BEGIN
    CREATE TABLE [album_files] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [album_id] UNIQUEIDENTIFIER NOT NULL,
        [file_id] UNIQUEIDENTIFIER NOT NULL,
        [sort_order] INT DEFAULT 0,
        [added_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([album_id]) REFERENCES [albums]([id]) ON DELETE CASCADE,
        FOREIGN KEY ([file_id]) REFERENCES [files]([id]) ON DELETE CASCADE
    );
    
    CREATE UNIQUE INDEX [idx_album_files_unique] ON [album_files] ([album_id], [file_id]);
    CREATE INDEX [idx_album_files_album] ON [album_files] ([album_id]);
    CREATE INDEX [idx_album_files_file] ON [album_files] ([file_id]);
    PRINT 'Album files table created';
END
GO

-- Tags table
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='tags' AND xtype='U')
BEGIN
    CREATE TABLE [tags] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [name] NVARCHAR(100) NOT NULL UNIQUE,
        [color] NVARCHAR(7),
        [description] NVARCHAR(MAX),
        [created_by] NVARCHAR(36) NOT NULL,
        [created_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([created_by]) REFERENCES [users]([id])
    );
    
    CREATE INDEX [idx_tags_name] ON [tags] ([name]);
    CREATE INDEX [idx_tags_created_by] ON [tags] ([created_by]);
    PRINT 'Tags table created';
END
GO

-- File tags junction table
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='file_tags' AND xtype='U')
BEGIN
    CREATE TABLE [file_tags] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [file_id] UNIQUEIDENTIFIER NOT NULL,
        [tag_id] UNIQUEIDENTIFIER NOT NULL,
        [added_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([file_id]) REFERENCES [files]([id]) ON DELETE CASCADE,
        FOREIGN KEY ([tag_id]) REFERENCES [tags]([id]) ON DELETE CASCADE
    );
    
    CREATE UNIQUE INDEX [idx_file_tags_unique] ON [file_tags] ([file_id], [tag_id]);
    CREATE INDEX [idx_file_tags_file] ON [file_tags] ([file_id]);
    CREATE INDEX [idx_file_tags_tag] ON [file_tags] ([tag_id]);
    PRINT 'File tags table created';
END
GO

-- Playlists table
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='playlists' AND xtype='U')
BEGIN
    CREATE TABLE [playlists] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [name] NVARCHAR(255) NOT NULL,
        [description] NVARCHAR(MAX),
        [is_public] BIT DEFAULT 0,
        [cover_image_id] UNIQUEIDENTIFIER,
        [created_by] NVARCHAR(36) NOT NULL,
        [created_at] DATETIME2 DEFAULT GETDATE(),
        [updated_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([cover_image_id]) REFERENCES [files]([id]),
        FOREIGN KEY ([created_by]) REFERENCES [users]([id])
    );
    
    CREATE INDEX [idx_playlists_created_by] ON [playlists] ([created_by]);
    PRINT 'Playlists table created';
END
GO

-- Playlist tracks junction table
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='playlist_tracks' AND xtype='U')
BEGIN
    CREATE TABLE [playlist_tracks] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [playlist_id] UNIQUEIDENTIFIER NOT NULL,
        [file_id] UNIQUEIDENTIFIER NOT NULL,
        [sort_order] INT DEFAULT 0,
        [added_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([playlist_id]) REFERENCES [playlists]([id]) ON DELETE CASCADE,
        FOREIGN KEY ([file_id]) REFERENCES [files]([id]) ON DELETE CASCADE
    );
    
    CREATE UNIQUE INDEX [idx_playlist_tracks_unique] ON [playlist_tracks] ([playlist_id], [file_id]);
    CREATE INDEX [idx_playlist_tracks_playlist] ON [playlist_tracks] ([playlist_id]);
    CREATE INDEX [idx_playlist_tracks_file] ON [playlist_tracks] ([file_id]);
    PRINT 'Playlist tracks table created';
END
GO

-- Play history table
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='play_history' AND xtype='U')
BEGIN
    CREATE TABLE [play_history] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [file_id] UNIQUEIDENTIFIER NOT NULL,
        [user_id] NVARCHAR(36) NOT NULL,
        [playlist_id] UNIQUEIDENTIFIER,
        [duration] INT NOT NULL, -- Play duration in seconds
        [completed] BIT DEFAULT 0, -- Whether played to completion
        [played_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([file_id]) REFERENCES [files]([id]),
        FOREIGN KEY ([user_id]) REFERENCES [users]([id]),
        FOREIGN KEY ([playlist_id]) REFERENCES [playlists]([id])
    );
    
    CREATE INDEX [idx_play_history_file] ON [play_history] ([file_id]);
    CREATE INDEX [idx_play_history_user] ON [play_history] ([user_id]);
    CREATE INDEX [idx_play_history_played_at] ON [play_history] ([played_at]);
    PRINT 'Play history table created';
END
GO

-- Activity logs table
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='activity_logs' AND xtype='U')
BEGIN
    CREATE TABLE [activity_logs] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [user_id] NVARCHAR(36) NOT NULL,
        [action] NVARCHAR(100) NOT NULL,
        [resource_type] NVARCHAR(50),
        [resource_id] NVARCHAR(36),
        [details] NVARCHAR(MAX), -- JSON details
        [ip_address] NVARCHAR(45),
        [user_agent] NVARCHAR(500),
        [created_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([user_id]) REFERENCES [users]([id])
    );
    
    CREATE INDEX [idx_activity_logs_user] ON [activity_logs] ([user_id]);
    CREATE INDEX [idx_activity_logs_action] ON [activity_logs] ([action]);
    CREATE INDEX [idx_activity_logs_created_at] ON [activity_logs] ([created_at]);
    PRINT 'Activity logs table created';
END
GO

-- System settings table
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='system_settings' AND xtype='U')
BEGIN
    CREATE TABLE [system_settings] (
        [id] UNIQUEIDENTIFIER NOT NULL PRIMARY KEY DEFAULT NEWID(),
        [key] NVARCHAR(100) NOT NULL UNIQUE,
        [value] NVARCHAR(MAX),
        [description] NVARCHAR(MAX),
        [is_public] BIT DEFAULT 0,
        [updated_by] NVARCHAR(36),
        [updated_at] DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY ([updated_by]) REFERENCES [users]([id])
    );
    
    CREATE INDEX [idx_system_settings_key] ON [system_settings] ([key]);
    PRINT 'System settings table created';
END
GO

-- Create full-text indexes for search functionality
IF EXISTS (SELECT * FROM sys.tables WHERE name = 'files')
BEGIN
    IF NOT EXISTS (SELECT * FROM sys.fulltext_indexes WHERE object_id = OBJECT_ID('files'))
    BEGIN
        CREATE FULLTEXT INDEX ON [files] ([original_name], [tags]) 
        KEY INDEX [PK__files__3213E83F] ON SecureGalleryFTCatalog;
        PRINT 'Full-text index created on files table';
    END
END
GO

-- Insert default system settings
IF NOT EXISTS (SELECT * FROM [system_settings] WHERE [key] = 'app_version')
BEGIN
    INSERT INTO [system_settings] ([key], [value], [description], [is_public])
    VALUES 
        ('app_version', '1.0.0', 'Application version', 1),
        ('maintenance_mode', 'false', 'Whether the application is in maintenance mode', 0),
        ('max_file_size', '2147483648', 'Maximum file upload size in bytes (2GB)', 0),
        ('allowed_file_types', '["jpg","jpeg","png","gif","webp","avif","mp4","avi","mov","mp3","wav","flac","pdf","doc","docx","txt","md"]', 'Allowed file extensions for upload', 0),
        ('thumbnail_quality', '80', 'JPEG thumbnail quality (1-100)', 0),
        ('session_timeout', '86400', 'Session timeout in seconds (24 hours)', 0);
    PRINT 'Default system settings inserted';
END
GO

-- Create triggers for updating timestamps
CREATE OR ALTER TRIGGER [tr_users_update] ON [users]
AFTER UPDATE
AS
BEGIN
    UPDATE [users] 
    SET [updated_at] = GETDATE() 
    WHERE [id] IN (SELECT [id] FROM inserted);
END
GO

CREATE OR ALTER TRIGGER [tr_categories_update] ON [categories]
AFTER UPDATE
AS
BEGIN
    UPDATE [categories] 
    SET [updated_at] = GETDATE() 
    WHERE [id] IN (SELECT [id] FROM inserted);
END
GO

CREATE OR ALTER TRIGGER [tr_files_update] ON [files]
AFTER UPDATE
AS
BEGIN
    UPDATE [files] 
    SET [updated_at] = GETDATE() 
    WHERE [id] IN (SELECT [id] FROM inserted);
END
GO

CREATE OR ALTER TRIGGER [tr_folders_update] ON [folders]
AFTER UPDATE
AS
BEGIN
    UPDATE [folders] 
    SET [updated_at] = GETDATE() 
    WHERE [id] IN (SELECT [id] FROM inserted);
END
GO

CREATE OR ALTER TRIGGER [tr_albums_update] ON [albums]
AFTER UPDATE
AS
BEGIN
    UPDATE [albums] 
    SET [updated_at] = GETDATE() 
    WHERE [id] IN (SELECT [id] FROM inserted);
END
GO

CREATE OR ALTER TRIGGER [tr_playlists_update] ON [playlists]
AFTER UPDATE
AS
BEGIN
    UPDATE [playlists] 
    SET [updated_at] = GETDATE() 
    WHERE [id] IN (SELECT [id] FROM inserted);
END
GO

PRINT 'Database schema creation completed successfully!';
PRINT 'Next steps:';
PRINT '1. Configure your connection string in .env file';
PRINT '2. Update your application to use SQL Server database type';
PRINT '3. Test the database connection';
GO