# SecureGallery Pro - Enterprise File Management System

## Overview

SecureGallery Pro is a comprehensive file management system with enterprise-grade features including multimedia support, hierarchical folder organization, and advanced content management. The platform combines a powerful media gallery, Spotify-like audio player with playlists, document viewer for PDFs and office files, and complete user administration capabilities. Built with modern web technologies, it provides professional file organization with bulk operations, tagging systems, albums, and permission-based sharing.

## User Preferences

- Preferred communication style: Simple, everyday language
- Focus on practical, working solutions
- Visual feedback for all operations
- Professional UI/UX design

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript for type safety and modern component patterns
- **Routing**: Wouter for lightweight client-side routing with authentication-based route protection
- **State Management**: TanStack Query (React Query) for server state management and caching
- **UI Framework**: Shadcn/ui components built on Radix UI primitives with Tailwind CSS for styling
- **Build Tool**: Vite for fast development and optimized production builds
- **Audio Playback**: HTML5 Audio API with custom React hooks for player state management

### Backend Architecture
- **Runtime**: Node.js with Express.js framework for RESTful API endpoints
- **Language**: TypeScript for full-stack type safety
- **Database ORM**: Drizzle ORM for type-safe database operations and migrations
- **File Processing**: Sharp for image processing and thumbnail generation
- **Authentication**: Replit Auth with OpenID Connect for secure user authentication
- **Session Management**: Express sessions with PostgreSQL store

### Database Design
- **Primary Database**: PostgreSQL with connection pooling via Neon Database serverless
- **Schema Management**: Drizzle Kit for database migrations and schema evolution
- **Core Tables**: 
  - Users (with admin role support)
  - Files (all file types with metadata)
  - Folders (hierarchical structure)
  - Media files (legacy support)
  - Categories (organization)
  - Albums (collections)
  - Tags (flexible labeling)
  - Playlists & playlist tracks
  - Play history tracking
  - Activity logs & audit trails
- **Relationships**: Hierarchical folders, user ownership, playlist management, and comprehensive audit logging

### Security Architecture
- **Encryption**: AES-256-GCM for vault content with PBKDF2 key derivation
- **Session Management**: Express sessions with PostgreSQL store for persistence
- **Authentication Flow**: OAuth2/OpenID Connect with JWT tokens
- **File Security**: SHA-256 hashing for duplicate detection and content verification
- **Access Control**: Role-based permissions (user/admin) with protected admin routes
- **Admin Protection**: Self-deletion and self-demotion prevention for admin users

### Media Processing Pipeline
- **Upload Handling**: Multer with memory storage for file processing
- **Image Processing**: Sharp for thumbnail generation and format optimization
- **Video Support**: Metadata extraction and thumbnail generation for video files
- **Audio Streaming**: Direct streaming from database with proper content headers
- **Document Support**: PDF rendering, text preview, office document handling
- **Storage**: Binary content storage in database with optional encryption
- **File Size Limits**: Enforced limits to prevent database overflow

### API Architecture
- **RESTful Design**: Standard HTTP methods with consistent response formats
- **Middleware Stack**: Authentication, logging, error handling, and CORS support
- **File Operations**: Full CRUD with rename, move, delete, favorite toggles
- **Pagination**: Offset-based pagination for large collections
- **Search**: Real-time text-based search across filenames and metadata
- **Admin Endpoints**: Protected routes for user management and data migration

## Key Features

### Gallery Management
- **Dual View Modes**: Toggle between Grid and List views
- **Real-time Search**: Instant filtering as you type
- **File Operations**: Delete, rename, move, download files
- **Bulk Selection**: Select multiple items for batch operations
- **Category Organization**: Organize media by categories
- **Favorite System**: Mark important files as favorites

### Music Player (Spotify-like)
- **Full Playback Controls**: Play, pause, skip, seek with progress bar
- **Playlist Management**: Create, edit, delete, and organize playlists
- **Queue System**: View and manage playback queue
- **Shuffle & Repeat**: Multiple playback modes
- **Volume Control**: Adjustable volume with visual feedback
- **Play History**: Track recently played and most played songs
- **Drag & Drop**: Reorder tracks in playlists
- **Search & Filter**: Find audio files quickly

### Document Management
- **PDF Viewer**: In-browser PDF rendering with zoom controls
- **Text Preview**: Syntax highlighting for code files
- **Office Support**: Download prompts for Word, Excel, PowerPoint
- **Full-screen Mode**: Distraction-free document viewing
- **Print Support**: Direct printing for compatible documents
- **Copy to Clipboard**: Quick text copying for code files

### File Manager
- **Multiple View Modes**: Grid, List, Tree, Timeline views
- **Folder Hierarchy**: Unlimited folder nesting with breadcrumb navigation
- **File Details Panel**: Comprehensive metadata, EXIF data, sharing options
- **Drag & Drop Upload**: Easy file uploading
- **Bulk Operations**: Move, copy, delete multiple files
- **Search & Sort**: Multiple sort options and filtering

### User Administration
- **User Management Table**: View all users with stats
- **Role Management**: Change user roles (user/admin)
- **User Statistics**: Storage usage, file counts, activity tracking
- **User Deletion**: Remove users and all associated data
- **Search & Filter**: Find users by name, email, or role
- **Sort Options**: Sort by various user attributes
- **Self-Protection**: Admins cannot delete themselves

### Admin Controls
- **Data Migration**: Sync media files to new file structure
- **Category Cleanup**: Remove duplicate categories
- **User Statistics**: Detailed usage analytics per user
- **Activity Logging**: Comprehensive audit trail of actions

## External Dependencies

### Core Framework Dependencies
- **@neondatabase/serverless**: PostgreSQL database connection and pooling
- **drizzle-orm**: Type-safe database ORM with schema management
- **express**: Web application framework for API endpoints
- **sharp**: High-performance image processing library
- **multer**: Middleware for handling multipart form data uploads

### Authentication & Security
- **passport**: Authentication middleware for Express
- **openid-client**: OpenID Connect client for Replit Auth integration
- **connect-pg-simple**: PostgreSQL session store for Express sessions
- **crypto**: Node.js built-in cryptography module for encryption operations

### Frontend UI Libraries
- **@radix-ui/***: Accessible component primitives for complex UI elements
- **@tanstack/react-query**: Server state management and caching
- **tailwindcss**: Utility-first CSS framework for styling
- **react-hook-form**: Form handling with validation
- **wouter**: Lightweight routing library for React
- **lucide-react**: Icon library for UI elements
- **framer-motion**: Animation library for smooth transitions

### Development & Build Tools
- **vite**: Fast build tool and development server
- **typescript**: Static type checking for JavaScript
- **@replit/vite-plugin-***: Replit-specific development plugins
- **drizzle-kit**: Database migration and schema management tool

### Utility Libraries
- **date-fns**: Date manipulation and formatting
- **clsx**: Conditional className utility
- **zod**: Runtime type validation and schema definition
- **nanoid**: URL-safe unique ID generation

## Recent Changes (September 21, 2025)

### Windows Deployment with PostgreSQL + IIS
- **Target Environment**: PostgreSQL + IIS reverse proxy configuration
- **File Storage**: Configurable location (D:\project\mediavault)
- **Web Location**: IIS deployment (C:\inetpub\wwwroot\mediavault)
- **Database**: PostgreSQL (production-ready, same as development)
- **Process Management**: PM2 with Windows service integration
- **Configuration**: Environment-specific .env files for seamless deployment

### Previous Changes (September 16, 2025)

### Major Features Implemented
1. **Fixed Gallery Issues**:
   - List View now properly toggles between grid and table formats
   - Search functionality connected between navbar and gallery with real-time filtering
   - Added comprehensive file operations (delete, rename, move, download, favorite)
   - Confirmation dialogs for destructive actions with toast notifications

2. **Audio Player System**:
   - Built Spotify-like player with bottom bar controls
   - Playlist management with CRUD operations
   - Queue management with drag-and-drop reordering
   - Shuffle and repeat modes
   - Play history tracking
   - Volume control and progress seeking

3. **Document Viewer**:
   - PDF rendering with zoom controls (50%-200%)
   - Text and code file preview with syntax highlighting
   - Office document support with download prompts
   - Full-screen mode and print functionality
   - Copy to clipboard for text content

4. **User Administration**:
   - Complete admin panel at /admin/users
   - User role management (user/admin)
   - Detailed user statistics and storage usage
   - User search, filter, and sort capabilities
   - Protected admin operations with self-protection

5. **Data Management**:
   - Admin controls for syncing media to files table
   - Duplicate category cleanup functionality
   - Bulk operations support
   - Comprehensive activity logging

### Technical Improvements
- Fixed Node.js memory issues with large files
- Added proper TypeScript interfaces for all components
- Implemented loading and error states throughout
- Added test-id attributes for all interactive elements
- Optimized database queries with proper indexing
- Enhanced security with role-based access control

### Navigation Updates
- Added Files, Documents, and Music links to main navbar
- Created functional Settings page with multiple tabs
- Added Admin tab in Settings for admin users only
- Implemented proper route protection for admin pages

## Usage Instructions

### For Regular Users
1. **Gallery**: Browse and manage your media files with search and filters
2. **Files**: Use the comprehensive file manager for all file types
3. **Documents**: View and manage PDFs and office documents
4. **Music**: Play audio files with playlist support
5. **Settings**: Configure your profile and preferences

### For Administrators
1. **Settings > Admin**: Access data migration and cleanup tools
2. **User Administration**: Manage users from /admin/users
3. **Sync Media**: Use "Sync Media to File Manager" to migrate existing files
4. **Clean Categories**: Remove duplicate categories with one click

## Performance Optimizations
- Lazy loading for large file lists
- Thumbnail caching for faster gallery loads
- Pagination for user lists and file queries
- Debounced search inputs
- Optimized database queries with proper indexing