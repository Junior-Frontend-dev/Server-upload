# File Share Platform

## Overview

This is an enhanced Node.js-based file sharing platform that allows users to browse and download shared files, with an advanced admin panel for file management. The application features a modern web interface with dark theme support, enhanced file upload capabilities, bulk operations, advanced search functionality, real-time statistics, file sharing links, and optimized download speeds with resume support.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Architecture
- **Framework**: Express.js server running on Node.js
- **File Upload**: Multer middleware for handling multipart/form-data file uploads
- **File Storage**: Local filesystem storage in an 'uploads' directory
- **Compression**: gzip compression for faster file downloads
- **Archive Support**: Archiver library for creating ZIP files for bulk downloads

### Frontend Architecture
- **UI Framework**: Bootstrap 5 with dark theme
- **Icons**: Font Awesome 6.0
- **JavaScript**: Vanilla JavaScript with async/await for API calls
- **Responsive Design**: Mobile-first approach with Bootstrap grid system

### Security Model
- **Admin Authentication**: Simple key-based authentication for admin access
- **File Type Validation**: Whitelist-based file type filtering
- **File Size Limits**: 100MB maximum file size for uploads
- **Access Control**: Separate admin and user interfaces

## Key Components

### Server Components
1. **Main Server** (`server.js`): Express application with file upload, download, and admin routes
2. **Static File Serving**: Public directory serving HTML, CSS, and JavaScript files
3. **Upload Handler**: Multer configuration with timestamp-based filename generation
4. **Archive Generator**: On-demand ZIP file creation for bulk downloads

### Frontend Components
1. **User Interface** (`index.html`): File browsing, search, and download functionality
2. **Admin Panel** (`admin.html`): File upload, management, and deletion capabilities
3. **Styling** (`style.css`): Custom CSS for enhanced user experience
4. **Client Scripts**: 
   - `main.js`: User-facing functionality (search, download, selection)
   - `admin.js`: Admin panel functionality (upload, delete, authentication)

### Enhanced File Management Features
- **Advanced Search**: Real-time file searching with debounced input, type-based filtering, and advanced search panel
- **Smart Filtering**: Search by file size, date range, and file type with operators (greater than, less than, equal to)
- **Bulk Operations**: Multi-file selection and bulk download as ZIP with progress tracking
- **File Preview**: Enhanced icon-based file type identification with preview support for images and text files
- **Upload Progress**: Visual feedback during file uploads with progress bars and status updates
- **Drag and Drop**: Modern file upload interface with enhanced visual feedback
- **File Sharing**: Generate shareable direct download links for individual files or bulk selections
- **Real-time Statistics**: Live tracking of total files, storage usage, download count, and latest uploads
- **Enhanced Download Speed**: Range request support for resumable downloads and optimized caching
- **File Deduplication**: SHA-256 hash generation for duplicate detection
- **Toast Notifications**: Modern toast notification system for user feedback

## Data Flow

### File Upload Process
1. Admin authenticates with secret key
2. Files uploaded via drag-drop or file picker
3. Multer processes multipart data and saves to uploads directory
4. Filename sanitized with timestamp to prevent conflicts
5. File metadata stored in memory for API responses

### File Download Process
1. User browses available files via REST API
2. Individual files downloaded directly from uploads directory
3. Bulk downloads trigger ZIP archive creation
4. Archives streamed to client with appropriate MIME types

### Admin Operations
1. Authentication via URL parameter or form input
2. File management operations (upload, delete, view)
3. Bulk operations for file management
4. Real-time file listing updates

## External Dependencies

### NPM Packages
- **express**: Web framework for Node.js
- **multer**: Middleware for handling file uploads
- **archiver**: Library for creating ZIP archives
- **compression**: Middleware for gzip compression
- **mime-types**: MIME type detection and handling

### Frontend Libraries
- **Bootstrap 5**: CSS framework with dark theme support
- **Font Awesome 6**: Icon library for UI elements

## Deployment Strategy

### Development Setup
- Entry point: `server.js`
- Port: 8000 (configurable)
- File storage: Local `uploads` directory (auto-created)
- Static assets: Served from `public` directory

### Production Considerations
- **File Storage**: Currently uses local filesystem (could be extended to cloud storage)
- **Security**: Basic key-based admin authentication (should be enhanced for production)
- **Scalability**: Single-server deployment (could be enhanced with load balancing)
- **Backup**: No automated backup strategy (should be implemented for production)

### Environment Requirements
- Node.js runtime
- Write permissions for uploads directory
- Network access for CDN resources (Bootstrap, Font Awesome)

The application is designed as a simple but functional file sharing platform suitable for small teams or personal use, with clear separation between user and admin functionality.