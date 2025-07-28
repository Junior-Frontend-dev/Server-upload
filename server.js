const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const compression = require("compression");
const archiver = require("archiver");
const mime = require("mime-types");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const SequelizeStore = require("connect-session-sequelize")(session.Store);
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

// Load environment variables
require("dotenv").config();

// Import database and models
const { sequelize, User, File, AuditLog, IPList, APIKey, Setting } = require("./models");

// Import middleware
const { isAdmin, authenticate, authorize, auditLog } = require("./middleware/auth");
const { validateUser, validateLogin, validateFile } = require("./middleware/validation");

// Import routes
const adminRoutes = require("./routes/admin");

// Import utilities
const logger = require("./utils/logger");

const app = express();
const port = process.env.PORT || 8000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "https://cdn.replit.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            connectSrc: ["'self'"]
        }
    }
}));

app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? false : true,
    credentials: true
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: (process.env.RATE_LIMIT_WINDOW || 15) * 60 * 1000, // 15 minutes
    max: process.env.RATE_LIMIT_MAX || 100, // limit each IP to 100 requests per windowMs
    message: {
        error: "Too many requests from this IP, please try again later."
    },
    standardHeaders: true,
    legacyHeaders: false
});

app.use(limiter);

// Compression middleware
app.use(compression({
    level: 9,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers["x-no-compression"]) {
            return false;
        }
        return compression.filter(req, res);
    },
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
const sessionStore = new SequelizeStore({
    db: sequelize,
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret-change-this',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Create session table
sessionStore.sync();

// Serve static files
app.use(express.static("public"));

// Create upload directory if it doesn't exist
const uploadDir = path.join(__dirname, process.env.UPLOAD_DIR || "uploads");
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const timestamp = Date.now();
        const ext = path.extname(file.originalname);
        const name = path.basename(file.originalname, ext);
        const sanitizedName = name.replace(/[^a-zA-Z0-9]/g, '_');
        cb(null, `${sanitizedName}_${timestamp}${ext}`);
    },
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: parseInt(process.env.MAX_FILE_SIZE) || 100 * 1024 * 1024, // 100MB default
    },
    fileFilter: (req, file, cb) => {
        // Basic file type validation
        const allowedTypes = /\.(jpg|jpeg|png|gif|pdf|doc|docx|txt|zip|rar|mp3|mp4|avi|mov|xlsx|pptx)$/i;
        if (allowedTypes.test(file.originalname)) {
            cb(null, true);
        } else {
            cb(new Error("File type not allowed"), false);
        }
    },
});

// IP filtering middleware
const checkIPAccess = async (req, res, next) => {
    try {
        const clientIP = req.ip || req.connection.remoteAddress;
        
        // Check blacklist first
        const blacklisted = await IPList.findOne({
            where: { 
                ipAddress: clientIP, 
                type: 'blacklist',
                isActive: true 
            }
        });
        
        if (blacklisted) {
            logger.warn(`Blocked request from blacklisted IP: ${clientIP}`);
            return res.status(403).json({ error: 'Access denied' });
        }
        
        // Check if whitelist exists and is enforced
        const whitelistCount = await IPList.count({
            where: { type: 'whitelist', isActive: true }
        });
        
        if (whitelistCount > 0) {
            const whitelisted = await IPList.findOne({
                where: { 
                    ipAddress: clientIP, 
                    type: 'whitelist',
                    isActive: true 
                }
            });
            
            if (!whitelisted) {
                logger.warn(`Blocked request from non-whitelisted IP: ${clientIP}`);
                return res.status(403).json({ error: 'Access denied' });
            }
        }
        
        next();
    } catch (error) {
        logger.error('IP check error:', error);
        next(); // Continue on error to avoid blocking legitimate requests
    }
};

app.use(checkIPAccess);

// Logging middleware
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.originalUrl} - ${req.ip}`);
    next();
});

// Authentication Routes
app.post('/api/register', validateUser, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check if registration is allowed
        const registrationSetting = await Setting.findOne({
            where: { key: 'general.allowRegistration' }
        });
        
        if (registrationSetting && !registrationSetting.value) {
            return res.status(403).json({ error: 'Registration is currently disabled' });
        }
        
        const user = await User.create({
            username,
            email,
            passwordHash: password,
            role: 'user',
            status: 'active'
        });

        // Create JWT token
        const token = jwt.sign(
            { userId: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET || 'your-jwt-secret',
            { expiresIn: '24h' }
        );

        // Store token in session
        req.session.token = token;
        req.session.userId = user.id;

        // Log registration
        await AuditLog.create({
            userId: user.id,
            action: 'REGISTER',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.status(201).json({
            message: 'Registration successful',
            user: user.toJSON(),
            token
        });
    } catch (error) {
        logger.error('Registration error:', error);
        if (error.name === 'SequelizeUniqueConstraintError') {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', validateLogin, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const user = await User.findOne({
            where: {
                [require('sequelize').Op.or]: [
                    { username },
                    { email: username }
                ]
            }
        });

        if (!user || !(await user.validatePassword(password))) {
            await AuditLog.create({
                action: 'LOGIN_FAILED',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                details: { username }
            });
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (user.status !== 'active') {
            return res.status(401).json({ error: 'Account is not active' });
        }

        // Update last login
        await user.update({ lastLogin: new Date() });

        // Create JWT token
        const token = jwt.sign(
            { userId: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET || 'your-jwt-secret',
            { expiresIn: '24h' }
        );

        // Store token in session
        req.session.token = token;
        req.session.userId = user.id;

        // Log successful login
        await AuditLog.create({
            userId: user.id,
            action: 'LOGIN',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            message: 'Login successful',
            user: user.toJSON(),
            token
        });
    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/logout', authenticate, async (req, res) => {
    try {
        // Log logout
        await AuditLog.create({
            userId: req.user.id,
            action: 'LOGOUT',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        // Destroy session
        req.session.destroy((err) => {
            if (err) {
                logger.error('Session destroy error:', err);
            }
        });

        res.json({ message: 'Logout successful' });
    } catch (error) {
        logger.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

app.get('/api/profile', authenticate, (req, res) => {
    res.json(req.user.toJSON());
});

app.put('/api/profile', authenticate, async (req, res) => {
    try {
        const { email, currentPassword, newPassword } = req.body;
        const user = req.user;

        // Verify current password if changing password
        if (newPassword) {
            if (!currentPassword || !(await user.validatePassword(currentPassword))) {
                return res.status(400).json({ error: 'Current password is incorrect' });
            }
            user.passwordHash = newPassword;
        }

        if (email) {
            user.email = email;
        }

        await user.save();

        // Log profile update
        await AuditLog.create({
            userId: user.id,
            action: 'UPDATE_PROFILE',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });

        res.json({
            message: 'Profile updated successfully',
            user: user.toJSON()
        });
    } catch (error) {
        logger.error('Profile update error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// File Management Routes
app.post("/api/upload", authenticate, upload.array("files", 20), auditLog('UPLOAD_FILES', 'file'), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ error: "No files uploaded." });
        }

        const user = req.user;
        const totalSize = req.files.reduce((sum, file) => sum + file.size, 0);

        // Check storage limit
        if (!user.canUpload(totalSize)) {
            // Clean up uploaded files
            req.files.forEach(file => {
                fs.unlink(file.path, () => {});
            });
            return res.status(400).json({ 
                error: "Storage limit exceeded",
                remaining: user.getRemainingStorage()
            });
        }

        const uploadedFiles = [];

        for (const file of req.files) {
            const fileRecord = await File.create({
                filename: file.filename,
                originalName: file.originalname,
                fileSize: file.size,
                mimeType: file.mimetype,
                userId: user.id,
                isPublic: req.body.isPublic !== 'false'
            });

            uploadedFiles.push({
                id: fileRecord.id,
                originalName: file.originalname,
                filename: file.filename,
                size: file.size,
                type: file.mimetype,
                uploadTime: fileRecord.createdAt
            });
        }

        // Update user storage
        await user.update({
            storageUsed: user.storageUsed + totalSize
        });

        res.json({
            message: `${req.files.length} file(s) uploaded successfully.`,
            files: uploadedFiles,
            totalSize,
            remainingStorage: user.getRemainingStorage()
        });
    } catch (error) {
        logger.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

app.get("/api/files", async (req, res) => {
    try {
        const userFiles = req.query.userFiles === 'true';
        const where = {};

        if (userFiles && req.user) {
            where.userId = req.user.id;
        } else if (!req.user) {
            where.isPublic = true;
        }

        const files = await File.findAll({
            where,
            order: [['createdAt', 'DESC']],
            include: req.user ? [{ 
                model: User, 
                as: 'user', 
                attributes: ['username'] 
            }] : []
        });

        const fileList = files.map(file => ({
            id: file.id,
            name: file.filename,
            originalName: file.originalName,
            size: file.fileSize,
            type: file.mimeType,
            created: file.createdAt,
            downloads: file.downloadCount,
            isPublic: file.isPublic,
            user: file.user?.username
        }));

        res.json(fileList);
    } catch (error) {
        logger.error('Get files error:', error);
        res.status(500).json({ error: "Error reading files." });
    }
});

app.get("/api/download/:filename", async (req, res) => {
    try {
        const filename = req.params.filename;
        const filePath = path.join(uploadDir, filename);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: "File not found." });
        }

        // Find file record
        const fileRecord = await File.findOne({ where: { filename } });
        if (fileRecord) {
            // Check if file is public or user owns it
            if (!fileRecord.isPublic && (!req.user || fileRecord.userId !== req.user.id)) {
                return res.status(403).json({ error: "Access denied." });
            }

            // Increment download count
            await fileRecord.increment('downloadCount');

            // Log download
            await AuditLog.create({
                userId: req.user?.id || null,
                action: 'DOWNLOAD_FILE',
                resource: 'file',
                resourceId: fileRecord.id,
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                details: { filename: fileRecord.originalName }
            });
        }

        const stats = fs.statSync(filePath);
        const mimeType = mime.lookup(filePath) || "application/octet-stream";
        const range = req.headers.range;

        // Support for range requests (resume/partial downloads)
        if (range) {
            const parts = range.replace(/bytes=/, "").split("-");
            const start = parseInt(parts[0], 10);
            const end = parts[1] ? parseInt(parts[1], 10) : stats.size - 1;

            if (start >= stats.size) {
                res.status(416).send(
                    "Requested range not satisfiable\n" +
                        start +
                        " >= " +
                        stats.size,
                );
                return;
            }

            const chunksize = end - start + 1;
            const fileStream = fs.createReadStream(filePath, { start, end });

            res.writeHead(206, {
                "Content-Range": `bytes ${start}-${end}/${stats.size}`,
                "Accept-Ranges": "bytes",
                "Content-Length": chunksize,
                "Content-Type": mimeType,
                "Content-Disposition": `attachment; filename="${fileRecord?.originalName || filename}"`,
            });

            fileStream.pipe(res);
        } else {
            // Regular download with optimized headers
            res.setHeader("Content-Type", mimeType);
            res.setHeader("Content-Length", stats.size);
            res.setHeader(
                "Content-Disposition",
                `attachment; filename="${fileRecord?.originalName || filename}"`,
            );
            res.setHeader("Accept-Ranges", "bytes");
            res.setHeader("Cache-Control", "public, max-age=31536000");
            res.setHeader("Last-Modified", stats.mtime.toUTCString());

            const etag = `"${stats.size}-${stats.mtime.getTime()}"`;
            res.setHeader("ETag", etag);

            if (req.headers["if-none-match"] === etag) {
                res.status(304).end();
                return;
            }

            const fileStream = fs.createReadStream(filePath);
            fileStream.pipe(res);
        }
    } catch (error) {
        logger.error('Download error:', error);
        res.status(500).json({ error: 'Download failed' });
    }
});

app.post("/api/download-multiple", async (req, res) => {
    try {
        const { files } = req.body;

        if (!files || !Array.isArray(files) || files.length === 0) {
            return res.status(400).json({ error: "No files specified." });
        }

        res.setHeader("Content-Type", "application/zip");
        res.setHeader("Content-Disposition", 'attachment; filename="files.zip"');

        const archive = archiver("zip", { zlib: { level: 9 } });
        archive.pipe(res);

        for (const filename of files) {
            const filePath = path.join(uploadDir, filename);
            if (fs.existsSync(filePath)) {
                const fileRecord = await File.findOne({ where: { filename } });
                const displayName = fileRecord?.originalName || filename;
                archive.file(filePath, { name: displayName });
            }
        }

        // Log bulk download
        if (req.user) {
            await AuditLog.create({
                userId: req.user.id,
                action: 'BULK_DOWNLOAD',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                details: { fileCount: files.length }
            });
        }

        archive.finalize();
    } catch (error) {
        logger.error('Bulk download error:', error);
        res.status(500).json({ error: 'Bulk download failed' });
    }
});

app.delete("/api/files/:filename", isAdmin, auditLog('DELETE_FILE', 'file'), async (req, res) => {
    try {
        const filename = req.params.filename;
        const filePath = path.join(uploadDir, filename);

        const fileRecord = await File.findOne({ where: { filename } });
        if (!fileRecord) {
            return res.status(404).json({ error: "File not found." });
        }

        // Check permissions
        if (!req.isAdmin && fileRecord.userId !== req.user?.id) {
            return res.status(403).json({ error: "Access denied." });
        }

        // Delete file from filesystem
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        // Update user storage if file had an owner
        if (fileRecord.userId) {
            const user = await User.findByPk(fileRecord.userId);
            if (user) {
                await user.update({
                    storageUsed: Math.max(0, user.storageUsed - fileRecord.fileSize)
                });
            }
        }

        // Delete file record
        await fileRecord.destroy();

        res.json({ message: "File deleted successfully." });
    } catch (error) {
        logger.error('Delete file error:', error);
        res.status(500).json({ error: "Error deleting file." });
    }
});

app.get("/api/preview/:filename", async (req, res) => {
    try {
        const filename = req.params.filename;
        const filePath = path.join(uploadDir, filename);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: "File not found." });
        }

        const fileRecord = await File.findOne({ where: { filename } });
        if (fileRecord && !fileRecord.isPublic && (!req.user || fileRecord.userId !== req.user.id)) {
            return res.status(403).json({ error: "Access denied." });
        }

        const mimeType = mime.lookup(filePath);

        if (mimeType && (mimeType.startsWith("image/") || mimeType.startsWith("text/"))) {
            res.setHeader("Content-Type", mimeType);
            res.setHeader("Cache-Control", "public, max-age=86400");
            fs.createReadStream(filePath).pipe(res);
        } else {
            res.status(415).json({
                error: "Preview not available for this file type.",
            });
        }
    } catch (error) {
        logger.error('Preview error:', error);
        res.status(500).json({ error: 'Preview failed' });
    }
});

// Admin routes
app.use('/api/admin', adminRoutes);

// Static routes
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/admin-enhanced", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin-enhanced.html"));
});

app.get("/auth", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "auth.html"));
});

// Error handling middleware
app.use((error, req, res, next) => {
    logger.error('Unhandled error:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === "LIMIT_FILE_SIZE") {
            return res.status(400).json({ 
                error: `File too large. Maximum size is ${Math.round(parseInt(process.env.MAX_FILE_SIZE || 104857600) / 1024 / 1024)}MB.` 
            });
        }
    }
    
    res.status(500).json({ 
        error: process.env.NODE_ENV === 'production' 
            ? 'Internal server error' 
            : error.message 
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Database initialization and server startup
async function startServer() {
    try {
        // Test database connection
        await sequelize.authenticate();
        logger.info('Database connection established successfully.');

        // Sync database models
        await sequelize.sync({ alter: process.env.NODE_ENV === 'development' });
        logger.info('Database models synchronized.');

        // Create default admin user if none exists
        const adminCount = await User.count({ where: { role: 'admin' } });
        if (adminCount === 0) {
            await User.create({
                username: 'admin',
                email: 'admin@example.com',
                passwordHash: 'admin123',
                role: 'admin',
                status: 'active',
                storageLimit: 1024 * 1024 * 1024 // 1GB for admin
            });
            logger.info('Default admin user created (username: admin, password: admin123)');
        }

        // Create default settings
        const defaultSettings = [
            { key: 'general.siteName', value: 'File Share Platform', type: 'string' },
            { key: 'general.allowRegistration', value: true, type: 'boolean' },
            { key: 'general.maxFileSize', value: 104857600, type: 'number' },
            { key: 'general.defaultStorage', value: 104857600, type: 'number' }
        ];

        for (const setting of defaultSettings) {
            await Setting.findOrCreate({
                where: { key: setting.key },
                defaults: setting
            });
        }

        // Start server
        app.listen(port, "0.0.0.0", () => {
            logger.info(`Enhanced file sharing server running at http://0.0.0.0:${port}`);
            logger.info(`Admin panel: http://0.0.0.0:${port}/admin-enhanced`);
            logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`Enhanced file sharing server running at http://0.0.0.0:${port}`);
            console.log(`Admin panel: http://0.0.0.0:${port}/admin-enhanced`);
        });

    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
    logger.info('SIGTERM received, shutting down gracefully');
    await sequelize.close();
    process.exit(0);
});

process.on('SIGINT', async () => {
    logger.info('SIGINT received, shutting down gracefully');
    await sequelize.close();
    process.exit(0);
});

// Start the server
startServer();