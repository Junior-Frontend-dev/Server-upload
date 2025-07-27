const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const compression = require("compression");
const archiver = require("archiver");
const mime = require("mime-types");

const app = express();
const port = 8000;

// Enable compression for faster downloads with optimized settings
app.use(
    compression({
        level: 9,
        threshold: 1024,
        filter: (req, res) => {
            if (req.headers["x-no-compression"]) {
                return false;
            }
            return compression.filter(req, res);
        },
    }),
);

// Serve static files
app.use(express.static("public"));
app.use(express.json());

// Create upload directory if it doesn't exist
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file uploads with better validation
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        // Add timestamp to prevent conflicts
        const timestamp = Date.now();
        const ext = path.extname(file.originalname);
        const name = path.basename(file.originalname, ext);
        cb(null, `${name}_${timestamp}${ext}`);
    },
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB limit
    },
    fileFilter: (req, file, cb) => {
        // Basic file type validation
        const allowedTypes =
            /\.(jpg|jpeg|png|gif|pdf|doc|docx|txt|zip|rar|mp3|mp4|avi)$/i;
        if (allowedTypes.test(file.originalname)) {
            cb(null, true);
        } else {
            cb(new Error("File type not allowed"), false);
        }
    },
});

// Admin authentication middleware
const isAdmin = (req, res, next) => {
    const adminKey = req.headers.authorization || req.query.adminKey;
    const validKey = process.env.ADMIN_KEY || "admin123";

    if (adminKey === validKey || adminKey === `Bearer ${validKey}`) {
        next();
    } else {
        res.status(403).json({ error: "Access denied. Admin key required." });
    }
};

// Get file statistics
const getFileStats = (filePath) => {
    try {
        const stats = fs.statSync(filePath);
        return {
            size: stats.size,
            created: stats.birthtime,
            modified: stats.mtime,
            type: mime.lookup(filePath) || "application/octet-stream",
        };
    } catch (error) {
        return null;
    }
};

// Generate file hash for duplicate detection
const generateFileHash = (filePath) => {
    try {
        const crypto = require("crypto");
        const fileBuffer = fs.readFileSync(filePath);
        const hashSum = crypto.createHash("sha256");
        hashSum.update(fileBuffer);
        return hashSum.digest("hex");
    } catch (error) {
        return null;
    }
};

// Get file usage statistics
const getStorageStats = () => {
    try {
        const files = fs.readdirSync(uploadDir);
        const stats = files.map((file) => {
            const filePath = path.join(uploadDir, file);
            const fileStats = fs.statSync(filePath);
            return {
                name: file,
                size: fileStats.size,
                created: fileStats.birthtime,
            };
        });

        const totalSize = stats.reduce((sum, file) => sum + file.size, 0);
        const totalFiles = stats.length;

        return {
            totalFiles,
            totalSize,
            averageSize: totalFiles > 0 ? totalSize / totalFiles : 0,
            files: stats,
        };
    } catch (error) {
        return { totalFiles: 0, totalSize: 0, averageSize: 0, files: [] };
    }
};

// API Routes

// Upload files (multiple files support with enhanced features)
app.post("/api/upload", isAdmin, upload.array("files", 20), (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: "No files uploaded." });
    }

    const uploadedFiles = req.files.map((file) => {
        const stats = fs.statSync(file.path);
        return {
            originalName: file.originalname,
            filename: file.filename,
            size: file.size,
            type: file.mimetype,
            uploadTime: new Date().toISOString(),
            hash: generateFileHash(file.path),
        };
    });

    res.json({
        message: `${req.files.length} file(s) uploaded successfully.`,
        files: uploadedFiles,
        totalSize: uploadedFiles.reduce((sum, file) => sum + file.size, 0),
    });
});

// Get all files with metadata
app.get("/api/files", (req, res) => {
    fs.readdir(uploadDir, (err, files) => {
        if (err) {
            return res.status(500).json({ error: "Error reading directory." });
        }

        const fileList = files
            .filter((file) => file !== ".gitkeep")
            .map((file) => {
                const filePath = path.join(uploadDir, file);
                const stats = getFileStats(filePath);
                return {
                    name: file,
                    originalName: file.replace(/_\d+(\.[^.]+)?$/, "$1"), // Remove timestamp
                    ...stats,
                };
            })
            .filter((file) => file.size !== null); // Filter out files with stat errors

        res.json(fileList);
    });
});

// Download individual file with streaming and range support
app.get("/api/download/:filename", (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDir, filename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "File not found." });
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
            "Content-Disposition": `attachment; filename="${filename}"`,
        });

        fileStream.pipe(res);
    } else {
        // Regular download with optimized headers
        res.setHeader("Content-Type", mimeType);
        res.setHeader("Content-Length", stats.size);
        res.setHeader(
            "Content-Disposition",
            `attachment; filename="${filename}"`,
        );
        res.setHeader("Accept-Ranges", "bytes");
        res.setHeader("Cache-Control", "public, max-age=31536000"); // 1 year cache
        res.setHeader("Last-Modified", stats.mtime.toUTCString());

        // Check if file hasn't changed (ETag support)
        const etag = `"${stats.size}-${stats.mtime.getTime()}"`;
        res.setHeader("ETag", etag);

        if (req.headers["if-none-match"] === etag) {
            res.status(304).end();
            return;
        }

        // Stream the file for better performance
        const fileStream = fs.createReadStream(filePath);
        fileStream.pipe(res);
    }
});

// Download multiple files as ZIP
app.post("/api/download-multiple", (req, res) => {
    const { files } = req.body;

    if (!files || !Array.isArray(files) || files.length === 0) {
        return res.status(400).json({ error: "No files specified." });
    }

    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", 'attachment; filename="files.zip"');

    const archive = archiver("zip", { zlib: { level: 9 } });
    archive.pipe(res);

    files.forEach((filename) => {
        const filePath = path.join(uploadDir, filename);
        if (fs.existsSync(filePath)) {
            archive.file(filePath, { name: filename });
        }
    });

    archive.finalize();
});

// Delete files (admin only)
app.delete("/api/files/:filename", isAdmin, (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDir, filename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "File not found." });
    }

    fs.unlink(filePath, (err) => {
        if (err) {
            return res.status(500).json({ error: "Error deleting file." });
        }
        res.json({ message: "File deleted successfully." });
    });
});

// Delete multiple files (admin only)
app.delete("/api/files", isAdmin, (req, res) => {
    const { files } = req.body;

    if (!files || !Array.isArray(files)) {
        return res.status(400).json({ error: "No files specified." });
    }

    const results = [];
    let completed = 0;

    files.forEach((filename) => {
        const filePath = path.join(uploadDir, filename);

        fs.unlink(filePath, (err) => {
            results.push({
                filename,
                success: !err,
                error: err ? err.message : null,
            });

            completed++;
            if (completed === files.length) {
                res.json({
                    message: `Processed ${files.length} files.`,
                    results,
                });
            }
        });
    });
});

// Get file preview/thumbnail
app.get("/api/preview/:filename", (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDir, filename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "File not found." });
    }

    const mimeType = mime.lookup(filePath);

    // Only serve images and text files as previews
    if (
        mimeType &&
        (mimeType.startsWith("image/") || mimeType.startsWith("text/"))
    ) {
        res.setHeader("Content-Type", mimeType);
        res.setHeader("Cache-Control", "public, max-age=86400"); // 24 hour cache
        fs.createReadStream(filePath).pipe(res);
    } else {
        res.status(415).json({
            error: "Preview not available for this file type.",
        });
    }
});

// Get storage statistics (admin only)
app.get("/api/stats", isAdmin, (req, res) => {
    try {
        const stats = getStorageStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: "Failed to get storage stats." });
    }
});

// Search files with advanced filtering
app.get("/api/search", (req, res) => {
    const { q, type, size, date } = req.query;

    try {
        const files = fs
            .readdirSync(uploadDir)
            .filter((file) => file !== ".gitkeep")
            .map((file) => {
                const filePath = path.join(uploadDir, file);
                const stats = getFileStats(filePath);
                return {
                    name: file,
                    originalName: file.replace(/_\d+(\.[^.]+)?$/, "$1"),
                    ...stats,
                };
            })
            .filter((file) => file.size !== null);

        let filteredFiles = files;

        // Text search
        if (q) {
            filteredFiles = filteredFiles.filter((file) =>
                file.originalName.toLowerCase().includes(q.toLowerCase()),
            );
        }

        // Type filter
        if (type) {
            filteredFiles = filteredFiles.filter((file) => {
                const category = getFileCategory(file.type);
                return category === type;
            });
        }

        // Size filter (in bytes)
        if (size) {
            const [operator, value] = size.split(":");
            const sizeBytes = parseInt(value);

            filteredFiles = filteredFiles.filter((file) => {
                switch (operator) {
                    case "gt":
                        return file.size > sizeBytes;
                    case "lt":
                        return file.size < sizeBytes;
                    case "eq":
                        return file.size === sizeBytes;
                    default:
                        return true;
                }
            });
        }

        // Date filter
        if (date) {
            const [operator, value] = date.split(":");
            const targetDate = new Date(value);

            filteredFiles = filteredFiles.filter((file) => {
                const fileDate = new Date(file.created);
                switch (operator) {
                    case "after":
                        return fileDate > targetDate;
                    case "before":
                        return fileDate < targetDate;
                    case "on":
                        return (
                            fileDate.toDateString() ===
                            targetDate.toDateString()
                        );
                    default:
                        return true;
                }
            });
        }

        res.json(filteredFiles);
    } catch (error) {
        res.status(500).json({ error: "Search failed." });
    }
});

// Get file category helper
function getFileCategory(mimeType) {
    if (!mimeType) return "other";

    if (mimeType.startsWith("image/")) return "image";
    if (mimeType.startsWith("video/")) return "video";
    if (mimeType.startsWith("audio/")) return "audio";
    if (
        mimeType.includes("zip") ||
        mimeType.includes("rar") ||
        mimeType.includes("archive")
    )
        return "archive";
    if (
        mimeType.includes("pdf") ||
        mimeType.includes("document") ||
        mimeType.includes("text") ||
        mimeType.includes("sheet") ||
        mimeType.includes("presentation")
    )
        return "document";

    return "other";
}

// Serve main page
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Serve admin page
app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// Error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === "LIMIT_FILE_SIZE") {
            return res
                .status(400)
                .json({ error: "File too large. Maximum size is 100MB." });
        }
    }
    res.status(500).json({ error: error.message || "Internal server error." });
});

// Start server
app.listen(port, "0.0.0.0", () => {
    console.log(
        `Enhanced file sharing server running at http://0.0.0.0:${port}`,
    );
    console.log(`Admin key: ${process.env.ADMIN_KEY || "admin123"}`);
});
