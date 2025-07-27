const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 8080;

// Cấu hình thư mục lưu trữ file upload
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Cấu hình multer để xử lý upload file
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});
const upload = multer({ storage: storage });

// Middleware kiểm tra admin
const isAdmin = (req, res, next) => {
    const adminKey = req.query.adminKey;
    if (adminKey === 'your-secret-key') {
        next();
    } else {
        res.status(403).send('Access denied. Admin key required.');
    }
};

// Route để admin upload file
app.post('/upload', isAdmin, upload.single('zipfile'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }
    res.send(`File ${req.file.originalname} uploaded successfully.`);
});

// Route để người dùng tải file
app.get('/download/:filename', (req, res) => {
    const filePath = path.join(uploadDir, req.params.filename);
    
    if (fs.existsSync(filePath)) {
        res.download(filePath, (err) => {
            if (err) {
                res.status(500).send('Error downloading file.');
            }
        });
    } else {
        res.status(404).send('File not found.');
    }
});

// Route hiển thị danh sách file
app.get('/', (req, res) => {
    fs.readdir(uploadDir, (err, files) => {
        if (err) {
            return res.status(500).send('Error reading directory.');
        }
        let html = '<h1>Available Files</h1><ul>';
        files.forEach(file => {
            html += `<li><a href="/download/${file}">${file}</a></li>`;
        });
        html += '</ul>';
        res.send(html);
    });
});

// Khởi động server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});