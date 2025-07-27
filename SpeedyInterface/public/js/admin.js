// Admin panel JavaScript

let adminKey = '';
let isAuthenticated = false;



// Setup event listeners
function setupEventListeners() {
    // Admin key input
    document.getElementById('adminKey').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            authenticate();
        }
    });

    // File input and drag-drop
    const fileInput = document.getElementById('fileInput');
    const uploadZone = document.getElementById('uploadZone');

    uploadZone.addEventListener('click', () => fileInput.click());
    uploadZone.addEventListener('dragover', handleDragOver);
    uploadZone.addEventListener('dragleave', handleDragLeave);
    uploadZone.addEventListener('drop', handleDrop);

    fileInput.addEventListener('change', handleFileSelect);

    // Select all checkbox
    document.getElementById('selectAllFiles').addEventListener('change', toggleSelectAll);

    // Delete selected button
    document.getElementById('deleteAllBtn').addEventListener('click', deleteSelectedFiles);

    // Search functionality
    document.getElementById('adminSearchInput').addEventListener('input', filterAdminFiles);
}

// Check if admin key is provided in URL
function checkAuthFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    const keyFromUrl = urlParams.get('adminKey');

    if (keyFromUrl) {
        document.getElementById('adminKey').value = keyFromUrl;
        authenticate();
    }
}

// Authenticate admin
async function authenticate() {
    const keyInput = document.getElementById('adminKey');
    adminKey = keyInput.value.trim();

    if (!adminKey) {
        showAuthError('Please enter admin key');
        return;
    }

    try {
        // Test authentication by trying to fetch files
        const response = await fetch('/api/files', {
            headers: {
                'Authorization': adminKey
            }
        });

        if (response.status === 403) {
            showAuthError('Invalid admin key');
            return;
        }

        isAuthenticated = true;
        hideAuthSection();
        showAdminDashboard();
        loadAdminFiles();

    } catch (error) {
        console.error('Auth error:', error);
        showAuthError('Authentication failed');
    }
}

// Show authentication error
function showAuthError(message) {
    const errorDiv = document.getElementById('authError');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
}

// Hide auth section and show dashboard
function hideAuthSection() {
    document.getElementById('authSection').style.display = 'none';
    document.getElementById('adminDashboard').style.display = 'block';
}

function showAdminDashboard() {
    document.getElementById('authSection').style.display = 'none';
    document.getElementById('adminDashboard').style.display = 'block';

    // Load admin statistics when dashboard is shown
    loadAdminStats();
}

// Drag and drop handlers
function handleDragOver(e) {
    e.preventDefault();
    e.currentTarget.classList.add('dragover');
}

function handleDragLeave(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('dragover');
}

function handleDrop(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('dragover');

    const files = Array.from(e.dataTransfer.files);
    uploadFiles(files);
}

// Handle file selection
function handleFileSelect(e) {
    const files = Array.from(e.target.files);
    uploadFiles(files);
}

// Upload files
async function uploadFiles(files) {
    if (files.length === 0) return;

    const formData = new FormData();
    files.forEach(file => {
        formData.append('files', file);
    });

    showUploadProgress();

    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            headers: {
                'Authorization': adminKey
            },
            body: formData
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Upload failed');
        }

        showUploadSuccess(result.message);
        loadAdminFiles();

        // Reset file input
        document.getElementById('fileInput').value = '';

    } catch (error) {
        console.error('Upload error:', error);
        showUploadError(error.message);
    }
}

// Show upload progress
function showUploadProgress() {
    document.getElementById('uploadProgress').style.display = 'block';
    document.getElementById('uploadResults').style.display = 'none';

    // Simulate progress (in real implementation, you'd track actual progress)
    const progressBar = document.querySelector('#uploadProgress .progress-bar');
    let progress = 0;

    const interval = setInterval(() => {
        progress += 10;
        progressBar.style.width = progress + '%';

        if (progress >= 90) {
            clearInterval(interval);
        }
    }, 100);
}

// Show upload success
function showUploadSuccess(message) {
    document.getElementById('uploadProgress').style.display = 'none';
    document.getElementById('uploadResults').style.display = 'block';
    document.getElementById('uploadSuccessMessage').textContent = message;

    setTimeout(() => {
        document.getElementById('uploadResults').style.display = 'none';
    }, 5000);
}

// Show upload error
function showUploadError(message) {
    document.getElementById('uploadProgress').style.display = 'none';

    const resultsDiv = document.getElementById('uploadResults');
    resultsDiv.innerHTML = `
        <div class="alert alert-danger">
            <i class="fas fa-exclamation-triangle me-2"></i>
            ${message}
        </div>
    `;
    resultsDiv.style.display = 'block';

    setTimeout(() => {
        resultsDiv.style.display = 'none';
    }, 5000);
}

// Load files for admin management
async function loadAdminFiles() {
    try {
        const response = await fetch('/api/files', {
            headers: {
                'Authorization': adminKey
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load files');
        }

        const files = await response.json();
        displayAdminFiles(files);

    } catch (error) {
        console.error('Error loading files:', error);
        showError('Failed to load files');
    }
}

// Display files in admin table
function displayAdminFiles(files) {
    const tbody = document.getElementById('filesTableBody');
    const noFilesDiv = document.getElementById('noAdminFiles');

    if (files.length === 0) {
        tbody.innerHTML = '';
        noFilesDiv.style.display = 'block';
        return;
    }

    noFilesDiv.style.display = 'none';

    tbody.innerHTML = files.map(file => `
        <tr>
            <td>
                <input type="checkbox" class="form-check-input file-select" value="${file.name}">
            </td>
            <td>
                <div class="d-flex align-items-center">
                    <i class="${getFileIcon(file.type).icon} me-2"></i>
                    <span title="${file.name}">${truncateFilename(file.originalName, 30)}</span>
                    ${file.isHidden ? '<i class="fas fa-eye-slash ms-2 text-warning" title="Hidden file"></i>' : ''}
                    ${file.isPasswordProtected ? '<i class="fas fa-lock ms-2 text-info" title="Password protected"></i>' : ''}
                    ${file.viewLimit ? `<i class="fas fa-hourglass-half ms-2 text-danger" title="Auto-delete after ${file.viewLimit} views"></i>` : ''}
                </div>
            </td>
            <td>${formatFileSize(file.size)}</td>
            <td>
                <span class="badge bg-secondary">${getFileTypeLabel(file.type)}</span>
                ${file.viewCount !== undefined ? `<br><small class="text-muted">Views: ${file.viewCount}${file.viewLimit ? `/${file.viewLimit}` : ''}</small>` : ''}
            </td>
            <td>${formatDate(file.created)}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-primary" onclick="downloadFile('${file.name}')">
                        <i class="fas fa-download"></i>
                    </button>
                    <button class="btn btn-outline-info" onclick="openFileSettings('${file.id || file.name}')" title="Settings">
                        <i class="fas fa-cog"></i>
                    </button>
                    <button class="btn btn-outline-warning" onclick="resetViewCount('${file.id || file.name}')" title="Reset Views">
                        <i class="fas fa-undo"></i>
                    </button>
                    <button class="btn btn-outline-danger" onclick="deleteFile('${file.name}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');

    // Add event listeners to checkboxes
    tbody.querySelectorAll('.file-select').forEach(checkbox => {
        checkbox.addEventListener('change', updateDeleteButton);
    });
}

// Get file type label
function getFileTypeLabel(mimeType) {
    if (!mimeType) return 'Unknown';

    if (mimeType.startsWith('image/')) return 'Image';
    if (mimeType.startsWith('video/')) return 'Video';
    if (mimeType.startsWith('audio/')) return 'Audio';
    if (mimeType.includes('pdf')) return 'PDF';
    if (mimeType.includes('zip') || mimeType.includes('rar')) return 'Archive';
    if (mimeType.includes('document') || mimeType.includes('word')) return 'Document';
    if (mimeType.startsWith('text/')) return 'Text';

    return mimeType.split('/')[0] || 'File';
}

// Toggle select all files
function toggleSelectAll() {
    const selectAll = document.getElementById('selectAllFiles');
    const fileCheckboxes = document.querySelectorAll('.file-select');

    fileCheckboxes.forEach(checkbox => {
        checkbox.checked = selectAll.checked;
    });

    updateDeleteButton();
}

// Update delete button visibility
function updateDeleteButton() {
    const selectedFiles = document.querySelectorAll('.file-select:checked');
    const deleteBtn = document.getElementById('deleteAllBtn');

    if (selectedFiles.length > 0) {
        deleteBtn.style.display = 'inline-block';
    } else {
        deleteBtn.style.display = 'none';
    }
}

// Delete single file
function deleteFile(filename) {
    const modal = new bootstrap.Modal(document.getElementById('deleteModal'));
    const confirmText = document.getElementById('deleteConfirmText');
    const confirmBtn = document.getElementById('confirmDeleteBtn');

    confirmText.textContent = `Are you sure you want to delete "${filename}"?`;

    confirmBtn.onclick = async () => {
        try {
            const response = await fetch(`/api/files/${filename}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': adminKey
                }
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Delete failed');
            }

            modal.hide();
            loadAdminFiles();
            showSuccess('File deleted successfully');

        } catch (error) {
            console.error('Delete error:', error);
            showError('Failed to delete file: ' + error.message);
        }
    };

    modal.show();
}

// Delete selected files
function deleteSelectedFiles() {
    const selectedCheckboxes = document.querySelectorAll('.file-select:checked');

    if (selectedCheckboxes.length === 0) {
        return;
    }

    const filenames = Array.from(selectedCheckboxes).map(cb => cb.value);

    const modal = new bootstrap.Modal(document.getElementById('deleteModal'));
    const confirmText = document.getElementById('deleteConfirmText');
    const confirmBtn = document.getElementById('confirmDeleteBtn');

    confirmText.textContent = `Are you sure you want to delete ${filenames.length} selected file(s)?`;

    confirmBtn.onclick = async () => {
        try {
            const response = await fetch('/api/files', {
                method: 'DELETE',
                headers: {
                    'Authorization': adminKey,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ files: filenames })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Delete failed');
            }

            modal.hide();
            loadAdminFiles();
            showSuccess(`${filenames.length} file(s) deleted successfully`);

            // Clear select all checkbox
            document.getElementById('selectAllFiles').checked = false;
            updateDeleteButton();

        } catch (error) {
            console.error('Delete error:', error);
            showError('Failed to delete files: ' + error.message);
        }
    };

    modal.show();
}

// Filter admin files
function filterAdminFiles() {
    const searchTerm = document.getElementById('adminSearchInput').value.toLowerCase();
    const rows = document.querySelectorAll('#filesTableBody tr');

    rows.forEach(row => {
        const filename = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
        if (filename.includes(searchTerm)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// Refresh file list
function refreshFileList() {
    loadAdminFiles();
}

// Download file (reuse from main.js)
function downloadFile(filename) {
    const link = document.createElement('a');
    link.href = `/api/download/${filename}`;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Utility functions (reuse from main.js)
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

function truncateFilename(filename, maxLength = 20) {
    if (filename.length <= maxLength) return filename;
    const ext = filename.substring(filename.lastIndexOf('.'));
    const name = filename.substring(0, filename.lastIndexOf('.'));
    return name.substring(0, maxLength - ext.length - 3) + '...' + ext;
}

function getFileIcon(mimeType) {
    if (!mimeType) return { icon: 'fas fa-file', class: 'default' };

    if (mimeType.startsWith('image/')) {
        return { icon: 'fas fa-image', class: 'image' };
    } else if (mimeType.startsWith('video/')) {
        return { icon: 'fas fa-video', class: 'video' };
    } else if (mimeType.startsWith('audio/')) {
        return { icon: 'fas fa-music', class: 'audio' };
    } else if (mimeType.includes('pdf')) {
        return { icon: 'fas fa-file-pdf', class: 'document' };
    } else if (mimeType.includes('word') || mimeType.includes('document')) {
        return { icon: 'fas fa-file-word', class: 'document' };
    } else if (mimeType.includes('sheet') || mimeType.includes('excel')) {
        return { icon: 'fas fa-file-excel', class: 'document' };
    } else if (mimeType.includes('presentation') || mimeType.includes('powerpoint')) {
        return { icon: 'fas fa-file-powerpoint', class: 'document' };
    } else if (mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('archive')) {
        return { icon: 'fas fa-file-archive', class: 'archive' };
    } else if (mimeType.startsWith('text/')) {
        return { icon: 'fas fa-file-alt', class: 'document' };
    } else {
        return { icon: 'fas fa-file', class: 'default' };
    }
}

function showSuccess(message) {
    // Simple alert for now - could be enhanced with toast notifications
    alert(message);
}

function showError(message) {
    alert('Error: ' + message);
}

// New functions for advanced features

// Open file settings modal
async function openFileSettings(fileId) {
    try {
        const response = await fetch(`/api/admin/files/${fileId}`, {
            headers: {
                'Authorization': adminKey
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load file details');
        }

        const file = await response.json();

        // Populate modal with file data
        document.getElementById('settingsFileId').value = file.id;
        document.getElementById('settingsFileName').textContent = file.originalName;
        document.getElementById('settingsViewCount').textContent = file.viewCount || 0;

        // Set form values
        document.getElementById('isHiddenToggle').checked = file.isHidden || false;
        document.getElementById('viewLimit').value = file.viewLimit || '';
        document.getElementById('passwordProtectionToggle').checked = file.isPasswordProtected || false;

        // Show/hide sections based on current settings
        toggleHiddenSection();
        togglePasswordSection();

        // Set hidden URL if available
        if (file.hiddenUrl) {
            document.getElementById('hiddenUrl').value = window.location.origin + file.hiddenUrl;
        }

        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('fileSettingsModal'));
        modal.show();

    } catch (error) {
        console.error('Error loading file settings:', error);
        showError('Failed to load file details: ' + error.message);
    }
}

// Toggle hidden URL section
function toggleHiddenSection() {
    const isHidden = document.getElementById('isHiddenToggle').checked;
    const section = document.getElementById('hiddenUrlSection');
    section.style.display = isHidden ? 'block' : 'none';
}

// Toggle password section
function togglePasswordSection() {
    const isProtected = document.getElementById('passwordProtectionToggle').checked;
    const section = document.getElementById('passwordSection');
    section.style.display = isProtected ? 'block' : 'none';
}

// Change admin password
async function changeAdminPassword() {
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;

    if (!currentPassword || !newPassword) {
        showError('Please enter both current and new passwords');
        return;
    }

    if (newPassword.length < 6) {
        showError('New password must be at least 6 characters long');
        return;
    }

    try {
        const response = await fetch('/api/admin/change-password', {
            method: 'POST',
            headers: {
                'Authorization': adminKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                currentPassword: currentPassword,
                newPassword: newPassword
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Failed to change password');
        }

        // Update admin key and clear form
        adminKey = newPassword;
        document.getElementById('currentPassword').value = '';
        document.getElementById('newPassword').value = '';

        showSuccess('Admin password changed successfully');

    } catch (error) {
        console.error('Change password error:', error);
        showError('Failed to change password: ' + error.message);
    }
}

// Load admin statistics
async function loadAdminStats() {
    try {
        const response = await fetch('/api/admin/stats', {
            headers: {
                'Authorization': adminKey
            }
        });

        if (!response.ok) {
            throw new Error('Failed to load statistics');
        }

        const stats = await response.json();

        // Update statistics display with fallbacks
        const totalLoginsEl = document.getElementById('totalLogins');
        const uniqueAdminIPsEl = document.getElementById('uniqueAdminIPs');
        const totalDownloadsEl = document.getElementById('totalDownloads');
        const uniqueDownloadIPsEl = document.getElementById('uniqueDownloadIPs');

        if (totalLoginsEl) totalLoginsEl.textContent = stats.adminStats?.totalLogins || 0;
        if (uniqueAdminIPsEl) uniqueAdminIPsEl.textContent = stats.adminStats?.uniqueAdminIPs || 0;
        if (totalDownloadsEl) totalDownloadsEl.textContent = stats.downloadStats?.totalDownloads || 0;
        if (uniqueDownloadIPsEl) uniqueDownloadIPsEl.textContent = stats.downloadStats?.uniqueDownloadIPs || 0;

        // Update admin logs table
        const adminLogsTable = document.getElementById('adminLogsTable');
        if (adminLogsTable && stats.adminStats?.recentLogins) {
            adminLogsTable.innerHTML = stats.adminStats.recentLogins.map(log => `
                <tr>
                    <td>${log.ip || 'Unknown'}</td>
                    <td>${formatDate(log.time)}</td>
                    <td>
                        <span class="badge ${log.success ? 'bg-success' : 'bg-danger'}">
                            ${log.success ? 'Success' : 'Failed'}
                        </span>
                    </td>
                    <td title="${log.userAgent || ''}">${truncateText(log.userAgent || 'Unknown', 30)}</td>
                </tr>
            `).join('');
        }

        // Update download logs table
        const downloadLogsTable = document.getElementById('downloadLogsTable');
        if (downloadLogsTable && stats.downloadStats?.recentDownloads) {
            downloadLogsTable.innerHTML = stats.downloadStats.recentDownloads.map(log => `
                <tr>
                    <td title="${log.fileName || ''}">${truncateText(log.fileName || 'Unknown', 20)}</td>
                    <td>${log.ip || 'Unknown'}</td>
                    <td>${formatDate(log.time)}</td>
                    <td>${formatFileSize(log.fileSize || 0)}</td>
                    <td title="${log.userAgent || ''}">${truncateText(log.userAgent || 'Unknown', 30)}</td>
                </tr>
            `).join('');
        }

    } catch (error) {
        console.error('Error loading admin stats:', error);
        
        // Set default values on error
        const elements = ['totalLogins', 'uniqueAdminIPs', 'totalDownloads', 'uniqueDownloadIPs'];
        elements.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = '0';
        });
        
        // Clear tables
        const adminLogsTable = document.getElementById('adminLogsTable');
        const downloadLogsTable = document.getElementById('downloadLogsTable');
        if (adminLogsTable) adminLogsTable.innerHTML = '<tr><td colspan="4">No data available</td></tr>';
        if (downloadLogsTable) downloadLogsTable.innerHTML = '<tr><td colspan="5">No data available</td></tr>';
    }
}

// Utility function to truncate text
function truncateText(text, maxLength) {
    if (!text) return '-';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

// Advanced admin features

// User management
async function loadUserManagement() {
    try {
        const response = await fetch('/api/admin/users', {
            headers: { 'Authorization': adminKey }
        });
        
        if (response.ok) {
            const users = await response.json();
            displayUserManagement(users);
        }
    } catch (error) {
        showError('Failed to load users');
    }
}

function displayUserManagement(users) {
    const container = document.getElementById('userManagementContainer');
    container.innerHTML = `
        <div class="card">
            <div class="card-header">
                <h5>User Management</h5>
                <button class="btn btn-primary btn-sm" onclick="showCreateUserModal()">
                    <i class="fas fa-plus"></i> Add User
                </button>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Storage Used</th>
                                <th>Storage Limit</th>
                                <th>Files</th>
                                <th>Created</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${users.map(user => `
                                <tr>
                                    <td>${user.username}</td>
                                    <td>${user.email}</td>
                                    <td>${formatFileSize(user.storageUsed)}</td>
                                    <td>${formatFileSize(user.storageLimit)}</td>
                                    <td>${user.fileCount || 0}</td>
                                    <td>${formatDate(user.createdAt)}</td>
                                    <td>
                                        <span class="badge ${user.isActive ? 'bg-success' : 'bg-danger'}">
                                            ${user.isActive ? 'Active' : 'Inactive'}
                                        </span>
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm">
                                            <button class="btn btn-outline-info" onclick="editUser(${user.id})">
                                                <i class="fas fa-edit"></i>
                                            </button>
                                            <button class="btn btn-outline-warning" onclick="toggleUserStatus(${user.id})">
                                                <i class="fas fa-toggle-on"></i>
                                            </button>
                                            <button class="btn btn-outline-primary" onclick="viewUserFiles(${user.id})">
                                                <i class="fas fa-folder"></i>
                                            </button>
                                            <button class="btn btn-outline-danger" onclick="deleteUser(${user.id})">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

// System monitoring
async function loadSystemMonitoring() {
    try {
        const response = await fetch('/api/admin/system-monitor', {
            headers: { 'Authorization': adminKey }
        });
        
        if (response.ok) {
            const data = await response.json();
            displaySystemMonitoring(data);
        }
    } catch (error) {
        showError('Failed to load system monitoring');
    }
}

function displaySystemMonitoring(data) {
    const container = document.getElementById('systemMonitoringContainer');
    container.innerHTML = `
        <div class="row">
            <div class="col-md-3">
                <div class="card bg-primary text-white">
                    <div class="card-body">
                        <h6>CPU Usage</h6>
                        <h3>${data.cpu}%</h3>
                        <div class="progress bg-light">
                            <div class="progress-bar bg-white" style="width: ${data.cpu}%"></div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-success text-white">
                    <div class="card-body">
                        <h6>Memory Usage</h6>
                        <h3>${data.memory}%</h3>
                        <div class="progress bg-light">
                            <div class="progress-bar bg-white" style="width: ${data.memory}%"></div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-warning text-white">
                    <div class="card-body">
                        <h6>Disk Usage</h6>
                        <h3>${data.disk}%</h3>
                        <div class="progress bg-light">
                            <div class="progress-bar bg-white" style="width: ${data.disk}%"></div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card bg-info text-white">
                    <div class="card-body">
                        <h6>Network I/O</h6>
                        <h3>${data.network} MB/s</h3>
                        <small>↑${data.networkUp} ↓${data.networkDown}</small>
                    </div>
                </div>
            </div>
        </div>
        <div class="row mt-3">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h6>Real-time Monitoring</h6>
                    </div>
                    <div class="card-body">
                        <canvas id="systemChart" width="400" height="200"></canvas>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Security management
async function loadSecurityManagement() {
    try {
        const response = await fetch('/api/admin/security', {
            headers: { 'Authorization': adminKey }
        });
        
        if (response.ok) {
            const data = await response.json();
            displaySecurityManagement(data);
        }
    } catch (error) {
        showError('Failed to load security data');
    }
}

function displaySecurityManagement(data) {
    const container = document.getElementById('securityContainer');
    container.innerHTML = `
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h6>Failed Login Attempts</h6>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Attempts</th>
                                        <th>Last Attempt</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.failedLogins.map(login => `
                                        <tr>
                                            <td>${login.ip}</td>
                                            <td>${login.attempts}</td>
                                            <td>${formatDate(login.lastAttempt)}</td>
                                            <td>
                                                <button class="btn btn-sm btn-outline-danger" onclick="blockIP('${login.ip}')">
                                                    Block
                                                </button>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h6>Blocked IPs</h6>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>IP Address</th>
                                        <th>Blocked Date</th>
                                        <th>Reason</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.blockedIPs.map(ip => `
                                        <tr>
                                            <td>${ip.address}</td>
                                            <td>${formatDate(ip.blockedDate)}</td>
                                            <td>${ip.reason}</td>
                                            <td>
                                                <button class="btn btn-sm btn-outline-success" onclick="unblockIP('${ip.address}')">
                                                    Unblock
                                                </button>
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Backup management
async function loadBackupManagement() {
    try {
        const response = await fetch('/api/admin/backups', {
            headers: { 'Authorization': adminKey }
        });
        
        if (response.ok) {
            const backups = await response.json();
            displayBackupManagement(backups);
        }
    } catch (error) {
        showError('Failed to load backups');
    }
}

function displayBackupManagement(backups) {
    const container = document.getElementById('backupContainer');
    container.innerHTML = `
        <div class="card">
            <div class="card-header d-flex justify-content-between">
                <h6>Backup Management</h6>
                <div>
                    <button class="btn btn-primary btn-sm" onclick="createBackup()">
                        <i class="fas fa-plus"></i> Create Backup
                    </button>
                    <button class="btn btn-success btn-sm" onclick="scheduleBackup()">
                        <i class="fas fa-clock"></i> Schedule
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Backup Name</th>
                                <th>Size</th>
                                <th>Created</th>
                                <th>Type</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${backups.map(backup => `
                                <tr>
                                    <td>${backup.name}</td>
                                    <td>${formatFileSize(backup.size)}</td>
                                    <td>${formatDate(backup.created)}</td>
                                    <td>
                                        <span class="badge bg-info">${backup.type}</span>
                                    </td>
                                    <td>
                                        <span class="badge ${backup.status === 'completed' ? 'bg-success' : 'bg-warning'}">
                                            ${backup.status}
                                        </span>
                                    </td>
                                    <td>
                                        <div class="btn-group btn-group-sm">
                                            <button class="btn btn-outline-primary" onclick="downloadBackup('${backup.id}')">
                                                <i class="fas fa-download"></i>
                                            </button>
                                            <button class="btn btn-outline-warning" onclick="restoreBackup('${backup.id}')">
                                                <i class="fas fa-undo"></i>
                                            </button>
                                            <button class="btn btn-outline-danger" onclick="deleteBackup('${backup.id}')">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

// Analytics and reporting
async function loadAnalytics() {
    try {
        const response = await fetch('/api/admin/analytics', {
            headers: { 'Authorization': adminKey }
        });
        
        if (response.ok) {
            const data = await response.json();
            displayAnalytics(data);
        }
    } catch (error) {
        showError('Failed to load analytics');
    }
}

function displayAnalytics(data) {
    const container = document.getElementById('analyticsContainer');
    container.innerHTML = `
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h6>Platform Analytics</h6>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-primary" onclick="exportReport('pdf')">
                                <i class="fas fa-file-pdf"></i> PDF
                            </button>
                            <button class="btn btn-outline-success" onclick="exportReport('excel')">
                                <i class="fas fa-file-excel"></i> Excel
                            </button>
                            <button class="btn btn-outline-info" onclick="exportReport('csv')">
                                <i class="fas fa-file-csv"></i> CSV
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3">
                                <div class="border rounded p-3 text-center">
                                    <h4 class="text-primary">${data.totalUsers}</h4>
                                    <small>Total Users</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="border rounded p-3 text-center">
                                    <h4 class="text-success">${data.totalFiles}</h4>
                                    <small>Total Files</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="border rounded p-3 text-center">
                                    <h4 class="text-warning">${formatFileSize(data.totalStorage)}</h4>
                                    <small>Storage Used</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="border rounded p-3 text-center">
                                    <h4 class="text-info">${data.totalDownloads}</h4>
                                    <small>Total Downloads</small>
                                </div>
                            </div>
                        </div>
                        <div class="row mt-4">
                            <div class="col-md-6">
                                <canvas id="userActivityChart"></canvas>
                            </div>
                            <div class="col-md-6">
                                <canvas id="fileTypeChart"></canvas>
                            </div>
                        </div>
                        <div class="row mt-4">
                            <div class="col-md-12">
                                <canvas id="downloadTrendsChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Configuration management
async function loadConfiguration() {
    try {
        const response = await fetch('/api/admin/config', {
            headers: { 'Authorization': adminKey }
        });
        
        if (response.ok) {
            const config = await response.json();
            displayConfiguration(config);
        }
    } catch (error) {
        showError('Failed to load configuration');
    }
}

function displayConfiguration(config) {
    const container = document.getElementById('configContainer');
    container.innerHTML = `
        <div class="card">
            <div class="card-header">
                <h6>System Configuration</h6>
            </div>
            <div class="card-body">
                <form onsubmit="event.preventDefault(); saveConfiguration();">
                    <div class="row">
                        <div class="col-md-6">
                            <h6>File Upload Settings</h6>
                            <div class="mb-3">
                                <label class="form-label">Max File Size (MB)</label>
                                <input type="number" class="form-control" id="maxFileSize" value="${config.maxFileSize}">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Allowed File Types</label>
                                <textarea class="form-control" id="allowedTypes" rows="3">${config.allowedTypes.join(', ')}</textarea>
                            </div>
                            <div class="mb-3">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="autoVirusScan" ${config.autoVirusScan ? 'checked' : ''}>
                                    <label class="form-check-label">Auto Virus Scan</label>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <h6>User Settings</h6>
                            <div class="mb-3">
                                <label class="form-label">Default Storage Limit (MB)</label>
                                <input type="number" class="form-control" id="defaultStorageLimit" value="${config.defaultStorageLimit}">
                            </div>
                            <div class="mb-3">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="allowRegistration" ${config.allowRegistration ? 'checked' : ''}>
                                    <label class="form-check-label">Allow User Registration</label>
                                </div>
                            </div>
                            <div class="mb-3">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="requireEmailVerification" ${config.requireEmailVerification ? 'checked' : ''}>
                                    <label class="form-check-label">Require Email Verification</label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <h6>Security Settings</h6>
                            <div class="mb-3">
                                <label class="form-label">Max Login Attempts</label>
                                <input type="number" class="form-control" id="maxLoginAttempts" value="${config.maxLoginAttempts}">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Session Timeout (minutes)</label>
                                <input type="number" class="form-control" id="sessionTimeout" value="${config.sessionTimeout}">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <h6>Notification Settings</h6>
                            <div class="mb-3">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="emailNotifications" ${config.emailNotifications ? 'checked' : ''}>
                                    <label class="form-check-label">Email Notifications</label>
                                </div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">SMTP Server</label>
                                <input type="text" class="form-control" id="smtpServer" value="${config.smtpServer}">
                            </div>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Save Configuration</button>
                </form>
            </div>
        </div>
    `;
}

// Plugin management
async function loadPluginManagement() {
    try {
        const response = await fetch('/api/admin/plugins', {
            headers: { 'Authorization': adminKey }
        });
        
        if (response.ok) {
            const plugins = await response.json();
            displayPluginManagement(plugins);
        }
    } catch (error) {
        showError('Failed to load plugins');
    }
}

function displayPluginManagement(plugins) {
    const container = document.getElementById('pluginContainer');
    container.innerHTML = `
        <div class="card">
            <div class="card-header d-flex justify-content-between">
                <h6>Plugin Management</h6>
                <button class="btn btn-primary btn-sm" onclick="showInstallPluginModal()">
                    <i class="fas fa-plus"></i> Install Plugin
                </button>
            </div>
            <div class="card-body">
                <div class="row">
                    ${plugins.map(plugin => `
                        <div class="col-md-4 mb-3">
                            <div class="card">
                                <div class="card-body">
                                    <h6 class="card-title">${plugin.name}</h6>
                                    <p class="card-text">${plugin.description}</p>
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="badge ${plugin.enabled ? 'bg-success' : 'bg-secondary'}">
                                            ${plugin.enabled ? 'Enabled' : 'Disabled'}
                                        </span>
                                        <div class="btn-group btn-group-sm">
                                            <button class="btn btn-outline-primary" onclick="togglePlugin('${plugin.id}')">
                                                ${plugin.enabled ? 'Disable' : 'Enable'}
                                            </button>
                                            <button class="btn btn-outline-info" onclick="configurePlugin('${plugin.id}')">
                                                <i class="fas fa-cog"></i>
                                            </button>
                                            <button class="btn btn-outline-danger" onclick="uninstallPlugin('${plugin.id}')">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// File management enhancements
function bulkFileOperations() {
    const selectedFiles = document.querySelectorAll('.file-select:checked');
    if (selectedFiles.length === 0) {
        showError('Please select files first');
        return;
    }
    
    const modal = new bootstrap.Modal(document.getElementById('bulkOperationsModal'));
    modal.show();
}

async function executeBulkOperation() {
    const operation = document.getElementById('bulkOperation').value;
    const selectedFiles = Array.from(document.querySelectorAll('.file-select:checked')).map(cb => cb.value);
    
    try {
        const response = await fetch('/api/admin/bulk-operations', {
            method: 'POST',
            headers: {
                'Authorization': adminKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                operation: operation,
                files: selectedFiles
            })
        });
        
        if (response.ok) {
            const result = await response.json();
            showSuccess(result.message);
            loadAdminFiles();
            bootstrap.Modal.getInstance(document.getElementById('bulkOperationsModal')).hide();
        }
    } catch (error) {
        showError('Bulk operation failed');
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    setupEventListeners();
    checkAuthFromUrl();

    // Add event listeners for file settings modal toggles
    const hiddenToggle = document.getElementById('isHiddenToggle');
    const passwordToggle = document.getElementById('passwordProtectionToggle');

    if (hiddenToggle) {
        hiddenToggle.addEventListener('change', toggleHiddenSection);
    }
    if (passwordToggle) {
        passwordToggle.addEventListener('change', togglePasswordSection);
    }
    
    // Initialize advanced admin features
    if (isAuthenticated) {
        loadUserManagement();
        loadSystemMonitoring();
        loadSecurityManagement();
        loadBackupManagement();
        loadAnalytics();
        loadConfiguration();
        loadPluginManagement();
    }
});

// Save file settings
async function saveFileSettings() {
    try {
        const fileId = document.getElementById('settingsFileId').value;
        const isHidden = document.getElementById('isHiddenToggle').checked;
        const viewLimit = parseInt(document.getElementById('viewLimit').value) || null;
        const password = document.getElementById('filePassword').value;

        const settings = {
            isHidden,
            viewLimit,
            password: password || null
        };

        const response = await fetch(`/api/admin/files/${fileId}/settings`, {
            method: 'PUT',
            headers: {
                'Authorization': adminKey,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(settings)
        });

        if (!response.ok) {
            throw new Error('Failed to update settings');
        }

        const result = await response.json();

        // Update hidden URL if generated
        if (result.hiddenUrl) {
            document.getElementById('hiddenUrl').value = window.location.origin + result.hiddenUrl;
        }

        // Close modal and refresh file list
        bootstrap.Modal.getInstance(document.getElementById('fileSettingsModal')).hide();
        loadAdminFiles();
        showSuccess('File settings updated successfully');

    } catch (error) {
        console.error('Error saving settings:', error);
        showError('Failed to save settings');
    }
}

// Reset view count
async function resetViewCount(fileId) {
    if (!confirm('Are you sure you want to reset the view count for this file?')) {
        return;
    }

    try {
        const response = await fetch(`/api/admin/files/${fileId}/reset-views`, {
            method: 'POST',
            headers: {
                'Authorization': adminKey
            }
        });

        if (!response.ok) {
            throw new Error('Failed to reset view count');
        }

        loadAdminFiles();
        showSuccess('View count reset successfully');

    } catch (error) {
        console.error('Error resetting view count:', error);
        showError('Failed to reset view count: ' + error.message);
    }
}

// Copy to clipboard utility
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    element.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(element.value).then(() => {
        showSuccess('Copied to clipboard!');
    }).catch(() => {
        document.execCommand('copy');
        showSuccess('Copied to clipboard!');
    });
}

// Upload zone click handler with folder support
document.getElementById('uploadZone').addEventListener('click', function() {
    const fileInput = document.getElementById('fileInput');

    // Toggle between file and folder selection
    if (event.ctrlKey || event.metaKey) {
        // Ctrl/Cmd + click for individual files
        fileInput.removeAttribute('webkitdirectory');
        fileInput.setAttribute('multiple', '');
    } else {
        // Normal click for folders
        fileInput.setAttribute('webkitdirectory', '');
        fileInput.setAttribute('multiple', '');
    }

    fileInput.click();
});

// Add button to toggle between file and folder upload
document.addEventListener('DOMContentLoaded', function() {
    const uploadZone = document.getElementById('uploadZone');
    if (uploadZone) {
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'btn btn-outline-secondary btn-sm mt-2';
        toggleBtn.innerHTML = '<i class="fas fa-exchange-alt me-1"></i>Toggle Files/Folders';
        toggleBtn.onclick = function(e) {
            e.stopPropagation();
            const fileInput = document.getElementById('fileInput');
            if (fileInput.hasAttribute('webkitdirectory')) {
                fileInput.removeAttribute('webkitdirectory');
                toggleBtn.innerHTML = '<i class="fas fa-folder me-1"></i>Select Folders';
                uploadZone.querySelector('h5').textContent = 'Drag & Drop Files Here';
            } else {
                fileInput.setAttribute('webkitdirectory', '');
                toggleBtn.innerHTML = '<i class="fas fa-file me-1"></i>Select Files';
                uploadZone.querySelector('h5').textContent = 'Drag & Drop Folders Here';
            }
        };
        uploadZone.querySelector('.upload-zone-content').appendChild(toggleBtn);
    }
});