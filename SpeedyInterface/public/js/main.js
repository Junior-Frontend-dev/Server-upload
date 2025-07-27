// Main JavaScript for file sharing platform

let allFiles = [];
let selectedFiles = new Set();
let downloadCount = 0;
let isAdvancedSearch = false;
let currentUser = null;

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    checkUserSession();
    loadFiles();
    setupEventListeners();
    loadStorageStats();
});

// Check user session
async function checkUserSession() {
    try {
        const response = await fetch('/api/profile');
        if (response.ok) {
            currentUser = await response.json();
            updateNavbarForUser();
            updateStorageDisplay();
        } else {
            updateNavbarForGuest();
        }
    } catch (error) {
        console.log('User not logged in');
        updateNavbarForGuest();
    }
}

function updateNavbarForUser() {
    const navbar = document.querySelector('.navbar-nav');
    navbar.innerHTML = `
        <div class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                <i class="fas fa-user me-1"></i>
                ${currentUser.username}
            </a>
            <ul class="dropdown-menu">
                <li><a class="dropdown-item" href="#" onclick="showProfile()">
                    <i class="fas fa-user-circle me-1"></i>
                    Profile
                </a></li>
                <li><a class="dropdown-item" href="#" onclick="showMyFiles()">
                    <i class="fas fa-folder me-1"></i>
                    My Files
                </a></li>
                <li><a class="dropdown-item" href="#" onclick="showUploadModal()">
                    <i class="fas fa-upload me-1"></i>
                    Upload Files
                </a></li>
                <li><hr class="dropdown-divider"></li>
                <li><a class="dropdown-item" href="/admin">
                    <i class="fas fa-cog me-1"></i>
                    Admin Panel
                </a></li>
                <li><a class="dropdown-item" href="#" onclick="logout()">
                    <i class="fas fa-sign-out-alt me-1"></i>
                    Logout
                </a></li>
            </ul>
        </div>
    `;
}

function updateNavbarForGuest() {
    const navbar = document.querySelector('.navbar-nav');
    navbar.innerHTML = `
        <a class="nav-link" href="/auth.html">
            <i class="fas fa-sign-in-alt me-1"></i>
            Login/Register
        </a>
        <a class="nav-link" href="/admin">
            <i class="fas fa-cog me-1"></i>
            Admin Panel
        </a>
    `;
}

function updateStorageDisplay() {
    if (!currentUser) return;
    
    const storageUsed = currentUser.storageUsed / (1024 * 1024);
    const storageLimit = currentUser.storageLimit / (1024 * 1024);
    const remainingStorage = currentUser.remainingStorage / (1024 * 1024);
    
    // Add storage info to file stats
    const statsContainer = document.getElementById('fileStats');
    const storageCard = document.createElement('div');
    storageCard.className = 'col-12 mb-3';
    storageCard.innerHTML = `
        <div class="card">
            <div class="card-body">
                <h6 class="card-title">
                    <i class="fas fa-database me-2"></i>
                    Your Storage (${currentUser.username})
                </h6>
                <div class="progress mb-2">
                    <div class="progress-bar ${storageUsed/storageLimit > 0.9 ? 'bg-danger' : storageUsed/storageLimit > 0.7 ? 'bg-warning' : 'bg-success'}" 
                         role="progressbar" 
                         style="width: ${(storageUsed/storageLimit*100).toFixed(1)}%">
                        ${(storageUsed/storageLimit*100).toFixed(1)}%
                    </div>
                </div>
                <div class="d-flex justify-content-between">
                    <small>Used: ${storageUsed.toFixed(1)} MB</small>
                    <small>Remaining: ${remainingStorage.toFixed(1)} MB</small>
                    <small>Total: ${storageLimit.toFixed(1)} MB</small>
                </div>
            </div>
        </div>
    `;
    
    statsContainer.appendChild(storageCard);
}

async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        currentUser = null;
        window.location.reload();
    } catch (error) {
        console.error('Logout error:', error);
    }
}

// Setup event listeners
function setupEventListeners() {
    // Search functionality
    document.getElementById('searchInput').addEventListener('input', debounce(filterFiles, 300));
    document.getElementById('typeFilter').addEventListener('change', filterFiles);
    document.getElementById('sortFilter').addEventListener('change', sortFiles);
    
    // Advanced search
    document.getElementById('advancedSearchBtn').addEventListener('click', toggleAdvancedSearch);
    document.getElementById('applyAdvancedSearch').addEventListener('click', applyAdvancedSearch);
    document.getElementById('clearAdvancedSearch').addEventListener('click', clearAdvancedSearch);
    
    // Bulk actions
    document.getElementById('downloadSelectedBtn').addEventListener('click', downloadSelectedFiles);
    document.getElementById('shareSelectedBtn').addEventListener('click', shareSelectedFiles);
    document.getElementById('clearSelectionBtn').addEventListener('click', clearSelection);
    
    // Share modal
    document.getElementById('copyAllLinksBtn').addEventListener('click', copyAllLinks);
}

// Load files from server
async function loadFiles() {
    try {
        showLoadingSpinner();
        const response = await fetch('/api/files');
        
        if (!response.ok) {
            throw new Error('Failed to load files');
        }
        
        allFiles = await response.json();
        displayFiles(allFiles);
        updateFileStats();
        hideLoadingSpinner();
        
    } catch (error) {
        console.error('Error loading files:', error);
        showError('Failed to load files. Please try again.');
        hideLoadingSpinner();
    }
}

// Load storage statistics
async function loadStorageStats() {
    try {
        const response = await fetch('/api/files');
        if (response.ok) {
            const files = await response.json();
            updateFileStats(files);
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Update file statistics display
function updateFileStats(files = allFiles) {
    const totalFiles = files.length;
    const totalSize = files.reduce((sum, file) => sum + file.size, 0);
    const latestFile = files.length > 0 ? files.reduce((latest, file) => 
        new Date(file.created) > new Date(latest.created) ? file : latest
    ) : null;
    
    document.getElementById('totalFiles').textContent = totalFiles;
    document.getElementById('totalSize').textContent = formatFileSize(totalSize);
    document.getElementById('downloadCount').textContent = downloadCount;
    document.getElementById('latestUpload').textContent = latestFile ? 
        formatDate(latestFile.created) : 'Never';
}

// Display files in grid
function displayFiles(files) {
    const container = document.getElementById('filesContainer');
    const noFilesMessage = document.getElementById('noFilesMessage');
    
    if (files.length === 0) {
        container.innerHTML = '';
        noFilesMessage.style.display = 'block';
        return;
    }
    
    noFilesMessage.style.display = 'none';
    
    container.innerHTML = files.map(file => createFileCard(file)).join('');
    
    // Add event listeners to file cards
    container.querySelectorAll('.file-card').forEach(card => {
        card.addEventListener('click', (e) => {
            if (!e.target.closest('.file-checkbox') && !e.target.closest('.btn')) {
                const filename = card.dataset.filename;
                const file = files.find(f => f.name === filename);
                if (file && isPreviewable(file)) {
                    showPreview(file);
                } else {
                    downloadFile(filename);
                }
            }
        });
    });
    
    // Add event listeners to checkboxes
    container.querySelectorAll('.file-checkbox input').forEach(checkbox => {
        checkbox.addEventListener('change', handleFileSelection);
    });
}

// Create file card HTML
function createFileCard(file) {
    const fileIcon = getFileIcon(file.type);
    const fileSize = formatFileSize(file.size);
    const fileDate = formatDate(file.created);
    const isSelected = selectedFiles.has(file.name);
    
    return `
        <div class="col-md-6 col-lg-4 col-xl-3 mb-4">
            <div class="card file-card file-card-appear ${isSelected ? 'selected' : ''}" data-filename="${file.name}">
                <div class="file-checkbox">
                    <input type="checkbox" class="form-check-input" ${isSelected ? 'checked' : ''} value="${file.name}">
                </div>
                <div class="card-body text-center">
                    <div class="file-icon ${fileIcon.class}">
                        <i class="${fileIcon.icon}"></i>
                    </div>
                    <h6 class="card-title" title="${file.originalName}">${truncateFilename(file.originalName)}</h6>
                    <p class="file-size">${fileSize}</p>
                    <p class="file-date">${fileDate}</p>
                    <div class="btn-group btn-file-action" role="group">
                        ${isPreviewable(file) ? `
                            <button class="btn btn-outline-primary btn-sm" onclick="event.stopPropagation(); showPreview(${JSON.stringify(file).replace(/"/g, '&quot;')})">
                                <i class="fas fa-eye"></i>
                            </button>
                        ` : ''}
                        <button class="btn btn-primary btn-sm" onclick="event.stopPropagation(); downloadFile('${file.name}')">
                            <i class="fas fa-download"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Get file icon based on type
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

// Check if file is previewable
function isPreviewable(file) {
    if (!file.type) return false;
    return file.type.startsWith('image/') || file.type.startsWith('text/');
}

// Show file preview
async function showPreview(file) {
    const modal = new bootstrap.Modal(document.getElementById('previewModal'));
    const title = document.getElementById('previewModalTitle');
    const body = document.getElementById('previewModalBody');
    const downloadBtn = document.getElementById('downloadFromPreview');
    
    title.textContent = file.originalName;
    body.innerHTML = '<div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div>';
    
    downloadBtn.onclick = () => downloadFile(file.name);
    
    modal.show();
    
    try {
        const response = await fetch(`/api/preview/${file.name}`);
        
        if (!response.ok) {
            throw new Error('Preview not available');
        }
        
        if (file.type.startsWith('image/')) {
            const imageUrl = `/api/preview/${file.name}`;
            body.innerHTML = `<img src="${imageUrl}" class="img-fluid" alt="${file.originalName}">`;
        } else if (file.type.startsWith('text/')) {
            const text = await response.text();
            body.innerHTML = `<pre class="text-start">${escapeHtml(text)}</pre>`;
        }
        
    } catch (error) {
        body.innerHTML = `
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle me-2"></i>
                Preview not available for this file type.
            </div>
        `;
    }
}

// Download single file with progress tracking
function downloadFile(filename) {
    downloadCount++;
    updateFileStats();
    
    const link = document.createElement('a');
    link.href = `/api/download/${filename}`;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    // Store download count in localStorage
    localStorage.setItem('downloadCount', downloadCount);
}

// Handle file selection
function handleFileSelection(event) {
    const filename = event.target.value;
    const card = event.target.closest('.file-card');
    
    if (event.target.checked) {
        selectedFiles.add(filename);
        card.classList.add('selected');
    } else {
        selectedFiles.delete(filename);
        card.classList.remove('selected');
    }
    
    updateBulkActions();
}

// Update bulk actions display
function updateBulkActions() {
    const bulkActions = document.getElementById('bulkActions');
    const selectedCount = document.getElementById('selectedCount');
    
    if (selectedFiles.size > 0) {
        bulkActions.style.display = 'block';
        selectedCount.textContent = selectedFiles.size;
    } else {
        bulkActions.style.display = 'none';
    }
}

// Download selected files
async function downloadSelectedFiles() {
    if (selectedFiles.size === 0) return;
    
    const modal = new bootstrap.Modal(document.getElementById('downloadModal'));
    const progressBar = document.querySelector('#downloadModal .progress-bar');
    const status = document.getElementById('downloadStatus');
    
    modal.show();
    
    try {
        status.textContent = 'Preparing download...';
        progressBar.style.width = '50%';
        
        const response = await fetch('/api/download-multiple', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                files: Array.from(selectedFiles)
            })
        });
        
        if (!response.ok) {
            throw new Error('Download failed');
        }
        
        progressBar.style.width = '100%';
        status.textContent = 'Download complete!';
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'selected_files.zip';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        
        setTimeout(() => {
            modal.hide();
            clearSelection();
        }, 1000);
        
    } catch (error) {
        console.error('Download error:', error);
        status.textContent = 'Download failed. Please try again.';
        progressBar.classList.add('bg-danger');
    }
}

// Missing functions that are referenced in HTML
function showProfile() {
    // Show user profile modal or redirect to profile page
    window.location.href = '/profile';
}

function showUploadModal() {
    // Show upload modal
    const modal = new bootstrap.Modal(document.getElementById('uploadModal'));
    modal.show();
}

function logout() {
    fetch('/api/logout', { method: 'POST' })
        .then(() => {
            window.location.reload();
        })
        .catch(error => {
            console.error('Logout failed:', error);
        });
}

// Clear selection
function clearSelection() {
    selectedFiles.clear();
    document.querySelectorAll('.file-card').forEach(card => {
        card.classList.remove('selected');
    });
    document.querySelectorAll('.file-checkbox input').forEach(checkbox => {
        checkbox.checked = false;
    });
    updateBulkActions();
}

// Filter files
function filterFiles() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const typeFilter = document.getElementById('typeFilter').value;
    
    let filteredFiles = allFiles.filter(file => {
        const matchesSearch = file.originalName.toLowerCase().includes(searchTerm);
        const matchesType = !typeFilter || getFileCategory(file.type) === typeFilter;
        return matchesSearch && matchesType;
    });
    
    displayFiles(filteredFiles);
}

// Get file category for filtering
function getFileCategory(mimeType) {
    if (!mimeType) return 'other';
    
    if (mimeType.startsWith('image/')) return 'image';
    if (mimeType.startsWith('video/')) return 'video';
    if (mimeType.startsWith('audio/')) return 'audio';
    if (mimeType.includes('zip') || mimeType.includes('rar') || mimeType.includes('archive')) return 'archive';
    if (mimeType.includes('pdf') || mimeType.includes('document') || mimeType.includes('text') || 
        mimeType.includes('sheet') || mimeType.includes('presentation')) return 'document';
    
    return 'other';
}

// Utility functions
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

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showLoadingSpinner() {
    document.getElementById('loadingSpinner').style.display = 'block';
    document.getElementById('filesContainer').style.display = 'none';
}

function hideLoadingSpinner() {
    document.getElementById('loadingSpinner').style.display = 'none';
    document.getElementById('filesContainer').style.display = 'block';
}

function showError(message) {
    console.error(message);
    showToast(message, 'error');
}

// Advanced search functionality
function toggleAdvancedSearch() {
    const panel = document.getElementById('advancedSearchPanel');
    const isVisible = panel.style.display !== 'none';
    panel.style.display = isVisible ? 'none' : 'block';
    
    const btn = document.getElementById('advancedSearchBtn');
    btn.innerHTML = isVisible ? '<i class="fas fa-filter"></i>' : '<i class="fas fa-times"></i>';
}

function applyAdvancedSearch() {
    const searchTerm = document.getElementById('searchInput').value;
    const typeFilter = document.getElementById('typeFilter').value;
    const sizeOperator = document.getElementById('sizeOperator').value;
    const sizeValue = parseFloat(document.getElementById('sizeValue').value);
    const dateOperator = document.getElementById('dateOperator').value;
    const dateValue = document.getElementById('dateValue').value;
    
    const params = new URLSearchParams();
    if (searchTerm) params.append('q', searchTerm);
    if (typeFilter) params.append('type', typeFilter);
    if (sizeValue) params.append('size', `${sizeOperator}:${sizeValue * 1024 * 1024}`);
    if (dateValue) params.append('date', `${dateOperator}:${dateValue}`);
    
    isAdvancedSearch = true;
    performAdvancedSearch(params);
}

function clearAdvancedSearch() {
    document.getElementById('sizeValue').value = '';
    document.getElementById('dateValue').value = '';
    document.getElementById('sizeOperator').value = 'gt';
    document.getElementById('dateOperator').value = 'after';
    
    isAdvancedSearch = false;
    filterFiles();
}

async function performAdvancedSearch(params) {
    try {
        showLoadingSpinner();
        const response = await fetch(`/api/search?${params}`);
        
        if (!response.ok) {
            throw new Error('Search failed');
        }
        
        const results = await response.json();
        displayFiles(results);
        hideLoadingSpinner();
        
    } catch (error) {
        console.error('Search error:', error);
        showError('Advanced search failed. Please try again.');
        hideLoadingSpinner();
    }
}

// Sort files functionality
function sortFiles() {
    const sortBy = document.getElementById('sortFilter').value;
    const sortedFiles = [...allFiles].sort((a, b) => {
        switch (sortBy) {
            case 'name':
                return a.originalName.localeCompare(b.originalName);
            case 'size':
                return b.size - a.size;
            case 'date':
                return new Date(b.created) - new Date(a.created);
            case 'type':
                return (a.type || '').localeCompare(b.type || '');
            default:
                return 0;
        }
    });
    
    displayFiles(sortedFiles);
}

// Share selected files
function shareSelectedFiles() {
    if (selectedFiles.size === 0) return;
    
    const modal = new bootstrap.Modal(document.getElementById('shareModal'));
    const container = document.getElementById('shareLinksContainer');
    
    let linksHtml = '';
    selectedFiles.forEach(filename => {
        const file = allFiles.find(f => f.name === filename);
        if (file) {
            const shareUrl = `${window.location.origin}/api/download/${filename}`;
            linksHtml += `
                <div class="mb-3">
                    <label class="form-label">${file.originalName}</label>
                    <div class="input-group">
                        <input type="text" class="form-control" value="${shareUrl}" readonly>
                        <button class="btn btn-outline-secondary" type="button" onclick="copyToClipboard('${shareUrl}')">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
            `;
        }
    });
    
    container.innerHTML = linksHtml;
    modal.show();
}

// Copy all links to clipboard
function copyAllLinks() {
    const links = [];
    selectedFiles.forEach(filename => {
        const file = allFiles.find(f => f.name === filename);
        if (file) {
            links.push(`${file.originalName}: ${window.location.origin}/api/download/${filename}`);
        }
    });
    
    copyToClipboard(links.join('\n'));
}

// Copy to clipboard utility
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Failed to copy: ', err);
        showToast('Failed to copy to clipboard', 'error');
    });
}

// Debounce function for search
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Toast notification system
// Show profile modal
function showProfile() {
    if (!currentUser) {
        showToast('Please login first', 'warning');
        return;
    }
    
    const modal = new bootstrap.Modal(document.getElementById('profileModal'));
    
    // Populate profile form
    document.getElementById('profileUsername').value = currentUser.username;
    document.getElementById('profileEmail').value = currentUser.email;
    document.getElementById('profileCurrentPassword').value = '';
    document.getElementById('profileNewPassword').value = '';
    
    modal.show();
}

// Update profile
async function updateProfile() {
    const email = document.getElementById('profileEmail').value.trim();
    const currentPassword = document.getElementById('profileCurrentPassword').value;
    const newPassword = document.getElementById('profileNewPassword').value;
    
    try {
        const response = await fetch('/api/profile', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email,
                currentPassword,
                newPassword
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentUser = data.user;
            showToast('Profile updated successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('profileModal')).hide();
            updateStorageDisplay();
        } else {
            showToast(data.error || 'Failed to update profile', 'error');
        }
    } catch (error) {
        console.error('Profile update error:', error);
        showToast('Failed to update profile', 'error');
    }
}

// Show my files
async function showMyFiles() {
    if (!currentUser) {
        showToast('Please login first', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/files?userFiles=true');
        if (response.ok) {
            const userFiles = await response.json();
            displayFiles(userFiles);
            showToast(`Showing ${userFiles.length} of your files`, 'info');
        }
    } catch (error) {
        console.error('Error loading user files:', error);
        showToast('Failed to load your files', 'error');
    }
}

// Show upload modal
function showUploadModal() {
    if (!currentUser) {
        showToast('Please login to upload files', 'warning');
        window.location.href = '/auth.html';
        return;
    }
    
    const modal = new bootstrap.Modal(document.getElementById('uploadModal'));
    modal.show();
}

// Handle file upload via modal
async function handleUpload() {
    const fileInput = document.getElementById('modalFileInput');
    const files = fileInput.files;
    
    if (files.length === 0) {
        showToast('Please select files to upload', 'warning');
        return;
    }
    
    const formData = new FormData();
    for (let file of files) {
        formData.append('files', file);
    }
    
    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showToast(result.message, 'success');
            loadFiles();
            updateStorageDisplay();
            bootstrap.Modal.getInstance(document.getElementById('uploadModal')).hide();
        } else {
            showToast(result.error || 'Upload failed', 'error');
        }
    } catch (error) {
        console.error('Upload error:', error);
        showToast('Upload failed', 'error');
    }
}

// File comparison feature
function compareFiles() {
    if (selectedFiles.size < 2) {
        showToast('Please select at least 2 files to compare', 'warning');
        return;
    }
    
    const modal = new bootstrap.Modal(document.getElementById('compareModal'));
    const container = document.getElementById('compareResults');
    
    let compareHtml = '<div class="row">';
    let index = 0;
    selectedFiles.forEach(filename => {
        const file = allFiles.find(f => f.name === filename);
        if (file && index < 4) { // Limit to 4 files for comparison
            compareHtml += `
                <div class="col-md-6 mb-3">
                    <div class="card">
                        <div class="card-header">
                            <h6>${file.originalName}</h6>
                        </div>
                        <div class="card-body">
                            <p><strong>Size:</strong> ${formatFileSize(file.size)}</p>
                            <p><strong>Type:</strong> ${file.type}</p>
                            <p><strong>Created:</strong> ${formatDate(file.created)}</p>
                            <p><strong>Category:</strong> ${getFileCategory(file.type)}</p>
                        </div>
                    </div>
                </div>
            `;
            index++;
        }
    });
    compareHtml += '</div>';
    
    container.innerHTML = compareHtml;
    modal.show();
}

// File tagging system
function tagFiles() {
    if (selectedFiles.size === 0) {
        showToast('Please select files to tag', 'warning');
        return;
    }
    
    const modal = new bootstrap.Modal(document.getElementById('tagModal'));
    modal.show();
}

async function applyTags() {
    const tags = document.getElementById('fileTags').value.split(',').map(tag => tag.trim()).filter(tag => tag);
    
    try {
        const response = await fetch('/api/files/tag', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                files: Array.from(selectedFiles),
                tags: tags
            })
        });
        
        if (response.ok) {
            showToast('Tags applied successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('tagModal')).hide();
            loadFiles();
        }
    } catch (error) {
        showToast('Failed to apply tags', 'error');
    }
}

// File favorites system
async function toggleFavorite(filename) {
    if (!currentUser) {
        showToast('Please login to use favorites', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/files/favorite', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ filename })
        });
        
        if (response.ok) {
            const result = await response.json();
            showToast(result.message, 'success');
            loadFiles();
        }
    } catch (error) {
        showToast('Failed to toggle favorite', 'error');
    }
}

// Show favorites
async function showFavorites() {
    if (!currentUser) {
        showToast('Please login first', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/files/favorites');
        if (response.ok) {
            const favorites = await response.json();
            displayFiles(favorites);
            showToast(`Showing ${favorites.length} favorite files`, 'info');
        }
    } catch (error) {
        showToast('Failed to load favorites', 'error');
    }
}

// File notes system
function addFileNote(filename) {
    const modal = new bootstrap.Modal(document.getElementById('noteModal'));
    document.getElementById('noteFilename').value = filename;
    document.getElementById('fileNote').value = '';
    modal.show();
}

async function saveFileNote() {
    const filename = document.getElementById('noteFilename').value;
    const note = document.getElementById('fileNote').value;
    
    try {
        const response = await fetch('/api/files/note', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ filename, note })
        });
        
        if (response.ok) {
            showToast('Note saved successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('noteModal')).hide();
            loadFiles();
        }
    } catch (error) {
        showToast('Failed to save note', 'error');
    }
}

// File sharing with expiration
function shareWithExpiration() {
    if (selectedFiles.size === 0) {
        showToast('Please select files to share', 'warning');
        return;
    }
    
    const modal = new bootstrap.Modal(document.getElementById('shareExpirationModal'));
    modal.show();
}

async function createExpirationShare() {
    const expirationHours = document.getElementById('shareExpiration').value;
    
    try {
        const response = await fetch('/api/files/share-expiration', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                files: Array.from(selectedFiles),
                expirationHours: parseInt(expirationHours)
            })
        });
        
        if (response.ok) {
            const result = await response.json();
            document.getElementById('expirationShareUrl').value = result.shareUrl;
            showToast('Share link created successfully', 'success');
        }
    } catch (error) {
        showToast('Failed to create share link', 'error');
    }
}

// File version history
async function showVersionHistory(filename) {
    try {
        const response = await fetch(`/api/files/${filename}/versions`);
        if (response.ok) {
            const versions = await response.json();
            const modal = new bootstrap.Modal(document.getElementById('versionModal'));
            
            const container = document.getElementById('versionList');
            container.innerHTML = versions.map(version => `
                <div class="list-group-item">
                    <div class="d-flex justify-content-between">
                        <span>Version ${version.version} - ${formatDate(version.created)}</span>
                        <button class="btn btn-sm btn-outline-primary" onclick="downloadVersion('${filename}', ${version.version})">
                            Download
                        </button>
                    </div>
                    <small class="text-muted">Size: ${formatFileSize(version.size)}</small>
                </div>
            `).join('');
            
            modal.show();
        }
    } catch (error) {
        showToast('Failed to load version history', 'error');
    }
}

// Download file version
function downloadVersion(filename, version) {
    const link = document.createElement('a');
    link.href = `/api/files/${filename}/versions/${version}`;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// File compression
async function compressFiles() {
    if (selectedFiles.size === 0) {
        showToast('Please select files to compress', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/files/compress', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                files: Array.from(selectedFiles)
            })
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'compressed_files.zip';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
            showToast('Files compressed and downloaded', 'success');
        }
    } catch (error) {
        showToast('Failed to compress files', 'error');
    }
}

// File encryption
async function encryptFiles() {
    if (selectedFiles.size === 0) {
        showToast('Please select files to encrypt', 'warning');
        return;
    }
    
    const password = prompt('Enter encryption password:');
    if (!password) return;
    
    try {
        const response = await fetch('/api/files/encrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                files: Array.from(selectedFiles),
                password: password
            })
        });
        
        if (response.ok) {
            showToast('Files encrypted successfully', 'success');
            loadFiles();
        }
    } catch (error) {
        showToast('Failed to encrypt files', 'error');
    }
}

// File sync with cloud storage
async function syncToCloud() {
    if (selectedFiles.size === 0) {
        showToast('Please select files to sync', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/files/cloud-sync', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                files: Array.from(selectedFiles)
            })
        });
        
        if (response.ok) {
            showToast('Files synced to cloud storage', 'success');
        }
    } catch (error) {
        showToast('Failed to sync files', 'error');
    }
}

// File duplicate detection
async function findDuplicates() {
    try {
        const response = await fetch('/api/files/duplicates');
        if (response.ok) {
            const duplicates = await response.json();
            const modal = new bootstrap.Modal(document.getElementById('duplicatesModal'));
            
            const container = document.getElementById('duplicatesList');
            container.innerHTML = duplicates.map(group => `
                <div class="card mb-3">
                    <div class="card-header">
                        Duplicate Group (${group.length} files)
                    </div>
                    <div class="card-body">
                        ${group.map(file => `
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <span>${file.originalName}</span>
                                <button class="btn btn-sm btn-outline-danger" onclick="deleteFile('${file.name}')">
                                    Delete
                                </button>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');
            
            modal.show();
        }
    } catch (error) {
        showToast('Failed to find duplicates', 'error');
    }
}

// File scheduling for deletion
function scheduleDelete() {
    if (selectedFiles.size === 0) {
        showToast('Please select files to schedule for deletion', 'warning');
        return;
    }
    
    const modal = new bootstrap.Modal(document.getElementById('scheduleDeleteModal'));
    modal.show();
}

async function applyScheduledDeletion() {
    const deleteDate = document.getElementById('deleteScheduleDate').value;
    
    try {
        const response = await fetch('/api/files/schedule-delete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                files: Array.from(selectedFiles),
                deleteDate: deleteDate
            })
        });
        
        if (response.ok) {
            showToast('Files scheduled for deletion', 'success');
            bootstrap.Modal.getInstance(document.getElementById('scheduleDeleteModal')).hide();
            loadFiles();
        }
    } catch (error) {
        showToast('Failed to schedule deletion', 'error');
    }
}

// File QR code generation
async function generateQRCode(filename) {
    try {
        const response = await fetch(`/api/files/${filename}/qr`);
        if (response.ok) {
            const result = await response.json();
            const modal = new bootstrap.Modal(document.getElementById('qrModal'));
            document.getElementById('qrCode').innerHTML = `<img src="${result.qrCode}" class="img-fluid">`;
            modal.show();
        }
    } catch (error) {
        showToast('Failed to generate QR code', 'error');
    }
}

// File batch operations
function batchRename() {
    if (selectedFiles.size === 0) {
        showToast('Please select files to rename', 'warning');
        return;
    }
    
    const modal = new bootstrap.Modal(document.getElementById('batchRenameModal'));
    modal.show();
}

async function applyBatchRename() {
    const pattern = document.getElementById('renamePattern').value;
    
    try {
        const response = await fetch('/api/files/batch-rename', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                files: Array.from(selectedFiles),
                pattern: pattern
            })
        });
        
        if (response.ok) {
            showToast('Files renamed successfully', 'success');
            bootstrap.Modal.getInstance(document.getElementById('batchRenameModal')).hide();
            loadFiles();
        }
    } catch (error) {
        showToast('Failed to rename files', 'error');
    }
}

// File metadata viewer
async function showMetadata(filename) {
    try {
        const response = await fetch(`/api/files/${filename}/metadata`);
        if (response.ok) {
            const metadata = await response.json();
            const modal = new bootstrap.Modal(document.getElementById('metadataModal'));
            
            const container = document.getElementById('metadataContent');
            container.innerHTML = Object.entries(metadata).map(([key, value]) => `
                <div class="row mb-2">
                    <div class="col-4"><strong>${key}:</strong></div>
                    <div class="col-8">${value}</div>
                </div>
            `).join('');
            
            modal.show();
        }
    } catch (error) {
        showToast('Failed to load metadata', 'error');
    }
}

// File activity log
async function showActivityLog(filename) {
    try {
        const response = await fetch(`/api/files/${filename}/activity`);
        if (response.ok) {
            const activities = await response.json();
            const modal = new bootstrap.Modal(document.getElementById('activityModal'));
            
            const container = document.getElementById('activityList');
            container.innerHTML = activities.map(activity => `
                <div class="list-group-item">
                    <div class="d-flex justify-content-between">
                        <span>${activity.action}</span>
                        <small>${formatDate(activity.timestamp)}</small>
                    </div>
                    <small class="text-muted">User: ${activity.user || 'Anonymous'}</small>
                </div>
            `).join('');
            
            modal.show();
        }
    } catch (error) {
        showToast('Failed to load activity log', 'error');
    }
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    toastContainer.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    // Remove toast element after it's hidden
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

// Initialize download count from localStorage
document.addEventListener('DOMContentLoaded', function() {
    downloadCount = parseInt(localStorage.getItem('downloadCount') || '0');
});
