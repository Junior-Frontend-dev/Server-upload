// Enhanced Admin Panel JavaScript

class AdminPanel {
    constructor() {
        this.currentSection = 'dashboard';
        this.users = [];
        this.currentPage = 1;
        this.usersPerPage = 10;
        this.selectedUsers = new Set();
        this.charts = {};
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadDashboard();
        this.setupCharts();
        this.loadUsers();
        this.loadAuditLogs();
        this.loadAPIKeys();
        this.loadBackups();
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-link[data-section]').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = e.target.closest('[data-section]').dataset.section;
                this.showSection(section);
            });
        });

        // User management
        document.getElementById('userSearch')?.addEventListener('input', 
            this.debounce(() => this.filterUsers(), 300));
        document.getElementById('roleFilter')?.addEventListener('change', () => this.filterUsers());
        document.getElementById('statusFilter')?.addEventListener('change', () => this.filterUsers());
        document.getElementById('selectAllUsers')?.addEventListener('change', (e) => this.selectAllUsers(e.target.checked));

        // Forms
        document.getElementById('userForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveUser();
        });

        document.getElementById('passwordPolicyForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.savePasswordPolicy();
        });

        document.getElementById('twoFactorForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.save2FASettings();
        });

        // Settings forms
        document.getElementById('generalSettingsForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveGeneralSettings();
        });

        document.getElementById('databaseSettingsForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveDatabaseSettings();
        });

        document.getElementById('emailSettingsForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveEmailSettings();
        });

        document.getElementById('backupSettingsForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveBackupSettings();
        });
    }

    showSection(sectionId) {
        // Hide all sections
        document.querySelectorAll('.content-section').forEach(section => {
            section.classList.remove('active');
        });

        // Show selected section
        const section = document.getElementById(sectionId);
        if (section) {
            section.classList.add('active');
            this.currentSection = sectionId;
        }

        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        document.querySelector(`[data-section="${sectionId}"]`)?.classList.add('active');

        // Load section-specific data
        this.loadSectionData(sectionId);
    }

    loadSectionData(sectionId) {
        switch (sectionId) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'user-management':
                this.loadUsers();
                break;
            case 'security':
                this.loadSecurityData();
                break;
            case 'configuration':
                this.loadConfiguration();
                break;
        }
    }

    // Dashboard Methods
    async loadDashboard() {
        try {
            const response = await fetch('/api/admin/dashboard');
            const data = await response.json();

            document.getElementById('totalUsers').textContent = data.totalUsers || 0;
            document.getElementById('activeSessions').textContent = data.activeSessions || 0;
            document.getElementById('totalFiles').textContent = data.totalFiles || 0;
            document.getElementById('securityAlerts').textContent = data.securityAlerts || 0;

            this.updateRecentActions(data.recentActions || []);
            this.updateActivityChart(data.activityData || []);
        } catch (error) {
            console.error('Error loading dashboard:', error);
            this.showToast('Failed to load dashboard data', 'error');
        }
    }

    updateRecentActions(actions) {
        const container = document.getElementById('recentActions');
        if (!container) return;

        container.innerHTML = actions.map(action => `
            <div class="list-group-item border-0 py-2">
                <div class="d-flex justify-content-between">
                    <span class="fw-bold">${action.user}</span>
                    <small class="text-muted">${this.formatDate(action.timestamp)}</small>
                </div>
                <small class="text-muted">${action.action}</small>
            </div>
        `).join('');
    }

    setupCharts() {
        const ctx = document.getElementById('activityChart');
        if (!ctx) return;

        this.charts.activity = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'User Activity',
                    data: [],
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.1)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    updateActivityChart(data) {
        if (!this.charts.activity) return;

        this.charts.activity.data.labels = data.map(d => d.date);
        this.charts.activity.data.datasets[0].data = data.map(d => d.count);
        this.charts.activity.update();
    }

    // User Management Methods
    async loadUsers() {
        try {
            const response = await fetch('/api/admin/users');
            const data = await response.json();
            this.users = data.users || [];
            this.renderUsers();
        } catch (error) {
            console.error('Error loading users:', error);
            this.showToast('Failed to load users', 'error');
        }
    }

    renderUsers() {
        const tbody = document.getElementById('usersTableBody');
        if (!tbody) return;

        const startIndex = (this.currentPage - 1) * this.usersPerPage;
        const endIndex = startIndex + this.usersPerPage;
        const paginatedUsers = this.users.slice(startIndex, endIndex);

        tbody.innerHTML = paginatedUsers.map(user => `
            <tr>
                <td>
                    <input type="checkbox" class="form-check-input user-checkbox" 
                           value="${user.id}" ${this.selectedUsers.has(user.id) ? 'checked' : ''}>
                </td>
                <td>
                    <img src="${user.avatar || 'https://via.placeholder.com/40x40'}" 
                         class="user-avatar" alt="${user.username}">
                </td>
                <td>${user.username}</td>
                <td>${user.email}</td>
                <td>
                    <span class="badge bg-${this.getRoleBadgeColor(user.role)}">${user.role}</span>
                </td>
                <td>
                    <span class="status-badge status-${user.status}">${user.status}</span>
                </td>
                <td>${user.lastLogin ? this.formatDate(user.lastLogin) : 'Never'}</td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" onclick="adminPanel.editUser(${user.id})">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn btn-outline-danger" onclick="adminPanel.deleteUser(${user.id})">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');

        // Add event listeners to checkboxes
        tbody.querySelectorAll('.user-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const userId = parseInt(e.target.value);
                if (e.target.checked) {
                    this.selectedUsers.add(userId);
                } else {
                    this.selectedUsers.delete(userId);
                }
                this.updateBulkActions();
            });
        });

        this.renderPagination();
    }

    renderPagination() {
        const pagination = document.getElementById('userPagination');
        if (!pagination) return;

        const totalPages = Math.ceil(this.users.length / this.usersPerPage);
        let paginationHTML = '';

        // Previous button
        paginationHTML += `
            <li class="page-item ${this.currentPage === 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="adminPanel.changePage(${this.currentPage - 1})">Previous</a>
            </li>
        `;

        // Page numbers
        for (let i = 1; i <= totalPages; i++) {
            paginationHTML += `
                <li class="page-item ${i === this.currentPage ? 'active' : ''}">
                    <a class="page-link" href="#" onclick="adminPanel.changePage(${i})">${i}</a>
                </li>
            `;
        }

        // Next button
        paginationHTML += `
            <li class="page-item ${this.currentPage === totalPages ? 'disabled' : ''}">
                <a class="page-link" href="#" onclick="adminPanel.changePage(${this.currentPage + 1})">Next</a>
            </li>
        `;

        pagination.innerHTML = paginationHTML;
    }

    changePage(page) {
        const totalPages = Math.ceil(this.users.length / this.usersPerPage);
        if (page >= 1 && page <= totalPages) {
            this.currentPage = page;
            this.renderUsers();
        }
    }

    filterUsers() {
        const search = document.getElementById('userSearch')?.value.toLowerCase() || '';
        const roleFilter = document.getElementById('roleFilter')?.value || '';
        const statusFilter = document.getElementById('statusFilter')?.value || '';

        this.users = this.users.filter(user => {
            const matchesSearch = user.username.toLowerCase().includes(search) || 
                                user.email.toLowerCase().includes(search);
            const matchesRole = !roleFilter || user.role === roleFilter;
            const matchesStatus = !statusFilter || user.status === statusFilter;

            return matchesSearch && matchesRole && matchesStatus;
        });

        this.currentPage = 1;
        this.renderUsers();
    }

    clearUserFilters() {
        document.getElementById('userSearch').value = '';
        document.getElementById('roleFilter').value = '';
        document.getElementById('statusFilter').value = '';
        this.loadUsers();
    }

    selectAllUsers(checked) {
        const checkboxes = document.querySelectorAll('.user-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.checked = checked;
            const userId = parseInt(checkbox.value);
            if (checked) {
                this.selectedUsers.add(userId);
            } else {
                this.selectedUsers.delete(userId);
            }
        });
        this.updateBulkActions();
    }

    updateBulkActions() {
        const bulkActions = document.getElementById('bulkUserActions');
        const selectedCount = document.getElementById('selectedUserCount');
        
        if (this.selectedUsers.size > 0) {
            bulkActions.style.display = 'block';
            selectedCount.textContent = this.selectedUsers.size;
        } else {
            bulkActions.style.display = 'none';
        }
    }

    showCreateUserModal() {
        document.getElementById('userModalTitle').textContent = 'Add New User';
        document.getElementById('userForm').reset();
        document.getElementById('userId').value = '';
        document.getElementById('passwordSection').style.display = 'block';
        new bootstrap.Modal(document.getElementById('userModal')).show();
    }

    editUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return;

        document.getElementById('userModalTitle').textContent = 'Edit User';
        document.getElementById('userId').value = user.id;
        document.getElementById('username').value = user.username;
        document.getElementById('email').value = user.email;
        document.getElementById('role').value = user.role;
        document.getElementById('status').value = user.status;
        document.getElementById('passwordSection').style.display = 'block';
        
        new bootstrap.Modal(document.getElementById('userModal')).show();
    }

    async saveUser() {
        const formData = new FormData();
        const userId = document.getElementById('userId').value;
        
        formData.append('username', document.getElementById('username').value);
        formData.append('email', document.getElementById('email').value);
        formData.append('role', document.getElementById('role').value);
        formData.append('status', document.getElementById('status').value);
        
        const password = document.getElementById('password').value;
        if (password) {
            formData.append('password', password);
        }

        const avatarFile = document.getElementById('avatar').files[0];
        if (avatarFile) {
            formData.append('avatar', avatarFile);
        }

        try {
            const url = userId ? `/api/admin/users/${userId}` : '/api/admin/users';
            const method = userId ? 'PUT' : 'POST';
            
            const response = await fetch(url, {
                method: method,
                body: formData
            });

            if (response.ok) {
                this.showToast('User saved successfully', 'success');
                bootstrap.Modal.getInstance(document.getElementById('userModal')).hide();
                this.loadUsers();
            } else {
                const error = await response.json();
                this.showToast(error.message || 'Failed to save user', 'error');
            }
        } catch (error) {
            console.error('Error saving user:', error);
            this.showToast('Failed to save user', 'error');
        }
    }

    async deleteUser(userId) {
        if (!confirm('Are you sure you want to delete this user?')) return;

        try {
            const response = await fetch(`/api/admin/users/${userId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                this.showToast('User deleted successfully', 'success');
                this.loadUsers();
            } else {
                this.showToast('Failed to delete user', 'error');
            }
        } catch (error) {
            console.error('Error deleting user:', error);
            this.showToast('Failed to delete user', 'error');
        }
    }

    // Bulk Actions
    async bulkActivateUsers() {
        await this.bulkUpdateUsers('active');
    }

    async bulkSuspendUsers() {
        await this.bulkUpdateUsers('suspended');
    }

    async bulkDeleteUsers() {
        if (!confirm(`Are you sure you want to delete ${this.selectedUsers.size} users?`)) return;

        try {
            const response = await fetch('/api/admin/users/bulk-delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userIds: Array.from(this.selectedUsers) })
            });

            if (response.ok) {
                this.showToast('Users deleted successfully', 'success');
                this.selectedUsers.clear();
                this.loadUsers();
            } else {
                this.showToast('Failed to delete users', 'error');
            }
        } catch (error) {
            console.error('Error deleting users:', error);
            this.showToast('Failed to delete users', 'error');
        }
    }

    async bulkUpdateUsers(status) {
        try {
            const response = await fetch('/api/admin/users/bulk-update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    userIds: Array.from(this.selectedUsers),
                    status: status
                })
            });

            if (response.ok) {
                this.showToast(`Users ${status} successfully`, 'success');
                this.selectedUsers.clear();
                this.loadUsers();
            } else {
                this.showToast(`Failed to ${status} users`, 'error');
            }
        } catch (error) {
            console.error(`Error updating users to ${status}:`, error);
            this.showToast(`Failed to ${status} users`, 'error');
        }
    }

    // Security Methods
    async loadSecurityData() {
        try {
            const response = await fetch('/api/admin/security');
            const data = await response.json();
            
            this.loadAuditLogs();
            this.loadIPLists();
        } catch (error) {
            console.error('Error loading security data:', error);
        }
    }

    async loadAuditLogs() {
        try {
            const response = await fetch('/api/admin/audit-logs');
            const logs = await response.json();
            
            const tbody = document.getElementById('auditLogsTable');
            if (!tbody) return;

            tbody.innerHTML = logs.map(log => `
                <tr>
                    <td>${this.formatDate(log.timestamp)}</td>
                    <td>${log.user}</td>
                    <td>${log.action}</td>
                    <td>${log.ipAddress}</td>
                    <td>${log.details || '-'}</td>
                </tr>
            `).join('');
        } catch (error) {
            console.error('Error loading audit logs:', error);
        }
    }

    async loadIPLists() {
        try {
            const response = await fetch('/api/admin/ip-lists');
            const data = await response.json();
            
            this.renderIPList('whitelistIPs', data.whitelist || [], 'success');
            this.renderIPList('blacklistIPs', data.blacklist || [], 'danger');
        } catch (error) {
            console.error('Error loading IP lists:', error);
        }
    }

    renderIPList(containerId, ips, type) {
        const container = document.getElementById(containerId);
        if (!container) return;

        container.innerHTML = ips.map(ip => `
            <div class="list-group-item d-flex justify-content-between align-items-center">
                <span>${ip.address}</span>
                <button class="btn btn-sm btn-outline-${type}" onclick="adminPanel.removeIP('${ip.id}', '${type}')">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `).join('');
    }

    async addWhitelistIP() {
        const ip = document.getElementById('whitelistIP').value.trim();
        if (!ip) return;

        await this.addIP(ip, 'whitelist');
        document.getElementById('whitelistIP').value = '';
    }

    async addBlacklistIP() {
        const ip = document.getElementById('blacklistIP').value.trim();
        if (!ip) return;

        await this.addIP(ip, 'blacklist');
        document.getElementById('blacklistIP').value = '';
    }

    async addIP(ip, type) {
        try {
            const response = await fetch('/api/admin/ip-lists', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, type })
            });

            if (response.ok) {
                this.showToast(`IP added to ${type}`, 'success');
                this.loadIPLists();
            } else {
                this.showToast(`Failed to add IP to ${type}`, 'error');
            }
        } catch (error) {
            console.error(`Error adding IP to ${type}:`, error);
            this.showToast(`Failed to add IP to ${type}`, 'error');
        }
    }

    async removeIP(ipId, type) {
        try {
            const response = await fetch(`/api/admin/ip-lists/${ipId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                this.showToast('IP removed successfully', 'success');
                this.loadIPLists();
            } else {
                this.showToast('Failed to remove IP', 'error');
            }
        } catch (error) {
            console.error('Error removing IP:', error);
            this.showToast('Failed to remove IP', 'error');
        }
    }

    async savePasswordPolicy() {
        const policy = {
            minLength: document.getElementById('minPasswordLength').value,
            expiry: document.getElementById('passwordExpiry').value,
            requireUppercase: document.getElementById('requireUppercase').checked,
            requireLowercase: document.getElementById('requireLowercase').checked,
            requireNumbers: document.getElementById('requireNumbers').checked,
            requireSpecialChars: document.getElementById('requireSpecialChars').checked
        };

        try {
            const response = await fetch('/api/admin/password-policy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(policy)
            });

            if (response.ok) {
                this.showToast('Password policy saved successfully', 'success');
            } else {
                this.showToast('Failed to save password policy', 'error');
            }
        } catch (error) {
            console.error('Error saving password policy:', error);
            this.showToast('Failed to save password policy', 'error');
        }
    }

    async save2FASettings() {
        const settings = {
            enforceAll: document.getElementById('enforce2FA').checked,
            enforceAdmins: document.getElementById('enforce2FAAdmins').checked,
            allowTOTP: document.getElementById('allowTOTP').checked,
            allowSMS: document.getElementById('allowSMS').checked,
            allowEmail: document.getElementById('allowEmail').checked
        };

        try {
            const response = await fetch('/api/admin/2fa-settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            });

            if (response.ok) {
                this.showToast('2FA settings saved successfully', 'success');
            } else {
                this.showToast('Failed to save 2FA settings', 'error');
            }
        } catch (error) {
            console.error('Error saving 2FA settings:', error);
            this.showToast('Failed to save 2FA settings', 'error');
        }
    }

    // Configuration Methods
    async loadConfiguration() {
        try {
            const response = await fetch('/api/admin/configuration');
            const config = await response.json();
            
            // Populate form fields with current configuration
            this.populateConfigurationForms(config);
        } catch (error) {
            console.error('Error loading configuration:', error);
        }
    }

    populateConfigurationForms(config) {
        // General settings
        if (config.general) {
            document.getElementById('siteName').value = config.general.siteName || '';
            document.getElementById('siteUrl').value = config.general.siteUrl || '';
            document.getElementById('maxFileSize').value = config.general.maxFileSize || 100;
            document.getElementById('defaultStorage').value = config.general.defaultStorage || 100;
            document.getElementById('allowRegistration').checked = config.general.allowRegistration || false;
        }

        // Database settings
        if (config.database) {
            document.getElementById('dbType').value = config.database.type || 'sqlite';
            document.getElementById('dbHost').value = config.database.host || 'localhost';
            document.getElementById('dbPort').value = config.database.port || 3306;
            document.getElementById('dbName').value = config.database.name || '';
            document.getElementById('dbPoolSize').value = config.database.poolSize || 10;
        }

        // Email settings
        if (config.email) {
            document.getElementById('smtpHost').value = config.email.smtpHost || '';
            document.getElementById('smtpPort').value = config.email.smtpPort || 587;
            document.getElementById('fromEmail').value = config.email.fromEmail || '';
            document.getElementById('fromName').value = config.email.fromName || '';
            document.getElementById('smtpAuth').checked = config.email.smtpAuth || false;
            document.getElementById('smtpTLS').checked = config.email.smtpTLS || false;
        }

        // Backup settings
        if (config.backup) {
            document.getElementById('autoBackup').checked = config.backup.autoBackup || false;
            document.getElementById('backupFrequency').value = config.backup.frequency || 'daily';
            document.getElementById('backupRetention').value = config.backup.retention || 30;
        }
    }

    async saveGeneralSettings() {
        const settings = {
            siteName: document.getElementById('siteName').value,
            siteUrl: document.getElementById('siteUrl').value,
            maxFileSize: document.getElementById('maxFileSize').value,
            defaultStorage: document.getElementById('defaultStorage').value,
            allowRegistration: document.getElementById('allowRegistration').checked
        };

        await this.saveConfiguration('general', settings);
    }

    async saveDatabaseSettings() {
        const settings = {
            type: document.getElementById('dbType').value,
            host: document.getElementById('dbHost').value,
            port: document.getElementById('dbPort').value,
            name: document.getElementById('dbName').value,
            poolSize: document.getElementById('dbPoolSize').value
        };

        await this.saveConfiguration('database', settings);
    }

    async saveEmailSettings() {
        const settings = {
            smtpHost: document.getElementById('smtpHost').value,
            smtpPort: document.getElementById('smtpPort').value,
            fromEmail: document.getElementById('fromEmail').value,
            fromName: document.getElementById('fromName').value,
            smtpAuth: document.getElementById('smtpAuth').checked,
            smtpTLS: document.getElementById('smtpTLS').checked
        };

        await this.saveConfiguration('email', settings);
    }

    async saveBackupSettings() {
        const settings = {
            autoBackup: document.getElementById('autoBackup').checked,
            frequency: document.getElementById('backupFrequency').value,
            retention: document.getElementById('backupRetention').value
        };

        await this.saveConfiguration('backup', settings);
    }

    async saveConfiguration(section, settings) {
        try {
            const response = await fetch(`/api/admin/configuration/${section}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            });

            if (response.ok) {
                this.showToast(`${section} settings saved successfully`, 'success');
            } else {
                this.showToast(`Failed to save ${section} settings`, 'error');
            }
        } catch (error) {
            console.error(`Error saving ${section} settings:`, error);
            this.showToast(`Failed to save ${section} settings`, 'error');
        }
    }

    async testDatabaseConnection() {
        this.showLoading('Testing database connection...');
        
        try {
            const response = await fetch('/api/admin/test-database', {
                method: 'POST'
            });

            const result = await response.json();
            
            if (response.ok) {
                this.showToast('Database connection successful', 'success');
            } else {
                this.showToast(result.error || 'Database connection failed', 'error');
            }
        } catch (error) {
            console.error('Error testing database connection:', error);
            this.showToast('Database connection failed', 'error');
        } finally {
            this.hideLoading();
        }
    }

    async testEmailSettings() {
        this.showLoading('Sending test email...');
        
        try {
            const response = await fetch('/api/admin/test-email', {
                method: 'POST'
            });

            if (response.ok) {
                this.showToast('Test email sent successfully', 'success');
            } else {
                this.showToast('Failed to send test email', 'error');
            }
        } catch (error) {
            console.error('Error sending test email:', error);
            this.showToast('Failed to send test email', 'error');
        } finally {
            this.hideLoading();
        }
    }

    // API Key Management
    async loadAPIKeys() {
        try {
            const response = await fetch('/api/admin/api-keys');
            const keys = await response.json();
            
            const tbody = document.getElementById('apiKeysTable');
            if (!tbody) return;

            tbody.innerHTML = keys.map(key => `
                <tr>
                    <td>${key.name}</td>
                    <td>
                        <code class="text-muted">
                            ${key.key.substring(0, 8)}...${key.key.substring(key.key.length - 8)}
                        </code>
                    </td>
                    <td>
                        ${key.permissions.map(p => `<span class="badge bg-secondary me-1">${p}</span>`).join('')}
                    </td>
                    <td>${this.formatDate(key.created)}</td>
                    <td>${key.lastUsed ? this.formatDate(key.lastUsed) : 'Never'}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-danger" onclick="adminPanel.deleteAPIKey('${key.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
            `).join('');
        } catch (error) {
            console.error('Error loading API keys:', error);
        }
    }

    async generateAPIKey() {
        const name = prompt('Enter API key name:');
        if (!name) return;

        try {
            const response = await fetch('/api/admin/api-keys', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });

            if (response.ok) {
                const result = await response.json();
                this.showToast('API key generated successfully', 'success');
                alert(`New API Key: ${result.key}\n\nPlease save this key as it won't be shown again.`);
                this.loadAPIKeys();
            } else {
                this.showToast('Failed to generate API key', 'error');
            }
        } catch (error) {
            console.error('Error generating API key:', error);
            this.showToast('Failed to generate API key', 'error');
        }
    }

    async deleteAPIKey(keyId) {
        if (!confirm('Are you sure you want to delete this API key?')) return;

        try {
            const response = await fetch(`/api/admin/api-keys/${keyId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                this.showToast('API key deleted successfully', 'success');
                this.loadAPIKeys();
            } else {
                this.showToast('Failed to delete API key', 'error');
            }
        } catch (error) {
            console.error('Error deleting API key:', error);
            this.showToast('Failed to delete API key', 'error');
        }
    }

    // Backup Management
    async loadBackups() {
        try {
            const response = await fetch('/api/admin/backups');
            const backups = await response.json();
            
            const container = document.getElementById('backupsList');
            if (!container) return;

            container.innerHTML = backups.map(backup => `
                <div class="list-group-item d-flex justify-content-between align-items-center">
                    <div>
                        <strong>${backup.name}</strong>
                        <br>
                        <small class="text-muted">${this.formatDate(backup.created)} - ${this.formatFileSize(backup.size)}</small>
                    </div>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" onclick="adminPanel.downloadBackup('${backup.id}')">
                            <i class="fas fa-download"></i>
                        </button>
                        <button class="btn btn-outline-danger" onclick="adminPanel.deleteBackup('${backup.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            `).join('');
        } catch (error) {
            console.error('Error loading backups:', error);
        }
    }

    async createBackup() {
        this.showLoading('Creating backup...');
        
        try {
            const response = await fetch('/api/admin/backups', {
                method: 'POST'
            });

            if (response.ok) {
                this.showToast('Backup created successfully', 'success');
                this.loadBackups();
            } else {
                this.showToast('Failed to create backup', 'error');
            }
        } catch (error) {
            console.error('Error creating backup:', error);
            this.showToast('Failed to create backup', 'error');
        } finally {
            this.hideLoading();
        }
    }

    showRestoreModal() {
        new bootstrap.Modal(document.getElementById('restoreModal')).show();
    }

    async restoreBackup() {
        const fileInput = document.getElementById('restoreFile');
        const file = fileInput.files[0];
        
        if (!file) {
            this.showToast('Please select a backup file', 'warning');
            return;
        }

        if (!confirm('This will overwrite all current data. Are you sure?')) return;

        this.showLoading('Restoring backup...');
        
        const formData = new FormData();
        formData.append('backup', file);

        try {
            const response = await fetch('/api/admin/restore', {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                this.showToast('Backup restored successfully', 'success');
                bootstrap.Modal.getInstance(document.getElementById('restoreModal')).hide();
                // Reload the page after successful restore
                setTimeout(() => window.location.reload(), 2000);
            } else {
                this.showToast('Failed to restore backup', 'error');
            }
        } catch (error) {
            console.error('Error restoring backup:', error);
            this.showToast('Failed to restore backup', 'error');
        } finally {
            this.hideLoading();
        }
    }

    async downloadBackup(backupId) {
        try {
            const response = await fetch(`/api/admin/backups/${backupId}/download`);
            
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `backup-${backupId}.zip`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            } else {
                this.showToast('Failed to download backup', 'error');
            }
        } catch (error) {
            console.error('Error downloading backup:', error);
            this.showToast('Failed to download backup', 'error');
        }
    }

    async deleteBackup(backupId) {
        if (!confirm('Are you sure you want to delete this backup?')) return;

        try {
            const response = await fetch(`/api/admin/backups/${backupId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                this.showToast('Backup deleted successfully', 'success');
                this.loadBackups();
            } else {
                this.showToast('Failed to delete backup', 'error');
            }
        } catch (error) {
            console.error('Error deleting backup:', error);
            this.showToast('Failed to delete backup', 'error');
        }
    }

    // Maintenance Mode
    async toggleMaintenanceMode() {
        try {
            const response = await fetch('/api/admin/maintenance-mode', {
                method: 'POST'
            });

            const result = await response.json();
            
            if (response.ok) {
                const status = result.enabled ? 'enabled' : 'disabled';
                this.showToast(`Maintenance mode ${status}`, 'info');
            } else {
                this.showToast('Failed to toggle maintenance mode', 'error');
            }
        } catch (error) {
            console.error('Error toggling maintenance mode:', error);
            this.showToast('Failed to toggle maintenance mode', 'error');
        }
    }

    // Utility Methods
    getRoleBadgeColor(role) {
        const colors = {
            admin: 'danger',
            moderator: 'warning',
            user: 'primary'
        };
        return colors[role] || 'secondary';
    }

    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    debounce(func, wait) {
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

    showLoading(text = 'Loading...') {
        document.getElementById('loadingText').textContent = text;
        new bootstrap.Modal(document.getElementById('loadingModal')).show();
    }

    hideLoading() {
        const modal = bootstrap.Modal.getInstance(document.getElementById('loadingModal'));
        if (modal) modal.hide();
    }

    showToast(message, type = 'info') {
        // Create toast container if it doesn't exist
        let toastContainer = document.getElementById('toastContainer');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toastContainer';
            toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
            toastContainer.style.zIndex = '9999';
            document.body.appendChild(toastContainer);
        }

        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        toastContainer.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();

        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    }

    // Profile and logout methods
    showProfile() {
        // Implementation for showing admin profile
        this.showToast('Profile functionality coming soon', 'info');
    }

    showSettings() {
        // Switch to configuration section
        this.showSection('configuration');
    }

    logout() {
        if (confirm('Are you sure you want to logout?')) {
            window.location.href = '/admin';
        }
    }

    refreshDashboard() {
        this.loadDashboard();
        this.showToast('Dashboard refreshed', 'success');
    }
}

// Initialize admin panel when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.adminPanel = new AdminPanel();
});

// Global functions for onclick handlers
function showCreateUserModal() {
    window.adminPanel.showCreateUserModal();
}

function saveUser() {
    window.adminPanel.saveUser();
}

function showRestoreModal() {
    window.adminPanel.showRestoreModal();
}

function restoreBackup() {
    window.adminPanel.restoreBackup();
}

function createBackup() {
    window.adminPanel.createBackup();
}

function generateAPIKey() {
    window.adminPanel.generateAPIKey();
}

function testDatabaseConnection() {
    window.adminPanel.testDatabaseConnection();
}

function testEmailSettings() {
    window.adminPanel.testEmailSettings();
}

function toggleMaintenanceMode() {
    window.adminPanel.toggleMaintenanceMode();
}

function addWhitelistIP() {
    window.adminPanel.addWhitelistIP();
}

function addBlacklistIP() {
    window.adminPanel.addBlacklistIP();
}

function clearUserFilters() {
    window.adminPanel.clearUserFilters();
}

function bulkActivateUsers() {
    window.adminPanel.bulkActivateUsers();
}

function bulkSuspendUsers() {
    window.adminPanel.bulkSuspendUsers();
}

function bulkDeleteUsers() {
    window.adminPanel.bulkDeleteUsers();
}

function refreshDashboard() {
    window.adminPanel.refreshDashboard();
}

function showProfile() {
    window.adminPanel.showProfile();
}

function showSettings() {
    window.adminPanel.showSettings();
}

function logout() {
    window.adminPanel.logout();
}