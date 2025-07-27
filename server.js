@@ .. @@
 // Serve admin page
 app.get("/admin", (req, res) => {
     res.sendFile(path.join(__dirname, "public", "admin.html"));
 });
 
+// Serve enhanced admin page
+app.get("/admin-enhanced", (req, res) => {
+    res.sendFile(path.join(__dirname, "public", "admin-enhanced.html"));
+});
+
+// Enhanced Admin API Routes
+
+// Dashboard data
+app.get("/api/admin/dashboard", isAdmin, (req, res) => {
+    try {
+        const stats = getStorageStats();
+        const dashboardData = {
+            totalUsers: 0, // Would come from user database
+            activeSessions: 0, // Would come from session store
+            totalFiles: stats.totalFiles,
+            securityAlerts: 0, // Would come from security monitoring
+            recentActions: [
+                {
+                    user: "Admin",
+                    action: "File uploaded",
+                    timestamp: new Date().toISOString()
+                }
+            ],
+            activityData: [
+                { date: "2024-01-01", count: 10 },
+                { date: "2024-01-02", count: 15 },
+                { date: "2024-01-03", count: 8 }
+            ]
+        };
+        res.json(dashboardData);
+    } catch (error) {
+        res.status(500).json({ error: "Failed to load dashboard data" });
+    }
+});
+
+// User management endpoints
+app.get("/api/admin/users", isAdmin, (req, res) => {
+    // Mock user data - in real implementation, this would come from database
+    const users = [
+        {
+            id: 1,
+            username: "john_doe",
+            email: "john@example.com",
+            role: "user",
+            status: "active",
+            lastLogin: new Date().toISOString(),
+            avatar: "https://via.placeholder.com/40x40"
+        },
+        {
+            id: 2,
+            username: "admin",
+            email: "admin@example.com",
+            role: "admin",
+            status: "active",
+            lastLogin: new Date().toISOString(),
+            avatar: "https://via.placeholder.com/40x40"
+        }
+    ];
+    res.json({ users });
+});
+
+// Security endpoints
+app.get("/api/admin/security", isAdmin, (req, res) => {
+    res.json({ status: "ok" });
+});
+
+app.get("/api/admin/audit-logs", isAdmin, (req, res) => {
+    const logs = [
+        {
+            timestamp: new Date().toISOString(),
+            user: "admin",
+            action: "User login",
+            ipAddress: "192.168.1.1",
+            details: "Successful login"
+        }
+    ];
+    res.json(logs);
+});
+
+app.get("/api/admin/ip-lists", isAdmin, (req, res) => {
+    const data = {
+        whitelist: [
+            { id: "1", address: "192.168.1.1" }
+        ],
+        blacklist: [
+            { id: "2", address: "10.0.0.1" }
+        ]
+    };
+    res.json(data);
+});
+
+// Configuration endpoints
+app.get("/api/admin/configuration", isAdmin, (req, res) => {
+    const config = {
+        general: {
+            siteName: "File Share Platform",
+            siteUrl: "https://example.com",
+            maxFileSize: 100,
+            defaultStorage: 100,
+            allowRegistration: true
+        },
+        database: {
+            type: "sqlite",
+            host: "localhost",
+            port: 3306,
+            name: "fileshare",
+            poolSize: 10
+        },
+        email: {
+            smtpHost: "",
+            smtpPort: 587,
+            fromEmail: "",
+            fromName: "File Share Platform",
+            smtpAuth: false,
+            smtpTLS: false
+        },
+        backup: {
+            autoBackup: false,
+            frequency: "daily",
+            retention: 30
+        }
+    };
+    res.json(config);
+});
+
+// API Keys endpoints
+app.get("/api/admin/api-keys", isAdmin, (req, res) => {
+    const keys = [
+        {
+            id: "1",
+            name: "Main API Key",
+            key: "sk_test_1234567890abcdef1234567890abcdef",
+            permissions: ["read", "write"],
+            created: new Date().toISOString(),
+            lastUsed: new Date().toISOString()
+        }
+    ];
+    res.json(keys);
+});
+
+// Backup endpoints
+app.get("/api/admin/backups", isAdmin, (req, res) => {
+    const backups = [
+        {
+            id: "1",
+            name: "backup-2024-01-01.zip",
+            created: new Date().toISOString(),
+            size: 1024 * 1024 * 10 // 10MB
+        }
+    ];
+    res.json(backups);
+});
+
+// Test endpoints
+app.post("/api/admin/test-database", isAdmin, (req, res) => {
+    // Mock database test
+    setTimeout(() => {
+        res.json({ success: true, message: "Database connection successful" });
+    }, 1000);
+});
+
+app.post("/api/admin/test-email", isAdmin, (req, res) => {
+    // Mock email test
+    setTimeout(() => {
+        res.json({ success: true, message: "Test email sent successfully" });
+    }, 1000);
+});
+
+// Maintenance mode endpoint
+app.post("/api/admin/maintenance-mode", isAdmin, (req, res) => {
+    // Mock maintenance mode toggle
+    const enabled = Math.random() > 0.5;
+    res.json({ enabled, message: `Maintenance mode ${enabled ? 'enabled' : 'disabled'}` });
+});
+
 // Error handling middleware
 app.use((error, req, res, next) => {
     if (error instanceof multer.MulterError) {