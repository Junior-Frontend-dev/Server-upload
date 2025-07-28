const express = require('express');
const { Op } = require('sequelize');
const { User, File, AuditLog, IPList, APIKey, Setting } = require('../models');
const { isAdmin, auditLog } = require('../middleware/auth');
const { validateUser, validateIP, validateSetting, validatePagination } = require('../middleware/validation');
const logger = require('../utils/logger');

const router = express.Router();

// Dashboard endpoint
router.get('/dashboard', isAdmin, async (req, res) => {
    try {
        const [totalUsers, totalFiles, activeSessions, securityAlerts] = await Promise.all([
            User.count(),
            File.count(),
            User.count({ where: { status: 'active' } }),
            AuditLog.count({ 
                where: { 
                    action: { [Op.like]: '%failed%' },
                    createdAt: { [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) }
                }
            })
        ]);

        const recentActions = await AuditLog.findAll({
            limit: 10,
            order: [['createdAt', 'DESC']],
            include: [{ model: User, as: 'user', attributes: ['username'] }]
        });

        // Get activity data for the last 7 days
        const activityData = await AuditLog.findAll({
            attributes: [
                [require('sequelize').fn('DATE', require('sequelize').col('created_at')), 'date'],
                [require('sequelize').fn('COUNT', '*'), 'count']
            ],
            where: {
                createdAt: { [Op.gte]: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
            },
            group: [require('sequelize').fn('DATE', require('sequelize').col('created_at'))],
            order: [[require('sequelize').fn('DATE', require('sequelize').col('created_at')), 'ASC']]
        });

        res.json({
            totalUsers,
            totalFiles,
            activeSessions,
            securityAlerts,
            recentActions: recentActions.map(action => ({
                user: action.user?.username || 'System',
                action: action.action,
                timestamp: action.createdAt
            })),
            activityData: activityData.map(item => ({
                date: item.getDataValue('date'),
                count: item.getDataValue('count')
            }))
        });
    } catch (error) {
        logger.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard data' });
    }
});

// User Management Routes
router.get('/users', isAdmin, validatePagination, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const offset = (page - 1) * limit;
        const search = req.query.search || '';
        const role = req.query.role || '';
        const status = req.query.status || '';

        const where = {};
        if (search) {
            where[Op.or] = [
                { username: { [Op.like]: `%${search}%` } },
                { email: { [Op.like]: `%${search}%` } }
            ];
        }
        if (role) where.role = role;
        if (status) where.status = status;

        const { count, rows: users } = await User.findAndCountAll({
            where,
            limit,
            offset,
            order: [['createdAt', 'DESC']],
            attributes: { exclude: ['passwordHash', 'twoFactorSecret'] }
        });

        res.json({
            users,
            pagination: {
                page,
                limit,
                total: count,
                pages: Math.ceil(count / limit)
            }
        });
    } catch (error) {
        logger.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

router.post('/users', isAdmin, validateUser, auditLog('CREATE_USER', 'user'), async (req, res) => {
    try {
        const { username, email, password, role, status } = req.body;
        
        const user = await User.create({
            username,
            email,
            passwordHash: password,
            role: role || 'user',
            status: status || 'active'
        });

        res.status(201).json({ 
            message: 'User created successfully',
            user: user.toJSON()
        });
    } catch (error) {
        logger.error('Create user error:', error);
        if (error.name === 'SequelizeUniqueConstraintError') {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        res.status(500).json({ error: 'Failed to create user' });
    }
});

router.put('/users/:id', isAdmin, validateUser, auditLog('UPDATE_USER', 'user'), async (req, res) => {
    try {
        const { id } = req.params;
        const { username, email, password, role, status } = req.body;
        
        const user = await User.findByPk(id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const updateData = { username, email, role, status };
        if (password) {
            updateData.passwordHash = password;
        }

        await user.update(updateData);
        
        res.json({ 
            message: 'User updated successfully',
            user: user.toJSON()
        });
    } catch (error) {
        logger.error('Update user error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

router.delete('/users/:id', isAdmin, auditLog('DELETE_USER', 'user'), async (req, res) => {
    try {
        const { id } = req.params;
        
        const user = await User.findByPk(id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        await user.destroy();
        
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        logger.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Bulk user operations
router.post('/users/bulk-update', isAdmin, auditLog('BULK_UPDATE_USERS', 'user'), async (req, res) => {
    try {
        const { userIds, status } = req.body;
        
        await User.update(
            { status },
            { where: { id: { [Op.in]: userIds } } }
        );
        
        res.json({ message: `Users ${status} successfully` });
    } catch (error) {
        logger.error('Bulk update users error:', error);
        res.status(500).json({ error: 'Failed to update users' });
    }
});

router.post('/users/bulk-delete', isAdmin, auditLog('BULK_DELETE_USERS', 'user'), async (req, res) => {
    try {
        const { userIds } = req.body;
        
        await User.destroy({
            where: { id: { [Op.in]: userIds } }
        });
        
        res.json({ message: 'Users deleted successfully' });
    } catch (error) {
        logger.error('Bulk delete users error:', error);
        res.status(500).json({ error: 'Failed to delete users' });
    }
});

// Security Routes
router.get('/security', isAdmin, async (req, res) => {
    try {
        const [ipLists, recentLogins, failedAttempts] = await Promise.all([
            IPList.findAll({ order: [['createdAt', 'DESC']] }),
            AuditLog.findAll({
                where: { action: 'LOGIN' },
                limit: 20,
                order: [['createdAt', 'DESC']],
                include: [{ model: User, as: 'user', attributes: ['username'] }]
            }),
            AuditLog.count({
                where: { 
                    action: 'LOGIN_FAILED',
                    createdAt: { [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) }
                }
            })
        ]);

        res.json({
            ipLists: {
                whitelist: ipLists.filter(ip => ip.type === 'whitelist'),
                blacklist: ipLists.filter(ip => ip.type === 'blacklist')
            },
            recentLogins,
            failedAttempts
        });
    } catch (error) {
        logger.error('Security data error:', error);
        res.status(500).json({ error: 'Failed to load security data' });
    }
});

// Audit logs
router.get('/audit-logs', isAdmin, validatePagination, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const offset = (page - 1) * limit;

        const logs = await AuditLog.findAll({
            limit,
            offset,
            order: [['createdAt', 'DESC']],
            include: [{ model: User, as: 'user', attributes: ['username'] }]
        });

        res.json(logs.map(log => ({
            timestamp: log.createdAt,
            user: log.user?.username || 'System',
            action: log.action,
            ipAddress: log.ipAddress,
            details: log.details
        })));
    } catch (error) {
        logger.error('Audit logs error:', error);
        res.status(500).json({ error: 'Failed to fetch audit logs' });
    }
});

// IP Management
router.get('/ip-lists', isAdmin, async (req, res) => {
    try {
        const ipLists = await IPList.findAll({
            order: [['createdAt', 'DESC']]
        });

        res.json({
            whitelist: ipLists.filter(ip => ip.type === 'whitelist'),
            blacklist: ipLists.filter(ip => ip.type === 'blacklist')
        });
    } catch (error) {
        logger.error('IP lists error:', error);
        res.status(500).json({ error: 'Failed to fetch IP lists' });
    }
});

router.post('/ip-lists', isAdmin, validateIP, auditLog('ADD_IP', 'ip'), async (req, res) => {
    try {
        const { ipAddress, type, description } = req.body;
        
        const ipEntry = await IPList.create({
            ipAddress,
            type,
            description
        });
        
        res.status(201).json({ 
            message: `IP added to ${type}`,
            ip: ipEntry
        });
    } catch (error) {
        logger.error('Add IP error:', error);
        res.status(500).json({ error: 'Failed to add IP' });
    }
});

router.delete('/ip-lists/:id', isAdmin, auditLog('REMOVE_IP', 'ip'), async (req, res) => {
    try {
        const { id } = req.params;
        
        const ipEntry = await IPList.findByPk(id);
        if (!ipEntry) {
            return res.status(404).json({ error: 'IP entry not found' });
        }

        await ipEntry.destroy();
        
        res.json({ message: 'IP removed successfully' });
    } catch (error) {
        logger.error('Remove IP error:', error);
        res.status(500).json({ error: 'Failed to remove IP' });
    }
});

// Configuration Routes
router.get('/configuration', isAdmin, async (req, res) => {
    try {
        const settings = await Setting.findAll();
        
        const config = {
            general: {},
            database: {},
            email: {},
            backup: {}
        };

        settings.forEach(setting => {
            const [category, key] = setting.key.split('.');
            if (config[category]) {
                config[category][key] = setting.value;
            }
        });

        res.json(config);
    } catch (error) {
        logger.error('Configuration error:', error);
        res.status(500).json({ error: 'Failed to load configuration' });
    }
});

router.post('/configuration/:section', isAdmin, auditLog('UPDATE_CONFIG', 'setting'), async (req, res) => {
    try {
        const { section } = req.params;
        const settings = req.body;

        for (const [key, value] of Object.entries(settings)) {
            const settingKey = `${section}.${key}`;
            
            await Setting.upsert({
                key: settingKey,
                value,
                type: typeof value
            });
        }

        res.json({ message: `${section} settings saved successfully` });
    } catch (error) {
        logger.error('Save configuration error:', error);
        res.status(500).json({ error: 'Failed to save configuration' });
    }
});

// API Key Management
router.get('/api-keys', isAdmin, async (req, res) => {
    try {
        const apiKeys = await APIKey.findAll({
            order: [['createdAt', 'DESC']],
            include: [{ model: User, as: 'user', attributes: ['username'] }]
        });

        res.json(apiKeys.map(key => ({
            id: key.id,
            name: key.name,
            key: key.keyHash.substring(0, 8) + '...' + key.keyHash.substring(key.keyHash.length - 8),
            permissions: key.permissions,
            created: key.createdAt,
            lastUsed: key.lastUsed,
            user: key.user?.username
        })));
    } catch (error) {
        logger.error('API keys error:', error);
        res.status(500).json({ error: 'Failed to fetch API keys' });
    }
});

router.post('/api-keys', isAdmin, auditLog('CREATE_API_KEY', 'api_key'), async (req, res) => {
    try {
        const { name, permissions = [] } = req.body;
        const key = APIKey.generateKey();
        const keyHash = APIKey.hashKey(key);

        const apiKey = await APIKey.create({
            name,
            keyHash,
            userId: req.user?.id || 1, // Default to admin user
            permissions
        });

        res.status(201).json({
            message: 'API key generated successfully',
            key, // Only show the key once
            id: apiKey.id
        });
    } catch (error) {
        logger.error('Generate API key error:', error);
        res.status(500).json({ error: 'Failed to generate API key' });
    }
});

router.delete('/api-keys/:id', isAdmin, auditLog('DELETE_API_KEY', 'api_key'), async (req, res) => {
    try {
        const { id } = req.params;
        
        const apiKey = await APIKey.findByPk(id);
        if (!apiKey) {
            return res.status(404).json({ error: 'API key not found' });
        }

        await apiKey.destroy();
        
        res.json({ message: 'API key deleted successfully' });
    } catch (error) {
        logger.error('Delete API key error:', error);
        res.status(500).json({ error: 'Failed to delete API key' });
    }
});

module.exports = router;