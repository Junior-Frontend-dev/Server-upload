const jwt = require('jsonwebtoken');
const { User, AuditLog } = require('../models');

// Admin authentication middleware
const isAdmin = async (req, res, next) => {
    try {
        const adminKey = req.headers.authorization?.replace('Bearer ', '') || 
                        req.query.adminKey || 
                        req.body.adminKey;
        
        const validKey = process.env.ADMIN_KEY || "admin123";

        if (adminKey === validKey) {
            req.isAdmin = true;
            return next();
        }

        // Check JWT token for admin users
        const token = req.headers.authorization?.replace('Bearer ', '');
        if (token) {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findByPk(decoded.userId);
            
            if (user && user.role === 'admin' && user.status === 'active') {
                req.user = user;
                req.isAdmin = true;
                return next();
            }
        }

        return res.status(403).json({ 
            error: 'Access denied. Admin privileges required.' 
        });
    } catch (error) {
        return res.status(401).json({ 
            error: 'Invalid authentication token.' 
        });
    }
};

// User authentication middleware
const authenticate = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '') ||
                     req.session?.token;

        if (!token) {
            return res.status(401).json({ 
                error: 'Authentication token required.' 
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findByPk(decoded.userId);

        if (!user || user.status !== 'active') {
            return res.status(401).json({ 
                error: 'Invalid or inactive user.' 
            });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ 
            error: 'Invalid authentication token.' 
        });
    }
};

// Role-based authorization middleware
const authorize = (roles = []) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                error: 'Authentication required.' 
            });
        }

        if (roles.length && !roles.includes(req.user.role)) {
            return res.status(403).json({ 
                error: 'Insufficient permissions.' 
            });
        }

        next();
    };
};

// Audit logging middleware
const auditLog = (action, resource = null) => {
    return async (req, res, next) => {
        const originalSend = res.send;
        
        res.send = function(data) {
            // Log the action after successful response
            if (res.statusCode < 400) {
                AuditLog.create({
                    userId: req.user?.id || null,
                    action,
                    resource,
                    resourceId: req.params.id || null,
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    details: {
                        method: req.method,
                        url: req.originalUrl,
                        body: req.method !== 'GET' ? req.body : undefined
                    }
                }).catch(console.error);
            }
            
            originalSend.call(this, data);
        };
        
        next();
    };
};

module.exports = {
    isAdmin,
    authenticate,
    authorize,
    auditLog
};