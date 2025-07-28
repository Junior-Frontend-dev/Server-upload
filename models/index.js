const sequelize = require('../config/database');
const User = require('./User');
const File = require('./File');
const AuditLog = require('./AuditLog');
const IPList = require('./IPList');
const APIKey = require('./APIKey');
const Setting = require('./Setting');

// Define associations
User.hasMany(File, { foreignKey: 'userId', as: 'files' });
File.belongsTo(User, { foreignKey: 'userId', as: 'user' });

User.hasMany(AuditLog, { foreignKey: 'userId', as: 'auditLogs' });
AuditLog.belongsTo(User, { foreignKey: 'userId', as: 'user' });

User.hasMany(APIKey, { foreignKey: 'userId', as: 'apiKeys' });
APIKey.belongsTo(User, { foreignKey: 'userId', as: 'user' });

module.exports = {
    sequelize,
    User,
    File,
    AuditLog,
    IPList,
    APIKey,
    Setting
};