const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const AuditLog = sequelize.define('AuditLog', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    userId: {
        type: DataTypes.INTEGER,
        allowNull: true,
        field: 'user_id',
        references: {
            model: 'users',
            key: 'id'
        }
    },
    action: {
        type: DataTypes.STRING(100),
        allowNull: false
    },
    resource: {
        type: DataTypes.STRING(100),
        allowNull: true
    },
    resourceId: {
        type: DataTypes.INTEGER,
        allowNull: true,
        field: 'resource_id'
    },
    ipAddress: {
        type: DataTypes.STRING(45),
        field: 'ip_address'
    },
    userAgent: {
        type: DataTypes.TEXT,
        field: 'user_agent'
    },
    details: {
        type: DataTypes.TEXT,
        get() {
            const rawValue = this.getDataValue('details');
            return rawValue ? JSON.parse(rawValue) : null;
        },
        set(value) {
            this.setDataValue('details', value ? JSON.stringify(value) : null);
        }
    }
}, {
    tableName: 'audit_logs',
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: false
});

module.exports = AuditLog;