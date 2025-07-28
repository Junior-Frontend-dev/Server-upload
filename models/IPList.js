const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const IPList = sequelize.define('IPList', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    ipAddress: {
        type: DataTypes.STRING(45),
        allowNull: false,
        field: 'ip_address',
        validate: {
            isIP: true
        }
    },
    type: {
        type: DataTypes.ENUM('whitelist', 'blacklist'),
        allowNull: false
    },
    description: {
        type: DataTypes.STRING(255),
        allowNull: true
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true,
        field: 'is_active'
    }
}, {
    tableName: 'ip_lists',
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at'
});

module.exports = IPList;