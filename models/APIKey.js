const { DataTypes } = require('sequelize');
const crypto = require('crypto');
const sequelize = require('../config/database');

const APIKey = sequelize.define('APIKey', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    name: {
        type: DataTypes.STRING(100),
        allowNull: false
    },
    keyHash: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: true,
        field: 'key_hash'
    },
    userId: {
        type: DataTypes.INTEGER,
        allowNull: false,
        field: 'user_id',
        references: {
            model: 'users',
            key: 'id'
        }
    },
    permissions: {
        type: DataTypes.TEXT,
        get() {
            const rawValue = this.getDataValue('permissions');
            return rawValue ? rawValue.split(',') : [];
        },
        set(value) {
            this.setDataValue('permissions', Array.isArray(value) ? value.join(',') : value);
        }
    },
    lastUsed: {
        type: DataTypes.DATE,
        field: 'last_used'
    },
    expiresAt: {
        type: DataTypes.DATE,
        field: 'expires_at'
    },
    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true,
        field: 'is_active'
    }
}, {
    tableName: 'api_keys',
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at'
});

// Static method to generate API key
APIKey.generateKey = function() {
    return crypto.randomBytes(32).toString('hex');
};

// Static method to hash API key
APIKey.hashKey = function(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
};

module.exports = APIKey;