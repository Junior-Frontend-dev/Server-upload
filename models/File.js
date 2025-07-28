const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const File = sequelize.define('File', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    filename: {
        type: DataTypes.STRING(255),
        allowNull: false
    },
    originalName: {
        type: DataTypes.STRING(255),
        allowNull: false,
        field: 'original_name'
    },
    fileSize: {
        type: DataTypes.BIGINT,
        allowNull: false,
        field: 'file_size'
    },
    mimeType: {
        type: DataTypes.STRING(100),
        field: 'mime_type'
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
    downloadCount: {
        type: DataTypes.INTEGER,
        defaultValue: 0,
        field: 'download_count'
    },
    isPublic: {
        type: DataTypes.BOOLEAN,
        defaultValue: true,
        field: 'is_public'
    },
    isPasswordProtected: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        field: 'is_password_protected'
    },
    passwordHash: {
        type: DataTypes.STRING(255),
        field: 'password_hash'
    },
    expiresAt: {
        type: DataTypes.DATE,
        field: 'expires_at'
    },
    tags: {
        type: DataTypes.TEXT,
        get() {
            const rawValue = this.getDataValue('tags');
            return rawValue ? rawValue.split(',') : [];
        },
        set(value) {
            this.setDataValue('tags', Array.isArray(value) ? value.join(',') : value);
        }
    }
}, {
    tableName: 'files',
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at'
});

module.exports = File;