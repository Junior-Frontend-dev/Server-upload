const { DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');
const sequelize = require('../config/database');

const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: {
        type: DataTypes.STRING(50),
        allowNull: false,
        unique: true,
        validate: {
            len: [3, 50],
            isAlphanumeric: true
        }
    },
    email: {
        type: DataTypes.STRING(100),
        allowNull: false,
        unique: true,
        validate: {
            isEmail: true
        }
    },
    passwordHash: {
        type: DataTypes.STRING(255),
        allowNull: false,
        field: 'password_hash'
    },
    role: {
        type: DataTypes.ENUM('admin', 'moderator', 'user'),
        defaultValue: 'user'
    },
    status: {
        type: DataTypes.ENUM('active', 'inactive', 'suspended'),
        defaultValue: 'active'
    },
    avatarUrl: {
        type: DataTypes.STRING(255),
        field: 'avatar_url'
    },
    storageUsed: {
        type: DataTypes.BIGINT,
        defaultValue: 0,
        field: 'storage_used'
    },
    storageLimit: {
        type: DataTypes.BIGINT,
        defaultValue: 104857600, // 100MB
        field: 'storage_limit'
    },
    lastLogin: {
        type: DataTypes.DATE,
        field: 'last_login'
    },
    twoFactorEnabled: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        field: 'two_factor_enabled'
    },
    twoFactorSecret: {
        type: DataTypes.STRING(255),
        field: 'two_factor_secret'
    }
}, {
    tableName: 'users',
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    hooks: {
        beforeCreate: async (user) => {
            if (user.passwordHash) {
                user.passwordHash = await bcrypt.hash(user.passwordHash, 12);
            }
        },
        beforeUpdate: async (user) => {
            if (user.changed('passwordHash')) {
                user.passwordHash = await bcrypt.hash(user.passwordHash, 12);
            }
        }
    }
});

// Instance methods
User.prototype.validatePassword = async function(password) {
    return bcrypt.compare(password, this.passwordHash);
};

User.prototype.getRemainingStorage = function() {
    return Math.max(0, this.storageLimit - this.storageUsed);
};

User.prototype.canUpload = function(fileSize) {
    return this.storageUsed + fileSize <= this.storageLimit;
};

User.prototype.toJSON = function() {
    const values = { ...this.get() };
    delete values.passwordHash;
    delete values.twoFactorSecret;
    return values;
};

module.exports = User;