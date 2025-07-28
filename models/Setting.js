const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const Setting = sequelize.define('Setting', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    key: {
        type: DataTypes.STRING(100),
        allowNull: false,
        unique: true
    },
    value: {
        type: DataTypes.TEXT,
        get() {
            const rawValue = this.getDataValue('value');
            try {
                return JSON.parse(rawValue);
            } catch {
                return rawValue;
            }
        },
        set(value) {
            this.setDataValue('value', typeof value === 'object' ? JSON.stringify(value) : value);
        }
    },
    type: {
        type: DataTypes.ENUM('string', 'number', 'boolean', 'json'),
        defaultValue: 'string'
    },
    description: {
        type: DataTypes.TEXT
    }
}, {
    tableName: 'settings',
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at'
});

module.exports = Setting;