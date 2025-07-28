const { body, param, query, validationResult } = require('express-validator');

// Validation error handler
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            error: 'Validation failed',
            details: errors.array()
        });
    }
    next();
};

// User validation rules
const validateUser = [
    body('username')
        .isLength({ min: 3, max: 50 })
        .withMessage('Username must be between 3 and 50 characters')
        .isAlphanumeric()
        .withMessage('Username must contain only letters and numbers'),
    body('email')
        .isEmail()
        .withMessage('Must be a valid email address')
        .normalizeEmail(),
    body('password')
        .optional()
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long'),
    body('role')
        .optional()
        .isIn(['admin', 'moderator', 'user'])
        .withMessage('Role must be admin, moderator, or user'),
    body('status')
        .optional()
        .isIn(['active', 'inactive', 'suspended'])
        .withMessage('Status must be active, inactive, or suspended'),
    handleValidationErrors
];

// Login validation rules
const validateLogin = [
    body('username')
        .notEmpty()
        .withMessage('Username is required'),
    body('password')
        .notEmpty()
        .withMessage('Password is required'),
    handleValidationErrors
];

// File validation rules
const validateFile = [
    body('tags')
        .optional()
        .isArray()
        .withMessage('Tags must be an array'),
    body('isPublic')
        .optional()
        .isBoolean()
        .withMessage('isPublic must be a boolean'),
    handleValidationErrors
];

// IP validation rules
const validateIP = [
    body('ipAddress')
        .isIP()
        .withMessage('Must be a valid IP address'),
    body('type')
        .isIn(['whitelist', 'blacklist'])
        .withMessage('Type must be whitelist or blacklist'),
    body('description')
        .optional()
        .isLength({ max: 255 })
        .withMessage('Description must be less than 255 characters'),
    handleValidationErrors
];

// Setting validation rules
const validateSetting = [
    body('key')
        .isLength({ min: 1, max: 100 })
        .withMessage('Key must be between 1 and 100 characters'),
    body('value')
        .notEmpty()
        .withMessage('Value is required'),
    body('type')
        .optional()
        .isIn(['string', 'number', 'boolean', 'json'])
        .withMessage('Type must be string, number, boolean, or json'),
    handleValidationErrors
];

// Pagination validation
const validatePagination = [
    query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer'),
    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1 and 100'),
    handleValidationErrors
];

module.exports = {
    validateUser,
    validateLogin,
    validateFile,
    validateIP,
    validateSetting,
    validatePagination,
    handleValidationErrors
};