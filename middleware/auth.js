// middleware/auth.js
const Organization = require('../models/Organization');
const { getOrganizationDB } = require('../db-connections');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');

        if (!token) {
            return res.status(401).json({ success: false, message: 'No token' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ success: false, message: 'Token invalid' });
    }
};

const requireAuth = async (req, res, next) => {
    try {
        // Check if user is logged in
        if (!req.session.userId || !req.session.organizationId) {
            return res.redirect('/login?error=Please login to access this page');
        }

        // Verify organization exists and is active
        const org = await Organization.findOne({
            organizationId: req.session.organizationId,
            isActive: true
        });

        if (!org) {
            req.session.destroy();
            return res.redirect('/login?error=Organization not found or inactive');
        }

        // Set organization context for all requests
        req.org_id = org._id;
        req.organizationId = org.organizationId;
        req.databaseName = org.databaseName;
        req.org_data = org;

        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        req.session.destroy();
        res.redirect('/login?error=Authentication error');
    }
};

const orgAuth = (req, res, next) => {
    try {
        const user = req.user; // From JWT token
        if (!user.org_id) {
            return res.status(403).json({
                success: false,
                message: "Organization access denied"
            });
        }

        // Set organization context for all requests
        req.org_id = user.org_id;
        req.org_db = `org_${user.org_id}_db`;

        next();
    } catch (error) {
        res.status(500).json({ success: false, message: "Org auth failed" });
    }
};

// Optional: For API routes if needed
const apiAuth = async (req, res, next) => {
    try {
        if (!req.session.userId || !req.session.organizationId) {
            return res.status(401).json({
                success: false,
                message: 'Please login to access this resource'
            });
        }

        // Same organization verification as above
        const org = await Organization.findOne({
            organizationId: req.session.organizationId,
            isActive: true
        });

        if (!org) {
            return res.status(401).json({
                success: false,
                message: 'Organization not found'
            });
        }

        req.org_id = org._id;
        req.organizationId = org.organizationId;
        req.databaseName = org.databaseName;
        next();
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Authentication failed'
        });
    }
};

const requireRole = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.session.userId) {
            return res.redirect('/login');
        }

        if (!allowedRoles.includes(req.session.userRole)) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Insufficient permissions.'
            });
        }

        next();
    };
};

module.exports = { requireAuth, orgAuth, auth, apiAuth, requireRole };