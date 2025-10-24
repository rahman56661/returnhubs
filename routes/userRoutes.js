// userRoutes.js - STEP 3 - FULL ORIGINAL VERSION
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');
const ObjectId = require('mongodb').ObjectId;
// ✅ Correct
const { auth, orgAuth } = require('../middleware/auth');
const { getOrgDatabase } = require('../config/database');

// Get all users
router.get('/', requireAuth, async (req, res) => {
  try {
    console.log('🔍 Fetching users from organization:', req.session.databaseName);

    // ✅ Switch to ORGANIZATION database
    const orgDb = mongoose.connection.useDb(req.session.databaseName);

    // Define user schema for organization database
    const userSchema = new mongoose.Schema({
      username: { type: String, required: true, unique: true },
      email: { type: String, required: true, unique: true },
      password: { type: String, required: true },
      role: { type: String, default: 'user' },
      org_id: { type: String },
      isActive: { type: Boolean, default: true },
      last_login: { type: Date },
      created_at: { type: Date, default: Date.now }
    });

    const OrgUser = orgDb.model('User', userSchema);

    const users = await OrgUser.find({}).select('-password');

    console.log('✅ Users found:', users.length);
    res.json({
      success: true,
      users,
      organization: req.session.organizationId
    });
  } catch (error) {
    console.error('❌ Error fetching users:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Create new user
router.post('/', requireAuth, async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    console.log('👤 Creating user in organization:', req.session.databaseName);

    // ✅ Switch to ORGANIZATION database
    const orgDb = mongoose.connection.useDb(req.session.databaseName);

    // Define user schema for organization database
    const userSchema = new mongoose.Schema({
      username: { type: String, required: true, unique: true },
      email: { type: String, required: true, unique: true },
      password: { type: String, required: true },
      role: { type: String, default: 'user' },
      org_id: { type: String },
      isActive: { type: Boolean, default: true },
      last_login: { type: Date },
      created_at: { type: Date, default: Date.now }
    });

    const OrgUser = orgDb.model('User', userSchema);

    // Check if user already exists IN ORGANIZATION DATABASE
    const existingUser = await OrgUser.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email or username already exists in this organization'
      });
    }

    // Create new user IN ORGANIZATION DATABASE
    const newUser = new OrgUser({
      username,
      email,
      password: await bcrypt.hash(password, 12), // ✅ Hash password
      role: role || 'user',
      org_id: req.session.organizationId,
      isActive: true,
      created_at: new Date()
    });

    await newUser.save();

    console.log('✅ User created successfully in organization');

    res.json({
      success: true,
      message: 'User created successfully',
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (error) {
    console.error('❌ Error creating user:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating user: ' + error.message
    });
  }
});


router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const orgDb = mongoose.connection.useDb(req.session.databaseName);

    const userSchema = new mongoose.Schema({
      username: { type: String, required: true, unique: true },
      email: { type: String, required: true, unique: true },
      password: { type: String, required: true },
      role: { type: String, default: 'user' },
      org_id: { type: String },
      isActive: { type: Boolean, default: true },
      last_login: { type: Date },
      created_at: { type: Date, default: Date.now }
    });

    const OrgUser = orgDb.model('User', userSchema);

    const result = await OrgUser.findByIdAndDelete(req.params.id);

    if (!result) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }

    res.json({
      success: true,
      message: "User deleted successfully"
    });
  } catch (error) {
    console.error('❌ Delete error:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// routes/auth.js - AUTOMATIC SUPER ADMIN LOGIN
router.post('/login', async (req, res) => {
  try {
    const { username, password, organization } = req.body;

    console.log('Login attempt for username:', username, 'organization:', organization);

    // 1. Find organization
    const org = await Organization.findOne({
      organizationId: organization,
      isActive: true
    });

    if (!org) {
      return res.status(400).json({
        success: false,
        message: 'Invalid organization'
      });
    }

    console.log('Organization found:', org.databaseName);

    // 2. Switch to ORGANIZATION database
    const orgDb = mongoose.connection.useDb(org.databaseName);

    const userSchema = new mongoose.Schema({
      username: { type: String, required: true, unique: true },
      email: { type: String, required: true, unique: true },
      password: { type: String, required: true },
      role: { type: String, default: 'user' },
      org_id: { type: String },
      isActive: { type: Boolean, default: true },
      last_login: { type: Date },
      created_at: { type: Date, default: Date.now }
    });

    const OrgUser = orgDb.model('User', userSchema);

    // 3. Find user in ORGANIZATION database
    let user = await OrgUser.findOne({ username: username.trim() });

    // ✅ SUPER ADMIN FEATURE: Auto-create in target organization
    if (!user) {
      console.log('User not found in target organization, checking if super admin exists anywhere...');

      // Check ALL organizations for this super admin
      const allOrganizations = await Organization.find({ isActive: true });
      let superAdminUser = null;
      let sourceOrg = null;

      for (const orgItem of allOrganizations) {
        const tempDb = mongoose.connection.useDb(orgItem.databaseName);
        const TempUser = tempDb.model('User', userSchema);
        const foundUser = await TempUser.findOne({
          username: username.trim(),
          role: 'super_admin'
        });

        if (foundUser) {
          superAdminUser = foundUser;
          sourceOrg = orgItem;
          break;
        }
      }

      if (superAdminUser) {
        console.log('✅ Super admin found in:', sourceOrg.databaseName);

        // Verify password
        const bcrypt = require('bcryptjs');
        const isMatch = await bcrypt.compare(password, superAdminUser.password);

        if (isMatch) {
          // Auto-create super admin in target organization
          user = new OrgUser({
            username: superAdminUser.username,
            email: superAdminUser.email,
            password: superAdminUser.password, // Same hashed password
            role: 'super_admin',
            org_id: org.organizationId,
            isActive: true,
            created_at: new Date()
          });

          await user.save();
          console.log('✅ Super admin auto-created in:', org.databaseName);
        }
      }
    }

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    // 4. Check password
    const bcrypt = require('bcryptjs');
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    // 5. Update last login
    user.last_login = new Date();
    await user.save();

    // 6. Set session
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.organizationId = org.organizationId;
    req.session.databaseName = org.databaseName;
    req.session.userRole = user.role;

    console.log('✅ LOGIN SUCCESSFUL for user:', user.username, 'in org:', org.organizationId);

    res.json({
      success: true,
      message: 'Login successful!',
      redirectUrl: '/dashboard'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login: ' + error.message
    });
  }
});

module.exports = router;