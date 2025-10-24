// routes/auth.js - CORRECTED VERSION
const express = require('express');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const Organization = require('../models/Organization'); // ✅ Add this
const User = require('../models/User');  // Main database user model

const router = express.Router();

router.post('/login', async (req, res) => {
  try {
    const { username, password, organization } = req.body;

    console.log('🔍 LOGIN ATTEMPT:', { username, organization });

    // 1. Find organization
    const org = await Organization.findOne({
      organizationId: organization,
      isActive: true
    });

    console.log('🏢 ORGANIZATION:', org ? org.databaseName : 'NOT FOUND');

    if (!org) {
      return res.status(400).json({
        success: false,
        message: 'Invalid organization'
      });
    }

    // 2. Switch to organization database
    const orgDb = mongoose.connection.useDb(org.databaseName, {
      useCache: true
    });

    // 3. ✅ CRITICAL FIX: Case insensitive user search
    const userSchema = new mongoose.Schema({
      username: { type: String, required: true, unique: true },
      email: { type: String, required: true, unique: true },
      password: { type: String, required: true },
      role: { type: String, default: 'admin', enum: ['super_admin', 'admin', 'manager', 'user'] },
      org_id: { type: String },
      isActive: { type: Boolean, default: true },
      last_login: { type: Date },
      created_at: { type: Date, default: Date.now }
    });

    const OrgUser = orgDb.model('User', userSchema);

    // ✅ FIX 1: Trim and case insensitive search
    const cleanUsername = username.trim().toLowerCase();
    console.log('🔍 SEARCHING USER:', cleanUsername);

    // ✅ FIX 2: Use regex for case insensitive search
    const user = await OrgUser.findOne({
      username: { $regex: new RegExp('^' + cleanUsername + '$', 'i') }
    });

    console.log('👤 USER FOUND:', user ? `YES - ${user.username}` : 'NO');

    if (!user) {
      // ✅ FIX 3: Also try exact match as fallback
      const userExact = await OrgUser.findOne({ username: username.trim() });
      console.log('👤 EXACT MATCH:', userExact ? `YES - ${userExact.username}` : 'NO');

      if (!userExact) {
        return res.status(400).json({
          success: false,
          message: 'Invalid username or password'
        });
      }

      // Use exact match user
      var finalUser = userExact;
    } else {
      var finalUser = user;
    }

    // 4. Verify password
    console.log('🔐 PASSWORD CHECK...');
    const isValidPassword = await bcrypt.compare(password, finalUser.password);
    console.log('🔐 PASSWORD VALID:', isValidPassword);

    if (!isValidPassword) {
      return res.status(400).json({
        success: false,
        message: 'Invalid username or password'
      });
    }

    // ✅ ROLE-BASED ORGANIZATION ACCESS
    if (user.role === 'admin' || user.role === 'user') {
      // Admin/User can only login to their assigned organization
      const userOrg = await Organization.findById(user.org_id);
      if (userOrg.organizationId !== organization) {
        return res.status(400).json({
          success: false,
          message: 'You can only login to your assigned organization'
        });
      }
    }

    // 5. ✅ SUCCESS: Create session
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.organizationId = org.organizationId; // Keep for display
    req.session.organizationObjectId = org._id; // ✅ ADD THIS - ObjectId
    req.session.databaseName = org.databaseName;
    req.session.userRole = user.role;

    console.log('✅ LOGIN SUCCESSFUL:', finalUser.username);

    res.json({
      success: true,
      message: 'Login successful!',
      redirectUrl: '/dashboard'
    });

  } catch (error) {
    console.error('❌ LOGIN ERROR:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
});

// Logout route
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Logout failed'
      });
    }
    res.json({
      success: true,
      message: 'Logout successful'
    });
  });
});


module.exports = router;