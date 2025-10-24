const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({

    organization: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        //required: true
    },
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        minlength: [3, 'Username must be at least 3 characters long']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, 'Please enter a valid email address']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters long']
    },// 🔑 Role & Permissions (NEW)
    role: {
        type: String,
        enum: ['superadmin', 'user', 'admin'],
        default: 'user',
    },
    permissions: {
        type: [String],
        default: function () {
            // default permissions based on role
            return this.role === 'admin' ? ['*'] : ['button1', 'button2'];
        }
    },

    isActive: {
        type: Boolean,
        default: true,
        description: 'If false, user cannot login'
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null,
    },
    last_login: {
        type: Date,
        default: null,
    },
    last_logout: {
        type: Date,
        default: null,
        description: 'Timestamp when the user last logged out'
    },
    autoMailEnabled: {
        type: Boolean,
        default: false,
        description: 'Enables or disables automatic email reports'
    },
    autoMailRecipient: {
        type: [String],
        default: [],
        validate: {
            validator: function (emails) {
                const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
                return emails.every(email => emailRegex.test(email));
            },
            message: 'All recipient email addresses must be valid'
        },
        description: 'Array of email addresses to receive automated reports'
    },
    autoMailTime: {
        type: String,
        default: '09:00',
        match: [/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, 'Please enter a valid time in HH:MM format'],
        description: 'Time of day to send automated email reports'
    },
    autoMailDays: {
        type: [String],
        default: ['Monday', 'Wednesday', 'Friday'],
        enum: {
            values: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'],
            message: '{VALUE} is not a valid day of the week'
        },
        description: 'Days of the week to send automated email reports'
    },
    created_at: {
        type: Date,
        default: Date.now,
        description: 'Timestamp when the user was created'
    },
    login_status: {
        type: String,
        enum: ['Logged In', 'Logged Out', 'Never Logged In'],
        default: 'Never Logged In'
    },
    // ✅ OPTIONAL: Payment history reference (add if you want)
    lastPaymentId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Payment'
    }
}, {
    timestamps: true // Adds createdAt and updatedAt fields automatically
});

// Hash password before saving
userSchema.pre('save', async function (next) {
    // Only hash the password if it has been modified (or is new)
    if (!this.isModified('password')) return next();

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(this.password, saltRounds);
        this.password = hashedPassword;
        next();
    } catch (error) {
        next(error);
    }
});

// In User.js, add this method to the userSchema
userSchema.methods.updateLastLogin = function () {
    this.lastLogin = new Date();
    return this.save();
};

// Compare password method for login
userSchema.methods.comparePassword = async function (candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw error;
    }
};

const User = mongoose.model('User', userSchema);
module.exports = User;