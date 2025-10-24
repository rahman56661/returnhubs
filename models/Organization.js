// models/Organization.js
const mongoose = require('mongoose');

const organizationSchema = new mongoose.Schema({
    organizationName: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    displayName: {
        type: String,
        required: true,
        trim: true
    },
    organizationId: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    description: {
        type: String,
        default: ''
    },
    contactEmail: {
        type: String,
        required: true,
        trim: true
    },
    phone: {
        type: String,
        default: ''
    },
    address: {
        street: String,
        city: String,
        state: String,
        country: String,
        zipCode: String
    },
    isActive: {
        type: Boolean,
        default: true
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    databaseName: {
        type: String,
        required: true,
        unique: true
    },
    // ✅ SUBSCRIPTION FIELD ADD PANNEN - IDHU DHAN IMPORTANT
    subscription: {
        planType: {
            type: String,
            enum: ['trial', 'monthly', 'quarterly', 'sixmonth', 'annual'],
            default: 'trial'
        },
        adminUsers: {
            type: Number,
            default: 1,
            min: 1
        },
        regularUsers: {
            type: Number,
            default: 3,
            min: 1
        },
        status: {
            type: String,
            enum: ['active', 'inactive', 'expired', 'cancelled'],
            default: 'active'
        },
        startDate: {
            type: Date,
            default: Date.now
        },
        endDate: {
            type: Date,
            default: function () {
                const date = new Date();
                date.setDate(date.getDate() + 30); // 30-day trial
                return date;
            }
        },
        freeTrial: {
            type: Boolean,
            default: true
        },
        freeTrialEnd: {
            type: Date,
            default: function () {
                const date = new Date();
                date.setMonth(date.getMonth() + 6); // 6 months free trial
                return date;
            }
        },
        lastPaymentId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Payment'
        },
        features: {
            videoRecording: { type: Boolean, default: true },
            dataManagement: { type: Boolean, default: true },
            reports: { type: Boolean, default: true },
            userManagement: { type: Boolean, default: false },
            organizationManagement: { type: Boolean, default: false }
        }
    }
}, {
    timestamps: true
});

// ✅ FIX: Database name auto-generate pannu
organizationSchema.pre('save', function (next) {
    if (!this.databaseName) {
        // Clean organizationId for database name
        const cleanId = this.organizationId.toLowerCase().replace(/[^a-z0-9]/g, '_');
        this.databaseName = `org_${cleanId}_db`;
    }
    next();
});

// ✅ Subscription status check panna method
organizationSchema.methods.checkSubscriptionStatus = function () {
    const now = new Date();
    if (this.subscription.freeTrial && now > this.subscription.freeTrialEnd) {
        this.subscription.freeTrial = false;
    }
    if (now > this.subscription.endDate) {
        this.subscription.status = 'expired';
    }
    return this.subscription.status;
};

// ✅ Check if organization can add more users
organizationSchema.methods.canAddUser = function (role) {
    const currentUsers = {
        admin: 0,
        regular: 0
    };

    // In real implementation, you'd count actual users from database
    if (role === 'admin') {
        return currentUsers.admin < this.subscription.adminUsers;
    } else {
        return currentUsers.regular < this.subscription.regularUsers;
    }
};

module.exports = mongoose.model('Organization', organizationSchema);