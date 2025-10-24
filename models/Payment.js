const mongoose = require('mongoose');

const paymentSchema = new mongoose.Schema({
    // User and Organization references
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    organizationId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization',
        required: true
    },

    // Plan details
    planType: {
        type: String,
        enum: ['monthly', 'quarterly', 'sixmonth', 'annual'],
        required: true
    },
    adminUsers: {
        type: Number,
        required: true,
        min: 1
    },
    regularUsers: {
        type: Number,
        required: true,
        min: 1
    },

    // Payment amount details
    amount: {
        type: Number,
        required: true,
        min: 0
    },
    currency: {
        type: String,
        default: 'INR'
    },
    taxAmount: {
        type: Number,
        default: 0
    },
    totalAmount: {
        type: Number,
        required: true
    },

    // Payment method details
    paymentMethod: {
        type: String,
        enum: ['card', 'upi', 'bank', 'cash'],
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'completed', 'failed', 'refunded', 'cancelled'],
        default: 'pending'
    },

    // Transaction references
    transactionId: String,
    stripePaymentIntentId: String,
    razorpayOrderId: String,
    razorpayPaymentId: String,
    bankReference: String,
    upiTransactionId: String,

    // Invoice details
    invoiceNumber: {
        type: String,
        unique: true
    },
    invoiceUrl: String,

    // Subscription period
    subscriptionStart: Date,
    subscriptionEnd: Date,
    freeTrial: {
        type: Boolean,
        default: true
    },
    freeTrialEnd: Date,

    // Payment gateway responses
    gatewayResponse: mongoose.Schema.Types.Mixed,
    errorMessage: String,

    // Timestamps
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    },
    paidAt: Date
}, {
    timestamps: true // This will automatically manage createdAt and updatedAt
});

// Pre-save middleware to generate invoice number
paymentSchema.pre('save', async function(next) {
    if (this.isNew) {
        const count = await mongoose.model('Payment').countDocuments();
        this.invoiceNumber = `INV-${(count + 1).toString().padStart(6, '0')}`;
    }
    next();
});

// Method to check if payment is active
paymentSchema.methods.isActive = function() {
    return this.status === 'completed' && new Date() <= this.subscriptionEnd;
};

// Method to calculate remaining days
paymentSchema.methods.getRemainingDays = function() {
    if (!this.subscriptionEnd) return 0;
    const remaining = this.subscriptionEnd - new Date();
    return Math.ceil(remaining / (1000 * 60 * 60 * 24));
};

// Static method to find successful payments by organization
paymentSchema.statics.findSuccessfulByOrganization = function(organizationId) {
    return this.find({
        organizationId: organizationId,
        status: 'completed'
    }).sort({ createdAt: -1 });
};

const Payment = mongoose.model('Payment', paymentSchema);

module.exports = Payment;