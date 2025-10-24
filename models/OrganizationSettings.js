const mongoose = require('mongoose');

const organizationSettingsSchema = new mongoose.Schema({
    organizationId: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    courierName: [{
        type: String,
        trim: true
    }],
    returnType: [{
        type: String,
        trim: true
    }],
    opsRemarks: [{
        type: String,
        trim: true
    }],
    channelName: [{
        type: String,
        trim: true
    }],
    config: {
        autoCreateFolders: { type: Boolean, default: true },
        enableVideoRecording: { type: Boolean, default: true },
        enableImageCapture: { type: Boolean, default: true },
        defaultStreamProtocol: { type: String, default: 'http' }
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

organizationSettingsSchema.index({ organizationId: 1 });

// 🔥 IMPORTANT: Check if model already exists before creating
const OrganizationSettings = mongoose.models.OrganizationSettings ||
    mongoose.model('OrganizationSettings', organizationSettingsSchema);

module.exports = OrganizationSettings;