const mongoose = require('mongoose');

const driveSettingsSchema = new mongoose.Schema({
    organizationId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    serviceAccountEmail: {
        type: String,
        required: true
    },
    privateKey: {
        type: String,
        required: true
    },
    rootFolderId: {
        type: String,
        required: true
    },
    masterSheetId: {
        type: String,
        required: true
    },
    additionalSheets: [{
        name: String,
        sheetId: String
    }],
    isActive: {
        type: Boolean,
        default: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Update the updatedAt field before saving
driveSettingsSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

// Static method to get settings with fallback
driveSettingsSchema.statics.getSettings = async function(organizationId) {
    const settings = await this.findOne({ organizationId, isActive: true });
    
    if (!settings) {
        console.warn(`⚠️ No Drive settings found for organization: ${organizationId}`);
        return null;
    }
    
    return settings;
};

module.exports = mongoose.model('DriveSettings', driveSettingsSchema);