const mongoose = require('mongoose');

const inventoryDataSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    username: { // ADD THIS FIELD
        type: String,
        required: true,
        trim: true
    },
    awbNo: {
        type: String,
        required: true,
        trim: true
    },
    categoryData: {
        good: {
            count: { type: Number, default: 0 },
            eans: [String]
        },
        bad: {
            count: { type: Number, default: 0 },
            eans: [String]
        },
        used: {
            count: { type: Number, default: 0 },
            eans: [String]
        },
        wrong: {
            count: { type: Number, default: 0 },
            eans: [String]
        }
    },
    recordings: [{
        videoFile: String,
        date: { type: Date, default: Date.now },
        scannedData: { type: String, default: 'None' }
    }],
    // NEW: Add mediaFiles array for images and other files
    mediaFiles: [{
        type: { type: String, enum: ['video', 'image'] },
        fileName: String,
        driveLink: String,
        awbFolderLink: String,
        scannedData: String,
        driveSyncDate: Date,
        uploadDate: { type: Date, default: Date.now }
    }],
    additionalInfo: {
        courierName: String,
        returnType: String,
        opsRemarks: String,
        channelName: String,
        userComment: String
    },
    orderId: {
        type: String,
        required: true
    },
    skuPairs: [
        {
            systemSku: String,
            physicalSku: String
        }
    ],
    organization: { type: String, required: true, default: 'default' },
    awbFolderLink: {
        type: String,
        default: ''
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastUpdated: {
        type: Date,
        default: Date.now
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Compound index to ensure unique AWB per user
//inventoryDataSchema.index({ userId: 1, awbNo: 1 }, { unique: true });

module.exports = mongoose.model('InventoryData', inventoryDataSchema);