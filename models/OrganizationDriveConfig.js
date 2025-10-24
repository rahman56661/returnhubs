const mongoose = require('mongoose');

const OrganizationDriveConfigSchema = new mongoose.Schema({
  organizationId: {
    type: String,
    required: true,
    unique: true
  },
  // Google Drive Configuration
  driveConfig: {
    rootDriveId: { type: String, required: true },
    serviceAccountEmail: { type: String, required: true },
    privateKey: { type: String, required: true }
  },
  // Google Sheets Configuration
  sheetsConfig: {
    masterSheetId: { type: String, required: true },
    additionalSheets: [{
      sheetName: String,
      sheetId: String
    }]
  },
  // Courier-specific sheets
  courierSheets: {
    amazon: String,
    delhivery: String,
    dtdc: String,
    ecom: String,
    ekart: String,
    franch_express: String,
    india_post: String,
    shadowfax: String,
    smarter: String,
    tracon: String,
    xpressbees: String
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('OrganizationDriveConfig', OrganizationDriveConfigSchema);