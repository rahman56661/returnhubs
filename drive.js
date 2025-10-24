// =========================
//  Google Drive Uploader (REAL) - Organization Friendly
// =========================

const fs = require("fs");
const path = require("path");
const { google } = require("googleapis");

// Folder caching
const folderCache = new Map();

// Organization settings storage
let organizationSettings = new Map();

// Load organization settings
async function loadOrganizationSettings(organizationId) {
  if (!organizationId) {
    throw new Error('Organization ID is required');
  }

  try {
    // Check if already cached
    if (organizationSettings.has(organizationId)) {
      return organizationSettings.get(organizationId);
    }

    const DriveSettings = require('./models/DriveSettings');
    const settings = await DriveSettings.getSettings(organizationId);

    if (!settings) {
      throw new Error(`No Drive settings found for organization: ${organizationId}`);
    }

    // Cache the settings
    organizationSettings.set(organizationId, settings);
    return settings;

  } catch (error) {
    console.error('Error loading organization settings:', error.message);
    throw error;
  }
}

// Get authentication for specific organization
async function getOrganizationAuth(organizationId) {
  try {
    let settings = organizationSettings.get(organizationId);

    if (!settings) {
      settings = await loadOrganizationSettings(organizationId);
    }

    return new google.auth.GoogleAuth({
      credentials: {
        client_email: settings.serviceAccountEmail,
        private_key: settings.privateKey.replace(/\\n/g, '\n'),
      },
      scopes: [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
      ],
    });
  } catch (error) {
    console.error('Error getting organization auth:', error);
    throw error;
  }
}

// Get drive instance for organization
async function getOrganizationDrive(organizationId) {
  const auth = await getOrganizationAuth(organizationId);
  return google.drive({ version: "v3", auth });
}

// Get sheets instance for organization
async function getOrganizationSheets(organizationId) {
  const auth = await getOrganizationAuth(organizationId);
  return google.sheets({ version: "v4", auth });
}

async function getOrCreateFolderFast(name, parentId = null, organizationId) {
  const cacheKey = `${organizationId}_${name}_${parentId || 'root'}`;

  if (folderCache.has(cacheKey)) {
    return folderCache.get(cacheKey);
  }

  try {
    const drive = await getOrganizationDrive(organizationId);
    const query = [
      `name='${name}'`,
      `mimeType='application/vnd.google-apps.folder'`,
      parentId ? `'${parentId}' in parents` : null,
      "trashed=false",
    ].filter(Boolean).join(" and ");

    const res = await drive.files.list({
      q: query,
      fields: "files(id)",
      pageSize: 1,
      supportsAllDrives: true,
      includeItemsFromAllDrives: true,
    });

    let folderId;

    if (res.data.files.length > 0) {
      folderId = res.data.files[0].id;
    } else {
      const fileMetadata = {
        name,
        mimeType: "application/vnd.google-apps.folder",
        parents: parentId ? [parentId] : [],
      };

      const folder = await drive.files.create({
        resource: fileMetadata,
        fields: "id",
        supportsAllDrives: true,
      });

      folderId = folder.data.id;
    }

    folderCache.set(cacheKey, folderId);
    setTimeout(() => folderCache.delete(cacheKey), 600000);

    return folderId;

  } catch (err) {
    console.error("❌ Folder creation error:", err.message);
    throw err;
  }
}

async function ensurePathFast(rootId, segments, organizationId) {
  let parentId = rootId;
  for (const segment of segments) {
    parentId = await getOrCreateFolderFast(segment, parentId, organizationId);
  }
  return parentId;
}

// Get month name in 3-letter format (Jan, Feb, etc.)
function getMonthName(month) {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return months[month - 1] || months[0];
}

// Format day to 2 digits (01, 02, etc.)
function formatDay(day) {
  return day.toString().padStart(2, '0');
}

// Create folder structure: Year/Month/Day/AWB/Type
function createFolderStructure(year, month, day, awbNo, fileType) {
  const monthName = typeof month === 'string' && month.length === 3 ?
    month : getMonthName(parseInt(month));
  const dayFormatted = formatDay(day);

  return [year, monthName, dayFormatted, awbNo, fileType];
}

// Detect file type based on extension
function detectFileType(fileName) {
  const ext = path.extname(fileName).toLowerCase();
  const imageExts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'];
  const videoExts = ['.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.webm', '.m4v'];

  if (imageExts.includes(ext)) {
    return 'Images';
  } else if (videoExts.includes(ext)) {
    return 'Videos';
  } else {
    return 'Files';
  }
}

// Get MIME type based on file type
function getMimeType(fileType, fileName) {
  const ext = path.extname(fileName).toLowerCase();

  if (fileType === 'Images') {
    switch (ext) {
      case '.jpg':
      case '.jpeg':
        return 'image/jpeg';
      case '.png':
        return 'image/png';
      case '.gif':
        return 'image/gif';
      case '.webp':
        return 'image/webp';
      case '.svg':
        return 'image/svg+xml';
      default:
        return 'image/jpeg';
    }
  } else if (fileType === 'Videos') {
    switch (ext) {
      case '.mp4':
        return 'video/mp4';
      case '.avi':
        return 'video/avi';
      case '.mov':
        return 'video/quicktime';
      case '.mkv':
        return 'video/x-matroska';
      case '.webm':
        return 'video/webm';
      default:
        return 'video/mp4';
    }
  } else {
    return 'application/octet-stream';
  }
}

// REAL Google Drive Upload Function with organization context
async function uploadToDriveReal(filePath, newFileName, year, month, day, awbNo, organizationId) {
  const startTime = Date.now();

  try {
    console.log(`⚡ REAL Drive Upload starting for org ${organizationId}: ${newFileName}`);

    if (!fs.existsSync(filePath)) {
      throw new Error("File does not exist: " + filePath);
    }

    const stats = fs.statSync(filePath);
    if (stats.size === 0) {
      throw new Error("File is empty");
    }

    console.log(`📦 File size: ${stats.size} bytes`);

    // Auto-detect file type
    const fileType = detectFileType(newFileName);
    console.log(`🔍 Detected file type: ${fileType}`);

    // Create folder structure
    const folderStructure = createFolderStructure(year, month, day, awbNo, fileType);
    console.log("📁 Target structure:", folderStructure.join('/'));

    // Get organization settings
    const settings = organizationSettings.get(organizationId);
    if (!settings) {
      throw new Error(`No settings found for organization: ${organizationId}`);
    }

    const rootId = settings.rootFolderId;
    if (!rootId) throw new Error("Root folder ID missing for organization");

    // Get the AWB folder ID
    const awbFolderPath = folderStructure.slice(0, -1);
    const awbFolderId = await ensurePathFast(rootId, awbFolderPath, organizationId);
    const targetFolderId = await ensurePathFast(rootId, folderStructure, organizationId);

    const drive = await getOrganizationDrive(organizationId);

    const fileMetadata = {
      name: newFileName,
      parents: [targetFolderId],
    };

    const media = {
      mimeType: getMimeType(fileType, newFileName),
      body: fs.createReadStream(filePath)
    };

    console.log("🚀 Uploading to REAL Google Drive...");

    // Upload with timeout
    const uploadedFile = await Promise.race([
      drive.files.create({
        resource: fileMetadata,
        media: media,
        fields: "id, name, webViewLink",
        supportsAllDrives: true,
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Upload timeout")), 300000)
      )
    ]);

    const uploadTime = Date.now() - startTime;
    console.log(`✅ REAL Drive upload completed in ${uploadTime}ms`);

    return {
      ...uploadedFile.data,
      processingTime: uploadTime,
      folderStructure: folderStructure.join('/'),
      awbFolderId: awbFolderId,
      awbFolderLink: `https://drive.google.com/drive/folders/${awbFolderId}`
    };

  } catch (error) {
    const totalTime = Date.now() - startTime;
    console.error(`❌ REAL Drive upload failed after ${totalTime}ms:`, error.message);
    throw error;
  }
}

// Update recording sheet with organization context
async function updateRecordingSheet(spreadsheetId, valuesArray, sheetName = "Sheet1", organizationId) {
  try {
    const sheets = await getOrganizationSheets(organizationId);

    // Validate the sheet name - remove any invalid characters
    const cleanSheetName = sheetName.replace(/[^\w\s]/gi, '').trim() || 'Sheet1';

    console.log(`📊 Updating sheet: ${cleanSheetName} in spreadsheet: ${spreadsheetId}`);

    // Always append rows
    await sheets.spreadsheets.values.append({
      spreadsheetId,
      range: `${cleanSheetName}!A:M`,
      valueInputOption: "USER_ENTERED",
      insertDataOption: "INSERT_ROWS",
      resource: { values: valuesArray },
    });

    console.log(`✅ Successfully updated sheet: ${cleanSheetName}`);

  } catch (err) {
    console.error("❌ Google Sheets API error:", err.message);

    // Provide more helpful error message
    if (err.message.includes('Unable to parse range')) {
      throw new Error(`Sheet "${sheetName}" not found. Available sheets might be: Sheet1, Sheet 1, Recordings, Main, Data`);
    }

    throw new Error(`Google Sheets append failed: ${err.message}`);
  }
}

// Update master and additional sheets
async function updateAllSheets(awbNo, rowData, organizationId) {
  try {
    const settings = organizationSettings.get(organizationId);
    if (!settings) {
      throw new Error(`No settings found for organization: ${organizationId}`);
    }

    // Update master sheet - try different sheet names
    if (settings.masterSheetId) {
      const possibleSheetNames = ["Recordings", "Sheet1", "Sheet 1", "Main", "Data"];
      let masterSheetUpdated = false;

      for (const sheetName of possibleSheetNames) {
        try {
          await updateRecordingSheet(settings.masterSheetId, [rowData], sheetName, organizationId);
          console.log(`✅ Updated master sheet "${sheetName}" for AWB: ${awbNo}`);
          masterSheetUpdated = true;
          break;
        } catch (error) {
          console.log(`⚠️ Failed to update sheet "${sheetName}":`, error.message);
          continue;
        }
      }

      if (!masterSheetUpdated) {
        console.warn(`❌ Could not update any sheet in master spreadsheet`);
      }
    }

    // Update additional sheets
    if (settings.additionalSheets && settings.additionalSheets.length > 0) {
      for (const sheet of settings.additionalSheets) {
        if (sheet.sheetId && sheet.name) {
          try {
            await updateRecordingSheet(sheet.sheetId, [rowData], sheet.name, organizationId);
            console.log(`✅ Updated additional sheet: ${sheet.name} for AWB: ${awbNo}`);
          } catch (error) {
            console.error(`❌ Failed to update sheet ${sheet.name}:`, error.message);
          }
        }
      }
    }

  } catch (error) {
    console.error('Error updating sheets:', error);
    throw error;
  }
}

// Convenience function with current date
async function uploadToDriveWithCurrentDate(filePath, newFileName, awbNo, organizationId) {
  const now = new Date();
  const year = now.getFullYear().toString();
  const month = now.getMonth() + 1;
  const day = now.getDate();

  const result = await uploadToDriveReal(filePath, newFileName, year, month, day, awbNo, organizationId);
  return result;
}

// Test connection for organization
async function testDriveConnection(organizationId) {
  try {
    const settings = organizationSettings.get(organizationId);
    if (!settings) {
      throw new Error(`No settings found for organization: ${organizationId}`);
    }

    const drive = await getOrganizationDrive(organizationId);
    const sheets = await getOrganizationSheets(organizationId);

    // Test Drive access
    const driveResult = await drive.files.get({
      fileId: settings.rootFolderId,
      fields: 'id, name'
    });

    // Test Sheets access
    const sheetsResult = await sheets.spreadsheets.get({
      spreadsheetId: settings.masterSheetId,
      fields: 'spreadsheetId, properties.title'
    });

    return {
      success: true,
      drive: {
        name: driveResult.data.name,
        id: driveResult.data.id
      },
      sheets: {
        title: sheetsResult.data.properties.title,
        id: sheetsResult.data.spreadsheetId
      }
    };

  } catch (error) {
    console.error('Drive connection test failed:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Pre-warm connection for organization
async function prewarmDriveConnection(organizationId = null) {
  try {
    // If no organization ID provided, skip prewarming
    if (!organizationId) {
      console.log('⚠️ Skipping Drive prewarm - no organization specified');
      return;
    }

    const drive = await getOrganizationDrive(organizationId);
    await drive.files.list({
      q: "name='prewarm' and trashed=false",
      fields: "files(id)",
      pageSize: 1,
      supportsAllDrives: true,
      timeout: 5000
    });
    console.log(`🔥 REAL Drive connection pre-warmed for org: ${organizationId}`);
  } catch (error) {
    console.log(`🔥 REAL Drive connection warming completed for org: ${organizationId}`);
  }
}

// Clear cache for organization (useful when settings change)
function clearOrganizationCache(organizationId) {
  // Clear folder cache for this organization
  const keysToDelete = [];
  for (const key of folderCache.keys()) {
    if (key.startsWith(`${organizationId}_`)) {
      keysToDelete.push(key);
    }
  }

  keysToDelete.forEach(key => folderCache.delete(key));

  // Clear settings cache
  organizationSettings.delete(organizationId);

  console.log(`🧹 Cleared cache for organization: ${organizationId}`);
}

module.exports = {
  uploadToDriveReal,
  uploadToDriveWithCurrentDate,
  createFolderStructure,
  detectFileType,
  getMimeType,
  getOrCreateFolderFast,
  ensurePathFast,
  prewarmDriveConnection,
  getMonthName,
  formatDay,
  updateRecordingSheet,
  updateAllSheets,
  testDriveConnection,
  clearOrganizationCache,
  loadOrganizationSettings
};