// check-folder-id.js
const { google } = require('googleapis');
const path = require('path');
require('dotenv').config();

const auth = new google.auth.GoogleAuth({
  keyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS,
  scopes: ['https://www.googleapis.com/auth/drive'],
});

const drive = google.drive({ version: 'v3', auth });

async function checkFolder() {
  try {
    console.log('🔍 Checking folder ID:', process.env.GDRIVE_RETURNS_ID);
    
    const response = await drive.files.get({
      fileId: process.env.GDRIVE_RETURNS_ID,
      fields: 'id, name, parents, mimeType',
      supportsAllDrives: true,
    });
    
    console.log('✅ Folder found:');
    console.log('   Name:', response.data.name);
    console.log('   Type:', response.data.mimeType);
    console.log('   ID:', response.data.id);
    
    // Check if it's in a shared drive
    if (response.data.parents && response.data.parents.length > 0) {
      const parent = await drive.files.get({
        fileId: response.data.parents[0],
        fields: 'name, driveId',
        supportsAllDrives: true,
      });
      console.log('   Parent folder:', parent.data.name);
      if (parent.data.driveId) {
        console.log('   ✅ This is in a Shared Drive!');
      }
    }
    
  } catch (error) {
    console.error('❌ Error checking folder:');
    console.error('   Message:', error.message);
    
    if (error.message.includes('not found')) {
      console.log('\n🔍 The folder ID is incorrect or');
      console.log('   Service account does not have access to this folder');
    }
  }
}

checkFolder();