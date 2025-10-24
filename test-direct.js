// test-direct.js
const { google } = require('googleapis');
const serviceAccount = require('./config/service_account.json');

const auth = new google.auth.JWT({
  email: serviceAccount.client_email,
  key: serviceAccount.private_key,
  scopes: ['https://www.googleapis.com/auth/drive']
  // ❌ subject வேண்டாம் - remove it
});

const drive = google.drive({ version: 'v3', auth });

async function testDirect() {
  try {
    console.log('Testing direct access...');
    
    const folder = await drive.files.get({
      fileId: '1wsjMcTSNPnsP3JUNOR7D2OfEwvxeoryW',
      fields: 'id,name,webViewLink'
    });
    
    console.log('✅ SUCCESS:', folder.data.name);
    return true;
  } catch (error) {
    console.log('❌ Error:', error.message);
    return false;
  }
}

testDirect();