// googleSheets.js
const { google } = require("googleapis");
const path = require("path");

const auth = new google.auth.GoogleAuth({
  keyFile: path.join(__dirname, "google-credentials.json"), // your service account file
  scopes: [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
  ],
});

// Function to append a new row in Recordings sheet
async function updateRecordingSheet(spreadsheetId, values) {
  const client = await auth.getClient();
  const sheets = google.sheets({ version: "v4", auth: client });

  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: "Recordings!A:J", // change if your sheet range differs
    valueInputOption: "USER_ENTERED",
    requestBody: {
      values: [values],
    },
  });

  console.log("✅ Google Sheet updated successfully");
}

module.exports = { updateRecordingSheet };
