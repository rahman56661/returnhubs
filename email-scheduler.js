const cron = require('node-cron');
const mongoose = require('mongoose');
const User = require('./models/User');
const InventoryData = require('./models/InventoryData');
const ExcelJS = require('exceljs');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');

// Load environment variables
dotenv.config();
/*
// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/warehouse-db')
    .then(() => console.log('MongoDB connected for email scheduler'))
    .catch((error) => {
        console.error('MongoDB connection error for email scheduler:', error);
    });
*/
// Create email transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Email sending function (updated to support attachments)
async function sendEmail(to, subject, message, attachmentPath = null) {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER || 'noreply@warehouse.com',
            to: Array.isArray(to) ? to.join(', ') : to, // Support multiple recipients
            subject: subject,
            text: message,
            html: `<div style="font-family: Arial, sans-serif; line-height: 1.6;">${message.replace(/\n/g, '<br>')}</div>`
        };

        // Add attachment if provided
        if (attachmentPath) {
            mailOptions.attachments = [
                {
                    filename: 'daily_recordings.xlsx',
                    path: attachmentPath
                }
            ];
        }

        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent successfully to:', to);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        return false;
    }
}

// Function to generate Excel file with only Recordings sheet for ALL users and CURRENT day
async function generateRecordingsExcelFile(tempExcelPath) {
    try {
        console.log('Generating Recordings Excel file for email attachment...');

        // Get current date (start of day)
        const startOfDay = new Date();
        startOfDay.setHours(0, 0, 0, 0);

        // Get end of current day
        const endOfDay = new Date();
        endOfDay.setHours(23, 59, 59, 999);

        // Get all inventory data for ALL users from current day only
        const inventoryData = await InventoryData.find({
            timestamp: {
                $gte: startOfDay,
                $lte: endOfDay
            }
        }).sort({ timestamp: -1 }).populate('userId', 'username');

        // Create Excel workbook
        const workbook = new ExcelJS.Workbook();

        // ===== ONLY RECORDINGS SHEET =====
        const recordingsSheet = workbook.addWorksheet('Recordings');
        recordingsSheet.addRow([
            'AWB No', 'Courier Name', 'Return Type', 'OPS Remarks', 'Channel Name',
            'Order ID', 'Date', 'Operator', 'Google Drive Link', 'Scanned Data',
            'System SKU', 'Physical SKU', 'User Comment'
        ]);

        recordingsSheet.columns = [
            { width: 15 }, { width: 20 }, { width: 15 }, { width: 20 }, { width: 20 },
            { width: 15 }, { width: 25 }, { width: 15 }, { width: 50 }, { width: 30 },
            { width: 15 }, { width: 15 }, { width: 20 }
        ];

        if (inventoryData.length > 0) {
            // Create a map to store AWB data with their media files
            const awbMap = new Map();

            inventoryData.forEach(item => {
                if (!awbMap.has(item.awbNo)) {
                    awbMap.set(item.awbNo, {
                        awbNo: item.awbNo,
                        courierName: item.additionalInfo?.courierName || 'Not specified',
                        returnType: item.additionalInfo?.returnType || 'Not specified',
                        opsRemarks: item.additionalInfo?.opsRemarks || 'Not specified',
                        channelName: item.additionalInfo?.channelName || 'Not specified',
                        orderId: item.orderId || 'Not specified',
                        timestamp: item.timestamp,
                        username: item.userId?.username || 'Unknown',
                        scannedData: '',
                        driveLink: '',
                        systemSku: '',
                        physicalSku: '',
                        userComment: item.additionalInfo?.userComment || ''
                    });
                }
                const awbData = awbMap.get(item.awbNo);

                // ✅ SKU PAIRS PROCESSING - Google Sheet apdiye
                if (item.skuPairs && item.skuPairs.length > 0) {
                    const skuPair = item.skuPairs[0]; // First pair only for email report
                    awbData.systemSku = skuPair.systemSku || 'N/A';
                    awbData.physicalSku = skuPair.physicalSku || 'N/A';
                } else {
                    awbData.systemSku = 'N/A';
                    awbData.physicalSku = 'N/A';
                }

                // Collect scanned data from all media files
                const scannedDetails = [];
                if (item.categoryData?.good?.eans?.length > 0) {
                    scannedDetails.push(`Good: ${item.categoryData.good.eans.join(', ')}`);
                }
                if (item.categoryData?.bad?.eans?.length > 0) {
                    scannedDetails.push(`Bad: ${item.categoryData.bad.eans.join(', ')}`);
                }
                if (item.categoryData?.used?.eans?.length > 0) {
                    scannedDetails.push(`Used: ${item.categoryData.used.eans.join(', ')}`);
                }
                if (item.categoryData?.wrong?.eans?.length > 0) {
                    scannedDetails.push(`Wrong: ${item.categoryData.wrong.eans.join(', ')}`);
                }

                awbData.scannedData = scannedDetails.join(' | ') || 'None';

                // Find any file that has a folder link
                const folderLink = item.mediaFiles.find(f => f.awbFolderLink)?.awbFolderLink;

                if (folderLink) {
                    awbData.driveLink = folderLink;   // Always use AWB folder link if available
                } else {
                    awbData.driveLink = item.awbFolderLink || (item.mediaFiles[0]?.driveLink || ''); // fallback: file link
                }
            });

            // Add each AWB as a single row
            awbMap.forEach(awbData => {
                const row = recordingsSheet.addRow([
                    awbData.awbNo,
                    awbData.courierName,
                    awbData.returnType,
                    awbData.opsRemarks,
                    awbData.channelName,
                    awbData.orderId,
                    awbData.timestamp.toLocaleString("en-IN", {
                        timeZone: "Asia/Kolkata",
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit'
                    }),
                    awbData.username,
                    '', // Placeholder for hyperlink
                    awbData.scannedData || 'None',
                    awbData.systemSku,
                    awbData.physicalSku,
                    awbData.userComment
                ]);

                // Add clickable hyperlink to Google Drive folder
                if (awbData.driveLink) {
                    const linkCell = recordingsSheet.getCell(`I${row.number}`);
                    linkCell.value = {
                        text: 'Open AWB Folder',
                        hyperlink: awbData.driveLink
                    };
                    linkCell.font = {
                        color: { argb: 'FF0000FF' },
                        underline: true
                    };
                }
            });

        } else {
            recordingsSheet.addRow(['No recording data available for today']);
        }

        // ✅ Format the header row exactly like Google Sheet
        recordingsSheet.getRow(1).font = { bold: true };
        recordingsSheet.getRow(1).fill = {
            type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6E6E6' }
        };

        // ✅ Auto-filter for easy data analysis
        recordingsSheet.autoFilter = {
            from: { row: 1, column: 1 },
            to: { row: recordingsSheet.rowCount, column: 13 } // A to M columns
        };

        console.log('Recordings Excel file generation complete');

        // Save the workbook to file
        const tempDir = path.join(__dirname, 'temp');
        if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

        await workbook.xlsx.writeFile(tempExcelPath);
        return true;
    } catch (error) {
        console.error('Error generating Recordings Excel file:', error);
        return false;
    }
}

// Store active scheduled jobs
const scheduledJobs = new Map();

// Function to schedule emails for a user
function scheduleUserEmails(user) {
    const userId = user._id.toString();

    console.log(`Scheduling email for user ${user.username}`);
    console.log(`- Days: ${user.autoMailDays.join(', ')}`);
    console.log(`- Time: ${user.autoMailTime}`);
    console.log(`- Recipients: ${user.autoMailRecipient.join(', ')}`);
    console.log(`- Enabled: ${user.autoMailEnabled}`);
    console.log(`Server time: ${new Date()}`);
    console.log(`Server timezone: ${Intl.DateTimeFormat().resolvedOptions().timeZone}`);

    if (scheduledJobs.has(userId)) {
        scheduledJobs.get(userId).forEach(job => job.stop());
        scheduledJobs.delete(userId);
    }

    if (!user.autoMailEnabled || !user.autoMailRecipient?.length) {
        console.log(`Skipping scheduling - auto mail disabled or no recipients for user ${user.username}`);
        return;
    }

    const jobs = [];

    user.autoMailDays.forEach(day => {
        const dayMap = { Sunday: 0, Monday: 1, Tuesday: 2, Wednesday: 3, Thursday: 4, Friday: 5, Saturday: 6 };
        const cronDay = dayMap[day];
        if (cronDay === undefined) return;

        const [hours, minutes] = user.autoMailTime.split(':').map(Number);
        const cronSchedule = `${minutes} ${hours} * * ${cronDay}`;

        const job = cron.schedule(cronSchedule, async () => {
            try {
                const now = new Date();
                const tempExcelPath = path.join(__dirname, `temp/daily_recordings_${now.toISOString().split('T')[0]}.xlsx`);

                // Generate Excel file with data from ALL users for CURRENT day only
                const success = await generateRecordingsExcelFile(tempExcelPath);

                if (success) {
                    const emailSubject = `NOBERO-TUP RVP BAD INVENTORY LIST TODAY - ${now.toLocaleDateString()}`;
                    const emailContent = `
<div style="font-family: Arial, sans-serif; line-height: 1.6;">
    Hi Suvakanta,<br><br>
    &nbsp;&nbsp;&nbsp;&nbsp;We have identified bad inventory in RVP.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;The list is below for your reference.<br><br>

    <strong>Report Details:</strong><br>
    - Date: ${now.toLocaleDateString()}<br>
    - Generated at: ${now.toLocaleTimeString()}<br><br>

    The Excel file includes:<br>
    • AWB Numbers with complete details<br>
    • Courier and return information<br>
    • Scanned EAN data with status<br>
    • Google Drive links to media files<br>
    • SKU matching information<br><br>

    <em>This is an automated email. Please do not reply.</em><br><br>

    Regards,
    Returns-Tup,
    Nobero.
</div>
`;
                    await sendEmail(user.autoMailRecipient, emailSubject, emailContent, tempExcelPath);

                    // Clean up temporary file
                    if (fs.existsSync(tempExcelPath)) {
                        fs.unlinkSync(tempExcelPath);
                    }
                } else {
                    console.error('Failed to generate Recordings Excel file for email');
                }
            } catch (error) {
                console.error('Error in scheduled email:', error);
            }
        });

        jobs.push(job);
    });

    scheduledJobs.set(userId, jobs);
    console.log(`Scheduled ${jobs.length} email jobs for user ${user.username}`);
}

// Function to load and schedule all users' emails
async function scheduleAllUsersEmails() {
    try {
        console.log('Loading users with auto email enabled...');
        console.log(`Current server time: ${new Date()}`);

        const users = await User.find({
            autoMailEnabled: true,
            autoMailRecipient: { $exists: true, $ne: [] } // Check for non-empty array
        });

        console.log(`Found ${users.length} users with auto email enabled`);

        users.forEach(user => {
            scheduleUserEmails(user);
        });
    } catch (error) {
        console.error('Error loading users for scheduling:', error);
    }
}

// Function to update scheduling when user settings change
async function updateUserEmailScheduling(userId) {
    try {
        const user = await User.findById(userId);
        if (user) {
            scheduleUserEmails(user);
        }
    } catch (error) {
        console.error('Error updating user email scheduling:', error);
    }
}

// Initial scheduling
scheduleAllUsersEmails();

// Reschedule daily at midnight to catch any changes
cron.schedule('0 0 * * *', () => {
    console.log('Daily rescheduling of email jobs');
    scheduleAllUsersEmails();
});

console.log('Smart email scheduler started...');

// Export for use in other parts of the application
module.exports = {
    scheduleUserEmails,
    updateUserEmailScheduling
};