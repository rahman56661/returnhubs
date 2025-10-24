const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const path = require('path');
const dotenv = require('dotenv');
const { MongoClient } = require('mongodb');
const client = new MongoClient(process.env.MONGODB_URI || 'mongodb+srv://rahman:rahman123@cluster0.s153gdl.mongodb.net/returnhubs');
const DriveSettings = require('./models/DriveSettings');
const { google } = require('googleapis');
const {
    loadOrganizationSettings,
    ensurePathFast,
    updateAllSheets,
    uploadToDriveReal,
    prewarmDriveConnection
} = require('./drive');
require('dotenv').config();
const bcrypt = require('bcryptjs');
const OrganizationSettings = require('./models/OrganizationSettings');
const authRoutes = require('./routes/auth');
//app.use('/', authRoutes);
const cors = require('cors');
const { initDatabase } = require('./config/database');
const ffmpeg = require('fluent-ffmpeg');
const https = require('https');
const { getOrganizationDB, mainDB } = require('./db-connections');
const fs = require('fs');
const ExcelJS = require('exceljs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const ip = require('ip');
const os = require('os');

const fetch = require('node-fetch');
const morgan = require('morgan');
const MongoStore = require('connect-mongo');
const { updateRecordingSheet } = require("./drive");
const userRoutes = require('./routes/userRoutes');
const recordingProcesses = {};
process.env.TZ = 'Asia/Kolkata'; // Set to your timezone
//const { requireAuth, blockIfRestricted } = require('./middleware/auth');
const { scheduleUserEmails } = require('./email-scheduler');
dotenv.config();
const tempVideoStorage = {};
const tempImageStorage = {};
const activeRecordings = {};
let workingSessionData = {};
const fileLocks = new Map();
const processingFiles = new Set();
const { getMonthName, formatDay, getOrCreateFolderFast } = require("./drive");
// At the top of your app.js file, add this import:
//const { uploadToDriveReal } = require('./drive');
const fse = require('fs-extra');
const MAX_CONCURRENT_PROCESSES = 2;
let activeProcessCount = 0;
const fileUpload = require('express-fileupload');
const driveUploadTimeout = 30000
const passwordResetTokens = {};
const userIdRecoveryTokens = {};


// Add this helper function to app.js (after the imports):
async function prewarmOrganizationDrive(organizationId) {
    try {
        await prewarmDriveConnection(organizationId);
    } catch (error) {
        console.log(`⚠️ Prewarm failed for org ${organizationId}:`, error.message);
    }
}

// SSL certificates
let sslOptions = null;

if (process.env.NODE_ENV !== 'production') {
    try {
        const sslKeyPath = path.join(__dirname, 'localhost-key.pem');
        const sslCertPath = path.join(__dirname, 'localhost.pem');

        if (fs.existsSync(sslKeyPath) && fs.existsSync(sslCertPath)) {
            sslOptions = {
                key: fs.readFileSync(sslKeyPath),
                cert: fs.readFileSync(sslCertPath)
            };
            console.log('🔒 SSL enabled for local development');
        } else {
            console.log('⚠️ SSL certificates not found, using HTTP');
        }
    } catch (err) {
        console.error('⚠️ SSL setup failed:', err.message);
    }
}

// And connect to MongoDB
async function connectDB() {
    try {
        await client.connect();
        console.log('✅ Database client connected');
    } catch (error) {
        console.error('❌ Database connection failed:', error);
    }
}
connectDB();
// Add retry functionality for Google Drive uploads
async function uploadWithRetry(filePath, fileName, year, month, day, awbNo, retries = 3) {
    let lastError;

    for (let i = 0; i < retries; i++) {
        try {
            console.log(`🔄 Upload attempt ${i + 1}/${retries} for ${fileName}`);
            return await uploadToDriveReal(filePath, fileName, year, month, day, awbNo);
        } catch (error) {
            lastError = error;
            console.log(`❌ Upload attempt ${i + 1} failed: ${error.message}`);

            if (i < retries - 1) {
                console.log(`⏳ Retrying in 5 seconds...`);
                await new Promise(resolve => setTimeout(resolve, 5000));
            }
        }
    }

    throw lastError;
}

const app = express();
const port = process.env.PORT || 3000;

app.use(morgan('dev'));
/*
// === Self-signed HTTPS for localhost ===
const options = {
    key: fs.readFileSync('./certs/server.key'),
    cert: fs.readFileSync('./certs/server.crt')
};*/

// --- MJPEG / HTTP Proxy ---
app.get('/video-proxy', async (req, res) => {
    try {
        const camera = req.query.camera;
        const cameraPath = req.query.path || '/video';
        const url = `http://${camera}${cameraPath}`;

        const response = await fetch(url);

        res.setHeader(
            'Content-Type',
            response.headers.get('content-type') || 'multipart/x-mixed-replace'
        );

        response.body.pipe(res); // Works with node-fetch@2
    } catch (err) {
        console.error('Proxy error:', err);
        res.status(500).send('Stream proxy error: ' + err.message);
    }
});


// --- RTSP → HLS Proxy Example (basic) ---
// You can integrate ffmpeg here if you want RTSP → HLS conversion
// frontend will call /rtsp-proxy?url=rtsp://camera_ip/... 
/*
app.get('/api/rtsp-proxy', (req, res) => {
    const rtspUrl = req.query.url;
    // You can launch ffmpeg process to convert RTSP → HLS segments
    // Then return JSON { hlsUrl: '/hls/stream.m3u8' }
   // res.json({ hlsUrl: '/hls/stream.m3u8' }); // placeholder
});*/


// HLS output folder
const streamsDir = path.join(__dirname, 'streams');
if (!fs.existsSync(streamsDir)) {
    fs.mkdirSync(streamsDir);
}

// Set FFmpeg path explicitly for Windows
ffmpeg.setFfmpegPath('C:\\Panther\\Startup_Project\\retutnhubs\\ffmpeg\\bin\\ffmpeg.exe');
ffmpeg.setFfprobePath('C:\\Panther\\Startup_Project\\retutnhubs\\ffmpeg\\bin\\ffprobe.exe');

// Add this after your other middleware
app.use(fileUpload({
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
    abortOnLimit: true,
    responseOnLimit: 'File size limit has been reached'
}));

// Add this helper function for finding images
function findImagesForAwb(awbNo, dateString = null) {
    const images = [];

    try {
        const datesToCheck = [];

        if (dateString) {
            const date = new Date(dateString);
            if (!isNaN(date.getTime())) {
                const year = date.getFullYear();
                const month = String(date.getMonth() + 1).padStart(2, '0');
                const day = String(date.getDate()).padStart(2, '0');
                datesToCheck.push({ year, month, day });
            }
        }

        // Always check today
        const today = new Date();
        const todayObj = {
            year: today.getFullYear(),
            month: String(today.getMonth() + 1).padStart(2, '0'),
            day: String(today.getDate()).padStart(2, '0')
        };
        datesToCheck.push(todayObj);

        console.log(`🔍 Searching images for AWB: ${awbNo}`);

        // Try different folder patterns
        const folderPatterns = [
            awbNo,
            `[${awbNo}]`,
            awbNo.replace(/[^a-zA-Z0-9]/g, '')
        ];

        for (const dateObj of datesToCheck) {
            for (const folderPattern of folderPatterns) {
                const cameraPath = path.join(__dirname, 'camera', dateObj.year.toString(), dateObj.month, dateObj.day, folderPattern);

                console.log(`📂 Checking: ${cameraPath}`);

                if (fs.existsSync(cameraPath)) {
                    console.log(`✅ Found folder: ${cameraPath}`);

                    try {
                        const files = fs.readdirSync(cameraPath);
                        const imageExtensions = ['.jpg', '.jpeg', '.png', '.bmp'];

                        const foundImages = files
                            .filter(file => {
                                const ext = path.extname(file).toLowerCase();
                                return imageExtensions.includes(ext);
                            })
                            .map(file => path.join(cameraPath, file));

                        images.push(...foundImages);

                        if (foundImages.length > 0) {
                            console.log(`🎉 Found ${foundImages.length} images`);
                            break;
                        }
                    } catch (readError) {
                        console.log(`❌ Error reading folder:`, readError.message);
                    }
                }
            }

            if (images.length > 0) break;
        }

        return images;

    } catch (error) {
        console.error(`❌ Error finding images for ${awbNo}:`, error.message);
        return [];
    }
}

// Middleware
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('trust proxy', 1);
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: 'mongodb+srv://rahman:rahman123@cluster0.s153gdl.mongodb.net/returnhubs',
        collectionName: 'sessions',
        ttl: 24 * 60 * 60 // 1 day
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use((req, res, next) => {
    if (req.session && req.session.user) {
        console.log('👤 User Info:', {
            id: req.session.user.id,
            username: req.session.user.username,
            organization: req.session.user.organization,
            organizationId: req.session.user.organizationId
        });
    }
    next();
});

function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        console.log('🔐 Auth Check - Session:', {
            sessionId: req.sessionID,
            userId: req.session.userId,
            username: req.session.username,
            organizationId: req.session.organizationId
        });
        next();
    } else {
        console.log('❌ Unauthorized access attempt');
        res.status(401).json({ error: 'Authentication required' });
    }
}


function getOrganizationId(req) {
    console.log('🔍 DEBUG - Session data:', {
        sessionId: req.sessionID,
        organizationId: req.session.organizationId,
        databaseName: req.session.databaseName,
        user: req.session.user
    });

    // ✅ METHOD 1: Check session organization (MOST IMPORTANT)
    if (req.session && req.session.organizationId) {
        console.log(`✅ Organization from session.organizationId: ${req.session.organizationId}`);
        return req.session.organizationId;
    }

    // ✅ METHOD 2: Check session user organization
    if (req.session && req.session.user && req.session.user.organization) {
        console.log(`✅ Organization from session.user.organization: ${req.session.user.organization}`);
        return req.session.user.organization;
    }

    // ✅ METHOD 3: Check database name from session
    if (req.session && req.session.databaseName) {
        // Extract organization from database name (org_easy_tech_db -> easy_tech)
        const orgFromDb = req.session.databaseName.replace('org_', '').replace('_db', '');
        console.log(`✅ Organization from databaseName: ${orgFromDb}`);
        return orgFromDb;
    }

    // ❌ FALLBACK: Using default (this should not happen)
    console.log('❌ WARNING: Using default organization - Session organization not found!');
    console.log('Session details:', {
        sessionId: req.sessionID,
        organizationId: req.session.organizationId,
        databaseName: req.session.databaseName,
        user: req.session.user
    });
    return 'default';
}

// =============================================================================
// MIDDLEWARE: Session Management - ALLOW MULTIPLE LOGINS
// =============================================================================
/*
const requireAuth = (req, res, next) => {
    if (req.session && req.session.userId) {
        // Session is valid - allow access
        console.log('User authenticated:', req.session.username);
        next();
    } else {
        // User is not logged in, redirect to login page
        console.log('User not authenticated, redirecting to login');
        res.redirect('/login?error=Please login to access this page');
    }
};*/


// =============================================================================
// MIDDLEWARE: Prevent Caching for ALL Responses
// =============================================================================

// Add cleanup for temp images (similar to temp videos)
setInterval(() => {
    const now = Date.now();
    const tempDir = path.join(__dirname, 'temp_images');

    Object.keys(tempImageStorage).forEach(key => {
        const storage = tempImageStorage[key];
        // Remove temp files older than 1 hour
        if (now - storage.timestamp > 3600000) {
            try {
                if (fs.existsSync(storage.tempFile)) {
                    fs.unlinkSync(storage.tempFile);
                    console.log(`Cleaned up expired temp image: ${storage.tempFile}`);
                }
                delete tempImageStorage[key];
            } catch (error) {
                console.error('Error cleaning up temp image:', error);
            }
        }
    });
}, 3600000); // Run every hour

// MongoDB connection
mongoose.connect('mongodb+srv://rahman:rahman123@cluster0.s153gdl.mongodb.net/returnhubs')
    .then(() => console.log('MongoDB connected'))
    .catch((error) => {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    });
prewarmDriveConnection().catch(console.error);
// Import User model
const User = require('./models/User');
// Import InventoryData model
const InventoryData = require('./models/InventoryData');
// After MongoDB connection
initDatabase().then(() => {
    console.log('✅ Multi-org database ready');
}).catch(err => {
    console.error('❌ Multi-org database failed:', err);
});
// 1. DEFAULT TRANSPORTER - Forgot UserID/Password ku
const defaultTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'blackpanther56661@gmail.com',
        pass: process.env.EMAIL_PASS || 'minciymeziqkinzv'
    }
});

// 2. ORGANIZATION TRANSPORTER - User-defined SMTP settings (adhuku separate function)
function getOrganizationTransporter(smtpSettings) {
    return nodemailer.createTransport({
        service: smtpSettings.smtpService || 'gmail',
        auth: {
            user: smtpSettings.smtpEmail,
            pass: smtpSettings.smtpPassword
        }
    });
}

// Helper function to generate random token
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// REAL email sending function
async function sendEmail(to, subject, message) {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER || 'noreply@warehouse.com',
            to: to,
            subject: subject,
            text: message,
            html: `<div style="font-family: Arial, sans-serif; line-height: 1.6;">${message.replace(/\n/g, '<br>')}</div>`
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent successfully to:', to);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        return false;
    }
}



// =============================================================================
// ROUTES (ORDER IS CRITICAL: Define routes BEFORE static files)
// =============================================================================

// ------- PROTECTED ROUTES (Require Login) -------
app.get('/dashboard', requireAuth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.sendFile(path.join(__dirname, 'Public', 'dashboard.html'));
});

// ADD THIS ROUTE FOR SETTINGS PAGE
app.get('/settings', requireAuth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.sendFile(path.join(__dirname, 'Public', 'settings.html'));
});

app.get('/mail-settings', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'mail-settings.html'));
});

function blockIfRestricted(page) {
    return (req, res, next) => {
        if (req.session.role === 'user' && (page === 'usermanagement' || page === 'emailsettings')) {
            return res.status(403).send('Access Denied');
        }
        next();
    };
}
/*
app.get('/usermanagement', requireAuth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.sendFile(path.join(__dirname, 'Public', 'usermanagement.html'));
});*/

app.get('/usermanagement', requireAuth, blockIfRestricted('usermanagement'), (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'usermanagement.html'));
});

// Serve organization registration page
app.get('/organization-register', (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'organization-register.html'));
});

// Serve organizations management page
app.get('/organizations', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'organizations.html'));
});
app.get('/email-settings', requireAuth, blockIfRestricted('emailsettings'), (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'email-settings.html'));
});
/*
// Email settings page route
app.get('/email-settings', requireAuth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.sendFile(path.join(__dirname, 'Public', 'email-settings.html'));
});
*/
app.get('/dashboard/*', requireAuth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.sendFile(path.join(__dirname, 'Public', 'dashboard.html'));
});

app.get('/bad1.html', requireAuth, (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('X-User-Session', req.session.userId);
    res.sendFile(path.join(__dirname, 'Public', 'bad1.html'));
});

app.get('/video-settings.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'video-settings.html'));
});

// Serve drive settings page
app.get('/drive-settings', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'drive-settings.html'));
})

// API endpoint for downloading reports
app.get('/api/reports/:type', requireAuth, async (req, res) => {
    try {
        const { type } = req.params;
        const { fromDate, toDate } = req.query;

        // âœ… GET CURRENT USER'S ORGANIZATION
        const organizationId = getOrganizationId(req);
        console.log(`ðŸ"Š Generating ${type} report for organization: ${organizationId}`);

        // Validate report type
        const validTypes = ['recordings', 'eans', 'summary'];
        if (!validTypes.includes(type)) {
            return res.status(400).json({ success: false, message: 'Invalid report type' });
        }

        // âœ… BUILD DATE FILTER + ORGANIZATION FILTER
        let dateFilter = {
            organization: organizationId  // ADD THIS LINE - CRITICAL!
        };

        if (fromDate && toDate) {
            dateFilter.timestamp = {
                $gte: new Date(fromDate),
                $lte: new Date(toDate)
            };
        }

        console.log('ðŸ" Filter being used:', dateFilter);

        // âœ… FETCH DATA WITH ORGANIZATION FILTER
        const InventoryData = mongoose.model('InventoryData');
        const data = await InventoryData.find(dateFilter).sort({ timestamp: -1 });

        console.log(`âœ… Found ${data.length} records for organization ${organizationId}`);

        const workbook = new ExcelJS.Workbook();

        switch (type) {
            case 'recordings':
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

                if (data.length > 0) {
                    const awbMap = new Map();

                    data.forEach(item => {
                        if (!awbMap.has(item.awbNo)) {
                            awbMap.set(item.awbNo, {
                                awbNo: item.awbNo,
                                courierName: item.additionalInfo?.courierName || 'Not specified',
                                returnType: item.additionalInfo?.returnType || 'Not specified',
                                opsRemarks: item.additionalInfo?.opsRemarks || 'Not specified',
                                channelName: item.additionalInfo?.channelName || 'Not specified',
                                orderId: item.orderId || 'Not specified',
                                timestamp: item.timestamp,
                                username: item.username || 'Unknown',
                                scannedData: '',
                                driveLink: '',
                                systemSku: '',
                                physicalSku: '',
                                userComment: item.additionalInfo?.userComment || ''
                            });
                        }

                        const awbData = awbMap.get(item.awbNo);

                        // SKU PAIRS PROCESSING
                        if (item.skuPairs && item.skuPairs.length > 0) {
                            const skuPair = item.skuPairs[0];
                            awbData.systemSku = skuPair.systemSku || 'N/A';
                            awbData.physicalSku = skuPair.physicalSku || 'N/A';
                        } else {
                            awbData.systemSku = 'N/A';
                            awbData.physicalSku = 'N/A';
                        }

                        // Collect scanned data
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

                        // Find folder link
                        const folderLink = item.mediaFiles.find(f => f.awbFolderLink)?.awbFolderLink;
                        if (folderLink) {
                            awbData.driveLink = folderLink;
                        } else {
                            awbData.driveLink = item.awbFolderLink || (item.mediaFiles[0]?.driveLink || '');
                        }
                    });

                    // Write each AWB row
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
                    recordingsSheet.addRow(['No recording data available']);
                }

                // Header formatting
                recordingsSheet.getRow(1).font = { bold: true };
                recordingsSheet.getRow(1).fill = {
                    type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6E6E6' }
                };
                break;

            case 'eans':
                const eanSheet = workbook.addWorksheet('EAN Details');
                eanSheet.addRow([
                    'AWB No', 'Courier Name', 'Return Type', 'OPS Remarks', 'Channel Name',
                    'EAN', 'Status', 'Date', 'Operator'
                ]);

                if (data.length > 0) {
                    data.forEach(item => {
                        ['good', 'bad', 'used', 'wrong'].forEach(status => {
                            const eanList = item.categoryData[status]?.eans || [];
                            eanList.forEach(ean => {
                                eanSheet.addRow([
                                    item.awbNo,
                                    item.additionalInfo?.courierName || 'Not specified',
                                    item.additionalInfo?.returnType || 'Not specified',
                                    item.additionalInfo?.opsRemarks || 'Not specified',
                                    item.additionalInfo?.channelName || 'Not specified',
                                    ean,
                                    status.charAt(0).toUpperCase() + status.slice(1),
                                    item.timestamp.toLocaleString(),
                                    item.username || 'Unknown'
                                ]);
                            });
                        });
                    });

                    eanSheet.getRow(1).font = { bold: true };
                    eanSheet.getRow(1).fill = {
                        type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6E6E6' }
                    };
                    eanSheet.columns.forEach(column => {
                        column.width = 20;
                    });
                } else {
                    eanSheet.addRow(['No EAN Details Data Available']);
                }
                break;

            case 'summary':
                const summarySheet = workbook.addWorksheet('Summary');
                summarySheet.addRow([
                    'AWB No', 'Courier Name', 'Return Type', 'OPS Remarks', 'Channel Name',
                    'Good', 'Bad', 'Used', 'Wrong', 'Total', 'Date', 'Operator'
                ]);

                summarySheet.columns = [
                    { width: 15 }, { width: 20 }, { width: 15 }, { width: 20 }, { width: 20 },
                    { width: 10 }, { width: 10 }, { width: 10 }, { width: 10 },
                    { width: 10 }, { width: 20 }, { width: 15 }
                ];

                if (data.length > 0) {
                    data.forEach(item => {
                        const total = item.categoryData.good.count + item.categoryData.bad.count +
                            item.categoryData.used.count + item.categoryData.wrong.count;

                        summarySheet.addRow([
                            item.awbNo,
                            item.additionalInfo?.courierName || 'Not specified',
                            item.additionalInfo?.returnType || 'Not specified',
                            item.additionalInfo?.opsRemarks || 'Not specified',
                            item.additionalInfo?.channelName || 'Not specified',
                            item.categoryData.good.count,
                            item.categoryData.bad.count,
                            item.categoryData.used.count,
                            item.categoryData.wrong.count,
                            total,
                            item.timestamp.toLocaleString(),
                            item.username || 'Unknown'
                        ]);
                    });
                } else {
                    summarySheet.addRow(['No Summary Data Available']);
                }

                // Format summary sheet
                summarySheet.getRow(1).font = { bold: true };
                summarySheet.getRow(1).fill = {
                    type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6E6E6' }
                };
                break;
        }

        // Set response headers with organization info
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename=${organizationId}_${type}_${new Date().toISOString().slice(0, 10)}.xlsx`);

        // Send the Excel file
        await workbook.xlsx.write(res);
        res.end();

    } catch (error) {
        console.error('Error generating report:', error);
        res.status(500).json({ success: false, message: 'Error generating report' });
    }
});

app.use('/streams', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    next();
});

app.use('/streams', express.static(streamsDir));
app.use('/api/users', userRoutes);

app.get('/bad1', requireAuth, (req, res) => {
    res.redirect('/bad1.html');
});

// ------- LOGOUT ROUTE -------
// In app.js, update the logout endpoint
app.post('/logout', requireAuth, async (req, res) => {
    try {
        if (req.session.userId && req.session.databaseName) {
            const userId = req.session.userId;
            const databaseName = req.session.databaseName;

            console.log('🔄 Logging out user from database:', databaseName);

            // ✅ SWITCH TO CORRECT ORGANIZATION DATABASE
            const orgDb = mongoose.connection.useDb(databaseName);

            // Define user schema for that database
            const userSchema = new mongoose.Schema({
                username: { type: String, required: true, unique: true },
                email: { type: String, required: true, unique: true },
                password: { type: String, required: true },
                role: { type: String, default: 'user' },
                org_id: { type: String },
                isActive: { type: Boolean, default: true },
                last_login: { type: Date },
                last_logout: { type: Date },
                last_activity: { type: Date },
                login_status: {
                    type: String,
                    enum: ['Logged In', 'Logged Out', 'Never Logged In'],
                    default: 'Never Logged In'
                },
                session_id: { type: String },
                created_at: { type: Date, default: Date.now }
            });

            const OrgUser = orgDb.model('User', userSchema);

            // ✅ UPDATE LAST LOGOUT AND STATUS
            await OrgUser.findByIdAndUpdate(userId, {
                last_logout: new Date(),
                last_activity: new Date(),
                login_status: 'Logged Out',
                session_id: null
            });

            console.log('✅ Logout recorded for user:', req.session.username);
            console.log('✅ Last logout time:', new Date());
        }

        // Destroy session
        req.session.destroy(err => {
            if (err) {
                console.error('Session destruction error:', err);
                return res.status(500).json({ success: false, message: 'Failed logout' });
            }

            res.clearCookie('connect.sid');
            res.json({ success: true, message: 'Logged out successfully' });
        });

    } catch (err) {
        console.error('Logout error:', err);
        res.status(500).json({ success: false, message: 'Logout failed' });
    }
});

// Organization creation la
app.post('/api/create-organization', async (req, res) => {
    try {
        const { orgName, orgId, adminEmail, adminPassword } = req.body;

        // Standardize organization ID
        const standardizedId = orgId.toLowerCase().replace(/[^a-z0-9]/g, '_');
        const databaseName = generateDatabaseName(standardizedId);

        // Check if organization already exists (case-insensitive)
        const existingOrg = await mainDB.collection('organizations').findOne({
            $or: [
                { orgId: standardizedId },
                { orgId: { $regex: new RegExp(`^${standardizedId}$`, 'i') } }
            ]
        });

        if (existingOrg) {
            return res.status(400).json({
                success: false,
                message: `Organization ID '${orgId}' already exists (case-insensitive match)`
            });
        }

        // Check if database already exists
        const dbExists = await checkDatabaseExists(databaseName);
        if (dbExists) {
            return res.status(400).json({
                success: false,
                message: `Database already exists for this organization ID`
            });
        }

        // Create organization with standardized ID
        const newOrganization = {
            orgName: orgName,
            orgId: standardizedId, // Store standardized ID
            databaseName: databaseName,
            adminEmail: adminEmail,
            createdAt: new Date(),
            status: 'active'
        };

        await mainDB.collection('organizations').insertOne(newOrganization);

        // Create database connection (this will create the database)
        const orgDB = await getOrganizationDB(standardizedId);

        // Setup collections in the new organization database
        await setupOrganizationCollections(orgDB);

        // Create admin user in the organization database
        await createAdminUser(orgDB, adminEmail, adminPassword, orgName);

        res.json({
            success: true,
            message: 'Organization created successfully',
            organization: {
                orgName: orgName,
                orgId: standardizedId,
                databaseName: databaseName
            }
        });

    } catch (error) {
        console.error('Organization creation error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/get-mail-settings', async (req, res) => {
    try {
        const userOrganization = req.user.organization; // From session

        // Use standardized organization ID
        const standardizedId = userOrganization.toLowerCase().replace(/[^a-z0-9]/g, '_');
        const orgDB = await getOrganizationDB(standardizedId);

        const settings = await orgDB.collection('mail_settings').findOne({});

        res.json({
            success: true,
            settings: settings || {}
        });

    } catch (error) {
        console.error('Error fetching mail settings:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Import Organization model
const Organization = require('./models/Organization');

// Register new organization - CORRECTED VERSION
app.post('/api/organizations/register', async (req, res) => {
    try {
        const {
            organizationName,
            displayName,
            organizationId,
            description,
            contactEmail,
            phone,
            adminUsername,
            adminEmail,
            adminPassword
        } = req.body;

        console.log('🏢 Creating organization:', {
            organizationName,
            displayName,
            organizationId,
            status: 'active'
        });



        // Validate required fields
        if (!organizationName || !displayName || !organizationId || !contactEmail ||
            !adminUsername || !adminEmail || !adminPassword) {
            return res.status(400).json({
                success: false,
                message: 'All required fields must be provided'
            });
        }

        // ✅ FIX: Correct field names in query
        const existingOrg = await Organization.findOne({
            $or: [
                { organizationName: organizationName }, // CHANGED: name -> organizationName
                { organizationId: organizationId }
            ]
        });

        if (existingOrg) {
            return res.status(400).json({
                success: false,
                message: 'Organization name or ID already exists'
            });
        }

        // ✅ FIX: Database name manually set pannu
        const databaseName = `org_${organizationId.toLowerCase().replace(/[^a-z0-9]/g, '_')}_db`;

        // ✅ FIX: Correct field names in organization creation
        const organization = new Organization({
            organizationName: organizationName,        // CHANGED: name -> organizationName
            displayName: displayName,
            organizationId: organizationId,
            description: description,
            contactEmail: contactEmail,
            phone: phone,
            databaseName: databaseName,
            status: 'active',                          // ✅ ADDED: Status field
            createdBy: req.session.userId || null
        });

        await organization.save();
        console.log('✅ Organization created in MAIN DB:', organization.organizationId);

        // ✅ CRITICAL FIX: Switch to NEW ORGANIZATION DATABASE
        const orgDb = mongoose.connection.useDb(databaseName, { useCache: true });

        // Create user schema for new organization database
        const userSchema = new mongoose.Schema({
            username: { type: String, required: true, unique: true },
            email: { type: String, required: true, unique: true },
            password: { type: String, required: true },
            role: { type: String, default: 'admin' },  // CHANGED: orgadmin -> admin
            organization: { type: String, default: organizationId },
            isActive: { type: Boolean, default: true },
            lastLogin: { type: Date },
            createdAt: { type: Date, default: Date.now },
            last_activity: { type: Date },
            login_status: { type: String, default: 'Logged Out' },
            session_id: { type: String }
        });

        // Check if model already exists
        let OrgUser;
        if (orgDb.models.User) {
            OrgUser = orgDb.models.User;
        } else {
            OrgUser = orgDb.model('User', userSchema);
        }

        // ✅ CRITICAL FIX: Create admin user in ORGANIZATION DATABASE
        const bcrypt = require('bcryptjs');
        const hashedPassword = await bcrypt.hash(adminPassword, 12);

        const adminUser = new OrgUser({
            username: adminUsername,
            email: adminEmail,
            password: hashedPassword,
            role: 'admin',  // CHANGED: orgadmin -> admin
            organization: organizationId,
            isActive: true,
            createdAt: new Date()
        });

        await adminUser.save();
        console.log('✅ Admin user created in ORGANIZATION DB:', adminUsername);

        // Get current super admin's details from default organization
        const defaultOrgDb = mongoose.connection.useDb('org_default_db', { useCache: true });
        const DefaultUser = defaultOrgDb.model('User', userSchema);

        const currentSuperAdmin = await DefaultUser.findOne({ username: 'rahman' });

        if (currentSuperAdmin) {
            // Create super admin account in NEW organization with same credentials
            const superAdminUser = new OrgUser({
                username: currentSuperAdmin.username, // "rahman"
                email: currentSuperAdmin.email, // "habeburrahman2003@gmail.com"
                password: currentSuperAdmin.password, // Same hashed password
                role: 'super_admin',
                organization: organizationId,
                isActive: true,
                createdAt: new Date()
            });

            await superAdminUser.save();
            console.log('✅✅ SUPER ADMIN account copied to new organization:', currentSuperAdmin.username);
        } else {
            // Fallback: Create default super admin account
            const superAdminUser = new OrgUser({
                username: 'rahman',
                email: 'habeburrahman2003@gmail.com',
                password: await bcrypt.hash('rahman123', 12), // Default password
                role: 'super_admin',
                organization: organizationId,
                isActive: true,
                createdAt: new Date()
            });

            await superAdminUser.save();
            console.log('✅✅ Default SUPER ADMIN account created in new organization');
        }

        // ✅ FIX: Send proper response
        res.json({
            success: true,
            message: 'Organization created successfully',
            organization: {
                id: organization._id,
                organizationName: organization.organizationName,
                displayName: organization.displayName,
                organizationId: organization.organizationId,
                databaseName: organization.databaseName,
                status: organization.status
            },
            adminUser: {
                id: adminUser._id,
                username: adminUser.username,
                email: adminUser.email,
                role: adminUser.role
            },
            superAdminUser: {
                username: currentSuperAdmin ? currentSuperAdmin.username : 'rahman',
                email: currentSuperAdmin ? currentSuperAdmin.email : 'habeburrahman2003@gmail.com',
                role: 'super_admin',
                note: 'Same credentials as default organization'
            }
        });

    } catch (error) {
        console.error('❌ Organization registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Error creating organization: ' + error.message
        });
    }
});

// Delete organization route
app.delete('/api/organizations/:orgId', requireAuth, async (req, res) => {
    try {
        const orgId = req.params.orgId;
        const currentUserRole = req.session.userRole;

        console.log('🗑️ Delete organization request:', orgId);

        // ✅ Only super admin can delete organizations
        if (currentUserRole !== 'super_admin') {
            return res.status(403).json({
                success: false,
                message: 'Only super administrators can delete organizations'
            });
        }

        // ✅ Find organization
        const organization = await Organization.findById(orgId);
        if (!organization) {
            return res.status(404).json({
                success: false,
                message: 'Organization not found'
            });
        }

        console.log('🔍 Organization to delete:', organization.organizationName);

        // ✅ PREVENT DELETING DEFAULT ORGANIZATION
        if (organization.organizationId === 'default') {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete default organization'
            });
        }

        // ✅ STEP 1: Delete organization database
        const databaseName = organization.databaseName;
        if (databaseName) {
            try {
                const orgDb = mongoose.connection.useDb(databaseName);

                // Drop all collections in the organization database
                const collections = await orgDb.db.listCollections().toArray();
                for (let collection of collections) {
                    await orgDb.db.dropCollection(collection.name);
                    console.log(`✅ Dropped collection: ${collection.name}`);
                }

                console.log(`✅ Organization database dropped: ${databaseName}`);
            } catch (dbError) {
                console.error('⚠️ Database drop error (might not exist):', dbError.message);
            }
        }

        // ✅ STEP 2: Delete organization from main database
        await Organization.findByIdAndDelete(orgId);
        console.log(`✅ Organization deleted from main DB: ${organization.organizationName}`);

        res.json({
            success: true,
            message: `Organization "${organization.displayName}" deleted successfully`
        });

    } catch (error) {
        console.error('❌ Organization deletion error:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting organization: ' + error.message
        });
    }
});

// Get all organizations for super admin
app.get('/api/organizations/all', async (req, res) => {
    try {
        const organizations = await Organization.find({ isActive: true })
            .select('organizationId organizationName displayName databaseName isActive');

        res.json({
            success: true,
            organizations: organizations
        });
    } catch (error) {
        console.error('Error fetching organizations:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch organizations'
        });
    }
});

// Super admin verification endpoint
app.post('/verify-superadmin', async (req, res) => {
    const { superadminPassword } = req.body;

    try {
        // Check super admin password (you can store this in environment variables)
        const validSuperAdminPassword = process.env.SUPER_ADMIN_ACCESS_PASSWORD || 'superadmin123';

        if (superadminPassword !== validSuperAdminPassword) {
            return res.json({
                success: false,
                message: 'Invalid super admin access password'
            });
        }

        res.json({
            success: true,
            message: 'Super admin access granted'
        });

    } catch (error) {
        console.error('Super admin verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during verification'
        });
    }
});

// app.js la add pannu
// Get specific organization details with users
app.get('/api/organizations/:id/users', requireAuth, async (req, res) => {
    try {
        const orgId = req.params.id;

        // Organization details get pannu
        const organization = await Organization.findById(orgId);
        if (!organization) {
            return res.status(404).json({
                success: false,
                message: 'Organization not found'
            });
        }

        // Switch to organization database
        const orgDb = mongoose.connection.useDb(organization.databaseName);

        // Define user schema
        const userSchema = new mongoose.Schema({
            username: String,
            email: String,
            password: String,
            role: String,
            org_id: String,
            isActive: Boolean,
            last_login: Date,
            last_logout: Date,
            login_status: String,
            created_at: Date
        });

        const OrgUser = orgDb.model('User', userSchema);

        // Get all users from organization database
        const users = await OrgUser.find({})
            .select('username email role isActive last_login created_at')
            .sort({ created_at: -1 });

        console.log(`✅ Found ${users.length} users in organization: ${organization.organizationName}`);

        res.json({
            success: true,
            users: users,
            organization: {
                id: organization._id,
                organizationName: organization.organizationName,
                displayName: organization.displayName,
                organizationId: organization.organizationId,
                databaseName: organization.databaseName,
                contactEmail: organization.contactEmail,
                phone: organization.phone,
                isActive: organization.isActive,
                createdAt: organization.createdAt
            }
        });

    } catch (error) {
        console.error('Error fetching organization users:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching organization users: ' + error.message
        });
    }
});

// Public API - login page ku organizations list
app.get('/api/organizations/Public', async (req, res) => {
    try {
        console.log('🔍 Fetching organizations for login page...');

        // Temporary: All organizations ah eduthuko (status filter pannama)
        const organizations = await Organization.find({})
            .select('organizationId displayName organizationName description')
            .sort({ displayName: 1 });

        console.log('📋 Organizations found:', organizations.length);
        organizations.forEach(org => {
            console.log(`- ${org.organizationId}: ${org.displayName} (status: ${org.status})`);
        });

        res.json({
            success: true,
            organizations: organizations
        });
    } catch (error) {
        console.error('Error fetching organizations:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching organizations'
        });
    }
});

// Get all organizations (for super admin)
app.get('/api/organizations', requireAuth, async (req, res) => {
    try {
        const organizations = await Organization.find({})
            .populate('createdBy', 'username')
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            organizations: organizations
        });
    } catch (error) {
        console.error('Error fetching organizations:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching organizations'
        });
    }
});

// Get specific organization details
app.get('/api/organizations/:id', requireAuth, async (req, res) => {
    try {
        const organization = await Organization.findById(req.params.id)
            .populate('createdBy', 'username');

        if (!organization) {
            return res.status(404).json({
                success: false,
                message: 'Organization not found'
            });
        }

        res.json({
            success: true,
            organization: organization
        });
    } catch (error) {
        console.error('Error fetching organization:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching organization'
        });
    }
});

// Additional stats API route
app.get('/api/organizations/:id/stats', requireAuth, async (req, res) => {
    try {
        const orgId = req.params.id;
        const organization = await Organization.findById(orgId);

        const orgDb = mongoose.connection.useDb(organization.databaseName);

        // User count
        const userCount = await orgDb.collection('users').countDocuments();

        // Active users count
        const activeUserCount = await orgDb.collection('users').countDocuments({ isActive: true });

        // Last activity
        const lastActiveUser = await orgDb.collection('users')
            .find({ last_login: { $exists: true } })
            .sort({ last_login: -1 })
            .limit(1)
            .toArray();

        res.json({
            success: true,
            stats: {
                totalUsers: userCount,
                activeUsers: activeUserCount,
                lastActivity: lastActiveUser[0]?.last_login || null,
                databaseSize: 'N/A' // Can add actual size calculation
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Update organization
app.put('/api/organizations/:id', requireAuth, async (req, res) => {
    try {
        const { displayName, description, contactEmail, phone, isActive } = req.body;

        const organization = await Organization.findByIdAndUpdate(
            req.params.id,
            {
                displayName,
                description,
                contactEmail,
                phone,
                isActive
            },
            { new: true }
        );

        if (!organization) {
            return res.status(404).json({
                success: false,
                message: 'Organization not found'
            });
        }

        res.json({
            success: true,
            message: 'Organization updated successfully',
            organization: organization
        });
    } catch (error) {
        console.error('Error updating organization:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating organization'
        });
    }
});

app.post('/api/heartbeat', requireAuth, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.session.userId, {
            lastActivity: new Date()
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// ------- PUBLIC ROUTES (No Login Required) -------
app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'signup.html'));
});

// ADD SETTINGS TO PUBLIC ROUTES (but it will still require auth via requireAuth middleware)
app.get('/settings', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'settings.html'));
});

// Serve the reports page
app.get('/reports', (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'reports.html'));
});

// app.js la route add pannu
app.get('/organization-details', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'organization-details.html'));
});

app.get('/forgot-userid', (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'forgot-userid.html'));
});

app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'Public', 'forgot-password.html'));
});

app.get('/reset-password', (req, res) => {
    const { token } = req.query;

    if (!token || !passwordResetTokens[token]) {
        return res.send(`
            <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
                <h2>Invalid Reset Link</h2>
                <p>This password reset link is invalid or has expired.</p>
                <a href="/forgot-password" style="color: #3498db;">Request a new password reset</a>
            </div>
        `);
    }

    if (passwordResetTokens[token].expires < Date.now()) {
        delete passwordResetTokens[token];
        return res.send(`
            <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
                <h2>Expired Reset Link</h2>
                <p>This password reset link has expired.</p>
                <a href="/forgot-password" style="color: #3498db;">Request a new password reset</a>
            </div>
        `);
    }

    res.sendFile(path.join(__dirname, 'Public', 'reset-password.html'));
});

// ------- SERVE STATIC FILES (PUBLIC FOLDER) -------
app.use(express.static('Public', {
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
    }
}));

// =============================================================================
// API ROUTES
// =============================================================================
app.post('/login', async (req, res) => {
    console.log('Full request body:', req.body);
    const { username, password, organization } = req.body; // ✅ Add organization

    console.log('Login attempt for username:', username, 'Organization:', organization);

    try {
        // ✅ STEP 1: CHECK IF SUPER ADMIN WANTS SPECIFIC ORGANIZATION
        let targetOrganization = null;

        if (organization && organization.trim() !== '') {
            // If organization provided, use that
            targetOrganization = await Organization.findOne({
                organizationId: organization.trim(),
                isActive: true
            });

            if (!targetOrganization) {
                console.log('❌ Selected organization not found:', organization);
                return res.status(400).json({
                    success: false,
                    message: 'Selected organization not found'
                });
            }
            console.log('✅ Using selected organization:', targetOrganization.organizationId);
        }

        // ✅ STEP 2: FIND USER (WITH ORGANIZATION PREFERENCE)
        const allOrganizations = await Organization.find({ isActive: true });
        let userFound = null;
        let targetOrg = null;
        let sourceDatabase = null;

        console.log('🔍 Searching across', allOrganizations.length, 'organizations...');

        // If organization specified, search there first
        if (targetOrganization) {
            const orgDb = mongoose.connection.useDb(targetOrganization.databaseName);

            const userSchema = new mongoose.Schema({
                username: { type: String, required: true, unique: true },
                email: { type: String, required: true, unique: true },
                password: { type: String, required: true },
                role: {
                    type: String,
                    enum: ['super_admin', 'admin', 'user'],
                    default: 'user'
                },
                org_id: { type: String },
                isActive: { type: Boolean, default: true },
                last_login: { type: Date },
                last_logout: { type: Date },
                last_activity: { type: Date },
                login_status: {
                    type: String,
                    enum: ['Logged In', 'Logged Out', 'Never Logged In'],
                    default: 'Never Logged In'
                },
                session_id: { type: String },
                created_at: { type: Date, default: Date.now }
            });

            const OrgUser = orgDb.model('User', userSchema);
            userFound = await OrgUser.findOne({
                username: username.trim(),
                isActive: true
            });

            if (userFound) {
                targetOrg = targetOrganization;
                sourceDatabase = targetOrganization.databaseName;
                console.log('✅ User found in SELECTED organization:', targetOrg.organizationId);
            }
        }

        // If not found in selected org OR no org specified, search all
        if (!userFound) {
            for (const org of allOrganizations) {
                const orgDb = mongoose.connection.useDb(org.databaseName);

                const userSchema = new mongoose.Schema({
                    username: { type: String, required: true, unique: true },
                    email: { type: String, required: true, unique: true },
                    password: { type: String, required: true },
                    role: {
                        type: String,
                        enum: ['super_admin', 'admin', 'user'],
                        default: 'user'
                    },
                    org_id: { type: String },
                    isActive: { type: Boolean, default: true },
                    last_login: { type: Date },
                    last_logout: { type: Date },
                    last_activity: { type: Date },
                    login_status: {
                        type: String,
                        enum: ['Logged In', 'Logged Out', 'Never Logged In'],
                        default: 'Never Logged In'
                    },
                    session_id: { type: String },
                    created_at: { type: Date, default: Date.now }
                });

                const OrgUser = orgDb.model('User', userSchema);
                const user = await OrgUser.findOne({
                    username: username.trim(),
                    isActive: true
                });

                if (user) {
                    userFound = user;
                    targetOrg = org;
                    sourceDatabase = org.databaseName;
                    console.log('✅ User found in organization:', org.organizationId);
                    break;
                }
            }
        }

        // ✅ STEP 3: IF USER NOT FOUND, RETURN ERROR
        if (!userFound) {
            console.log('❌ User not found in any organization:', username);
            return res.status(400).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        // ✅ STEP 4: CHECK PASSWORD
        const bcrypt = require('bcryptjs');
        const isMatch = await bcrypt.compare(password, userFound.password);
        if (!isMatch) {
            console.log('❌ Password does not match');
            return res.status(400).json({
                success: false,
                message: 'Invalid username or password'
            });
        }

        console.log('✅ Password verified for user:', userFound.username);

        // ✅ STEP 5: SUPER ADMIN ORGANIZATION SWITCHING
        if (userFound.role === 'super_admin' && targetOrganization && targetOrg.organizationId !== targetOrganization.organizationId) {
            console.log('🔄 Super admin switching to organization:', targetOrganization.organizationId);

            // Switch to the selected organization
            const selectedOrgDb = mongoose.connection.useDb(targetOrganization.databaseName);
            const SelectedOrgUser = selectedOrgDb.model('User', userSchema);

            // Check if super admin exists in selected org
            let selectedOrgUser = await SelectedOrgUser.findOne({
                username: userFound.username,
                role: 'super_admin'
            });

            if (!selectedOrgUser) {
                // Create super admin in selected organization
                selectedOrgUser = new SelectedOrgUser({
                    username: userFound.username,
                    email: userFound.email,
                    password: userFound.password,
                    role: 'super_admin',
                    org_id: targetOrganization.organizationId,
                    isActive: true,
                    created_at: new Date()
                });
                await selectedOrgUser.save();
                console.log('✅ Super admin auto-created in:', targetOrganization.organizationId);
            }

            // Use the selected organization user
            userFound = selectedOrgUser;
            targetOrg = targetOrganization;
        }

        // ✅ STEP 6: UPDATE LAST LOGIN AND STATUS
        const crypto = require('crypto');
        const sessionId = crypto.randomBytes(16).toString('hex');
        userFound.last_login = new Date();
        userFound.last_activity = new Date();
        userFound.login_status = 'Logged In';
        userFound.session_id = sessionId;
        await userFound.save();

        // ✅ STEP 7: SET SESSION WITH CORRECT ORGANIZATION
        req.session.user = {
            id: userFound._id.toString(),
            username: userFound.username,
            organization: targetOrg.organizationId,
            organizationId: targetOrg.organizationId,
            databaseName: targetOrg.databaseName,
            role: userFound.role,
            sessionId: sessionId,
            loginTime: new Date(),
            lastActivity: new Date()
        };

        // Also set directly in session for easy access
        req.session.userId = userFound._id.toString();
        req.session.username = userFound.username;
        req.session.organizationId = targetOrg.organizationId;
        req.session.databaseName = targetOrg.databaseName;
        req.session.userRole = userFound.role;
        req.session.sessionId = sessionId;
        req.session.loginTime = new Date();
        req.session.lastActivity = new Date();

        console.log('✅ LOGIN SUCCESSFUL - Organization:', {
            userId: req.session.userId,
            username: req.session.username,
            organizationId: req.session.organizationId,
            userRole: req.session.userRole,
            sessionId: req.sessionID
        });

        // Force session save
        req.session.save((err) => {
            if (err) {
                console.error('❌ Session save error:', err);
                return res.status(500).json({
                    success: false,
                    message: 'Session error'
                });
            }

            console.log('✅ Session saved successfully');
            res.json({
                success: true,
                message: 'Login successful!',
                redirectUrl: '/dashboard',
                user: {
                    username: userFound.username,
                    role: userFound.role,
                    organization: targetOrg.organizationId
                }
            });
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during login: ' + error.message
        });
    }
});

app.post('/signup', async (req, res) => {
    const { username, email, password, confirm_password } = req.body;

    console.log('Signup attempt with:', { username, email });

    if (password !== confirm_password) {
        return res.status(400).json({
            success: false,
            message: 'Passwords do not match'
        });
    }

    if (password.length < 6) {
        return res.status(400).json({
            success: false,
            message: 'Password must be at least 6 characters long'
        });
    }

    try {
        const existingUsername = await User.findOne({
            username: { $regex: new RegExp(`^${username}$`, 'i') }
        });
        if (existingUsername) {
            return res.status(400).json({
                success: false,
                message: 'Username is already taken'
            });
        }

        const existingEmail = await User.findOne({
            email: { $regex: new RegExp(`^${email}$`, 'i') }
        });
        if (existingEmail) {
            return res.status(400).json({
                success: false,
                message: 'Email is already registered'
            });
        }

        const newUser = new User({
            username: username,
            email: email,
            password: password
        });

        const savedUser = await newUser.save();
        console.log('User saved successfully:', savedUser);

        res.json({
            success: true,
            message: 'Signup successful! You can now log in with your credentials.',
            redirectUrl: '/login'
        });
    } catch (error) {
        console.error('Error during signup:', error);

        if (error.code === 11000) {
            if (error.keyPattern.username) {
                return res.status(400).json({
                    success: false,
                    message: 'Username is already taken'
                });
            } else if (error.keyPattern.email) {
                return res.status(400).json({
                    success: false,
                    message: 'Email is already registered'
                });
            }
        }

        res.status(500).json({
            success: false,
            message: 'Error saving user data'
        });
    }
});

app.post('/forgot-userid', async (req, res) => {
    const { email } = req.body;

    try {
        console.log(`🔍 Searching for user with email: ${email}`);

        // Search ALL organizations for this email
        const allOrganizations = await Organization.find({ isActive: true });
        let userFound = null;
        let targetOrg = null;

        for (const org of allOrganizations) {
            const orgDb = mongoose.connection.useDb(org.databaseName);

            const userSchema = new mongoose.Schema({
                username: String,
                email: String,
            });

            const OrgUser = orgDb.model('User', userSchema);
            const user = await OrgUser.findOne({
                email: { $regex: new RegExp(`^${email}$`, 'i') }
            });

            if (user) {
                userFound = user;
                targetOrg = org;
                break;
            }
        }

        if (!userFound) {
            // Still return success for security
            return res.json({
                success: true,
                message: `If an account with this email exists, your User ID has been sent.`
            });
        }

        const emailSubject = 'Your User ID Recovery - Returnhubs System';
        const emailMessage = `
Hello,

You requested your User ID for the Returnhubs System.

Your User ID is: ${userFound.username}
Organization: ${targetOrg.displayName}

If you didn't request this information, please ignore this email.

Best regards,
Returnhubs System Team
        `;

        // ✅ USE DEFAULT TRANSPORTER FOR FORGOT USERID
        const mailOptions = {
            from: process.env.EMAIL_USER || 'blackpanther56661@gmail.com',
            to: email,
            subject: emailSubject,
            text: emailMessage,
            html: `<div style="font-family: Arial, sans-serif;">${emailMessage.replace(/\n/g, '<br>')}</div>`
        };

        console.log(`📧 Sending UserID recovery to: ${email}`);
        await defaultTransporter.sendMail(mailOptions);

        res.json({
            success: true,
            message: `Your User ID has been sent to ${email}. Please check your email inbox.`
        });

    } catch (error) {
        console.error('Error in forgot-userid:', error);
        res.status(500).json({
            success: false,
            message: 'Server error occurred. Please try again later.'
        });
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        // Search ALL organizations
        const allOrganizations = await Organization.find({ isActive: true });
        let userFound = null;
        let targetOrg = null;

        for (const org of allOrganizations) {
            const orgDb = mongoose.connection.useDb(org.databaseName);

            const userSchema = new mongoose.Schema({
                username: String,
                email: String,
            });

            const OrgUser = orgDb.model('User', userSchema);
            const user = await OrgUser.findOne({
                email: { $regex: new RegExp(`^${email}$`, 'i') }
            });

            if (user) {
                userFound = user;
                targetOrg = org;
                break;
            }
        }

        if (!userFound) {
            return res.json({
                success: true,
                message: `If an account with this email exists, password reset instructions have been sent.`
            });
        }

        const token = generateToken();
        passwordResetTokens[token] = {
            userId: userFound._id,
            email: userFound.email,
            organizationId: targetOrg.organizationId, // Store org for database access
            expires: Date.now() + 3600000
        };

        const resetLink = `${process.env.CLIENT_BASE_URL || 'http://localhost:3000'}/reset-password?token=${token}`;

        const emailSubject = 'Password Reset Instructions - Returnhubs System';
        const emailMessage = `
Hello ${userFound.username},

You requested to reset your password for the Returnhubs System.

To reset your password, please click on the following link:
${resetLink}

This link will expire in 1 hour.

If you didn't request a password reset, please ignore this email.

Best regards,
Returnhubs System Team
        `;

        // ✅ USE DEFAULT TRANSPORTER FOR FORGOT PASSWORD
        const mailOptions = {
            from: process.env.EMAIL_USER || 'blackpanther56661@gmail.com',
            to: email,
            subject: emailSubject,
            text: emailMessage,
            html: `<div style="font-family: Arial, sans-serif;">${emailMessage.replace(/\n/g, '<br>')}</div>`
        };

        console.log(`📧 Sending password reset to: ${email}`);
        await defaultTransporter.sendMail(mailOptions);

        res.json({
            success: true,
            message: `Password reset instructions have been sent to ${email}. Please check your email inbox.`
        });

    } catch (error) {
        console.error('Error in forgot-password:', error);
        res.status(500).json({
            success: false,
            message: 'Server error occurred. Please try again later.'
        });
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword, confirmPassword } = req.body;

    try {
        if (!token || !passwordResetTokens[token]) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset token.'
            });
        }

        if (passwordResetTokens[token].expires < Date.now()) {
            delete passwordResetTokens[token];
            return res.status(400).json({
                success: false,
                message: 'Reset token has expired. Please request a new password reset.'
            });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Passwords do not match.'
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long.'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await User.findByIdAndUpdate(passwordResetTokens[token].userId, {
            password: hashedPassword
        });

        delete passwordResetTokens[token];

        res.json({
            success: true,
            message: 'Password has been reset successfully! You can now login with your new password.',
            redirectUrl: '/login'
        });

    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({
            success: false,
            message: 'Server error occurred. Please try again later.'
        });
    }
});

// ✅ Helper function to format dates
function formatDate(date) {
    if (!date) return 'Never';

    return new Date(date).toLocaleString('en-IN', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    });
}

// Add this debug route to check session
app.get('/api/debug-session', (req, res) => {
    const orgId = getOrganizationId(req);

    console.log('=== SESSION DEBUG INFO ===');
    console.log('Session ID:', req.sessionID);
    console.log('Session data:', req.session);
    console.log('Detected Organization:', orgId);
    console.log('==========================');

    res.json({
        sessionId: req.sessionID,
        session: req.session,
        detectedOrganization: orgId,
        message: 'Check server console for detailed debug info'
    });
});

// server.js la ADD THIS (before app.listen)
/*
// Fix user status for specific organization
app.get('/api/fix-status/:orgId', requireAuth, async (req, res) => {
    try {
        const orgId = req.params.orgId;
        console.log('🛠️ Fixing status for organization:', orgId);

        const org = await Organization.findOne({ organizationId: orgId });
        if (!org) {
            return res.status(404).json({ error: 'Organization not found' });
        }

        const orgDb = mongoose.connection.useDb(org.databaseName);

        const userSchema = new mongoose.Schema({
            username: String,
            email: String,
            role: String,
            last_login: Date,
            last_logout: Date,
            login_status: String,
            created_at: Date
        });

        const OrgUser = orgDb.model('User', userSchema);

        const users = await OrgUser.find({});
        let updatedCount = 0;

        for (let user of users) {
            let updates = {};

            if (user.last_login && !user.login_status) {
                updates.login_status = 'Logged In';
            } else if (user.last_logout && !user.login_status) {
                updates.login_status = 'Logged Out';
            } else if (!user.login_status) {
                updates.login_status = 'Never Logged In';
            }

            if (Object.keys(updates).length > 0) {
                await OrgUser.findByIdAndUpdate(user._id, updates);
                console.log(`✅ Updated ${user.username}: ${updates.login_status}`);
                updatedCount++;
            }
        }

        res.json({
            success: true,
            message: `Updated ${updatedCount} users in ${orgId}`,
            updated: updatedCount
        });

    } catch (error) {
        console.error('Fix error:', error);
        res.status(500).json({ error: error.message });
    }
});
*/



/*
// server.js la add pannu - Existing users ku status set pannum
app.get('/api/fix-all-users-status', requireAuth, async (req, res) => {
    try {
        const databaseName = req.session.databaseName;
        console.log('🛠️ Fixing users in database:', databaseName);

        const orgDb = mongoose.connection.useDb(databaseName);

        const userSchema = new mongoose.Schema({
            username: String,
            email: String,
            password: String,
            role: String,
            org_id: String,
            isActive: Boolean,
            last_login: Date,
            last_logout: Date,
            login_status: String,
            created_at: Date
        });

        const OrgUser = orgDb.model('User', userSchema);

        const users = await OrgUser.find({});
        let updatedCount = 0;

        for (let user of users) {
            let updates = {};

            // If user has last_login but no status
            if (user.last_login && !user.login_status) {
                updates.login_status = 'Logged In';
                updatedCount++;
            }
            // If user has last_logout but no status  
            else if (user.last_logout && !user.login_status) {
                updates.login_status = 'Logged Out';
                updatedCount++;
            }
            // If no activity data at all
            else if (!user.login_status) {
                updates.login_status = 'Never Logged In';
                updatedCount++;
            }

            if (Object.keys(updates).length > 0) {
                await OrgUser.findByIdAndUpdate(user._id, updates);
                console.log(`✅ Updated ${user.username}:`, updates);
            }
        }

        res.json({
            success: true,
            message: `Updated ${updatedCount} users with status in ${databaseName}`,
            updated: updatedCount
        });

    } catch (error) {
        console.error('Fix error:', error);
        res.status(500).json({ error: error.message });
    }
});*/

// Get drive settings for current organization
app.get('/api/get-drive-settings', requireAuth, async (req, res) => {
    try {
        const organizationId = getOrganizationId(req);
        console.log('🔧 DEBUG: Fetching Drive settings for organization:', organizationId);

        const DriveSettings = require('./models/DriveSettings');
        const settings = await DriveSettings.findOne({ organizationId });

        console.log('🔧 DEBUG: Found Drive settings:', settings);

        res.json({
            success: true,
            settings: settings || null
        });
    } catch (error) {
        console.error('❌ Error fetching drive settings:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching drive settings'
        });
    }
});

// Save drive settings for current organization
app.post('/api/save-drive-settings', requireAuth, async (req, res) => {
    try {
        const organizationId = getOrganizationId(req);
        const {
            serviceAccountEmail,
            privateKey,
            rootFolderId,
            masterSheetId,
            additionalSheets
        } = req.body;

        console.log('🔧 DEBUG: Saving Drive settings for organization:', organizationId);
        console.log('🔧 DEBUG: Request body:', {
            serviceAccountEmail: serviceAccountEmail ? '***SET***' : 'MISSING',
            privateKey: privateKey ? '***SET***' : 'MISSING',
            rootFolderId: rootFolderId ? '***SET***' : 'MISSING',
            masterSheetId: masterSheetId ? '***SET***' : 'MISSING',
            additionalSheetsCount: additionalSheets?.length || 0
        });

        // Validate required fields
        if (!serviceAccountEmail || !privateKey || !rootFolderId || !masterSheetId) {
            console.log('❌ Validation failed: Missing required fields');
            return res.status(400).json({
                success: false,
                message: 'All required fields must be filled'
            });
        }

        const DriveSettings = require('./models/DriveSettings');

        // Save or update settings
        const settings = await DriveSettings.findOneAndUpdate(
            { organizationId },
            {
                organizationId,
                serviceAccountEmail,
                privateKey,
                rootFolderId,
                masterSheetId,
                additionalSheets: additionalSheets || [],
                updatedAt: new Date()
            },
            {
                upsert: true,
                new: true
            }
        );

        console.log('✅ DEBUG: Drive settings saved successfully:', {
            id: settings._id,
            organizationId: settings.organizationId
        });

        // Clear organization cache
        const { clearOrganizationCache } = require('./drive');
        clearOrganizationCache(organizationId);

        res.json({
            success: true,
            message: 'Drive settings saved successfully',
            settings: {
                id: settings._id,
                organizationId: settings.organizationId,
                serviceAccountEmail: settings.serviceAccountEmail,
                rootFolderId: settings.rootFolderId,
                masterSheetId: settings.masterSheetId,
                additionalSheets: settings.additionalSheets
            }
        });

    } catch (error) {
        console.error('❌ Error saving drive settings:', error);
        res.status(500).json({
            success: false,
            message: 'Error saving drive settings: ' + error.message
        });
    }
});

// Test Drive connection with provided settings
app.post('/api/test-drive-connection', requireAuth, async (req, res) => {
    try {
        const organizationId = getOrganizationId(req);
        const {
            serviceAccountEmail,
            privateKey,
            rootFolderId,
            masterSheetId
        } = req.body;

        console.log('🔧 DEBUG: Testing Drive connection for organization:', organizationId);
        console.log('🔧 DEBUG: Test connection data:', {
            serviceAccountEmail: serviceAccountEmail ? '***SET***' : 'MISSING',
            privateKey: privateKey ? '***SET***' : 'MISSING',
            rootFolderId: rootFolderId ? '***SET***' : 'MISSING',
            masterSheetId: masterSheetId ? '***SET***' : 'MISSING'
        });

        if (!serviceAccountEmail || !privateKey || !rootFolderId || !masterSheetId) {
            return res.status(400).json({
                success: false,
                message: 'All settings are required for connection test'
            });
        }

        // Make sure google is imported
        if (typeof google === 'undefined') {
            throw new Error('Google APIs not properly imported');
        }

        // Test Drive connection
        const driveAuth = new google.auth.GoogleAuth({
            credentials: {
                client_email: serviceAccountEmail,
                private_key: privateKey.replace(/\\n/g, '\n'),
            },
            scopes: [
                "https://www.googleapis.com/auth/spreadsheets",
                "https://www.googleapis.com/auth/drive"
            ],
        });

        const testDrive = google.drive({ version: "v3", auth: driveAuth });
        const testSheets = google.sheets({ version: "v4", auth: driveAuth });

        // Test Drive access
        const driveResult = await testDrive.files.get({
            fileId: rootFolderId,
            fields: 'id, name'
        });

        // Test Sheets access - try multiple sheet names
        let sheetsTestSuccessful = false;
        let sheetsResult = null;
        const possibleSheetNames = ["Recordings", "Sheet1", "Sheet 1", "Main", "Data"];

        for (const sheetName of possibleSheetNames) {
            try {
                sheetsResult = await testSheets.spreadsheets.get({
                    spreadsheetId: masterSheetId,
                    fields: 'spreadsheetId, properties.title'
                });
                sheetsTestSuccessful = true;
                console.log(`✅ Sheets connection successful with sheet: ${sheetName}`);
                break;
            } catch (sheetError) {
                console.log(`⚠️ Sheets test failed for "${sheetName}":`, sheetError.message);
                continue;
            }
        }

        if (!sheetsTestSuccessful) {
            return res.status(400).json({
                success: false,
                message: 'Sheets connection failed - please check your Sheet ID and ensure the sheet exists',
                details: 'Tried sheet names: ' + possibleSheetNames.join(', ')
            });
        }

        console.log('✅ DEBUG: Connection test successful:', {
            drive: driveResult.data.name,
            sheets: sheetsResult.data.properties.title
        });

        res.json({
            success: true,
            message: 'All connections successful',
            details: `Drive: ${driveResult.data.name}, Sheets: ${sheetsResult.data.properties.title}`
        });

    } catch (error) {
        console.error('❌ Drive connection test failed:', error);
        res.status(500).json({
            success: false,
            message: 'Connection test failed',
            details: error.message
        });
    }
});

// Quick status check without auth (for testing)
app.get('/api/quick-check', async (req, res) => {
    try {
        // Check default organization
        const orgDb = mongoose.connection.useDb('org_default_db');

        const userSchema = new mongoose.Schema({
            username: String,
            email: String,
            role: String,
            last_login: Date,
            last_logout: Date,
            login_status: String
        });

        const OrgUser = orgDb.model('User', userSchema);

        const users = await OrgUser.find({}).select('username role last_login last_logout login_status');

        res.json({
            success: true,
            users: users
        });

    } catch (error) {
        console.error('Quick check error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add this endpoint to get all users with their details
app.get('/api/users', requireAuth, async (req, res) => {
    try {
        const databaseName = req.session.databaseName;
        console.log('🔍 DEBUG: Fetching users from:', databaseName);

        const orgDb = mongoose.connection.useDb(databaseName);

        // ✅ USE NATIVE MONGODB - NO SCHEMA ISSUES
        const usersCollection = orgDb.collection('users');
        const orgUsers = await usersCollection.find({}).toArray();

        console.log('✅ DEBUG: Found', orgUsers.length, 'users');

        // ✅ FIX: Handle missing fields properly
        const formattedUsers = orgUsers.map(user => {
            console.log('🔍 DEBUG: User:', user.username, '| Status:', user.login_status, '| Last Login:', user.last_login);

            // ✅ CRITICAL: Handle undefined/null values
            const loginStatus = user.login_status || 'Never Logged In';
            const lastLogin = user.last_login;
            const lastLogout = user.last_logout;
            const createdAt = user.created_at;

            let status = 'Never Logged In';
            let lastActivity = 'No Activity';
            let statusIcon = '⚫ ';

            // ✅ DETERMINE STATUS BASED ON ACTUAL DATA
            if (loginStatus === 'Logged In' && lastLogin) {
                status = '🟢 Logged In';
                lastActivity = `Since: ${new Date(lastLogin).toLocaleString('en-IN', {
                    day: '2-digit', month: '2-digit', year: 'numeric',
                    hour: '2-digit', minute: '2-digit', second: '2-digit',
                    hour12: true, timeZone: 'Asia/Kolkata'
                })}`;
            }
            else if (loginStatus === 'Logged Out' && lastLogout) {
                status = '🔴 Logged Out';
                lastActivity = `Last: ${new Date(lastLogout).toLocaleString('en-IN', {
                    day: '2-digit', month: '2-digit', year: 'numeric',
                    hour: '2-digit', minute: '2-digit', second: '2-digit',
                    hour12: true, timeZone: 'Asia/Kolkata'
                })}`;
            }
            else if (lastLogin && !lastLogout) {
                // If has last_login but no status, assume logged in
                status = '🟢 Logged In';
                lastActivity = `Since: ${new Date(lastLogin).toLocaleString('en-IN', {
                    day: '2-digit', month: '2-digit', year: 'numeric',
                    hour: '2-digit', minute: '2-digit', second: '2-digit',
                    hour12: true, timeZone: 'Asia/Kolkata'
                })}`;
            }
            else if (lastLogout) {
                // If has last_logout but no status, assume logged out
                status = '🔴 Logged Out';
                lastActivity = `Last: ${new Date(lastLogout).toLocaleString('en-IN', {
                    day: '2-digit', month: '2-digit', year: 'numeric',
                    hour: '2-digit', minute: '2-digit', second: '2-digit',
                    hour12: true, timeZone: 'Asia/Kolkata'
                })}`;
            }
            else {
                // No activity data
                status = '⚫ Never Logged In';
                lastActivity = createdAt ? `Created: ${new Date(createdAt).toLocaleDateString('en-IN')}` : 'No Activity';
            }

            console.log('✅ DEBUG: Formatted:', user.username, 'as', status);

            return {
                _id: user._id.toString(),
                username: user.username,
                email: user.email,
                role: user.role,
                status: status,  // ✅ This will have the icon + text
                lastActivity: lastActivity
            };
        });

        console.log('📤 DEBUG: Sending', formattedUsers.length, 'users to frontend');

        res.json({
            success: true,
            users: formattedUsers
        });

    } catch (err) {
        console.error('❌ DEBUG: Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});


// ✅ REAL-TIME USER STATUS API
app.get('/api/users/status', requireAuth, async (req, res) => {
    try {
        const databaseName = req.session.databaseName;
        console.log('🔍 Fetching REAL-TIME users from:', databaseName);

        const orgDb = mongoose.connection.useDb(databaseName);

        // ✅ USE NATIVE MONGODB FOR BETTER PERFORMANCE
        const usersCollection = orgDb.collection('users');
        const orgUsers = await usersCollection.find({}).toArray();

        console.log('✅ REAL-TIME: Found', orgUsers.length, 'users');

        // ✅ ENHANCED STATUS CALCULATION
        const formattedUsers = orgUsers.map(user => {
            // ✅ DETERMINE CURRENT STATUS
            let status = 'Never Logged In';
            let statusIcon = '⚫ ';
            let lastActivity = 'No Activity';

            // ✅ CHECK IF USER IS CURRENTLY LOGGED IN
            if (user.login_status === 'Logged In' && user.session_id) {
                status = '🟢 Logged In';
                statusIcon = '🟢 ';
                lastActivity = user.last_activity ?
                    `Active: ${formatDate(user.last_activity)}` :
                    `Since: ${formatDate(user.last_login)}`;
            }
            // ✅ CHECK IF USER LOGGED OUT
            else if (user.login_status === 'Logged Out' && user.last_logout) {
                status = '🔴 Logged Out';
                statusIcon = '🔴 ';
                lastActivity = `Last: ${formatDate(user.last_logout)}`;
            }
            // ✅ CHECK IF NEVER LOGGED IN
            else if (!user.last_login) {
                status = '⚫ Never Logged In';
                statusIcon = '⚫ ';
                lastActivity = 'Not logged in yet';
            }
            // ✅ FALLBACK: HAS LOGIN BUT NO CLEAR STATUS
            else if (user.last_login) {
                status = '🔴 Logged Out'; // Assume logged out
                statusIcon = '🔴 ';
                lastActivity = `Last: ${formatDate(user.last_login)}`;
            }

            return {
                _id: user._id.toString(),
                username: user.username,
                email: user.email,
                role: user.role,
                status: status,
                lastActivity: lastActivity,
                isCurrentUser: user.username === req.session.username // ✅ Highlight current user
            };
        });

        res.json({
            success: true,
            users: formattedUsers,
            timestamp: new Date().toISOString()
        });

    } catch (err) {
        console.error('❌ REAL-TIME Status Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ✅ HELPER FUNCTION FOR DATE FORMATTING
function formatDate(date) {
    if (!date) return 'Never';

    return new Date(date).toLocaleString('en-IN', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
        timeZone: 'Asia/Kolkata'
    });
}


// ✅ ACTIVITY HEARTBEAT - Update user's last activity
app.post('/api/activity-heartbeat', requireAuth, async (req, res) => {
    try {
        const databaseName = req.session.databaseName;
        const userId = req.session.userId;

        const orgDb = mongoose.connection.useDb(databaseName);
        const usersCollection = orgDb.collection('users');

        // ✅ UPDATE LAST ACTIVITY TIMESTAMP
        await usersCollection.updateOne(
            { _id: new require('mongodb').ObjectId(userId) },
            {
                $set: {
                    last_activity: new Date(),
                    login_status: 'Logged In' // Ensure status is logged in
                }
            }
        );

        res.json({ success: true, message: 'Activity updated' });
    } catch (err) {
        console.error('Heartbeat error:', err);
        res.json({ success: false }); // Don't break frontend on error
    }
});

// ADD THIS ENDPOINT TO GET DETAILED USER INFO
app.get('/api/get-user-details', requireAuth, async (req, res) => {
    try {
        console.log('✅ Get user details API called');
        console.log('Session userId:', req.session.userId);
        console.log('Organization:', req.session.organizationId);

        if (!req.session.userId) {
            return res.json({ success: false, message: 'Not logged in' });
        }

        // 🔥 MULTI-ORG FIX: Get organization database and register User model
        const orgDb = mongoose.connection.useDb(`org_${req.session.organizationId}_db`);

        // Check if User model already registered, if not register it
        let OrgUser;
        if (!orgDb.models.User) {
            // Use the same User schema as your main application
            const userSchema = new mongoose.Schema({
                username: { type: String, required: true, unique: true },
                email: { type: String, required: true, unique: true },
                password: { type: String, required: true },
                role: { type: String, default: 'user' },
                createdAt: { type: Date, default: Date.now },
                updatedAt: { type: Date, default: Date.now }
            });

            OrgUser = orgDb.model('User', userSchema);
        } else {
            OrgUser = orgDb.model('User');
        }

        const user = await OrgUser.findById(req.session.userId);
        console.log('User found:', user ? 'Yes' : 'No');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found in organization database'
            });
        }

        res.json({
            success: true,
            username: user.username,
            email: user.email,
            createdAt: user.createdAt,
            role: user.role
        });
    } catch (error) {
        console.error('❌ Error in get-user-details:', error);
        res.status(500).json({
            success: false,
            message: 'Server error: ' + error.message
        });
    }
});


// Add this endpoint after the existing API routes but before inventory routes
app.get('/api/get-user-info', requireAuth, async (req, res) => {
    try {
        console.log('🔍 DEBUG - Session data:', {
            sessionId: req.sessionID,
            organizationId: req.session.organizationId,
            databaseName: req.session.databaseName,
            user: req.session.user
        });

        // Switch to organization database
        const orgDb = mongoose.connection.useDb(req.session.databaseName);

        const userSchema = new mongoose.Schema({
            username: String,
            email: String,
            role: String,
        }, { collection: 'users' }); // Explicitly specify collection name

        const OrgUser = orgDb.model('User', userSchema);

        const user = await OrgUser.findById(req.session.userId);

        if (user) {
            res.json({
                success: true,
                _id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                organization: req.session.organizationId // Add organization info
            });
        } else {
            res.status(404).json({
                success: false,
                message: 'User not found in organization database'
            });
        }
    } catch (error) {
        console.error('❌ Error in get-user-info:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Get email settings
app.get('/api/get-email-settings', requireAuth, async (req, res) => {
    try {
        const organizationId = req.session.organizationId;
        const db = client.db('org_' + organizationId + '_db');
        const settingsCollection = db.collection('email_settings');

        const settings = await settingsCollection.findOne({});

        console.log('🔍 Loading email settings for org:', organizationId);
        console.log('⏰ Time from database:', settings?.autoMailTime); // DEBUG

        if (settings) {
            res.json({
                success: true,
                autoMailEnabled: settings.autoMailEnabled || false,
                autoMailRecipients: settings.autoMailRecipients || [],
                autoMailTime: settings.autoMailTime || '09:00', // Default fallback
                autoMailDays: settings.autoMailDays || ['Monday', 'Wednesday', 'Friday']
            });
        } else {
            res.json({
                success: true,
                autoMailEnabled: false,
                autoMailRecipients: [],
                autoMailTime: '09:00',
                autoMailDays: ['Monday', 'Wednesday', 'Friday']
            });
        }
    } catch (error) {
        console.error('Error loading email settings:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Get email recipients with names
app.get('/api/get-email-recipients', requireAuth, async (req, res) => {
    try {
        const orgDb = mongoose.connection.useDb(`org_${req.session.organizationId}_db`);

        // Use helper function to get model
        const EmailSetting = getEmailSettingModel(orgDb);

        const settings = await EmailSetting.findOne({ organization: req.session.organizationId });

        if (!settings || !settings.autoMailRecipients) {
            return res.json({ success: true, recipients: [] });
        }

        const recipients = settings.autoMailRecipients.map(recipient => ({
            name: recipient.name,
            email: recipient.email
        }));

        res.json({ success: true, recipients });
    } catch (error) {
        console.error('Error getting recipients:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get mail template
app.get('/api/get-mail-template', requireAuth, async (req, res) => {
    try {
        const orgDb = mongoose.connection.useDb(`org_${req.session.organizationId}_db`);

        // Use helper function to get model
        const MailTemplate = getMailTemplateModel(orgDb);

        let template = await MailTemplate.findOne({ organization: req.session.organizationId });

        if (!template) {
            // Create default template with empty SMTP credentials
            template = {
                subject: 'Daily Inventory Report - {date}',
                salutationField: 'name',
                body: `Please find the attached daily inventory report for {date}.\n\nThis report contains:\n- Current stock levels\n- Low inventory alerts\n- Recent transactions\n\nLet me know if you need any additional information.`,
                signature: `Best regards,\nThank you,\nWarehouse Management Team\n{organization}`,
                smtpEmail: '',
                smtpPassword: '',
                smtpService: 'gmail',
                smtpHost: '',
                smtpPort: 587
            };
            return res.json({ success: true, ...template });
        }

        res.json({ success: true, ...template._doc });
    } catch (error) {
        console.error('Error getting mail template:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Save mail template
app.post('/api/save-mail-template', requireAuth, async (req, res) => {
    try {
        const organizationId = req.session.organizationId;
        const { smtpEmail, smtpPassword, smtpService, smtpHost, smtpPort } = req.body;

        console.log('💾 Saving SMTP settings for org:', organizationId);
        console.log('🔐 SMTP Email:', smtpEmail);

        const db = client.db('org_' + organizationId + '_db');
        const settingsCollection = db.collection('mail_settings');

        // Use update with upsert and specific type
        const result = await settingsCollection.updateOne(
            { type: 'smtp_settings' }, // specific filter
            {
                $set: {
                    type: 'smtp_settings',
                    smtpEmail,
                    smtpPassword,
                    smtpService,
                    smtpHost,
                    smtpPort,
                    updatedAt: new Date()
                }
            },
            { upsert: true } // create if doesn't exist
        );

        console.log('✅ SMTP settings saved:', result);
        res.json({ success: true, message: 'Mail template saved' });

    } catch (error) {
        console.error('❌ Error saving mail template:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/debug-database', async (req, res) => {
    try {
        const organizationId = req.session.organizationId;
        const db = client.db('org_' + organizationId + '_db');

        // Check email settings
        const emailSettings = await db.collection('email_settings').find({}).toArray();
        const mailSettings = await db.collection('mail_settings').find({}).toArray();

        console.log('🔍 DEBUG DATABASE:');
        console.log('📧 Email Settings:', emailSettings);
        console.log('🔐 Mail Settings:', mailSettings);

        res.json({
            emailSettings: emailSettings,
            mailSettings: mailSettings
        });
    } catch (error) {
        console.error('Debug error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ✅ SMTP Test Connection Route - FIXED VERSION
app.post('/api/test-smtp', async (req, res) => {
    let organizationId; // Declare organizationId at function scope

    try {
        organizationId = req.session.organizationId;
        const { email, password, service, host, port } = req.body;

        if (!organizationId) {
            return res.status(400).json({
                success: false,
                message: 'Organization ID not found in session'
            });
        }

        console.log('🔐 Testing SMTP for organization:', organizationId);

        // Use provided credentials or get from database
        const testEmail = email || req.body.smtpEmail;
        const testPassword = password || req.body.smtpPassword;
        const testService = service || req.body.smtpService || 'gmail';

        if (!testEmail || !testPassword) {
            return res.status(400).json({
                success: false,
                message: 'Email and password are required for testing'
            });
        }

        console.log('📧 Testing with:', { email: testEmail, service: testService });

        // Create test transporter
        const testTransporter = nodemailer.createTransport({
            service: testService,
            auth: {
                user: testEmail,
                pass: testPassword
            }
        });

        // Verify connection
        await testTransporter.verify();
        testTransporter.close();

        console.log('✅ SMTP test successful for org:', organizationId);
        res.json({
            success: true,
            message: 'SMTP connection successful!'
        });
    } catch (error) {
        console.error('❌ SMTP test failed for org:', organizationId, 'Error:', error.message);
        res.status(500).json({
            success: false,
            message: 'SMTP test failed: ' + error.message
        });
    }
});

// Add this route to app.js to check email scheduler status
app.get('/api/email-scheduler-status', requireAuth, async (req, res) => {
    try {
        const orgDb = mongoose.connection.useDb(`org_${req.session.organizationId}_db`);

        // Get email settings
        const EmailSetting = getEmailSettingModel(orgDb);
        const settings = await EmailSetting.findOne({ organization: req.session.organizationId });

        // Get mail template
        const MailTemplate = getMailTemplateModel(orgDb);
        const template = await MailTemplate.findOne({ organization: req.session.organizationId });

        const currentTime = new Date();
        const currentDay = currentTime.toLocaleDateString('en-US', { weekday: 'long' });
        const currentHour = currentTime.getHours();
        const currentMinute = currentTime.getMinutes();

        // Parse scheduled time
        const [scheduledHour, scheduledMinute] = (settings?.autoMailTime || '09:00').split(':').map(Number);

        res.json({
            success: true,
            schedulerInfo: {
                currentTime: currentTime.toLocaleString(),
                currentDay: currentDay,
                currentTime24: `${currentHour.toString().padStart(2, '0')}:${currentMinute.toString().padStart(2, '0')}`,
                scheduledTime: settings?.autoMailTime || '09:00',
                isAutoMailEnabled: settings?.autoMailEnabled || false,
                scheduledDays: settings?.autoMailDays || [],
                recipientsCount: settings?.autoMailRecipients?.length || 0,
                hasSmtpCredentials: !!(template?.smtpEmail && template?.smtpPassword),
                isRightDay: settings?.autoMailDays?.includes(currentDay) || false,
                isRightTime: (currentHour === scheduledHour && currentMinute === scheduledMinute),
                shouldSendNow: settings?.autoMailEnabled &&
                    settings?.autoMailDays?.includes(currentDay) &&
                    (currentHour === scheduledHour && currentMinute === scheduledMinute)
            }
        });
    } catch (error) {
        console.error('Error checking scheduler status:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ✅ Send Test Email Route
app.post('/api/send-test-email', async (req, res) => {
    try {
        const organizationId = req.session.organizationId;

        console.log('📧 Sending test email for organization:', organizationId);
        console.log('🔍 DEBUG: client variable exists?', typeof client !== 'undefined');

        if (typeof client === 'undefined') {
            console.log('❌ MongoDB client is not defined!');
            return res.status(500).json({
                success: false,
                message: 'Database connection not available'
            });
        }

        // Get recipient emails from database
        const db = client.db('org_' + organizationId + '_db');
        const settingsCollection = db.collection('email_settings');

        const emailSettings = await settingsCollection.findOne({});
        console.log('🔍 DEBUG: Email settings found:', !!emailSettings);

        let recipientEmail = 'habeburrahman2003@gmail.com'; // default fallback

        if (emailSettings && emailSettings.autoMailRecipients && emailSettings.autoMailRecipients.length > 0) {
            recipientEmail = emailSettings.autoMailRecipients[0].email;
            console.log('📧 Using recipient:', recipientEmail);
        } else {
            console.log('⚠️ No recipients found, using default:', recipientEmail);
        }

        // Get SMTP settings
        const mailSettingsCollection = db.collection('mail_settings');
        const smtpSettings = await mailSettingsCollection.findOne({
            type: 'smtp_settings'
        });

        console.log('🔍 DEBUG: SMTP settings found:', !!smtpSettings);

        if (!smtpSettings) {
            console.log('❌ SMTP settings not found in database');
            return res.status(400).json({
                success: false,
                message: 'SMTP settings not found. Please save your email credentials in Mail Settings first.'
            });
        }

        if (!smtpSettings.smtpEmail || !smtpSettings.smtpPassword) {
            console.log('❌ SMTP credentials incomplete');
            return res.status(400).json({
                success: false,
                message: 'Email credentials not configured. Please enter both sender email and password.'
            });
        }

        console.log('🔐 Using SMTP:', smtpSettings.smtpEmail);

        // Create transporter and send email
        const transporter = nodemailer.createTransport({
            service: smtpSettings.smtpService || 'gmail',
            auth: {
                user: smtpSettings.smtpEmail,
                pass: smtpSettings.smtpPassword
            }
        });

        const mailOptions = {
            from: smtpSettings.smtpEmail,
            to: recipientEmail,
            subject: 'Test Email - Warehouse System',
            text: `This is a test email from ${organizationId}`,
            html: `<h3>Test Email</h3><p>This is a test from organization: <strong>${organizationId}</strong></p>`
        };

        console.log('📤 Attempting to send email to:', recipientEmail);
        const result = await transporter.sendMail(mailOptions);
        transporter.close();

        console.log('✅ Test email sent successfully to:', recipientEmail);
        res.json({
            success: true,
            message: 'Test email sent successfully! Check your inbox.'
        });

    } catch (error) {
        console.error('❌ Error sending test email:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to send test email: ' + error.message
        });
    }
});


// Test Excel generation function
async function generateTestExcel(organizationId) {
    try {
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Test Inventory Report');

        // Add headers
        worksheet.columns = [
            { header: 'Item Name', key: 'name', width: 20 },
            { header: 'Category', key: 'category', width: 15 },
            { header: 'Quantity', key: 'quantity', width: 10 },
            { header: 'Status', key: 'status', width: 15 }
        ];

        // Add test data
        const testData = [
            { name: 'Test Item 1', category: 'Electronics', quantity: 50, status: 'In Stock' },
            { name: 'Test Item 2', category: 'Furniture', quantity: 15, status: 'Low Stock' },
            { name: 'Test Item 3', category: 'Office Supplies', quantity: 200, status: 'In Stock' }
        ];

        testData.forEach(item => {
            worksheet.addRow(item);
        });

        // Return Excel buffer
        return await workbook.xlsx.writeBuffer();
    } catch (error) {
        console.error('Error generating test Excel:', error);
        throw error;
    }
}

// Update your email scheduler function in app.js
function startEmailScheduler() {
    console.log('🕒 Email scheduler started - checking every minute');

    // Check every minute instead of waiting for specific time
    setInterval(async () => {
        try {
            const now = new Date();
            const currentDay = now.toLocaleDateString('en-US', { weekday: 'long' });
            const currentTime = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;

            console.log(`🔍 Email Scheduler Check - ${currentTime} on ${currentDay}`);

            const orgs = await Organization.find({});
            let totalEmailsSent = 0;

            for (const org of orgs) {
                const orgDb = mongoose.connection.useDb(`org_${org._id}_db`);

                // Get email settings
                const EmailSetting = getEmailSettingModel(orgDb);
                const settings = await EmailSetting.findOne({ organization: org._id });

                if (!settings || !settings.autoMailEnabled) {
                    continue;
                }

                // Check if it's the right day and time
                const isRightDay = settings.autoMailDays.includes(currentDay);
                const isRightTime = currentTime === settings.autoMailTime;

                console.log(`📋 Org: ${org._id}, Day: ${currentDay} (${isRightDay}), Time: ${currentTime} (${isRightTime})`);

                if (isRightDay && isRightTime) {
                    // Get mail template
                    const MailTemplate = getMailTemplateModel(orgDb);
                    const template = await MailTemplate.findOne({ organization: org._id });

                    if (!template || !template.smtpEmail || !template.smtpPassword) {
                        console.log(`❌ No SMTP credentials for ${org._id}`);
                        continue;
                    }

                    // Generate Excel file
                    const excelBuffer = await generateOrganizationExcel(org._id);

                    // Send emails
                    for (const recipient of settings.autoMailRecipients) {
                        try {
                            await sendAutoEmail(recipient, template, excelBuffer, org._id);
                            totalEmailsSent++;
                            console.log(`✅ Email sent to ${recipient.email}`);
                        } catch (emailError) {
                            console.error(`❌ Failed to send to ${recipient.email}:`, emailError.message);
                        }
                    }
                }
            }

            if (totalEmailsSent > 0) {
                console.log(`📨 ${totalEmailsSent} emails sent successfully`);
            }

        } catch (error) {
            console.error('❌ Error in email scheduler:', error);
        }
    }, 60000); // Check every 60 seconds (1 minute)
}

function getEmailSettingModel(orgDb) {
    if (!orgDb.models.EmailSetting) {
        const emailSettingSchema = new mongoose.Schema({
            organization: String,
            autoMailEnabled: Boolean,
            autoMailRecipients: [{
                name: String,
                email: String
            }],
            autoMailTime: String,
            autoMailDays: [String],
            updatedAt: { type: Date, default: Date.now }
        });
        return orgDb.model('EmailSetting', emailSettingSchema);
    }
    return orgDb.model('EmailSetting');
}

function getMailTemplateModel(orgDb) {
    if (!orgDb.models.MailTemplate) {
        const mailTemplateSchema = new mongoose.Schema({
            organization: String,
            subject: String,
            salutationField: String,
            body: String,
            signature: String,
            // SMTP credentials
            smtpEmail: String,
            smtpPassword: String,
            smtpService: String,
            smtpHost: String,
            smtpPort: Number,
            updatedAt: { type: Date, default: Date.now }
        });
        return orgDb.model('MailTemplate', mailTemplateSchema);
    }
    return orgDb.model('MailTemplate');
}

async function checkAndSendScheduledEmails() {
    try {
        const currentTime = new Date();
        const currentDay = currentTime.toLocaleDateString('en-US', { weekday: 'long' });
        const currentHour = currentTime.getHours();
        const currentMinute = currentTime.getMinutes();
        const currentTimeString = `${currentHour.toString().padStart(2, '0')}:${currentMinute.toString().padStart(2, '0')}`;

        console.log(`🕒 SCHEDULER CHECK - ${currentTimeString} on ${currentDay}`);

        // ✅ FIX: Get all organizations and check their email settings
        const organizations = await Organization.find({});
        console.log(`🔍 Checking ${organizations.length} organizations`);

        for (const org of organizations) {
            try {
                const orgDb = client.db('org_' + org.organizationId + '_db');
                const emailSettings = await orgDb.collection('email_settings').findOne({});

                if (!emailSettings || !emailSettings.autoMailEnabled) {
                    continue;
                }

                console.log(`📧 Org ${org.organizationId} - Auto email enabled`);

                // Check if it's the right day
                const isRightDay = emailSettings.autoMailDays.includes(currentDay);
                const isRightTime = currentTimeString === emailSettings.autoMailTime;

                console.log(`   Day: ${currentDay} (${isRightDay}), Time: ${currentTimeString} vs ${emailSettings.autoMailTime} (${isRightTime})`);

                if (isRightDay && isRightTime) {
                    console.log(`🚀 TIME TO SEND EMAIL for ${org.organizationId}!`);
                    await sendScheduledEmail(org.organizationId);
                }

            } catch (orgError) {
                console.error(`❌ Error checking org ${org.organizationId}:`, orgError.message);
            }
        }

    } catch (error) {
        console.error('❌ Scheduler error:', error);
    }
}

// Start the scheduler
setInterval(checkAndSendScheduledEmails, 60000); // Check every minute
console.log('✅ Email scheduler started (checking every minute)');

async function sendScheduledEmail(organizationId) {
    try {
        console.log(`📧 SENDING SCHEDULED EMAIL for ${organizationId}`);

        const orgDb = client.db('org_' + organizationId + '_db');

        // Get email settings
        const emailSettings = await orgDb.collection('email_settings').findOne({});
        if (!emailSettings || !emailSettings.autoMailRecipients || emailSettings.autoMailRecipients.length === 0) {
            console.log(`❌ No recipients found for ${organizationId}`);
            return;
        }

        // Get SMTP settings
        const mailSettings = await orgDb.collection('mail_settings').findOne({
            type: 'smtp_settings'
        });

        if (!mailSettings || !mailSettings.smtpEmail || !mailSettings.smtpPassword) {
            console.log(`❌ SMTP settings not found for ${organizationId}`);
            return;
        }

        // ✅ GET MAIL TEMPLATE FROM DATABASE
        const mailTemplate = await orgDb.collection('mail_templates').findOne({});
        console.log('📝 Mail template found:', !!mailTemplate);

        const currentDate = new Date().toLocaleDateString();

        // ✅ USE TEMPLATE FROM DATABASE OR DEFAULT
        const subject = mailTemplate?.subject?.replace(/{date}/g, currentDate) || `Daily Inventory Report - ${currentDate}`;

        let emailBody = mailTemplate?.body?.replace(/{date}/g, currentDate) ||
            `This is your scheduled daily inventory report for ${currentDate} from ${organizationId}.`;

        let emailSignature = mailTemplate?.signature?.replace(/{organization}/g, organizationId) ||
            'Best regards,\nWarehouse Management Team';

        console.log(`✅ Sending email for ${organizationId}`);
        console.log(`   From: ${mailSettings.smtpEmail}`);
        console.log(`   To: ${emailSettings.autoMailRecipients.length} recipients`);
        console.log(`   Subject: ${subject}`);

        // ✅ GENERATE EXCEL FILE FOR ATTACHMENT
        let excelBuffer = null;
        let attachmentFilename = `inventory_report_${currentDate.replace(/\//g, '-')}.xlsx`;

        try {
            excelBuffer = await generateOrganizationExcel(organizationId);
            console.log(`📊 Excel file generated: ${attachmentFilename}`);
        } catch (excelError) {
            console.error('❌ Excel generation failed:', excelError.message);
            // Continue without attachment
        }

        // ✅ ACTUAL EMAIL SENDING
        const transporter = nodemailer.createTransport({
            service: mailSettings.smtpService || 'gmail',
            auth: {
                user: mailSettings.smtpEmail,
                pass: mailSettings.smtpPassword
            }
        });

        // Send to each recipient
        for (const recipient of emailSettings.autoMailRecipients) {
            try {
                // ✅ DETERMINE SALUTATION BASON TEMPLATE SETTING
                let salutation = recipient.name || 'Sir/Madam';
                if (mailTemplate?.salutationField === 'email') {
                    salutation = recipient.email;
                } else if (mailTemplate?.salutationField === 'sir') {
                    salutation = 'Sir/Madam';
                }

                const finalText = `Hi ${salutation},\n\n${emailBody}\n\n${emailSignature}`;
                const finalHtml = `
                    <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                        <h3 style="color: #333;">${subject}</h3>
                        <p>Hi <strong>${salutation}</strong>,</p>
                        <p>${emailBody.replace(/\n/g, '<br>')}</p>
                        <p><strong>Organization:</strong> ${organizationId}</p>
                        <p><strong>Date:</strong> ${currentDate}</p>
                        <br>
                        <p>${emailSignature.replace(/\n/g, '<br>')}</p>
                    </div>
                `;

                const mailOptions = {
                    from: mailSettings.smtpEmail,
                    to: recipient.email,
                    subject: subject,
                    text: finalText,
                    html: finalHtml
                };

                // ✅ ADD EXCEL ATTACHMENT IF AVAILABLE
                if (excelBuffer) {
                    mailOptions.attachments = [
                        {
                            filename: attachmentFilename,
                            content: excelBuffer,
                            contentType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                        }
                    ];
                }

                const result = await transporter.sendMail(mailOptions);
                console.log(`✅ Email sent to ${recipient.email} (${recipient.name}) with ${excelBuffer ? 'attachment' : 'no attachment'}`);

            } catch (emailError) {
                console.error(`❌ Failed to send to ${recipient.email}:`, emailError.message);
            }
        }

        transporter.close();
        console.log(`🎉 ALL EMAILS SENT for ${organizationId}`);

    } catch (error) {
        console.error(`❌ Error sending scheduled email for ${organizationId}:`, error);
    }
}

async function sendAutoEmail(recipient, template, excelBuffer, organizationId) {
    try {
        const currentDate = new Date().toLocaleDateString();

        console.log('🔐 SMTP Details for sending:');
        console.log(' - From Email:', template.smtpEmail);
        console.log(' - To Email:', recipient.email);
        console.log(' - Service:', template.smtpService);

        // Determine salutation
        let salutation = recipient.name || 'Sir/Madam';
        if (template.salutationField === 'email') {
            salutation = recipient.email;
        } else if (template.salutationField === 'sir') {
            salutation = 'Sir/Madam';
        }

        // Replace template variables
        let emailBody = template.body.replace(/{date}/g, currentDate);
        let emailSignature = template.signature.replace(/{organization}/g, organizationId);
        let emailSubject = template.subject.replace(/{date}/g, currentDate);

        const finalContent = `Hi ${salutation},\n\n${emailBody}\n\n${emailSignature}`;

        // Determine SMTP config
        let smtpConfig = {};
        switch (template.smtpService) {
            case 'gmail':
                smtpConfig = {
                    host: 'smtp.gmail.com',
                    port: 587,
                    secure: false,
                    requireTLS: true
                };
                break;
            case 'outlook':
                smtpConfig = {
                    host: 'smtp-mail.outlook.com',
                    port: 587,
                    secure: false,
                    requireTLS: true
                };
                break;
            case 'yahoo':
                smtpConfig = {
                    host: 'smtp.mail.yahoo.com',
                    port: 587,
                    secure: false,
                    requireTLS: true
                };
                break;
            case 'custom':
                smtpConfig = {
                    host: template.smtpHost,
                    port: template.smtpPort || 587,
                    secure: false,
                    requireTLS: true
                };
                break;
            default:
                smtpConfig = {
                    host: 'smtp.gmail.com',
                    port: 587,
                    secure: false,
                    requireTLS: true
                };
        }

        console.log('📤 Attempting to send email...');

        // Send email with organization's SMTP
        await sendEmailWithAttachment(
            recipient.email,          // TO
            emailSubject,            // SUBJECT
            finalContent,            // BODY
            excelBuffer,             // ATTACHMENT
            `inventory_report_${currentDate.replace(/\//g, '-')}.xlsx`, // FILENAME
            template.smtpEmail,      // FROM (SMTP EMAIL) - 🔥 THIS IS IMPORTANT
            template.smtpPassword,   // SMTP PASSWORD - 🔥 THIS IS IMPORTANT
            smtpConfig               // SMTP CONFIG
        );

        console.log(`✅ Email sent to ${recipient.name} using ${template.smtpEmail}`);
        return true;

    } catch (error) {
        console.error(`❌ Failed to send to ${recipient.email}:`, error.message);
        console.error('SMTP Email used:', template.smtpEmail);
        throw error;
    }
}

// Debug route to check exact SMTP values
app.get('/api/debug-smtp-values', requireAuth, async (req, res) => {
    try {
        const orgDb = mongoose.connection.useDb(`org_${req.session.organizationId}_db`);
        const MailTemplate = getMailTemplateModel(orgDb);

        const template = await MailTemplate.findOne({ organization: req.session.organizationId });

        if (!template) {
            return res.json({ success: false, message: 'No mail template found' });
        }

        res.json({
            success: true,
            smtpEmail: template.smtpEmail,
            smtpPassword: template.smtpPassword ? '***' + template.smtpPassword.slice(-3) : 'Not set',
            smtpService: template.smtpService,
            smtpHost: template.smtpHost,
            smtpPort: template.smtpPort
        });
    } catch (error) {
        console.error('Debug SMTP error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

async function sendEmailWithAttachment(to, subject, text, buffer, filename, smtpEmail, smtpPassword, smtpConfig) {
    try {
        const transporter = nodemailer.createTransport({
            ...smtpConfig,
            auth: {
                user: smtpEmail,
                pass: smtpPassword
            }
        });

        const mailOptions = {
            from: smtpEmail,
            to: to,
            subject: subject,
            text: text,
            attachments: [
                {
                    filename: filename,
                    content: buffer,
                    contentType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                }
            ]
        };

        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}

async function generateOrganizationExcel(organizationId) {
    try {
        console.log(`📊 Generating Excel for organization: ${organizationId} from MAIN database - TODAY ONLY`);

        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);

        // Get data from MAIN database
        const InventoryData = mongoose.model('InventoryData');
        const todayData = await InventoryData.find({
            organization: organizationId,
            $or: [
                { createdAt: { $gte: today, $lt: tomorrow } },
                { timestamp: { $gte: today, $lt: tomorrow } }
            ]
        }).sort({ createdAt: -1 });

        console.log(`📋 Found ${todayData.length} records for TODAY`);

        const workbook = new ExcelJS.Workbook();
        const recordingsSheet = workbook.addWorksheet('Recordings');

        recordingsSheet.addRow([
            'AWB No', 'Courier Name', 'Return Type', 'OPS Remarks', 'Channel Name',
            'Order Id', 'Date', 'Operator', 'Google Drive Link', 'Scanned Data', 'System Sku', 'Physical Sku', 'User Comment'
        ]);

        if (todayData.length > 0) {
            todayData.forEach((item, index) => {
                // Scanned Data Summary
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

                const scannedData = scannedDetails.join(' | ') || 'None';
                const skuPair = item.skuPairs && item.skuPairs.length > 0 ? item.skuPairs[0] : {};
                const recordDate = item.timestamp || item.createdAt || new Date();

                // ✅ FIX: Get actual Google Drive folder link
                let driveLink = '';
                let linkText = 'No Folder';

                if (item.awbFolderLink) {
                    driveLink = item.awbFolderLink;
                    linkText = 'Open AWB Folder';
                } else if (item.mediaFiles && item.mediaFiles.length > 0) {
                    // Try to get from media files
                    const folderLink = item.mediaFiles.find(f => f.awbFolderLink)?.awbFolderLink;
                    if (folderLink) {
                        driveLink = folderLink;
                        linkText = 'Open AWB Folder';
                    } else {
                        // Fallback to file link
                        const fileLink = item.mediaFiles[0]?.driveLink;
                        if (fileLink) {
                            driveLink = fileLink;
                            linkText = 'Open File';
                        }
                    }
                }

                // Add row data
                const row = recordingsSheet.addRow([
                    item.awbNo || 'N/A',
                    item.additionalInfo?.courierName || 'Not specified',
                    item.additionalInfo?.returnType || 'Not specified',
                    item.additionalInfo?.opsRemarks || 'Not specified',
                    item.additionalInfo?.channelName || 'Not specified',
                    item.orderId || 'Not specified',
                    recordDate.toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }),
                    item.username || 'Unknown',
                    linkText, // This will be the clickable text
                    scannedData,
                    skuPair.systemSku || 'N/A',
                    skuPair.physicalSku || 'N/A',
                    item.additionalInfo?.userComment || ''
                ]);

                // ✅ FIX: Add clickable hyperlink to Google Drive column (column I)
                if (driveLink) {
                    const driveLinkCell = recordingsSheet.getCell(`I${row.number}`);

                    // Method 1: Using Excel hyperlink formula (recommended)
                    driveLinkCell.value = {
                        formula: `HYPERLINK("${driveLink}", "${linkText}")`,
                        result: linkText
                    };

                    // Method 2: Styling the cell to look like a link
                    driveLinkCell.font = {
                        color: { argb: 'FF0000FF' },
                        underline: true
                    };

                    console.log(`✅ Added hyperlink for ${item.awbNo}: ${driveLink}`);
                }
            });
        } else {
            recordingsSheet.addRow(['No data available for today']);
        }

        // Format header
        recordingsSheet.getRow(1).font = { bold: true };
        recordingsSheet.getRow(1).fill = {
            type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6E6E6' }
        };

        // Auto-size columns
        recordingsSheet.columns = [
            { width: 15 }, { width: 15 }, { width: 15 }, { width: 15 }, { width: 15 },
            { width: 15 }, { width: 20 }, { width: 15 }, { width: 20 }, { width: 30 },
            { width: 15 }, { width: 15 }, { width: 20 }
        ];

        console.log(`✅ Excel generated with ${todayData.length} records and clickable Drive links`);
        return await workbook.xlsx.writeBuffer();

    } catch (error) {
        console.error('Error generating Excel:', error);
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Recordings');
        worksheet.addRow(['Error generating Excel file']);
        worksheet.addRow([`Error: ${error.message}`]);
        return await workbook.xlsx.writeBuffer();
    }
}

// ADD THIS ROUTE - Check data in MAIN database
app.get('/api/debug-main-db-data', requireAuth, async (req, res) => {
    try {
        const organizationId = req.session.organizationId;

        // Check data in MAIN database
        const InventoryData = mongoose.model('InventoryData');
        const allData = await InventoryData.find({
            organization: organizationId
        }).sort({ createdAt: -1 });

        console.log(`🔍 MAIN DATABASE DEBUG for ${organizationId}: ${allData.length} records`);

        allData.forEach((item, index) => {
            console.log(`   ${index + 1}. AWB: ${item.awbNo}, Courier: ${item.additionalInfo?.courierName}`);
            console.log(`      Organization: ${item.organization}, Date: ${item.createdAt}`);
        });

        res.json({
            success: true,
            organization: organizationId,
            recordCount: allData.length,
            data: allData.map(item => ({
                awbNo: item.awbNo,
                courierName: item.additionalInfo?.courierName,
                returnType: item.additionalInfo?.returnType,
                opsRemarks: item.additionalInfo?.opsRemarks,
                channelName: item.additionalInfo?.channelName,
                orderId: item.orderId,
                organization: item.organization,
                createdAt: item.createdAt,
                timestamp: item.timestamp,
                username: item.username
            }))
        });
    } catch (error) {
        console.error('Main DB debug error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// =============================================================================
// WORKING SESSION DATA API ROUTES - NEW
// =============================================================================

// Get working session data
app.get('/api/get-working-session', requireAuth, (req, res) => {
    try {
        const userId = req.session.userId;
        const sessionData = workingSessionData[userId] || {
            tempData: { good: [], bad: [], used: [], wrong: [] },
            currentAwbNo: '',
            streamIP: '',
            currentScannedData: '',
            isRecording: false,
            streamConnected: false
        };

        res.json({ success: true, data: sessionData });
    } catch (error) {
        console.error('Error fetching working session data:', error);
        res.status(500).json({ success: false, message: 'Error fetching session data' });
    }
});


// Update the user creation endpoint
app.post('/api/users', requireAuth, async (req, res) => {
    try {
        const { username, email, password, role } = req.body;
        const databaseName = req.session.databaseName;
        const organizationId = req.session.organizationId;

        console.log('🆕 Creating new user:', { username, email, role, databaseName });

        // Validation
        if (!username || !email || !password || !role) {
            return res.json({
                success: false,
                message: 'All fields are required'
            });
        }

        const orgDb = mongoose.connection.useDb(databaseName);

        // Check if user already exists
        const existingUser = await orgDb.collection('users').findOne({
            $or: [{ username }, { email }]
        });

        if (existingUser) {
            return res.json({
                success: false,
                message: 'Username or email already exists'
            });
        }

        // Create new user
        const newUser = {
            username,
            email,
            password, // Note: In production, hash this password!
            role,
            organizationId,
            login_status: 'Never Logged In',
            created_at: new Date(),
            last_activity: new Date()
        };

        // Insert into organization database
        const result = await orgDb.collection('users').insertOne(newUser);

        console.log('✅ User created successfully:', username);

        res.json({
            success: true,
            message: 'User created successfully',
            user: {
                _id: result.insertedId,
                username,
                email,
                role,
                status: '⚫ Never Logged In',
                lastActivity: 'No Activity'
            }
        });

    } catch (err) {
        console.error('❌ User creation error:', err);
        res.json({
            success: false,
            message: 'Server error: ' + err.message
        });
    }
});

// Update working session data
app.post('/api/update-working-session', requireAuth, (req, res) => {
    try {
        const userId = req.session.userId;
        const updateData = req.body;

        if (!workingSessionData[userId]) {
            workingSessionData[userId] = {
                tempData: { good: [], bad: [], used: [], wrong: [] },
                currentAwbNo: '',
                streamIP: '',
                currentScannedData: '',
                isRecording: false,
                streamConnected: false,
                version: 0
            };
        }

        // Check for version conflict
        if (updateData.version < workingSessionData[userId].version) {
            return res.status(409).json({
                success: false,
                message: 'Session data conflict. Please refresh the page to get the latest data.'
            });
        }

        // Merge the update data
        workingSessionData[userId] = { ...workingSessionData[userId], ...updateData };

        res.json({ success: true, message: 'Session data updated' });
    } catch (error) {
        console.error('Error updating working session data:', error);
        res.status(500).json({ success: false, message: 'Error updating session data' });
    }
});

// AWB Data Matching API
app.post('/api/awb-matching', requireAuth, async (req, res) => {
    try {
        if (!req.files || !req.files.file) {
            return res.status(400).json({
                success: false,
                message: 'No Excel file uploaded'
            });
        }

        const uploadedFile = req.files.file;
        const { params } = req.body;
        const dateRange = params ? JSON.parse(params) : {};

        // Parse the Excel file
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.load(uploadedFile.data);

        const worksheet = workbook.worksheets[0];
        const awbData = [];

        // Extract data from Excel (skip header row)
        worksheet.eachRow((row, rowNumber) => {
            if (rowNumber > 1) { // Skip header row
                const awbNo = row.getCell(1).value;
                const date = row.getCell(2).value;
                const courierName = row.getCell(3).value;
                const returnType = row.getCell(4).value;
                const operator = row.getCell(5).value;
                const remarks = row.getCell(6).value;

                if (awbNo) {
                    awbData.push({
                        awbNo: awbNo.toString(),
                        date: date ? new Date(date) : null,
                        courierName: courierName ? courierName.toString() : '',
                        returnType: returnType ? returnType.toString() : '',
                        operator: operator ? operator.toString() : '',
                        remarks: remarks ? remarks.toString() : ''
                    });
                }
            }
        });

        // Build date filter if provided
        let dateFilter = {};
        if (dateRange.fromDate && dateRange.toDate) {
            dateFilter.timestamp = {
                $gte: new Date(dateRange.fromDate),
                $lte: new Date(dateRange.toDate)
            };
        }

        // Match AWB data with inventory
        const matchingResults = {
            completed: [],
            pending: [],
            completedCount: 0,
            pendingCount: 0,
            totalCount: awbData.length
        };

        for (const awbItem of awbData) {
            // Find matching inventory record
            const inventoryRecord = await InventoryData.findOne({
                awbNo: awbItem.awbNo,
                ...dateFilter
            });

            if (inventoryRecord) {
                // Found match
                matchingResults.completed.push({
                    ...awbItem,
                    matched: true,
                    inventoryData: {
                        goodCount: inventoryRecord.categoryData.good.count,
                        badCount: inventoryRecord.categoryData.bad.count,
                        usedCount: inventoryRecord.categoryData.used.count,
                        wrongCount: inventoryRecord.categoryData.wrong.count,
                        totalCount: inventoryRecord.categoryData.good.count +
                            inventoryRecord.categoryData.bad.count +
                            inventoryRecord.categoryData.used.count +
                            inventoryRecord.categoryData.wrong.count,
                        timestamp: inventoryRecord.timestamp,
                        username: inventoryRecord.username
                    }
                });
                matchingResults.completedCount++;
            } else {
                // No match found
                matchingResults.pending.push({
                    ...awbItem,
                    matched: false
                });
                matchingResults.pendingCount++;
            }
        }

        res.json({
            success: true,
            ...matchingResults
        });

    } catch (error) {
        console.error('Error processing AWB matching:', error);
        res.status(500).json({
            success: false,
            message: 'Error processing AWB data: ' + error.message
        });
    }
});

// Download AWB Matching Results
app.post('/api/awb-matching/download', requireAuth, async (req, res) => {
    try {
        const { type, results } = req.body;

        if (!results || !type) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameters'
            });
        }

        const workbook = new ExcelJS.Workbook();

        if (type === 'completed') {
            const completedSheet = workbook.addWorksheet('Completed Records');
            completedSheet.addRow([
                'AWB No', 'Courier Name',
            ]);

            results.completed.forEach(item => {
                completedSheet.addRow([
                    item.awbNo || '',
                    item.courierName || '',
                ]);
            });

            completedSheet.getRow(1).font = { bold: true };

        } else if (type === 'pending') {
            const pendingSheet = workbook.addWorksheet('Pending Records');
            pendingSheet.addRow([
                'AWB No', 'Courier Name'
            ]);

            results.pending.forEach(item => {
                pendingSheet.addRow([
                    item.awbNo || '',
                    item.courierName || ''
                ]);
            });

            pendingSheet.getRow(1).font = { bold: true };
        }

        res.setHeader(
            'Content-Type',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        );
        res.setHeader(
            'Content-Disposition',
            `attachment; filename=${type}_awb_results_${new Date().toISOString().slice(0, 10)}.xlsx`
        );

        await workbook.xlsx.write(res);
        res.end();

    } catch (error) {
        console.error('Error downloading matching results:', error);
        res.status(500).json({
            success: false,
            message: 'Error downloading results: ' + error.message
        });
    }
});


const activeOperations = new Map();
// Update existing /api/save-data route to handle tempKey

function cleanupOldTempFiles() {
    const now = Date.now();
    const maxAge = 3600000; // 1 hour

    // Clean video files
    Object.keys(tempVideoStorage).forEach(key => {
        if (now - tempVideoStorage[key].timestamp > maxAge &&
            !processingFiles.has(key)) {
            try {
                if (fs.existsSync(tempVideoStorage[key].tempFile)) {
                    fs.unlinkSync(tempVideoStorage[key].tempFile);
                    console.log(`Cleaned up expired temp video: ${key}`);
                }
                delete tempVideoStorage[key];
            } catch (error) {
                console.error('Error cleaning up temp video:', error);
            }
        }
    });

    // Clean image files
    Object.keys(tempImageStorage).forEach(key => {
        if (now - tempImageStorage[key].timestamp > maxAge &&
            !processingFiles.has(key)) {
            try {
                if (fs.existsSync(tempImageStorage[key].tempFile)) {
                    fs.unlinkSync(tempImageStorage[key].tempFile);
                    console.log(`Cleaned up expired temp image: ${key}`);
                }
                delete tempImageStorage[key];
            } catch (error) {
                console.error('Error cleaning up temp image:', error);
            }
        }
    });
}

// ADD THIS DEBUG ROUTE - Check ALL data in database
app.get('/api/debug-all-data', requireAuth, async (req, org, res) => {
    try {
        const orgDb = mongoose.connection.useDb(`org_${req.session.organizationId}_db`);

        const inventorySchema = new mongoose.Schema({}, { strict: false }); // Allow any fields

        let InventoryData;
        try {
            InventoryData = orgDb.model('InventoryData', inventorySchema);
        } catch {
            InventoryData = orgDb.model('InventoryData');
        }

        // Get ALL data without date filter
        const allData = await InventoryData.find({}).sort({ createdAt: -1 });

        console.log(`🔍 ALL DATA DEBUG: ${allData.length} total records`);
        console.log('📊 Sample records:');

        allData.slice(0, 5).forEach((item, index) => {
            console.log(`   ${index + 1}. AWB: ${item.awbNo}`);
            console.log(`      Created: ${item.createdAt}`);
            console.log(`      Timestamp: ${item.timestamp}`);
            console.log(`      Fields: ${Object.keys(item).join(', ')}`);
        });

        res.json({
            success: true,
            totalRecords: allData.length,
            sampleData: allData.slice(0, 5).map(item => ({
                awbNo: item.awbNo,
                createdAt: item.createdAt,
                timestamp: item.timestamp,
                additionalInfo: item.additionalInfo,
                allFields: Object.keys(item)
            }))
        });
    } catch (error) {
        console.error('Debug error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Save email settings
// In your app.js, in the /api/save-email-settings route
app.post('/api/save-email-settings', requireAuth, async (req, res) => {
    try {
        const organizationId = req.session.organizationId;
        const { autoMailEnabled, autoMailRecipients, autoMailTime, autoMailDays } = req.body;

        console.log('💾 Saving email settings for org:', organizationId);
        console.log('⏰ Time being saved:', autoMailTime); // DEBUG
        console.log('📧 Recipients:', autoMailRecipients);

        const db = client.db('org_' + organizationId + '_db');
        const settingsCollection = db.collection('email_settings');

        // Use update with upsert to create if doesn't exist
        const result = await settingsCollection.updateOne(
            {}, // empty filter to update first document
            {
                $set: {
                    autoMailEnabled,
                    autoMailRecipients,
                    autoMailTime,
                    autoMailDays,
                    updatedAt: new Date()
                }
            },
            { upsert: true } // create if doesn't exist
        );

        console.log('✅ Email settings saved:', result);
        res.json({ success: true, message: 'Settings saved' });

    } catch (error) {
        console.error('❌ Error saving email settings:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// =============================================================================
// INVENTORY DATA API ROUTES
// =============================================================================

// Save inventory data
// Add debug logging to the /api/save-inventory endpoint
app.post('/api/save-inventory', requireAuth, async (req, res) => {
    try {
        const { awbNo, categoryData, recordings, additionalInfo, orderId, skuPairs } = req.body;
        const userId = req.session.userId;
        const username = req.session.username || "Unknown";
        const organizationId = getOrganizationId(req);

        console.log('Saving inventory data for user:', username);
        console.log('AWB:', awbNo);
        console.log('Organization:', organizationId);
        console.log('Additional info:', additionalInfo);

        // ✅ Validate AWB
        if (!awbNo || !awbNo.trim()) {
            return res.status(400).json({ success: false, message: "AWB No is required" });
        }

        if (!orderId || !orderId.trim()) {
            return res.status(400).json({ success: false, message: "Order Id is required" });
        }

        // ✅ Validate additional info (all 3 must be filled)
        if (!additionalInfo?.courierName || !additionalInfo?.returnType || !additionalInfo?.opsRemarks || !additionalInfo?.channelName) {
            return res.status(400).json({
                success: false,
                message: "All additional information fields are required"
            });
        }

        // ✅ Find existing record
        let inventoryData = await InventoryData.findOne({ awbNo: awbNo.trim(), userId, organization: organizationId });

        if (inventoryData) {
            console.log('Updating existing inventory record in organization:', organizationId);

            inventoryData.categoryData = categoryData;
            inventoryData.skuPairs = skuPairs || [];
            inventoryData.additionalInfo = additionalInfo;
            inventoryData.orderId = orderId;
            inventoryData.username = username;
            inventoryData.lastUpdated = new Date();

            // Append recordings if new ones exist
            if (recordings?.length > 0) {
                inventoryData.recordings = [...(inventoryData.recordings || []), ...recordings];
            }

            await inventoryData.save();
        } else {
            console.log('Creating new inventory record');

            inventoryData = new InventoryData({
                userId,
                awbNo: awbNo.trim(),
                orderId,
                categoryData,
                recordings: recordings || [],
                username,
                additionalInfo,
                skuPairs: skuPairs || [],
                organization: organizationId,
                createdAt: new Date(),
                lastUpdated: new Date()
            });

            await inventoryData.save();
        }

        // ✅ Ensure AWB Folder in Google Drive
        let awbFolderLink = '';
        try {
            // Load organization Drive settings
            const driveSettings = await loadOrganizationSettings(organizationId);

            if (driveSettings && driveSettings.rootFolderId) {
                const now = new Date();
                const year = now.getFullYear().toString();
                const month = now.getMonth() + 1;
                const day = now.getDate();

                // Create AWB folder structure: Year/Month/Day/AWB
                const folderPath = [year, getMonthName(month), formatDay(day), awbNo.trim()];
                const awbFolderId = await ensurePathFast(driveSettings.rootFolderId, folderPath, organizationId);

                if (awbFolderId) {
                    awbFolderLink = `https://drive.google.com/drive/folders/${awbFolderId}`;

                    // 🔄 Save in DB also (so we can reuse later)
                    inventoryData.awbFolderLink = awbFolderLink;
                    await inventoryData.save();

                    console.log(`✅ AWB Folder created: ${awbFolderLink}`);
                }
            } else {
                console.warn("⚠️ No Drive settings found for organization:", organizationId);
            }
        } catch (err) {
            console.error("❌ Failed to create/find AWB folder:", err.message);
        }

        // ✅ Google Sheet Update
        try {
            // Load organization settings for sheets
            const driveSettings = await loadOrganizationSettings(organizationId);

            if (driveSettings && driveSettings.masterSheetId) {
                // Prepare scanned summary
                const scannedDetails = [];
                if (categoryData.good?.eans?.length > 0) {
                    scannedDetails.push(`Good: ${categoryData.good.eans.join(', ')}`);
                }
                if (categoryData.bad?.eans?.length > 0) {
                    scannedDetails.push(`Bad: ${categoryData.bad.eans.join(', ')}`);
                }
                if (categoryData.used?.eans?.length > 0) {
                    scannedDetails.push(`Used: ${categoryData.used.eans.join(', ')}`);
                }
                if (categoryData.wrong?.eans?.length > 0) {
                    scannedDetails.push(`Wrong: ${categoryData.wrong.eans.join(', ')}`);
                }

                const scannedSummary = scannedDetails.join(' | ') || 'None';
                const rowsToAppend = (skuPairs && skuPairs.length > 0 ? skuPairs : [{ systemSku: 'N/A', physicalSku: 'N/A' }]).map(pair => [
                    awbNo.trim(),
                    additionalInfo.courierName,
                    additionalInfo.returnType,
                    additionalInfo.opsRemarks,
                    additionalInfo.channelName,
                    orderId || 'Not specified',
                    new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }),
                    username,
                    awbFolderLink ? `=HYPERLINK("${awbFolderLink}", "Open AWB Folder")` : 'No folder yet',
                    scannedSummary,
                    pair.systemSku || 'N/A',
                    pair.physicalSku || 'N/A',
                    additionalInfo.userComment || ''
                ]);

                // Update all sheets (master + additional) for the organization
                await updateAllSheets(awbNo.trim(), rowsToAppend[0], organizationId);

                rowsToAppend.forEach(row => console.log('📊 Appended row to Google Sheet:', row));

            } else {
                console.warn("⚠️ No master sheet configured for organization:", organizationId);
            }
        } catch (sheetError) {
            console.error("❌ Failed to update Google Sheet:", sheetError.message);
        }

        // ✅ Clear working session
        if (workingSessionData[userId]) {
            workingSessionData[userId].tempData = { good: [], bad: [], used: [], wrong: [] };
            workingSessionData[userId].currentScannedData = '';
        }

        console.log('✅ Inventory data saved successfully for organization:', organizationId);

        res.json({
            success: true,
            message: 'Data saved successfully to DB and Google Sheet',
            data: {
                awbNo: inventoryData.awbNo,
                totalItems: Object.values(categoryData).reduce((sum, cat) => sum + (cat.count || 0), 0),
                additionalInfo: inventoryData.additionalInfo,
                awbFolderLink,
                organization: organizationId
            }
        });

    } catch (error) {
        console.error('❌ Error in /api/save-inventory:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to save inventory data: ' + error.message
        });
    }
});



// Add this route to update existing records with username
app.get('/api/migrate-usernames', requireAuth, async (req, res) => {
    try {
        console.log('Starting username migration...');

        // Get all inventory records without username
        const allRecords = await InventoryData.find({});

        console.log(`Found ${allRecords.length} records total`);

        let updatedCount = 0;

        // Update each record with username from user collection
        for (const record of allRecords) {
            try {
                const user = await User.findById(record.userId);
                if (user) {
                    // Check if username is different or doesn't exist
                    if (record.username !== user.username) {
                        record.username = user.username;
                        await record.save();
                        updatedCount++;
                        console.log(`Updated record ${record._id} with username: ${user.username}`);
                    }
                } else {
                    console.log(`User not found for record ${record._id}, userId: ${record.userId}`);
                }
            } catch (error) {
                console.error(`Error updating record ${record._id}:`, error);
            }
        }

        res.json({
            success: true,
            message: `Migrated ${updatedCount} records with usernames`
        });
    } catch (error) {
        console.error('Error migrating usernames:', error);
        res.status(500).json({ success: false, message: 'Error migrating usernames' });
    }
});

// app.js-la add pannu
app.get('/api/debug-fix-usernames', requireAuth, async (req, res) => {
    try {
        console.log('DEBUG: Fixing all usernames manually...');

        const allRecords = await InventoryData.find({});
        console.log(`Found ${allRecords.length} records to fix`);

        for (const record of allRecords) {
            try {
                const user = await User.findById(record.userId);
                if (user) {
                    console.log(`Updating record ${record._id} (AWB: ${record.awbNo}) with username: ${user.username}`);
                    await InventoryData.findByIdAndUpdate(
                        record._id,
                        { username: user.username }
                    );
                } else {
                    console.log(`User not found for record ${record._id}, userId: ${record.userId}`);
                }
            } catch (error) {
                console.error(`Error updating record ${record._id}:`, error);
            }
        }

        res.json({
            success: true,
            message: `Debug username fix completed. Check server console for details.`
        });
    } catch (error) {
        console.error('Error in debug fix:', error);
        res.status(500).json({ success: false, message: 'Error fixing usernames' });
    }
});

// Get user's inventory data
app.get('/api/get-inventory', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;   // ✅ Use logged-in user's ID
        const organization = getOrganizationId(req);
        console.log('📋 Loading inventory for organization:', organization);

        const inventoryData = await InventoryData.find({
            organization: organization
        }).sort({ createdAt: -1 });
        console.log(`✅ Found ${inventoryData.length} records for organization ${organization}`);

        res.json({ success: true, data: inventoryData, organization: organization });
    } catch (error) {
        console.error('Error fetching inventory data:', error);
        res.status(500).json({ success: false, message: 'Error fetching data' });
    }
});

// Get specific AWB data
app.get('/api/get-inventory/:awbNo', requireAuth, async (req, res) => {
    try {
        //const userId = req.session.userId;
        const { awbNo } = req.params;
        const inventoryData = await InventoryData.findOne({ awbNo });

        if (!inventoryData) {
            return res.json({ success: true, data: null });
        }

        res.json({ success: true, data: inventoryData });
    } catch (error) {
        console.error('Error fetching AWB data:', error);
        res.status(500).json({ success: false, message: 'Error fetching AWB data' });
    }
});


/*
// Delete specific AWB data
app.delete('/api/delete-inventory/:awbNo', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { awbNo } = req.params;
        const organization = getOrganizationId(req);

        console.log(`🗑️ Deleting inventory from organization ${organization}: ${awbNo}`);

        const inventoryData = await InventoryData.findOne({
            awbNo: awbNo,
            organization: organization
        });

        if (!inventoryData) {
            return res.status(404).json({ success: false, message: 'Data not found in your organization' });
        }

        // Check if the current user owns this data
        if (inventoryData.userId.toString() !== userId.toString()) {
            return res.status(403).json({
                success: false,
                message: 'You can only delete your own data'
            });
        }
        await InventoryData.deleteOne({ awbNo, userId, organization });

        console.log(`✅ Data deleted from organization ${organization}: ${awbNo}`);

        res.json({ success: true, message: 'Data deleted successfully' });
    } catch (error) {
        console.error('Error deleting inventory data:', error);
        res.status(500).json({ success: false, message: 'Error deleting data' });
    }
});*/

app.delete('/api/delete-inventory/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        await InventoryData.findByIdAndDelete(id);
        res.json({ success: true, message: 'Data deleted successfully' });
    } catch (error) {
        console.error('Error deleting inventory data:', error);
        res.status(500).json({ success: false, message: 'Error deleting data' });
    }
});

app.delete('/api/delete-inventory/awb/:awbNo', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { awbNo } = req.params;
        const organization = getOrganizationId(req);

        console.log(`🗑️ Deleting inventory by AWB: ${awbNo}`);

        const inventoryData = await InventoryData.findOne({
            awbNo: awbNo,
            organization: organization
        });

        if (!inventoryData) {
            return res.status(404).json({
                success: false,
                message: 'Data not found in your organization'
            });
        }

        // Check if the current user owns this data
        if (inventoryData.userId.toString() !== userId.toString()) {
            return res.status(403).json({
                success: false,
                message: 'You can only delete your own data'
            });
        }

        await InventoryData.deleteOne({ awbNo, userId, organization });
        console.log(`✅ Data deleted by AWB: ${awbNo}`);

        res.json({ success: true, message: 'Data deleted successfully' });
    } catch (error) {
        console.error('Error deleting inventory data by AWB:', error);
        res.status(500).json({ success: false, message: 'Error deleting data' });
    }
});

app.delete('/api/users/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;

        // Prevent users from deleting themselves
        if (id === req.session.userId) {
            return res.status(400).json({
                success: false,
                message: 'You cannot delete your own account'
            });
        }

        const result = await User.findByIdAndDelete(id);

        if (!result) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({ success: true, message: 'User deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Error deleting user' });
    }
});


// Add this API endpoint to get all users
app.get('/api/get-all-users', requireAuth, async (req, res) => {
    try {
        const users = await User.find({}, 'username');
        res.json({ success: true, users: users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ success: false, message: 'Error fetching users' });
    }
});




// =============================================================================
// PROTECTED API ROUTES (Require Login) - Updated for AWB system
// =============================================================================
// Global storage for temporary files


// Start recording endpoint
// Start recording endpoint
app.post('/api/start-recording', requireAuth, async (req, res) => {
    const { awbNo, scannedData, streamUrl, streamType } = req.body;
    const userId = req.session.userId;

    if (!awbNo || !streamUrl) {
        return res.status(400).json({ error: 'AWB number and Stream URL are required' });
    }

    try {
        const tempKey = `video_${userId}_${awbNo}_${Date.now()}`;
        const tempDir = path.join(__dirname, 'temp_videos');
        if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

        const tempFile = path.join(tempDir, `${tempKey}.mp4`);

        // Input/output options
        let inputOptions = [];
        let outputOptions = [
            '-c:v', 'libx264',
            '-preset', 'medium',
            '-tune', 'zerolatency',
            '-crf', '18',
            '-profile:v', 'high',
            '-level', '4.0',
            '-maxrate', '4M',
            '-bufsize', '8M',
            '-pix_fmt', 'yuv420p',
            '-movflags', '+faststart',
            '-f', 'mp4'
        ];

        // Camera-specific optimizations
        if (streamType === 'rtsp') {
            inputOptions = [
                '-rtsp_transport', 'tcp',
                '-timeout', '5000000',
                '-fflags', 'nobuffer',
                '-flags', 'low_delay'
            ];
        } else if (streamType === 'http') {
            inputOptions = [
                '-f', 'mjpeg',
                '-fflags', 'nobuffer',
                '-flags', 'low_delay'
            ];

            // For MJPEG streams, use higher quality encoding
            outputOptions = outputOptions.concat([
                '-qscale:v', '2'        // Quality scale for MJPEG sources
            ]);
        }

        const command = ffmpeg(streamUrl)
            .inputOptions(inputOptions)
            .outputOptions(outputOptions)
            .output(tempFile)
            .on('start', cmd => {
                console.log('🎥 HIGH QUALITY Recording started');
                console.log('Settings:', { inputOptions, outputOptions });
            })
            .on('error', err => {
                console.error('❌ Recording error:', err.message);
                console.error('FFmpeg stderr:', stderr);
                if (fs.existsSync(tempFile)) {
                    try { fs.unlinkSync(tempFile); } catch { }
                }
                delete activeRecordings[tempKey];
            })
            .on('end', () => {
                console.log('🎬 Recording finished, checking file quality...');
                // Verify file quality
                if (fs.existsSync(tempFile)) {
                    const stats = fs.statSync(tempFile);
                    console.log(`📊 Recorded file size: ${(stats.size / (1024 * 1024)).toFixed(2)} MB`);
                }
            });

        // Save active recording
        activeRecordings[tempKey] = {
            awbNo,
            userId,
            tempFile,
            scannedData: scannedData || 'None',
            command,
            quality: 'high'  // Mark as high quality recording
        };

        command.run();

        res.json({
            success: true,
            tempKey,
            message: 'High quality recording started'
        });
    } catch (err) {
        console.error('❌ Start recording failed:', err.message);
        res.status(500).json({ error: 'Failed to start recording: ' + err.message });
    }
});

// Stop recording endpoint
// Update the /api/stop-recording endpoint
app.post('/api/stop-recording', requireAuth, async (req, res) => {
    const { tempKey } = req.body; // 🔑 frontend must pass tempKey

    if (!tempKey || !activeRecordings[tempKey]) {
        return res.status(400).json({ error: 'No active recording found' });
    }

    const recording = activeRecordings[tempKey];

    try {
        // Graceful stop
        if (recording.command && recording.command.ffmpegProc) {
            try {
                if (recording.command.ffmpegProc.stdin &&
                    recording.command.ffmpegProc.stdin.writable) {
                    recording.command.ffmpegProc.stdin.write('q');
                }

                setTimeout(() => {
                    if (recording.command &&
                        recording.command.ffmpegProc &&
                        recording.command.ffmpegProc.exitCode === null) {
                        recording.command.ffmpegProc.kill('SIGKILL');
                    }
                }, 3000);
            } catch (err) {
                console.log('⚠️ Fallback: force killing recording process');
                try { recording.command.kill('SIGKILL'); } catch { }
            }
        } else {
            console.log('⚠️ No ffmpegProc found, process already ended');
        }


        // Wait for file finalization
        await new Promise(r => setTimeout(r, 3000));

        // Validate file
        if (!fs.existsSync(recording.tempFile)) {
            delete activeRecordings[tempKey];
            return res.status(400).json({ error: 'Recording file not created' });
        }

        const stats = fs.statSync(recording.tempFile);
        if (stats.size < 1024) {
            delete activeRecordings[tempKey];
            return res.status(400).json({ error: 'Recording file too small' });
        }

        // Move to temp storage
        tempVideoStorage[tempKey] = {
            tempFile: recording.tempFile,
            scannedData: recording.scannedData,
            timestamp: Date.now()
        };

        delete activeRecordings[tempKey];

        res.json({
            success: true,
            tempKey,
            scannedData: recording.scannedData,
            fileSize: stats.size
        });
    } catch (err) {
        console.error('❌ Stop recording failed:', err.message);
        res.status(500).json({ error: 'Failed to stop recording' });
    }
});

// New route to save or discard video
//const { uploadToDrive, ensurePathFast } = require("./drive");

async function syncToGoogleDriveInBackground(filePath, fileName, folderStructure, tempKey, awbNo, mediaType, scannedData, userId) {
    let fileExistsAtStart = fs.existsSync(filePath);

    if (!fileExistsAtStart) {
        console.log(`❌ File already missing at start: ${filePath}`);

        // Try to find the file in local backup
        const localBackupPath = path.join(__dirname, 'local_backup', ...folderStructure, fileName);
        if (fs.existsSync(localBackupPath)) {
            console.log(`🔍 Found file in local backup, using that: ${localBackupPath}`);
            filePath = localBackupPath; // Use the backup copy
        } else {
            console.log(`❌ File not found anywhere, cannot upload: ${fileName}`);
            return;
        }
    }

    try {
        console.log(`🔄 REAL Background sync to Google Drive: ${fileName}`);

        // Get current date for new structure
        const now = new Date();
        const year = now.getFullYear().toString();
        const month = now.getMonth() + 1; // 1-12
        const day = now.getDate();

        // Upload using NEW structure: year, month, day, awbNo
        const fileDetails = await uploadToDrive(filePath, fileName, year, month, day, awbNo);
        console.log(`✅ REAL Background sync completed: ${fileName}`);
        console.log(`📁 New structure: ${year}/${getMonthName(month)}/${formatDay(day)}/${awbNo}/${mediaType === 'video' ? 'Videos' : 'Images'}`);

        // Update database with Google Drive link
        await updateDatabaseWithDriveLink(awbNo,
            fileName,
            fileDetails.webViewLink,
            mediaType,
            scannedData,
            userId,
            fileDetails.awbFolderLink);

    } catch (error) {
        console.error(`❌ REAL Background sync failed: ${fileName}`, error);

        // Retry logic here...
    } finally {
        // Only clean up the temp file, not the backup
        try {
            const tempStorage = mediaType === 'video' ? tempVideoStorage : tempImageStorage;
            const originalTempFile = tempStorage[tempKey]?.tempFile;

            // Only delete the original temp file if it exists and is different from backup
            if (originalTempFile && fs.existsSync(originalTempFile) && originalTempFile === filePath) {
                fs.unlinkSync(originalTempFile);
            }

            delete tempStorage[tempKey];
        } catch (cleanupError) {
            console.error('Cleanup error:', cleanupError);
        }
        processingFiles.delete(tempKey);
    }
}

// Handle USB recording upload
app.post('/api/save-usb-recording', requireAuth, async (req, res) => {
    try {
        if (!req.files || !req.files.file) {
            return res.status(400).json({
                success: false,
                error: 'No file uploaded'
            });
        }

        const awbNo = req.body.awbNo;
        const scannedData = req.body.scannedData || 'None';
        const userId = req.session.userId;
        const uploadedFile = req.files.file;

        // Generate temp key
        const tempKey = `video_${userId}_${awbNo}_${Date.now()}`;
        const tempDir = path.join(__dirname, 'temp_videos');

        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }

        const tempFile = path.join(tempDir, `${tempKey}.webm`);

        // Save the uploaded file
        await uploadedFile.mv(tempFile);

        // Store in temp storage
        tempVideoStorage[tempKey] = {
            tempFile: tempFile,
            scannedData: scannedData,
            timestamp: Date.now()
        };

        res.json({
            success: true,
            tempKey: tempKey,
            scannedData: scannedData
        });

    } catch (error) {
        console.error('Error saving USB recording:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to save USB recording'
        });
    }
});

// Handle USB image upload
app.post('/api/save-usb-image', requireAuth, async (req, res) => {
    try {
        if (!req.files || !req.files.file) {
            return res.status(400).json({
                success: false,
                error: 'No file uploaded'
            });
        }

        const awbNo = req.body.awbNo;
        const scannedData = req.body.scannedData || 'None';
        const userId = req.session.userId;
        const uploadedFile = req.files.file;

        // Generate temp key
        const tempKey = `image_${userId}_${awbNo}_${Date.now()}`;
        const tempDir = path.join(__dirname, 'temp_images');

        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }

        const tempFile = path.join(tempDir, `${tempKey}.png`);

        // Save the uploaded file
        await uploadedFile.mv(tempFile);

        // Store in temp storage
        tempImageStorage[tempKey] = {
            tempFile: tempFile,
            scannedData: scannedData,
            timestamp: Date.now()
        };

        res.json({
            success: true,
            tempKey: tempKey,
            scannedData: scannedData
        });

    } catch (error) {
        console.error('Error saving USB image:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to save USB image'
        });
    }
});

// RTSP to HLS proxy endpoint
app.get('/api/rtsp-proxy', (req, res) => {
    const { url } = req.query;

    if (!url || !url.startsWith('rtsp://')) {
        return res.status(400).json({ error: 'Invalid RTSP URL' });
    }

    const streamKey = crypto.createHash('md5').update(url).digest('hex');
    const streamPath = path.join(streamsDir, streamKey);

    // Clean up old streams
    cleanupOldStreams();

    // Always recreate the stream directory to ensure fresh stream
    if (fs.existsSync(streamPath)) {
        try {
            fs.rmSync(streamPath, { recursive: true });
            console.log('Removed old stream directory:', streamPath);
        } catch (error) {
            console.error('Error removing old stream directory:', error);
        }
    }

    // Create fresh stream directory
    fs.mkdirSync(streamPath, { recursive: true });

    console.log('Creating LIVE RTSP stream for:', url);

    // Create a proper HLS playlist first
    const playlistContent = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:2
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-PLAYLIST-TYPE:EVENT
`;

    fs.writeFileSync(path.join(streamPath, 'index.m3u8'), playlistContent);

    // FFmpeg command for RTSP → HLS
    const command = ffmpeg(url)
        .inputOptions([
            '-rtsp_transport', 'tcp',
            '-timeout', '5000000',

        ])
        .outputOptions([
            '-c:v', 'copy',
            '-c:a', 'aac',
            '-hls_time', '2',
            '-hls_list_size', '5',
            '-hls_flags', 'delete_segments',
            '-hls_segment_type', 'mpegts',
            '-hls_segment_filename', path.join(streamPath, 'segment%03d.ts'),
            '-f', 'hls'
        ])
        .output(path.join(streamPath, 'index.m3u8'))
        .on('start', (cmd) => {
            console.log('FFmpeg RTSP LIVE stream started:', cmd);
        })
        .on('error', (err, stdout, stderr) => {
            console.error('FFmpeg RTSP LIVE error:', err.message);
            console.error('FFmpeg stderr:', stderr);
            try {
                if (fs.existsSync(streamPath)) {
                    fs.rmSync(streamPath, { recursive: true });
                }
            } catch (cleanupError) {
                console.error('Error cleaning up stream directory:', cleanupError);
            }
        })
        .on('end', () => {
            console.log('FFmpeg RTSP LIVE stream ended');
        });

    command.run();

    res.json({
        hlsUrl: `/streams/${streamKey}/index.m3u8`,
        streamKey: streamKey,
        live: true
    });
});

// Add this new endpoint for direct RTSP playback info
app.get('/api/rtsp-direct', (req, res) => {
    const { url } = req.query;

    if (!url || !url.startsWith('rtsp://')) {
        return res.status(400).json({ error: 'Invalid RTSP URL' });
    }

    // For direct RTSP playback, we just return the URL
    // The client will handle it using appropriate players
    res.json({
        rtspUrl: url,
        direct: true
    });
});

// Add this function to handle persistent stream connections
function setupPersistentStream(streamUrl, streamType) {
    const streamKey = crypto.createHash('md5').update(streamUrl).digest('hex');

    if (!activeStreams[streamKey]) {
        activeStreams[streamKey] = {
            url: streamUrl,
            type: streamType,
            lastAccessed: Date.now(),
            clients: 0
        };

        console.log(`New persistent stream: ${streamKey} (${streamType})`);
    }

    activeStreams[streamKey].clients++;
    activeStreams[streamKey].lastAccessed = Date.now();

    return streamKey;
}

// Add this to maintain active streams
const activeStreams = {};
setInterval(() => {
    const now = Date.now();
    Object.keys(activeStreams).forEach(key => {
        // Remove streams with no clients that haven't been accessed in 5 minutes
        if (activeStreams[key].clients === 0 &&
            now - activeStreams[key].lastAccessed > 300000) {
            console.log(`Cleaning up unused stream: ${key}`);
            delete activeStreams[key];
        }
    });
}, 60000); // Check every minute

// Helper function to clean up old streams
function cleanupOldStreams() {
    const now = Date.now();
    const maxAge = 600000; // 10 minutes

    if (!fs.existsSync(streamsDir)) return;

    try {
        const streams = fs.readdirSync(streamsDir);
        streams.forEach(stream => {
            const streamPath = path.join(streamsDir, stream);
            try {
                const stats = fs.statSync(streamPath);
                if (now - stats.mtimeMs > maxAge) {
                    fs.rmSync(streamPath, { recursive: true });
                    console.log(`Cleaned up old stream: ${stream}`);
                }
            } catch (error) {
                console.error(`Error cleaning up stream ${stream}:`, error);
            }
        });
    } catch (error) {
        console.error('Error cleaning up old streams:', error);
    }
}

// Serve HLS files


//app.listen(3000, () => console.log('Server running on port 3000'));


app.get('/api/test-drive', requireAuth, async (req, res) => {
    try {
        // Test if we can access Google Drive
        const response = await drive.files.list({
            pageSize: 1,
            fields: 'files(id, name)',
            supportsAllDrives: true,
            includeItemsFromAllDrives: true,
        });

        res.json({
            success: true,
            message: 'Google Drive connection successful',
            fileCount: response.data.files.length
        });
    } catch (error) {
        console.error('Google Drive test failed:', error);
        res.status(500).json({
            success: false,
            error: 'Google Drive connection failed',
            details: error.message
        });
    }
});

// Capture image endpoint


app.post('/api/capture-image', requireAuth, async (req, res) => {
    const { awbNo, scannedData, streamUrl, streamType } = req.body;
    const userId = req.session.userId;

    if (!awbNo) {
        return res.status(400).json({ error: 'AWB number is required' });
    }

    if (!streamUrl) {
        return res.status(400).json({ error: 'Stream URL is required' });
    }

    try {
        console.log(`📷 Capturing image for AWB: ${awbNo}`);
        console.log(`Stream URL: ${streamUrl}`);
        console.log(`Stream type: ${streamType}`);

        const tempKey = `image_${userId}_${awbNo}_${Date.now()}`;
        const tempDir = path.join(__dirname, 'temp_images');

        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }

        const tempFile = path.join(tempDir, `${tempKey}.jpg`);

        // Common FFmpeg options
        let inputOptions = [];
        let outputOptions = [
            '-vframes', '1',
            '-q:v', '2',
            '-y'
        ];

        // Set protocol-specific options
        if (streamType === 'rtsp') {
            inputOptions = [
                '-rtsp_transport', 'tcp',
                '-timeout', '10000000',  // Increased timeout to 10 seconds for RTSP
                "-skip_frame", "nokey"
            ];
            // Add video filter for RTSP to ensure proper JPEG encoding
            outputOptions = [
                '-vframes', '1',
                '-q:v', '2',
                '-y',
                '-vf', 'scale=1920:1080:flags=lanczos',  // Force specific pixel format for better compatibility
                '-r', '30',
            ];
        } else {
            inputOptions = [
                '-f', 'mjpeg',
                '-timeout', '5000000',  // 5 seconds for HTTP
            ];
        }

        await new Promise((resolve, reject) => {
            const captureCommand = ffmpeg(streamUrl)
                .inputOptions(inputOptions)
                .outputOptions(outputOptions)
                .output(tempFile)
                .on('end', () => {
                    console.log('✅ Image capture completed');
                    resolve();
                })
                .on('error', (err, stdout, stderr) => {
                    console.error('❌ Image capture error:', err.message);
                    console.error('FFmpeg stderr:', stderr);
                    reject(err);
                });

            // Set timeout for capture - longer for RTSP
            const timeoutDuration = streamType === 'rtsp' ? 15000 : 10000;
            const timeout = setTimeout(() => {
                captureCommand.kill('SIGTERM');
                reject(new Error(`${streamType.toUpperCase()} Image capture timeout`));
            }, timeoutDuration);

            captureCommand.on('end', () => clearTimeout(timeout));
            captureCommand.on('error', () => clearTimeout(timeout));

            captureCommand.run();
        });

        // File validation
        if (!fs.existsSync(tempFile)) {
            throw new Error('Image file was not created');
        }

        const stats = fs.statSync(tempFile);
        if (stats.size === 0) {
            fs.unlinkSync(tempFile);
            throw new Error('Captured image file is empty');
        }

        // Additional validation for RTSP images
        if (streamType === 'rtsp' && stats.size < 1024) {
            console.warn('RTSP image is very small, might be corrupted:', stats.size, 'bytes');
            // Continue anyway, but log a warning
        }

        // Store in temp storage
        tempImageStorage[tempKey] = {
            tempFile: tempFile,
            scannedData: scannedData || 'None',
            timestamp: Date.now(),
            streamType: streamType  // Store stream type for debugging
        };

        console.log(`🎉 Image captured: ${tempKey} (${stats.size} bytes) from ${streamType} stream`);

        res.json({
            success: true,
            message: 'Image captured successfully',
            tempKey: tempKey,
            scannedData: scannedData || 'None',
            fileSize: stats.size,
            streamType: streamType
        });

    } catch (error) {
        console.error('❌ Error capturing image:', error);

        // Clean up any temporary file that might have been created
        try {
            if (tempFile && fs.existsSync(tempFile)) {
                fs.unlinkSync(tempFile);
            }
        } catch (cleanupError) {
            console.error('Error cleaning up temp file:', cleanupError);
        }

        res.status(500).json({ error: 'Failed to capture image: ' + error.message });
    }
});



// In app.js - Fix the save-data endpoint
app.post('/api/save-data', requireAuth, async (req, res) => {
    const { awbNo, tempKey, mediaType, save, courierName, returnType, opsRemarks, channelName, orderId } = req.body;
    const userId = req.session.userId;
    const username = req.session.username || "Unknown";
    const organizationId = getOrganizationId(req);

    if (!tempKey) {
        return res.status(400).json({ error: 'Temp key is required' });
    }

    const tempStorage = mediaType === 'video' ? tempVideoStorage : tempImageStorage;

    if (processingFiles.has(tempKey)) {
        return res.status(409).json({
            success: false,
            error: 'File is already being processed'
        });
    }

    if (!tempStorage[tempKey]) {
        return res.status(400).json({ error: 'Temp file not found' });
    }

    processingFiles.add(tempKey);

    try {
        const { tempFile, scannedData } = tempStorage[tempKey];

        if (!fs.existsSync(tempFile)) {
            delete tempStorage[tempKey];
            return res.status(400).json({ error: 'Temp file no longer exists' });
        }

        const stats = fs.statSync(tempFile);
        if (stats.size === 0) throw new Error("File is empty");

        if (!save) {
            fs.unlinkSync(tempFile);
            delete tempStorage[tempKey];
            processingFiles.delete(tempKey);
            return res.json({
                success: true,
                message: `${mediaType} discarded successfully`
            });
        }

        // Define new file name
        const fileExtension = mediaType === 'video' ? 'mp4' : 'jpg';
        const newFileName = `${awbNo}_${Date.now()}.${fileExtension}`;

        // Date components for folder structure
        const now = new Date();
        const year = now.getFullYear().toString();
        const month = now.getMonth() + 1; // 1-12
        const day = now.getDate();

        console.log(`⚡ Processing ${mediaType} for org ${organizationId}: ${newFileName}`);
        console.log(`📁 New structure: ${year}/${getMonthName(month)}/${formatDay(day)}/${awbNo}/${mediaType === 'video' ? 'Videos' : 'Images'}`);

        // 1. Send instant response
        res.json({
            success: true,
            message: `${mediaType} saved successfully`,
            driveSync: 'in-progress'
        });

        // 2. Local backup
        try {
            const folderStructure = [year, getMonthName(month), formatDay(day), awbNo, mediaType === 'video' ? 'Videos' : 'Images'];
            const localBackupPath = path.join(__dirname, 'local_backup', ...folderStructure);
            if (!fs.existsSync(localBackupPath)) fs.mkdirSync(localBackupPath, { recursive: true });
            const localDestination = path.join(localBackupPath, newFileName);
            fs.copyFileSync(tempFile, localDestination);
            console.log(`💾 Local backup created: ${localDestination}`);
        } catch (backupError) {
            console.error('Local backup failed (non-critical):', backupError.message);
        }

        // 3. Google Drive AWB folder creation
        let awbFolderLink = '';
        try {
            const driveSettings = await loadOrganizationSettings(organizationId);

            if (driveSettings && driveSettings.rootFolderId) {
                // Create complete folder structure including file type
                const folderPath = [year, getMonthName(month), formatDay(day), awbNo, mediaType === 'video' ? 'Videos' : 'Images'];
                const targetFolderId = await ensurePathFast(driveSettings.rootFolderId, folderPath, organizationId);

                // Also get the AWB folder ID for the link
                const awbFolderPath = [year, getMonthName(month), formatDay(day), awbNo];
                const awbFolderId = await ensurePathFast(driveSettings.rootFolderId, awbFolderPath, organizationId);

                if (awbFolderId) {
                    awbFolderLink = `https://drive.google.com/drive/folders/${awbFolderId}`;
                    console.log(`✅ AWB Folder created: ${awbFolderLink}`);
                } else {
                    console.warn("⚠️ AWB folder creation returned null ID");
                }
            } else {
                console.warn("⚠️ No Drive settings found for organization:", organizationId);
                awbFolderLink = "Folder creation pending - No Drive settings";
            }
        } catch (err) {
            console.error("❌ Failed to create/find AWB folder:", err.message);
            awbFolderLink = "Error creating folder";
        }

        // 4. HIGH QUALITY PROCESSING (VIDEOS ONLY)
        let finalUploadFile = tempFile;
        let processedHighQuality = false;

        if (mediaType === 'video') {
            try {
                console.log('🎬 Starting high quality video processing...');

                const highQualityTempFile = path.join(__dirname, 'temp_videos', `hq_${tempKey}.mp4`);

                await processHighQualityVideo(tempFile, highQualityTempFile);

                // Verify the high quality file was created
                if (fs.existsSync(highQualityTempFile)) {
                    const hqStats = fs.statSync(highQualityTempFile);
                    if (hqStats.size > 0) {
                        finalUploadFile = highQualityTempFile;
                        processedHighQuality = true;
                        console.log('✅ High quality processing completed');
                    } else {
                        console.warn('⚠️ High quality file is empty, using original');
                    }
                }
            } catch (processingError) {
                console.error('❌ High quality processing failed, using original:', processingError.message);
                // Continue with original file
            }
        }

        // 5. Google Drive upload
        try {
            console.log(`🔄 Starting Google Drive upload for org ${organizationId}: ${newFileName}`);

            // Use the REAL upload function with organization context
            const fileDetails = await uploadToDriveReal(
                finalUploadFile,
                newFileName,
                year,
                month,
                day,
                awbNo,
                organizationId
            );

            console.log(`✅ Google Drive upload completed: ${newFileName}`);
            console.log(`📁 File placed at: ${fileDetails.folderStructure}`);
            console.log(`🔗 File link: ${fileDetails.webViewLink}`);

            // Update DB with Drive link
            await updateDatabaseWithDriveLink(
                awbNo,
                newFileName,
                fileDetails.webViewLink,
                mediaType,
                scannedData,
                userId,
                fileDetails.awbFolderLink || awbFolderLink,
                courierName,
                returnType,
                opsRemarks,
                channelName,
                organizationId,
                orderId
            );

        } catch (driveError) {
            console.error(`❌ Google Drive upload failed after retries: ${driveError.message}`);
            // Check if it's a database error (file uploaded but db failed)
            if (driveError.message.includes('orderId') || driveError.message.includes('validation')) {
                console.log('📊 Detected database error, adding to retry queue for database update only');

                // Add to queue with existing drive link if available
                addToRetryQueue(
                    tempFile,
                    newFileName,
                    year, month, day, awbNo,
                    mediaType,
                    scannedData,
                    userId,
                    courierName,
                    returnType,
                    opsRemarks,
                    channelName,
                    organizationId
                );
            } else {
                // Actual upload error
                addToRetryQueue(
                    tempFile,
                    newFileName,
                    year, month, day, awbNo,
                    mediaType,
                    scannedData,
                    userId,
                    organizationId
                );
            }
        }

        // 6. Cleanup
        try {
            // Clean up high quality temp file if it exists
            if (processedHighQuality) {
                const hqFile = path.join(__dirname, 'temp_videos', `hq_${tempKey}.mp4`);
                if (fs.existsSync(hqFile)) {
                    fs.unlinkSync(hqFile);
                }
            }

            // Clean up original temp file
            if (fs.existsSync(tempFile)) {
                fs.unlinkSync(tempFile);
            }

            delete tempStorage[tempKey];
        } catch (cleanupError) {
            console.error('Cleanup error:', cleanupError);
        }

    } catch (error) {
        console.error(`❌ Error processing ${mediaType}:`, error);
        try {
            const { tempFile } = tempStorage[tempKey] || {};
            if (tempFile && fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
            delete tempStorage[tempKey];
        } catch (cleanupError) {
            console.error('Cleanup error:', cleanupError);
        }

        if (!res.headersSent) {
            res.status(500).json({ success: false, error: `Failed to process ${mediaType}: ${error.message}` });
        }
    } finally {
        processingFiles.delete(tempKey);
    }
});

// HIGH QUALITY VIDEO PROCESSING FUNCTION (Add outside the endpoint)
async function processHighQualityVideo(inputPath, outputPath) {
    return new Promise((resolve, reject) => {
        ffmpeg(inputPath)
            .outputOptions([
                '-c:v', 'libx264',
                '-preset', 'medium',      // Better quality than 'ultrafast'
                '-crf', '18',             // Lower CRF = better quality (18-23 is good)
                '-profile:v', 'high',
                '-maxrate', '5M',         // Increased max bitrate
                '-bufsize', '10M',        // Increased buffer size
                '-pix_fmt', 'yuv420p',
                '-movflags', '+faststart',
                '-y'                      // Overwrite output file
            ])
            .output(outputPath)
            .on('end', () => {
                console.log('✅ High quality video processing completed');
                resolve();
            })
            .on('error', (err) => {
                console.error('❌ High quality processing error:', err);
                reject(err);
            })
            .on('progress', (progress) => {
                if (progress.percent) {
                    console.log(`Processing: ${Math.round(progress.percent)}% done`);
                }
            })
            .run();
    });
}

// Organization settings storage (in production, use database)
const organizationSettings = {};

// Get organization settings
app.get('/api/get-organization-settings', async (req, res) => {
    try {
        const organizationId = req.session.organizationId || req.session.user?.organizationId;

        if (!organizationId) {
            console.log('⚠️ Organization not found in session');
            return res.json({
                success: false,
                courierName: [],
                returnType: [],
                opsRemarks: [],
                channelName: [],
                message: 'Organization not found'
            });
        }

        console.log('✅ Loading settings for organization:', organizationId);

        const settings = await OrganizationSettings.findOne({ organizationId });

        if (settings) {
            console.log('✅ Found saved settings:', {
                courierName: settings.courierName?.length || 0,
                returnType: settings.returnType?.length || 0,
                opsRemarks: settings.opsRemarks?.length || 0,
                channelName: settings.channelName?.length || 0
            });

            // ✅ Return the actual data arrays, not nested in "settings"
            res.json({
                success: true,
                organizationId: settings.organizationId,
                courierName: settings.courierName || [],
                returnType: settings.returnType || [],
                opsRemarks: settings.opsRemarks || [],
                channelName: settings.channelName || []
            });
        } else {
            console.log('⚠️ No saved settings found, returning empty arrays');
            // Return empty arrays, frontend will use defaults
            res.json({
                success: false,
                organizationId: organizationId,
                courierName: [],
                returnType: [],
                opsRemarks: [],
                channelName: [],
                message: 'No saved settings found'
            });
        }
    } catch (error) {
        console.error('❌ Error loading organization settings:', error);
        res.json({
            success: false,
            courierName: [],
            returnType: [],
            opsRemarks: [],
            channelName: [],
            error: error.message
        });
    }
});
// Save organization settings
app.post('/api/save-organization-settings', async (req, res) => {
    try {
        const orgId = getOrganizationId(req);
        const { settings } = req.body;

        console.log(`Saving settings for organization: ${orgId}`);
        console.log(`📦 Settings data:`, settings);

        // Validate settings structure
        const requiredKeys = ['courierName', 'returnType', 'opsRemarks', 'channelName'];
        const isValid = requiredKeys.every(key =>
            settings[key] && Array.isArray(settings[key])
        );

        if (!isValid) {
            return res.json({
                success: false,
                message: 'Invalid settings structure'
            });
        }

        // 🔥 MONGO DB LA SAVE PANNU - Memory la alla!
        const result = await OrganizationSettings.findOneAndUpdate(
            { organizationId: orgId },
            {
                organizationId: orgId,
                courierName: settings.courierName,
                returnType: settings.returnType,
                opsRemarks: settings.opsRemarks,
                channelName: settings.channelName,
                updatedAt: new Date()
            },
            {
                upsert: true, // Create if not exists
                new: true
            }
        );

        console.log('✅ Settings saved to MongoDB:', result);

        res.json({
            success: true,
            message: 'Settings saved permanently to database',
            organizationId: orgId
        });
    } catch (error) {
        console.error('Error saving organization settings:', error);
        res.json({
            success: false,
            message: 'Error saving settings to database'
        });
    }
});

// Handle page unload
app.post('/api/page-unload', (req, res) => {
    console.log('📄 Page unload detected');
    // You can add cleanup logic here if needed
    res.json({ message: 'Page unload recorded' });
});

// Get dropdown options for current organization
app.get('/api/get-dropdown-options', async (req, res) => {
    try {
        const orgId = getOrganizationId(req);

        if (!orgId) {
            return res.status(400).json({
                success: false,
                error: 'Organization ID not found in session'
            });
        }

        console.log(`Loading dropdown options for organization: ${orgId}`);

        // Check MongoDB for saved settings
        const savedSettings = await OrganizationSettings.findOne({ organizationId: orgId });

        if (savedSettings) {
            console.log('✅ Using saved settings from MongoDB:', savedSettings);
            res.json({
                success: true,
                courierName: savedSettings.courierName || [],
                returnType: savedSettings.returnType || [],
                opsRemarks: savedSettings.opsRemarks || [],
                channelName: savedSettings.channelName || []
            });
        } else {
            // Use default settings only if no saved settings
            console.log('⚠️ Using default settings - no saved settings found');
            const defaultSettings = {
                success: true,
                courierName: ['Amazon', 'Delhivery', 'DTDC', 'Other'],
                returnType: ['RTO', 'RVP', 'Other'],
                opsRemarks: ['Good', 'Damaged', 'Missing Items', 'Other'],
                channelName: ['Shopify', 'Amazon', 'Flipkart', 'Other']
            };
            res.json(defaultSettings);
        }
    } catch (error) {
        console.error('Error loading dropdown options:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to load dropdown options'
        });
    }
});

// Initialize default settings for organizations
function initializeDefaultSettings() {
    const defaultSettings = {
        courierName: ['Amazon', 'Delhivery', 'DTDC', 'Ecom', 'Ekart', 'Franch Express', 'India Post', 'Shadowfax', 'Smarter', 'Tracon', 'Xpressbees', 'Other'],
        returnType: ['RTO', 'RVP', 'Other'],
        opsRemarks: ['Other Brand', 'Good', 'Damaged', 'Tag Missing', 'SKU Mismatch', 'Missing Items', 'Size Mismatch', 'Color Mismatch', 'Ean Mismatch'],
        channelName: ['Shopify', 'Amazon', 'Flipkart', 'Myntra', 'Nykaa', 'Other']
    };

    // Initialize some sample organizations
    organizationSettings['easy_tech'] = JSON.parse(JSON.stringify(defaultSettings));
    organizationSettings['newone_123'] = JSON.parse(JSON.stringify(defaultSettings));
    organizationSettings['default'] = JSON.parse(JSON.stringify(defaultSettings));

    console.log('Default organization settings initialized');
    Object.keys(organizationSettings).forEach(org => {
        console.log(`   ${org}: ${organizationSettings[org].courierName.length} couriers`);
    });
}
// Call this when server starts
initializeDefaultSettings();

/*
app.post("/api/save-recording-data", requireAuth, async (req, res) => {
    try {
        const { awbNo, courierName, returnType, opsRemarks } = req.body;
        const username = req.session.username || "Unknown";
        const userId = req.session.userId;

        if (!awbNo || !awbNo.trim()) {
            return res.status(400).json({ success: false, message: "AWB No is required" });
        }

        // ✅ Only update fields that exist to prevent empty overwrites
        const updateFields = { lastUpdated: new Date() };
        if (courierName) updateFields['additionalInfo.courierName'] = courierName;
        if (returnType) updateFields['additionalInfo.returnType'] = returnType;
        if (opsRemarks) updateFields['additionalInfo.opsRemarks'] = opsRemarks;

        const updateResult = await InventoryData.updateOne(
            { userId, awbNo: awbNo.trim() },
            { $set: updateFields }
        );

        if (updateResult.matchedCount === 0) {
            return res.status(404).json({
                success: false,
                message: "AWB not found in database. Please upload an image first."
            });
        }

        // ✅ Get updated DB record
        const inventoryData = await InventoryData.findOne({ userId, awbNo: awbNo.trim() });

        const spreadsheetId = process.env.RECORDING_SHEET_ID;
        const client = await auth.getClient();
        const sheets = google.sheets({ version: "v4", auth: client });

        // Get all rows
        const getRows = await sheets.spreadsheets.values.get({
            spreadsheetId,
            range: "Recordings!A:H",
        });
        const rows = getRows.data.values || [];

        const rowIndex = rows.findIndex(r => (r[0] || '').trim().toLowerCase() === awbNo.trim().toLowerCase());

        const updatedRow = [
            inventoryData.awbNo,
            inventoryData.additionalInfo?.courierName || '',
            inventoryData.additionalInfo?.returnType || '',
            inventoryData.additionalInfo?.opsRemarks || '',
            rows[rowIndex]?.[4] || new Date().toLocaleString("en-IN"),
            rows[rowIndex]?.[5] || username,
            rows[rowIndex]?.[6] || "Open AWB Folder",
            rows[rowIndex]?.[7] || "None"
        ];

        if (rowIndex !== -1) {
            await sheets.spreadsheets.values.update({
                spreadsheetId,
                range: `Recordings!A${rowIndex + 1}:H${rowIndex + 1}`,
                valueInputOption: "USER_ENTERED",
                resource: { values: [updatedRow] },
            });
        } else {
            await sheets.spreadsheets.values.append({
                spreadsheetId,
                range: "Recordings!A:H",
                valueInputOption: "USER_ENTERED",
                insertDataOption: "INSERT_ROWS",
                resource: { values: [updatedRow] },
            });
        }

        res.json({ success: true, message: "Data saved successfully", data: updatedRow });

    } catch (err) {
        console.error("❌ Error:", err);
        res.status(500).json({ success: false, message: `Failed: ${err.message}` });
    }
});
*/

app.post('/api/debug-email', async (req, res) => {
    try {
        const organizationId = req.session.organizationId;
        console.log('🔍 DEBUG ROUTE - Organization:', organizationId);
        console.log('🔍 DEBUG ROUTE - Client exists:', typeof client !== 'undefined');

        // Test database access
        const db = client.db('org_' + organizationId + '_db');

        // Test email settings
        const settingsCollection = db.collection('mail_settings');
        const smtpSettings = await settingsCollection.findOne({ type: 'smtp_settings' });
        console.log('🔍 DEBUG ROUTE - SMTP Settings:', smtpSettings ? 'Found' : 'Not found');

        // Test recipient settings
        const emailSettingsCollection = db.collection('email_settings');
        const emailSettings = await emailSettingsCollection.findOne({});
        console.log('🔍 DEBUG ROUTE - Email Settings:', emailSettings ? 'Found' : 'Not found');

        res.json({
            success: true,
            client: typeof client !== 'undefined',
            smtpSettings: !!smtpSettings,
            emailSettings: !!emailSettings
        });

    } catch (error) {
        console.error('❌ DEBUG ROUTE Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});


// Clean up any leftover temp files on server start
function cleanupOnStartup() {
    console.log('🧹 Cleaning up temp files on startup...');

    const tempDirs = [
        path.join(__dirname, 'temp_videos'),
        path.join(__dirname, 'temp_images')
    ];

    tempDirs.forEach(dir => {
        if (fs.existsSync(dir)) {
            try {
                const files = fs.readdirSync(dir);
                files.forEach(file => {
                    // Skip directories - only delete files
                    if (file.includes('.') && !file.startsWith('2025')) { // Simple check for files with extensions
                        const filePath = path.join(dir, file);
                        try {
                            const stats = fs.statSync(filePath);

                            // Delete files older than 1 hour (only files, not directories)
                            if (stats.isFile() && Date.now() - stats.mtimeMs > 86400000) {
                                fs.unlinkSync(filePath);
                                console.log(`Deleted old temp file: ${file}`);
                            }
                        } catch (fileError) {
                            console.error(`Error stating file ${file}:`, fileError.message);
                        }
                    }
                });
            } catch (error) {
                console.error('Error reading temp directory:', error.message);
            }
        }
    });
}

// Call this when your server starts
cleanupOnStartup();
async function getOrganizationTransporter(organizationId) {
    try {
        // Get SMTP settings from database for this organization
        const db = client.db('org_' + organizationId + '_db');
        const settingsCollection = db.collection('mail_settings');

        const smtpSettings = await settingsCollection.findOne({
            type: 'smtp_settings'
        });

        if (!smtpSettings || !smtpSettings.smtpEmail || !smtpSettings.smtpPassword) {
            throw new Error('SMTP credentials not found for organization: ' + organizationId);
        }

        // Create transporter with organization-specific credentials
        return nodemailer.createTransport({
            service: smtpSettings.smtpService || 'gmail',
            auth: {
                user: smtpSettings.smtpEmail,
                pass: smtpSettings.smtpPassword
            }
        });
    } catch (error) {
        console.error('Error getting organization transporter:', error);
        throw error;
    }
}


// Instead of using the global transporter, use:

/* Then send email with org-specific transporter
await orgTransporter.sendMail({
    from: smtpSettings.smtpEmail,
    to: recipient.email,
    subject: emailSubject,
    text: emailText,
    html: emailHtml,
    attachments: attachments
});*/

async function sendOrganizationEmail(client, organizationId, mailOptions) {
    try {
        console.log('🔐 Getting SMTP settings for organization:', organizationId);

        // Get SMTP settings from database for this organization
        const db = client.db('org_' + organizationId + '_db');
        const settingsCollection = db.collection('mail_settings');

        const smtpSettings = await settingsCollection.findOne({
            type: 'smtp_settings'
        });

        if (!smtpSettings) {
            throw new Error('SMTP settings not found. Please save your email settings first.');
        }

        if (!smtpSettings.smtpEmail || !smtpSettings.smtpPassword) {
            throw new Error('Email credentials not configured. Please enter sender email and password.');
        }

        console.log('📧 Using SMTP:', smtpSettings.smtpEmail);

        // Create transporter and send email
        const orgTransporter = nodemailer.createTransport({
            service: smtpSettings.smtpService || 'gmail',
            auth: {
                user: smtpSettings.smtpEmail,
                pass: smtpSettings.smtpPassword
            }
        });

        const result = await orgTransporter.sendMail({
            from: smtpSettings.smtpEmail,
            ...mailOptions
        });

        orgTransporter.close();
        return { success: true, result };

    } catch (error) {
        console.error('❌ Email error:', error.message);
        return { success: false, error: error.message };
    }
}


// Add queue for failed uploads (simple in-memory queue)
const failedUploadsQueue = [];
const MAX_QUEUE_SIZE = 100;

function addToRetryQueue(filePath, fileName, year, month, day, awbNo, mediaType, scannedData, userId, organizationId, courierName = null, returnType = null, opsRemarks = null, channelName = null, existingDriveLink = null) {
    if (failedUploadsQueue.length >= MAX_QUEUE_SIZE) {
        console.log('📛 Upload queue full, discarding oldest item');
        failedUploadsQueue.shift();
    }

    failedUploadsQueue.push({
        filePath,
        fileName,
        year,
        month,
        day,
        awbNo,
        mediaType,
        scannedData,
        userId,
        organizationId, // Add organization ID
        courierName,
        returnType,
        opsRemarks,
        channelName,
        existingDriveLink,
        retryCount: 0,
        addedAt: new Date()
    });

    console.log(`📥 Added to retry queue: ${fileName} for org ${organizationId} (queue size: ${failedUploadsQueue.length})`);
}

// Process the retry queue periodically
async function processUploadQueue() {
    if (failedUploadsQueue.length === 0) return;


    const item = failedUploadsQueue[0];

    // Check if file already exists in Google Drive before retrying
    console.log(`🔍 Checking if file already uploaded: ${item.fileName}`);

    try {
        // ONLY RETRY DATABASE UPDATE, NOT FILE UPLOAD
        console.log(`🔄 Retrying queued upload: ${item.fileName}`);

        // Assume file already uploaded, just update database
        const fileDetails = {
            webViewLink: item.existingDriveLink || 'https://drive.google.com/drive/folders/unknown', // Use existing link if available
            awbFolderLink: item.existingFolderLink || 'https://drive.google.com/drive/folders/unknown'
        };

        // Update database
        await updateDatabaseWithDriveLink(
            item.awbNo,
            item.fileName,
            fileDetails.webViewLink,
            item.mediaType,
            item.scannedData,
            item.userId,
            fileDetails.awbFolderLink, // ✅ extra param
            item.courierName,    // Add these missing fields
            item.returnType,
            item.opsRemarks,
            item.channelName,
            item.orderId || 'NOT_SPECIFIED'  // ADD ORDERID HERE
        );
        console.log(`✅ Database update succeeded for: ${item.fileName}`);
        // Remove from queue
        failedUploadsQueue.shift();

    } catch (error) {
        console.error(`❌ Queued upload failed: ${item.fileName}`, error);

        // Update retry count
        item.retryCount++;

        // Remove if too many retries
        if (item.retryCount >= 5) {
            console.log(`📛 Removing from queue after ${item.retryCount} failures: ${item.fileName}`);
            failedUploadsQueue.shift();

            // File already uploaded, no need to clean up
            console.log(`⚠️ File uploaded but database not updated: ${item.fileName}`);
        }
    }
}

// Process the upload queue every minute
setInterval(processUploadQueue, 60000);

// Increase timeout for Google Drive uploads (5 minutes)
const DRIVE_UPLOAD_TIMEOUT = 300000; // 5 minutes

// Add this function after your existing requires
function ensureDirectoryExists(dirPath) {
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
}

// Create local backup function using regular fs
// CORRECTED Local backup function - COPY instead of MOVE
async function saveToLocalBackup(filePath, newFileName, folderStructure) {
    try {
        const localBasePath = path.join(__dirname, 'local_backup');
        const fullPath = path.join(localBasePath, ...folderStructure);

        // Ensure directory exists
        if (!fs.existsSync(fullPath)) {
            fs.mkdirSync(fullPath, { recursive: true });
        }

        const destination = path.join(fullPath, newFileName);

        // COPY the file (don't move it!) - This is the fix
        fs.copyFileSync(filePath, destination);

        return {
            success: true,
            localPath: destination,
            message: 'File copied locally'
        };
    } catch (error) {
        console.error('Local backup error:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

async function updateDatabaseAsync(userId, awbNo, mediaType, fileName, fileDetails, scannedData) {
    try {
        let inventory = await InventoryData.findOne({ awbNo, userId });

        if (!inventory) {
            inventory = new InventoryData({
                userId,
                awbNo,
                categoryData: {
                    good: { count: 0, eans: [] },
                    bad: { count: 0, eans: [] },
                    used: { count: 0, eans: [] },
                    wrong: { count: 0, eans: [] }
                },
                mediaFiles: []
            });
        }

        if (!inventory.mediaFiles) {
            inventory.mediaFiles = [];
        }

        inventory.mediaFiles.push({
            type: mediaType,
            fileName: fileName,
            driveLink: fileDetails.webViewLink,
            scannedData: scannedData,
            uploadDate: new Date()
        });

        await inventory.save();
        console.log(`📝 Database updated with ${mediaType} file info`);

    } catch (dbError) {
        console.error('❌ Database update error:', dbError);
        // Don't propagate error since upload was successful
    }
}

// Function to update database with drive link later
async function updateDatabaseWithDriveLink(awbNo, fileName, driveLink, mediaType, scannedData, userId, awbFolderLink, courierName, returnType, opsRemarks, channelName, organizationId, orderId = 'NOT_SPECIFIED') {
    try {
        // Switch to organization database
        const orgDb = mongoose.connection.useDb(`org_${organizationId}_db`);

        // Define user schema for organization database
        const userSchema = new mongoose.Schema({
            username: String,
            email: String,
            password: String,
            role: String,
            org_id: String,
            isActive: Boolean,
            last_login: Date,
            last_logout: Date,
            login_status: String,
            created_at: Date
        });

        const OrgUser = orgDb.model('User', userSchema);

        // Get user from organization database
        const user = await OrgUser.findById(userId);
        if (!user) {
            console.error('User not found in organization database for ID:', userId);
            // Try to get username from session as fallback
            const username = 'easyadmin'; // You might need to pass this as parameter
            console.log('Using fallback username:', username);

            // Continue with fallback username
            const inventory = await InventoryData.findOne({ awbNo, organization: organizationId });
            if (inventory) {
                inventory.username = username;
                await inventory.save();
            }
            return;
        }

        // Find or create inventory
        let inventory = await InventoryData.findOne({ awbNo, organization: organizationId });
        if (!inventory) {
            inventory = new InventoryData({
                userId,
                username: user.username,
                awbNo,
                courierName,
                returnType,
                opsRemarks,
                channelName,
                orderId,
                categoryData: {
                    good: { count: 0, eans: [] },
                    bad: { count: 0, eans: [] },
                    used: { count: 0, eans: [] },
                    wrong: { count: 0, eans: [] }
                },
                mediaFiles: [],
                awbFolderLink: awbFolderLink || null,
                organization: organizationId
            });
        }

        // Always keep latest folder link
        if (awbFolderLink && (!inventory.awbFolderLink || inventory.awbFolderLink !== awbFolderLink)) {
            inventory.awbFolderLink = awbFolderLink;
        }

        if (!inventory.mediaFiles) inventory.mediaFiles = [];

        // Update existing file or add new
        const existingFileIndex = inventory.mediaFiles.findIndex(f => f.fileName === fileName);
        if (existingFileIndex !== -1) {
            inventory.mediaFiles[existingFileIndex].driveLink = driveLink;
            inventory.mediaFiles[existingFileIndex].awbFolderLink = awbFolderLink || inventory.mediaFiles[existingFileIndex].awbFolderLink;
            inventory.mediaFiles[existingFileIndex].driveSyncDate = new Date();
        } else {
            inventory.mediaFiles.push({
                type: mediaType,
                fileName,
                driveLink,
                awbFolderLink: awbFolderLink || null,
                scannedData: scannedData || 'None',
                uploadDate: new Date(),
                driveSyncDate: new Date()
            });
        }

        await inventory.save();
        console.log(`📝 Database updated with REAL Drive link for ${fileName} in org ${organizationId}`);
        return inventory.awbFolderLink;
    } catch (err) {
        console.error('❌ Error updating database with Drive link:', err);
        throw err;
    }
}



// Cleanup expired temp files function (call this periodically)
function cleanupTempFiles() {
    const now = Date.now();
    const maxAge = 3600000; // 1 hour

    // Clean video files
    Object.keys(tempVideoStorage).forEach(key => {
        if (now - tempVideoStorage[key].timestamp > maxAge) {
            try {
                if (fs.existsSync(tempVideoStorage[key].tempFile)) {
                    fs.unlinkSync(tempVideoStorage[key].tempFile);
                }
                delete tempVideoStorage[key];
                console.log(`Cleaned up expired temp video: ${key}`);
            } catch (error) {
                console.error('Error cleaning up temp video:', error);
            }
        }
    });

    // Clean image files
    Object.keys(tempImageStorage).forEach(key => {
        if (now - tempImageStorage[key].timestamp > maxAge) {
            try {
                if (fs.existsSync(tempImageStorage[key].tempFile)) {
                    fs.unlinkSync(tempImageStorage[key].tempFile);
                }
                delete tempImageStorage[key];
                console.log(`Cleaned up expired temp image: ${key}`);
            } catch (error) {
                console.error('Error cleaning up temp image:', error);
            }
        }
    });
}

// Run cleanup every hour
setInterval(cleanupTempFiles, 3600000);



// Replace the entire /generate-excel endpoint with this improved version
// In app.js - Replace the /generate-excel endpoint
app.post('/generate-excel', requireAuth, async (req, res) => {
    try {
        const { summaryData, eanDetailsData, recordingsData } = req.body;
        const userId = req.session.userId;

        console.log('=== EXCEL GENERATION START ===');

        // Get all inventory data for this user
        const inventoryData = await InventoryData.find({ userId }).sort({ timestamp: -1 });

        // Create Excel workbook
        const workbook = new ExcelJS.Workbook();

        // ===== SHEET 1: SUMMARY SHEET =====
        const summarySheet = workbook.addWorksheet('Summary');
        summarySheet.addRow([
            'AWB No', 'Courier Name', 'Return Type', 'OPS Remarks', 'Channel Name',
            'Good', 'Bad', 'Used', 'Wrong', 'Total', 'Date', 'Operator'
        ]);

        summarySheet.columns = [
            { width: 15 }, { width: 10 }, { width: 10 }, { width: 10 }, { width: 20 },
            { width: 10 }, { width: 10 }, { width: 20 }, { width: 15 }
        ];

        if (inventoryData.length > 0) {
            inventoryData.forEach(item => {
                const total = item.categoryData.good.count + item.categoryData.bad.count +
                    item.categoryData.used.count + item.categoryData.wrong.count;

                summarySheet.addRow([
                    item.awbNo,
                    item.additionalInfo?.courierName || 'Not specified',
                    item.additionalInfo?.returnType || 'Not specified',
                    item.additionalInfo?.opsRemarks || 'Not specified',
                    item.additionalInfo?.channelName || 'Not specified',
                    item.categoryData.good.count,
                    item.categoryData.bad.count,
                    item.categoryData.used.count,
                    item.categoryData.wrong.count,
                    total,
                    item.timestamp.toLocaleString(),
                    req.session.username || 'Unknown'
                ]);
            });
        } else {
            summarySheet.addRow(['No Summary Data Available']);
        }

        // Format summary sheet
        summarySheet.getRow(1).font = { bold: true };
        summarySheet.getRow(1).fill = {
            type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6E6E6' }
        };

        // ===== SHEET 2: EAN DETAILS SHEET =====
        const eanSheet = workbook.addWorksheet('EAN Details');

        if (inventoryData.length > 0) {
            eanSheet.addRow([
                'AWB No', 'Courier Name', 'Return Type', 'OPS Remarks', 'Channe Name',
                'EAN', 'Status', 'Date', 'Operator'
            ]);

            inventoryData.forEach(item => {
                ['good', 'bad', 'used', 'wrong'].forEach(status => {
                    const eanList = item.categoryData[status]?.eans || [];
                    eanList.forEach(ean => {
                        eanSheet.addRow([
                            item.awbNo,
                            item.additionalInfo?.courierName || 'Not specified',
                            item.additionalInfo?.returnType || 'Not specified',
                            item.additionalInfo?.opsRemarks || 'Not specified',
                            item.additionalInfo?.channelName || 'Not specified',
                            ean,
                            status.charAt(0).toUpperCase() + status.slice(1),
                            item.timestamp.toLocaleString(),
                            req.session.username || 'Unknown'
                        ]);
                    });
                });
            });

            eanSheet.getRow(1).font = { bold: true };
            eanSheet.getRow(1).fill = {
                type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6E6E6' }
            };
            eanSheet.columns.forEach(column => {
                column.width = 20;
            });
        } else {
            eanSheet.addRow(['No EAN Details Data Available']);
        }

        // ===== SHEET 3: RECORDINGS SHEET (UPDATED) =====
        const recordingsSheet = workbook.addWorksheet('Recordings');
        recordingsSheet.addRow([
            'AWB No', 'Courier Name', 'Return Type', 'OPS Remarks', 'Channel Name',
            'Date', 'Operator', 'Google Drive Link', 'Scanned Data'
        ]);

        recordingsSheet.columns = [
            { width: 15 }, { width: 20 }, { width: 15 }, { width: 20 }, { width: 20 },
            { width: 25 }, { width: 15 }, { width: 50 }, { width: 30 }
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
                        timestamp: item.timestamp,
                        username: item.username || 'Unknown',
                        scannedData: '',
                        driveLink: ''
                    });
                }
                const awbData = awbMap.get(item.awbNo);

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

                // ✅ New safe logic: find any file that has a folder link
                const folderLink = item.mediaFiles.find(f => f.awbFolderLink)?.awbFolderLink;

                if (folderLink) {
                    awbData.driveLink = folderLink;   // Always use AWB folder link if available
                } else {
                    awbData.driveLink = item.mediaFiles[0]?.driveLink || ''; // fallback: file link
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
                    awbData.timestamp.toLocaleString(),
                    awbData.username,
                    '', // Placeholder for hyperlink
                    awbData.scannedData || 'None'
                ]);

                // Add clickable hyperlink to Google Drive folder
                if (awbData.driveLink) {
                    const linkCell = recordingsSheet.getCell(`H${row.number}`);
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

            // If no media files found at all
            if (recordingsSheet.rowCount === 1) {
                recordingsSheet.addRow(['No media files uploaded yet']);
            }
        } else {
            recordingsSheet.addRow(['No recording data available']);
        }

        // Format the header row
        recordingsSheet.getRow(1).font = { bold: true };
        recordingsSheet.getRow(1).fill = {
            type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE6E6E6' }
        };

        console.log('=== EXCEL GENERATION COMPLETE ===');

        // Send Excel file
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename=warehouse_export_${Date.now()}.xlsx`);

        await workbook.xlsx.write(res);
        res.end();

    } catch (error) {
        console.error('❌ Excel Generation Error:', error);
        res.status(500).json({ error: 'Failed to generate Excel file: ' + error.message });
    }
});


// DEBUG ROUTE
app.get('/debug-users', async (req, res) => {
    try {
        const users = await User.find({});
        console.log('All users in database:', users);
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Error fetching users' });
    }
});

// Test route
app.get('/test-ffmpeg', (req, res) => {
    ffmpeg.getAvailableFormats((err, formats) => {
        if (err) {
            console.error('FFmpeg test failed:', err);
            return res.status(500).json({
                error: 'FFmpeg not working',
                details: err.message
            });
        }

        console.log('FFmpeg is working. Available formats:', Object.keys(formats).length);
        res.json({
            message: 'FFmpeg is working correctly',
            availableFormats: Object.keys(formats).length
        });
    });
});

// Session cleanup on server shutdown
process.on('SIGINT', () => {
    console.log('\nServer shutting down...');

    // Stop all active recordings
    Object.values(activeRecordings).forEach(({ command }) => {
        command.kill('SIGINT');
    });

    // Clear working session data
    Object.keys(workingSessionData).forEach(userId => {
        delete workingSessionData[userId];
    });

    mongoose.connection.close();
    process.exit(0);
});

// Clean up expired temp videos periodically (every hour)
setInterval(() => {
    const now = Date.now();
    const tempDir = path.join(__dirname, 'temp_videos');

    Object.keys(tempVideoStorage).forEach(key => {
        const storage = tempVideoStorage[key];
        // Remove temp files older than 1 hour
        if (now - storage.timestamp > 3600000) {
            try {
                if (fs.existsSync(storage.tempFile)) {
                    fs.unlinkSync(storage.tempFile);
                    console.log(`Cleaned up expired temp video: ${storage.tempFile}`);
                }
                delete tempVideoStorage[key];
            } catch (error) {
                console.error('Error cleaning up temp video:', error);
            }
        }
    });
}, 3600000); // Run every hour

// Function to get the actual LAN IP address
function getLanIp() {
    const nets = os.networkInterfaces();

    if (nets['Wi-Fi']) {
        for (const net of nets['Wi-Fi']) {
            if (net.family === 'IPv4' && !net.internal && ip.isPrivate(net.address)) {
                return net.address;
            }
        }
    }

    for (const name of Object.keys(nets)) {
        if (
            name.toLowerCase().includes('virtual') ||
            name.toLowerCase().includes('vmware') ||
            name.toLowerCase().includes('hyper-v') ||
            name.toLowerCase().includes('vbox') ||
            name.toLowerCase().includes('loopback')
        ) {
            continue;
        }

        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal && ip.isPrivate(net.address)) {
                return net.address;
            }
        }
    }

    return ip.address();
}

const lanIp = getLanIp();

if (sslOptions && process.env.NODE_ENV !== 'production') {
    // 🔒 Local Development - HTTPS Server
    https.createServer(sslOptions, app).listen(port, '0.0.0.0', () => {
        console.log(`=================================================`);
        console.log(`🔒 HTTPS Server running (Local Development)`);
        console.log(`Local access:   https://localhost:${port}`);
        console.log(`Network access: https://${lanIp}:${port}`);
        console.log(`Share this URL with others on the same network:`);
        console.log(`>>> https://${lanIp}:${port} <<<`);
        console.log(`=================================================`);

        const dirs = ['videos', 'camera', 'temp_videos'];
        dirs.forEach(dir => {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
        });
    });
} else {
    // 🌐 Production - HTTP Server (Render handles HTTPS)
    app.listen(port, '0.0.0.0', () => {
        console.log(`=================================================`);
        console.log(`🚀 Server is running!`);
        console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log(`Port: ${port}`);
        console.log(`=================================================`);

        const dirs = ['videos', 'camera', 'temp_videos'];
        dirs.forEach(dir => {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
        });
    });
}