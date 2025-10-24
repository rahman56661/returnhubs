// db-connections.js (Root directory - app.js oda same folder la create pannu)
const mongoose = require('mongoose');

const connections = {};

// Database name standardization function
function generateDatabaseName(organizationId) {
    // Always convert to lowercase and remove special characters
    const cleanId = organizationId.toLowerCase().replace(/[^a-z0-9]/g, '_');
    return `org_${cleanId}_db`;
}

// Check if database exists (case-insensitive)
async function checkDatabaseExists(dbName) {
    try {
        const adminDb = mongoose.connection.db.admin();
        const databases = await adminDb.listDatabases();
        return databases.databases.some(db => 
            db.name.toLowerCase() === dbName.toLowerCase()
        );
    } catch (error) {
        console.error('Error checking database existence:', error);
        return false;
    }
}

async function getOrganizationDB(organizationId) {
    // Standardize the organization ID
    const standardizedId = organizationId.toLowerCase().replace(/[^a-z0-9]/g, '_');
    const databaseName = generateDatabaseName(organizationId);
    
    console.log(`🔄 Requested org: ${organizationId}, Standardized: ${standardizedId}, DB: ${databaseName}`);
    
    // Check if connection already exists for standardized ID
    if (connections[standardizedId]) {
        console.log(`✅ Using existing connection for: ${standardizedId}`);
        return connections[standardizedId];
    }
    
    // Check if database exists with different case
    const existingDbs = await mongoose.connection.db.admin().listDatabases();
    const existingDb = existingDbs.databases.find(db => 
        db.name.toLowerCase() === databaseName.toLowerCase()
    );
    
    let actualDatabaseName = databaseName;
    
    if (existingDb && existingDb.name !== databaseName) {
        // Case mismatch found - use existing database name
        console.warn(`⚠️ Database case mismatch: Using existing ${existingDb.name} instead of ${databaseName}`);
        actualDatabaseName = existingDb.name;
    }
    
    const connectionString = `mongodb://127.0.0.1:27017/${actualDatabaseName}`;
    
    console.log(`🔄 Creating database connection for: ${actualDatabaseName}`);
    
    try {
        connections[standardizedId] = await mongoose.createConnection(connectionString, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        console.log(`✅ Database connection created for organization: ${standardizedId} (DB: ${actualDatabaseName})`);
        return connections[standardizedId];
    } catch (error) {
        console.error(`❌ Database connection failed for ${actualDatabaseName}:`, error);
        throw error;
    }
}

// Get actual database name for an organization (for display purposes)
async function getActualDatabaseName(organizationId) {
    const databaseName = generateDatabaseName(organizationId);
    const existingDbs = await mongoose.connection.db.admin().listDatabases();
    const existingDb = existingDbs.databases.find(db => 
        db.name.toLowerCase() === databaseName.toLowerCase()
    );
    
    return existingDb ? existingDb.name : databaseName;
}

// Cleanup function to close connections
function closeOrganizationConnection(organizationId) {
    const standardizedId = organizationId.toLowerCase().replace(/[^a-z0-9]/g, '_');
    if (connections[standardizedId]) {
        connections[standardizedId].close();
        delete connections[standardizedId];
        console.log(`🔴 Closed connection for organization: ${standardizedId}`);
    }
}

// Default/main database connection (existing warehouse-db)
const mainDB = mongoose.connection;

module.exports = { 
    getOrganizationDB, 
    mainDB, 
    generateDatabaseName,
    getActualDatabaseName,
    closeOrganizationConnection
};