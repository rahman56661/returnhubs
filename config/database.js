const { MongoClient } = require('mongodb');

let client = null;

const getOrgDatabase = (org_id) => {
    try {
        if (!client) {
            throw new Error('Database client not initialized. Call initDatabase first.');
        }
        
        const dbName = `org_${org_id}_db`;
        return client.db(dbName);
    } catch (error) {
        console.error('Database error:', error);
        throw error;
    }
};

// Add initialization function
const initDatabase = async () => {
    try {
        client = new MongoClient(process.env.MONGODB_URI || 'mongodb://localhost:27017');
        await client.connect();
        console.log('✅ Database client connected');
    } catch (error) {
        console.error('❌ Database connection failed:', error);
        throw error;
    }
};

module.exports = { getOrgDatabase, initDatabase };