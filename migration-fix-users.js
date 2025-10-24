// migration-fix-users.js (create this file)
const mongoose = require('mongoose');
require('dotenv').config();

async function migrateUsers() {
    try {
        //await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/warehouse-db');
        console.log('Connected to MongoDB');

        const User = require('./models/User');
        const Organization = require('./models/Organization');

        // Find or create default organization
        let defaultOrg = await Organization.findOne({ organizationId: 'default' });
        if (!defaultOrg) {
            defaultOrg = new Organization({
                name: 'Default Organization',
                displayName: 'Default Organization',
                organizationId: 'default',
                description: 'Default organization for existing users',
                contactEmail: 'admin@default.com',
                databaseName: 'org_default_db'
            });
            await defaultOrg.save();
            console.log('✅ Created default organization');
        }

        // Update all existing users
        const result = await User.updateMany(
            { 
                $or: [
                    { organization: { $exists: false } },
                    { organization: null },
                    { role: { $nin: ['superadmin', 'orgadmin', 'user', 'admin'] } }
                ]
            },
            { 
                $set: { 
                    organization: defaultOrg._id,
                    role: 'user'
                } 
            }
        );

        console.log(`✅ Migrated ${result.modifiedCount} users`);
        console.log('Migration completed successfully');
        
        process.exit(0);
    } catch (error) {
        console.error('Migration error:', error);
        process.exit(1);
    }
}

migrateUsers();