// scripts/setupDefaultOrg.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Organization = require('../models/Organization');
const readline = require('readline');

// For user input
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function askQuestion(question) {
    return new Promise((resolve) => {
        rl.question(question, resolve);
    });
}

async function setupDefaultOrganization() {
    try {
        // MongoDB connection to MAIN database
        await mongoose.connect('mongodb+srv://rahman:rahman123@cluster0.s153gdl.mongodb.net/returnhubs', {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });

        console.log('✅ Connected to MongoDB (main database)');
        console.log('================================');

        // Check if default organization already exists
        const existingOrg = await Organization.findOne({ organizationId: 'default' });
        
        if (existingOrg) {
            console.log('⚠️ Default organization already exists');
            
            const overwrite = await askQuestion('Do you want to recreate admin user? (y/n): ');
            if (overwrite.toLowerCase() !== 'y') {
                await mongoose.connection.close();
                rl.close();
                return;
            }
        }

        // Create or get default organization
        let defaultOrg;
        if (existingOrg) {
            defaultOrg = existingOrg;
            console.log('✅ Using existing organization:', defaultOrg.organizationId);
        } else {
            defaultOrg = new Organization({
                name: "Default Organization",
                displayName: "Default Organization", 
                organizationId: "default",
                organizationName: "default_organization",
                description: "Default organization for existing users",
                contactEmail: "admin@default.com",
                phone: "+91 9876543210",
                isActive: true,
                databaseName: "org_default_db"
                // databaseName auto-generates from pre-save hook
            });
            await defaultOrg.save();
            console.log('✅ Default organization created');
        }

        console.log('   Database:', defaultOrg.databaseName);
        console.log('================================');

        // Switch to ORGANIZATION database
        const orgDb = mongoose.connection.useDb(defaultOrg.databaseName);
        
        // Create User model for organization database
        const userSchema = new mongoose.Schema({
            username: { type: String, required: true, unique: true },
            email: { type: String, required: true, unique: true },
            password: { type: String, required: true },
            role: { type: String, default: 'admin', enum: ['super_admin', 'admin', 'manager', 'user'] },
            org_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization' },
            isActive: { type: Boolean, default: true },
            last_login: { type: Date },
            created_at: { type: Date, default: Date.now }
        });

        const OrgUser = orgDb.model('User', userSchema);

        // Check if admin user already exists
        const existingAdmin = await OrgUser.findOne({ role: 'super_admin' });
        if (existingAdmin) {
            console.log('⚠️ Super admin already exists:', existingAdmin.username);
            
            const recreate = await askQuestion('Create new admin user? (y/n): ');
            if (recreate.toLowerCase() !== 'y') {
                await mongoose.connection.close();
                rl.close();
                return;
            }
        }

        // Get admin details from user
        console.log('\n🎯 CREATE SUPER ADMIN ACCOUNT');
        console.log('================================');
        
        const username = await askQuestion('Super Admin Username: ');
        const email = await askQuestion('Super Admin Email: ');
        const password = await askQuestion('Super Admin Password: ');
        const confirmPassword = await askQuestion('Confirm Password: ');

        if (password !== confirmPassword) {
            console.log('❌ Passwords do not match!');
            await mongoose.connection.close();
            rl.close();
            return;
        }

        // Create super admin user
        const superAdmin = new OrgUser({
            username: username.trim(),
            email: email.trim(),
            password: await bcrypt.hash(password, 12),
            role: 'super_admin',
            org_id: defaultOrg._id,
            isActive: true
        });

        await superAdmin.save();

        console.log('\n✅ SUPER ADMIN ACCOUNT CREATED!');
        console.log('================================');
        console.log('   Organization:', defaultOrg.displayName);
        console.log('   Database:', defaultOrg.databaseName);
        console.log('   Username:', superAdmin.username);
        console.log('   Email:', superAdmin.email);
        console.log('   Role:', superAdmin.role);
        console.log('   Created:', new Date().toLocaleString());
        console.log('================================');
        console.log('⚠️  Keep these credentials secure!');
        console.log('================================');

        await mongoose.connection.close();
        rl.close();
        console.log('✅ Setup completed successfully!');

    } catch (error) {
        console.error('❌ Setup error:', error);
        process.exit(1);
    }
}

// Run the setup
setupDefaultOrganization();