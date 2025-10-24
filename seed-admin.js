// admin-setup.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const readline = require('readline');

// Create interface for user input
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// User Schema (matches your User.js)
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        minlength: [3, 'Username must be at least 3 characters long']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, 'Please enter a valid email address']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters long']
    },
    role: {
        type: String,
        default: 'admin',
        enum: ['admin', 'user']
    },
    autoMailEnabled: {
        type: Boolean,
        default: false
    },
    autoMailRecipient: {
        type: [String],
        default: []
    },
    autoMailTime: {
        type: String,
        default: '09:00'
    },
    autoMailDays: {
        type: [String],
        default: ['Monday', 'Wednesday', 'Friday']
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    
    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(this.password, saltRounds);
        this.password = hashedPassword;
        next();
    } catch (error) {
        next(error);
    }
});

const User = mongoose.model('User', userSchema);

// Function to validate email format
function isValidEmail(email) {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
}

// Function to validate password strength
function isValidPassword(password) {
    return password.length >= 6;
}

// Function to get input from user
function askQuestion(question) {
    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            resolve(answer);
        });
    });
}

// Main function
async function main() {
    console.log('================================');
    console.log('   ADMIN ACCOUNT SETUP');
    console.log('================================\n');

    try {
        // Get database connection details
        const dbHost = await askQuestion('Database host (default: localhost): ') || 'localhost';
        const dbPort = await askQuestion('Database port (default: 27017): ') || '27017';
        const dbName = await askQuestion('Database name: ');
        
        if (!dbName) {
            console.log('\n❌ Database name is required!');
            rl.close();
            return;
        }

        // Construct MongoDB URI
        const mongoURI = `mongodb://${dbHost}:${dbPort}/${dbName}`;
        
        console.log(`\n🔗 Connecting to MongoDB: ${mongoURI}`);
        
        // Connect to MongoDB
        await mongoose.connect(mongoURI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        
        console.log('✅ Connected to MongoDB successfully!');

        // Check if admin already exists
        const adminExists = await User.findOne({ role: 'admin' });
        if (adminExists) {
            console.log('\n⚠️ Admin account already exists:');
            console.log(`   Username: ${adminExists.username}`);
            console.log(`   Email: ${adminExists.email}`);
            console.log(`   Created: ${adminExists.createdAt}`);
            
            const continueSetup = await askQuestion('\nDo you want to create another admin? (y/N): ');
            if (continueSetup.toLowerCase() !== 'y') {
                console.log('Setup cancelled.');
                rl.close();
                return;
            }
        }

        // Get admin account details
        console.log('\nPlease enter admin account details:');
        
        let username, email, password, confirmPassword;
        let validInput = false;
        
        while (!validInput) {
            username = await askQuestion('Username: ');
            if (!username || username.length < 3) {
                console.log('❌ Username must be at least 3 characters long');
                continue;
            }
            
            // Check if username already exists
            const existingUser = await User.findOne({ username });
            if (existingUser) {
                console.log('❌ Username already exists. Please choose a different one.');
                continue;
            }
            
            email = await askQuestion('Email: ');
            if (!isValidEmail(email)) {
                console.log('❌ Please enter a valid email address');
                continue;
            }
            
            // Check if email already exists
            const existingEmail = await User.findOne({ email });
            if (existingEmail) {
                console.log('❌ Email already exists. Please use a different one.');
                continue;
            }
            
            password = await askQuestion('Password: ');
            if (!isValidPassword(password)) {
                console.log('❌ Password must be at least 6 characters long');
                continue;
            }
            
            confirmPassword = await askQuestion('Confirm Password: ');
            if (password !== confirmPassword) {
                console.log('❌ Passwords do not match');
                continue;
            }
            
            validInput = true;
        }

        // Create admin user
        const adminUser = new User({
            username,
            email,
            password,
            role: 'admin',
            autoMailEnabled: false,
            autoMailRecipient: [],
            autoMailTime: '09:00',
            autoMailDays: ['Monday', 'Wednesday', 'Friday']
        });

        // Save to database
        await adminUser.save();
        
        console.log('\n✅ Admin account created successfully!');
        console.log('================================');
        console.log('   ADMIN ACCOUNT DETAILS');
        console.log('================================');
        console.log(`   Username: ${adminUser.username}`);
        console.log(`   Email: ${adminUser.email}`);
        console.log(`   Role: ${adminUser.role}`);
        console.log(`   Created: ${adminUser.createdAt}`);
        console.log('================================');
        console.log('⚠️ Please keep these details secure!');

    } catch (error) {
        console.error('\n❌ Error:', error.message);
    } finally {
        rl.close();
        mongoose.connection.close();
    }
}

// Run the script
main();