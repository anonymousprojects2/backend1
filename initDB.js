const mongoose = require('mongoose');
const connectDB = require('./db');

async function initializeDatabase() {
    try {
        // Connect to MongoDB
        await connectDB();
        console.log('Connected to MongoDB successfully');

        // Create indexes for better query performance and unique constraints
        const collections = await mongoose.connection.db.collections();
        
        // If users collection doesn't exist, it will be created automatically
        // when the first document is inserted
        const usersCollection = mongoose.connection.db.collection('users');
        
        // Create indexes
        await usersCollection.createIndex({ email: 1 }, { unique: true });
        await usersCollection.createIndex({ username: 1 }, { unique: true });

        console.log('Database initialized successfully');
        process.exit(0);
    } catch (error) {
        console.error('Error initializing database:', error);
        process.exit(1);
    }
}

initializeDatabase(); 