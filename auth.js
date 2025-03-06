const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// User Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        trim: true,
        minlength: [3, 'Username must be at least 3 characters long'],
        maxlength: [30, 'Username cannot exceed 30 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email address']
    },
    password: {
        type: String,
        required: function() { return !this.googleId && !this.githubId; }, // Only required if not using social auth
        minlength: [6, 'Password must be at least 6 characters long']
    },
    role: {
        type: String,
        required: [true, 'Role is required'],
        enum: ['professional', 'student', 'company'],
        default: 'student'
    },
    googleId: {
        type: String,
        sparse: true,
        unique: true
    },
    githubId: {
        type: String,
        sparse: true,
        unique: true
    },
    profilePicture: {
        type: String
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date
    },
    isActive: {
        type: Boolean,
        default: true
    }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    next();
});

// Method to check password
userSchema.methods.comparePassword = async function(password) {
    return await bcrypt.compare(password, this.password);
};

// Method to generate auth token
userSchema.methods.generateAuthToken = function() {
    const token = jwt.sign(
        { 
            userId: this._id,
            username: this.username,
            email: this.email,
            role: this.role
        },
        'your-secret-key', // Replace this with a secure secret key in production
        { expiresIn: '24h' }
    );
    return token;
};

// Static method to validate user data
userSchema.statics.validateUser = function(userData) {
    const errors = {};

    if (!userData.username || userData.username.length < 3) {
        errors.username = 'Username must be at least 3 characters long';
    }

    if (!userData.email || !userData.email.match(/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/)) {
        errors.email = 'Please enter a valid email address';
    }

    if (!userData.password || userData.password.length < 6) {
        errors.password = 'Password must be at least 6 characters long';
    }

    if (!userData.role || !['professional', 'student', 'company'].includes(userData.role)) {
        errors.role = 'Please select a valid role';
    }

    return {
        isValid: Object.keys(errors).length === 0,
        errors
    };
};

const User = mongoose.model('User', userSchema);

module.exports = User;
