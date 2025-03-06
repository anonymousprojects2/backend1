require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const connectDB = require('./db');
const User = require('./auth');
const path = require('path');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;

const app = express();

// Connect to MongoDB
connectDB();

// Passport configuration
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            user = await User.create({
                username: profile.displayName,
                email: profile.emails[0].value,
                googleId: profile.id,
                profilePicture: profile.photos[0].value,
                role: 'student' // Default role
            });
        }
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/api/auth/github/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ githubId: profile.id });
        if (!user) {
            user = await User.create({
                username: profile.username,
                email: profile.emails[0].value,
                githubId: profile.id,
                profilePicture: profile.photos[0].value,
                role: 'student' // Default role
            });
        }
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(passport.initialize());

// Serve static files from the Frontend directory
app.use(express.static(path.join(__dirname, '../Frontend')));
app.use('/static', express.static(path.join(__dirname, '../Frontend/static')));

// Serve index.html for the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../Frontend/index.html'));
});

// Signup Route
app.post('/api/signup', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        // Validate user input
        const validation = User.validateUser({ username, email, password, role });
        if (!validation.isValid) {
            return res.status(400).json({ 
                message: 'Validation failed',
                errors: validation.errors
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ 
                message: 'User already exists',
                error: existingUser.email === email ? 'Email already in use' : 'Username already taken'
            });
        }

        // Create new user
        const user = new User({ username, email, password, role });
        await user.save();

        // Generate token
        const token = user.generateAuthToken();

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ 
            message: 'Error creating user', 
            error: error.message 
        });
    }
});

// Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Check if user is active
        if (!user.isActive) {
            return res.status(401).json({ message: 'Account is deactivated' });
        }

        // Check password
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate token
        const token = user.generateAuthToken();

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                lastLogin: user.lastLogin
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            message: 'Error logging in', 
            error: error.message 
        });
    }
});

// Get user profile
app.get('/api/profile', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const decoded = jwt.verify(token, 'your-secret-key');
        const user = await User.findById(decoded.userId).select('-password');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ user });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

// Social Authentication Routes
app.get('/api/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback',
    passport.authenticate('google', { session: false }),
    (req, res) => {
        const token = req.user.generateAuthToken();
        res.redirect(`/auth-success.html?token=${token}`);
    }
);

app.get('/api/auth/github',
    passport.authenticate('github', { scope: ['user:email'] })
);

app.get('/api/auth/github/callback',
    passport.authenticate('github', { session: false }),
    (req, res) => {
        const token = req.user.generateAuthToken();
        res.redirect(`/auth-success.html?token=${token}`);
    }
);

// Handle all other routes by serving index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../Frontend/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});