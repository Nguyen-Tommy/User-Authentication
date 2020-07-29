// User Authentication
// Local web server application, hash passwords with bcrypt, authenticate using passport, stores users in an array

'use strict';

// Load environment variables if not production mode
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// Import packages as variables 
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');

// Import and initialize passport configurations
const initializePassport = require('./passport-config');
initializePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
);

const users = [];

app.set('view-engine', 'ejs');

// Use package variables
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

// Render index page with user name if authenticated 
app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name })
});

// Render login page 
app.get('/login', (req, res) => {
    res.render('login.ejs');
});

// Login page authentication response
app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

// Render register page 
app.get('/register', (req, res) => {
    res.render('register.ejs');
});

// Register page add new user with encrypted password
app.post('/register', async (req, res) => {
    try {

        // Get encrypted password with salt
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        // Add new user to array
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        });
        res.redirect('/login');
    } catch {
        res.redirect('/register');
    }
});

// Logout of application 
app.delete('/logout', (req, res) => {
    req.logOut();
    res.redirect('/login');
});

// Check if user is authenticated
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

// Check if user is not authenticated
function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    next();
}

app.listen(process.env.PORT || '3000', () => {
    console.log(`Server is running on port: ${process.env.PORT || '3000'}`);
});
