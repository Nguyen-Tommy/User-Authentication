// Passport configuration
// Authenticate user's inputs locally

'use strict';

// Import packages as variables
const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt');

// Initialize authentication
function initialize(passport, getUserByEmail, getUserById) {
    const authenticateUser = async (email, password, done) => {
        const user = getUserByEmail(email);

        // User not found
        if (user == null) {
            return done(null, false, { message: 'No user with that email' });
        }
        try {

            // Compare user input with user password 
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Password incorrect' });
            }
        } catch (e) {
            return done(e);
        }
    }

    // Use local strategy, de/serialize user
    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))
    passport.serializeUser((user, done) => done(null, user.id))
    passport.deserializeUser((id, done) => {
        return done(null, getUserById(id));
    });
}

module.exports = initialize;
