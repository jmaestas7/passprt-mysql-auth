// load all the things we need
var LocalStrategy = require('passport-local').Strategy;

// load up the user model
var User = require('../app/models/user');

//load mysql package, load connection config, create db connection
var mysql = require('mysql');
var dbconfig = require('./database');
connection = mysql.createConnection(dbconfig.config);
connection.connect(function (err) {
    if (err) {
        console.error('error connecting: ' + err.stack);
        return;
    }
    console.log('connected as id ' + connection.threadId);
});

module.exports = function (passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function (user, done) {
        console.log(user);
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function (id, done) {
        connection.query("SELECT * FROM core_user WHERE id = ?", id, function (err, rows) {
            done(err, rows[0]);
        });
    });

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    passport.use(
        'local-login',
        new LocalStrategy({
            // by default, local strategy uses username and password, we will override with email
            usernameField: 'email',
            passwordField: 'password',
            passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
        },
            function (req, email, password, done) {
                if (email)
                    email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching
                console.log("Email: " + email +
                    "\nPassword: " + password);
                // asynchronous
                process.nextTick(function () {
                    connection.query("SELECT * FROM core_user WHERE email = ?", email, function (err, rows) {
                        // if there are any errors, return the error
                        if (err) {
                            console.log('Error: ' + err);
                            return done(err);
                        }
                        // if no user is found, return the message
                        if (!rows[0]) {
                            console.log('No user found');
                            return done(null, false, req.flash('loginMessage', 'No user found.'));
                        }
                        // if password is wrong but email is correct
                        if (!User.validPassword(password, rows[0].password)) {
                            console.log('Wrong password');
                            return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));
                        }
                        // all is well, return user
                        else {
                            console.log("Login successful!");
                            return done(null, rows[0]);
                        }
                    });
                });
            }));

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
        function (req, email, password, done) {
            if (email)
                email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching
            // asynchronous
            process.nextTick(function () {
            // if the user is not already logged in:
                if (!req.user) {
                    connection.query("SELECT * FROM core_user WHERE email = ?", email, function (err, rows) {
                        // if there are any errors, return the error
                        if (err) {
                            return done(err);
                        }
                        // check to see if theres already a user with that email
                        if (rows[0]) {
                            return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
                        } else {

                            // create the user
                            var newUser = User;
                            newUser.email = email;
                            newUser.password = newUser.generateHash(password);

                            // insert user into databaes
                            var insertQuery = "INSERT INTO core_user ( email, password ) VALUES (?,?)";
                            connection.query(insertQuery, [newUser.email, newUser.password], function (err) {
                                if (err) {
                                    return done(err);
                                }
                                else {
                                    // query newly created user from email
                                    connection.query("SELECT * FROM core_user WHERE email = ?", email, function (err, rows) {
                                        if (err) {
                                            return done(err);
                                        }
                                        var user = rows[0];
                                        return done(null, user);
                                    });
                                }
                            });
                        }
                    });
                    // if the user is logged in but has no local account...
                }
                // else if (!req.user.email) {
                //     // ...presumably they're trying to connect a local account
                //     // BUT let's check if the email used to connect a local account is being used by another user
                //     connection.query("SELECT * FROM core_user WHERE email = ?", [email], function (err, rows) {
                //         if (err)
                //             return done(err);

                //         if (rows[0]) {
                //             return done(null, false, req.flash('loginMessage', 'That email is already taken.'));
                //             // Using 'loginMessage instead of signupMessage because it's used by /connect/local'
                //         } else {
                //             var user = rows[0];
                //             user.email = email;
                //             user.password = user.generateHash(password);

                //             var insertQuery = "INSERT INTO core_user ( email, password ) VALUES (?,?)";
                //             connection.query(insertQuery, [user.email, user.password], function (err) {
                //                 if (err)
                //                     return done(err);
                //                 return done(null, user);
                //             });
                //         }
                //     });
                // }
                else {
                    // user is logged in and already has a local account. Ignore signup. (You should log out before trying to create a new account, user!)
                    return done(null, req.user);
                }
            });
        }));
};
