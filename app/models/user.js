// app/models/user.js
// load the things we need
var bcrypt = require('bcrypt-nodejs');

// define the schema for our user constructor
var user = {
    email: '',
    password: ''
};

// methods ======================
// generating a hash
user.generateHash = function (password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

// checking if password is valid
user.validPassword = function (password, crypt) {
    return bcrypt.compareSync(password, crypt);
};

// create the model for users and expose it to our app
module.exports = user;