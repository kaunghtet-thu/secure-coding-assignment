const express = require('express');
const rateLimit = require('express-rate-limit');
const iptables = require('iptables');
const morgan = require('morgan');
const rfs = require('rotating-file-stream');
const path = require('path');
const db = require('./databaseConfig.js');
const config = require('../config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();

// Logging setup
const logStream = rfs.createStream('access.log', {
    interval: '1d', // rotate daily
    path: path.join(__dirname, 'log')
});

app.use(morgan('combined', { stream: logStream }));

// Rate limiting middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    handler: function (req, res, next) {
        const ip = req.ip;
        blockIP(ip);
        res.status(429).send('Too many failed login attempts. Your IP has been blocked.');
    }
});

// Block IP using iptables
function blockIP(ip) {
    iptables.newChain('BLOCKED_IPS', function (err) {
        if (err) throw err;

        iptables.insertRule('INPUT', 1, ['-s', ip, '-j', 'DROP'], function (err) {
            if (err) throw err;
            console.log(`Blocked IP: ${ip}`);
        });
    });
}

// Apply rate limiting to login route
app.use('/login', limiter);

// Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    userDB.loginUser(email, password, (err, token, result) => {
        if (err) {
            res.status(401).json({ message: 'Login failed', error: err.message });
        } else {
            res.status(200).json({ token, user: result });
        }
    });
});

// UserDB module (as provided)
var userDB = {
    loginUser: function (email, password, callback) {
        var conn = db.getConnection();

        conn.connect(function (err) {
            if (err) {
                console.log(err);
                return callback(err, null, null);
            } else {
                console.log("Connected!");

                var sql = 'SELECT * FROM users WHERE email = ?';
                conn.query(sql, [email], async function (err, result) {
                    conn.end();

                    if (err) {
                        console.log("Err: " + err);
                        return callback(err, null, null);
                    }

                    if (result.length === 1) {
                        const user = result[0];

                        // Compare the hashed password stored in the database with the input password
                        const match = await bcrypt.compare(password, user.password);

                        if (match) {
                            // Generate JWT token
                            const token = jwt.sign({ id: user.id }, config.key, {
                                expiresIn: 86400 // Expires in 24 hours
                            });

                            console.log("@@token " + token);
                            return callback(null, token, result);
                        } else {
                            console.log("Incorrect password");
                            return callback(new Error("Email/Password does not match."), null, null);
                        }
                    } else {
                        console.log("User not found");
                        return callback(new Error("Email/Password does not match."), null, null);
                    }
                });
            }
        });
    },

    updateUser: function (username, firstname, lastname, id, callback) {
        var conn = db.getConnection();
        conn.connect(function (err) {
            if (err) {
                console.log(err);
                return callback(err, null);
            } else {
                console.log("Connected!");

                var sql = "update users set username = ?,firstname = ?,lastname = ? where id = ?;";

                conn.query(sql, [username, firstname, lastname, id], function (err, result) {
                    conn.end();

                    if (err) {
                        console.log(err);
                        return callback(err, null);
                    } else {
                        console.log("No. of records updated successfully: " + result.affectedRows);
                        return callback(null, result.affectedRows);
                    }
                })
            }
        })
    },

    addUser: function (username, email, password, firstname, lastname, callback) {
        console.log(firstname, lastname)
        var conn = db.getConnection();

        conn.connect(async function (err) {
            if (err) {
                console.log(err);
                return callback(err, null);
            } else {
                console.log("Connected!");

                try {
                    // Hash password before storing
                    const hashedPassword = await bcrypt.hash(password, saltRounds);

                    var sql = "INSERT INTO users(username, email, password, firstname, lastname) VALUES (?, ?, ?, ?, ?)";
                    conn.query(sql, [username, email, hashedPassword, firstname, lastname], function (err, result) {
                        conn.end();

                        if (err) {
                            console.log(err);
                            return callback(err, null);
                        } else {
                            return callback(null, result);
                        }
                    });
                } catch (hashErr) {
                    console.log(hashErr);
                    return callback(hashErr, null);
                }
            }
        });
    }
};

module.exports = userDB;