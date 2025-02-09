var db = require('./databaseConfig.js');
var config = require('../config.js');
var jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); // Import bcrypt
const saltRounds = 10; // Define salt rounds

var userDB = {

	// Old Login 
	// loginUser: function (email, password, callback) {

	// 	var conn = db.getConnection();

	// 	conn.connect(function (err) {
	// 		if (err) {
	// 			console.log(err);
	// 			return callback(err, null);
	// 		}
	// 		else {
	// 			console.log("Connected!");

	// 			var sql = 'select * from users where email = ? and password=?';
	// 			conn.query(sql, [email, password], function (err, result) {
	// 				conn.end();

	// 				if (err) {
	// 					console.log("Err: " + err);
	// 					return callback(err, null, null);

	// 				} else {
	// 					var token = "";

	// 					if (result.length == 1) {
	// 						token = jwt.sign({ id: result[0].id }, config.key, {
	// 							expiresIn: 86400 //expires in 24 hrs
	// 						});
	// 						console.log("@@token " + token);
	// 						return callback(null, token, result);
	// 					} //if(res)
	// 					else {
	// 						console.log("email/password does not match");
	// 						var err2 = new Error("Email/Password does not match.");
	// 						err2.statusCode = 404;
	// 						console.log(err2);
	// 						return callback(err2, null, null);
	// 					}
	// 				}  //else
	// 			});
	// 		}
	// 	});
	// },
	// Update login 
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
							return callback(null, token, user);
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