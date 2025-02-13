var db = require('../model/databaseConfig.js');
var config = require('../config.js');
var jwt = require('jsonwebtoken');
var express = require('express');
var bodyParser = require('body-parser');
var app = express();
var user = require('../model/user.js');
var listing = require('../model/listing');
var offers = require('../model/offer');
var likes = require('../model/likes');
var images = require('../model/images')
var verifyToken = require('../auth/verifyToken.js');
const fs = require("fs");
const morgan = require("morgan");
const rfs = require("rotating-file-stream");

const validatorFn  = require('../validator/validatorFn.js');

var path = require("path");
var multer = require('multer')

var cors = require('cors');//Just use(security feature)

var urlencodedParser = bodyParser.urlencoded({ extended: false });

app.options('*', cors());//Just use
app.use(cors());//Just use
app.use(bodyParser.json());
app.use(urlencodedParser);

const logStream = rfs.createStream("access.log", {
  interval: "1d", // Rotate daily
  path: "./logs",
});
// Define a custom Morgan token for login attempts
morgan.token('login-attempt', (req, res) => {
  if (req.originalUrl === '/user/login' && req.method === 'POST') {
    const email = req.body.email || 'unknown';
    const status = res.statusCode;
    const success = status === 200 ? 'SUCCESS' : 'FAILURE';
    return `LOGIN_ATTEMPT: ${email} - ${success} - Status: ${status}`;
  }
  return '';
});
// Configure Morgan to use the custom token
app.use(morgan(':method :url :status :res[content-length] - :response-time ms :login-attempt', {
  stream: logStream,
}));

// Configure Morgan to use the custom token

app.use(express.json());
// app.use(morgan("combined", { stream: logStream }));

const failedLoginAttempts = {}; // { email: { count, lockedUntil } }

// Check if an email is locked
const isEmailLocked = (email) => {
  const record = failedLoginAttempts[email];
  return record && record.lockedUntil && Date.now() < record.lockedUntil;
};

// Function to log failed attempts
const logLoginAttempt = (email, success, message) => {
  console.log(`[LOGIN] Email: ${email}, Success: ${success}, Message: ${message}`);
};

// User login route
app.post("/user/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  if (isEmailLocked(email)) {
    const lockoutTimeRemaining = Math.ceil((failedLoginAttempts[email].lockedUntil - Date.now()) / 1000);
    const message = `Account is temporarily locked. Try again in ${lockoutTimeRemaining} seconds.`;
    logLoginAttempt(email, false, message);
    return res.status(423).json({ message, lockout: true, lockoutTimeRemaining });
  }

  user.loginUser(email, password, (err, token, result) => {
    if (err) {
      failedLoginAttempts[email] = failedLoginAttempts[email] || { count: 0, lockedUntil: null };
      failedLoginAttempts[email].count++;

      if (failedLoginAttempts[email].count > 5) {
        failedLoginAttempts[email].lockedUntil = Date.now() + 30 * 1000;
        const message = "Too many failed attempts. Locked for 30s.";
        logLoginAttempt(email, false, message);
        return res.status(403).json({ message, lockout: true, lockoutTimeRemaining: 30 });
      }

      const message = "Invalid credentials.";
      logLoginAttempt(email, false, message);
      return res.status(401).json({ message });
    }

    // Reset failure count on successful login
    delete failedLoginAttempts[email];
    delete result[0]['password']; // Clear the password in JSON
    console.log(`🚀 ~ res.status ~ result:`, result);

    const message = "You are successfully logged in!";
    logLoginAttempt(email, true, message);
    res.json({ success: true, UserData: JSON.stringify(result), token: token, status: message });
  });
});

// Read logs every minute to detect failed login attempts
const detectFailedLogins = () => {
  fs.readFile("./logs/access.log", "utf8", (err, data) => {
    if (err) return console.error("Error reading logs:", err);

    const failedAttempts = (data.match(/401/g) || []).length;
    console.log(`Detected ${failedAttempts} failed login attempts.`);
  });
};

setInterval(detectFailedLogins, 60 * 1000);

app.post('/user', function (req, res) {//Create User
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;
  var profile_pic_url = req.body.profile_pic_url
  var role = req.body.role

  user.addUser(username, email, password, profile_pic_url, role, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(201).json({ success: true, result });
    }	
  });	
});	

app.post('/user/logout', function (req, res) {//Logout
  console.log("..logging out.");
  res.clearCookie('session-id'); //clears the cookie in the response
  res.setHeader('Content-Type', 'application/json');
  res.json({ success: true, status: 'Log out successful!' });
});

app.put('/user/update/', verifyToken, function (req, res) {//Update user info
  var id = req.id
  var username = req.body.username;
  var firstname = req.body.firstname;
  var lastname = req.body.lastname;
  user.updateUser(username, firstname, lastname, id, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(200).json({ success: true });
    }
  });
});

//Listing APIs
app.post('/listing/', verifyToken, validatorFn.validateListingInputData, function (req, res) {//Add Listing
  var title = req.body.title;
  var category = req.body.category;
  var description = req.body.description;
  var price = req.body.price;
  var fk_poster_id = req.id;
  listing.addListing(title, category, description, price, fk_poster_id, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(201).json({ success: true, id: result.insertId });
    }
  });
});

app.get('/user/listing', verifyToken, function (req, res) {//Get all Listings of the User
  var userid = req.id;
  listing.getUserListings(userid, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(200).json({ success: true, result });
    }
  });
});

app.get('/listing/:id', function (req, res) {//View a listing
  var id = req.params.id
  listing.getListing(id, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(200).json({ success: true, result });
    }
  });
});

app.get('/search/:query', verifyToken, function (req, res) {//View all other user's listing that matches the search
  var query = req.params.query;
  var userid = req.id;
  listing.getOtherUsersListings(query, userid, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(200).json({ success: true, result });
    }
  });
});

app.put('/listing/update/', function (req, res) {//View a listing
  var title = req.body.title;
  var category = req.body.category;
  var description = req.body.description;
  var price = req.body.price;
  var id = req.body.id;
  listing.updateListing(title, category, description, price, id, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(200).json({ success: true });
    }
  });
});

app.delete('/listing/delete/', function (req, res) {//View a listing
  var id = req.body.id;

  listing.deleteListing(id, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(200).json({ success: true });
    }
  });
});

//Offers API
app.post('/offer/', verifyToken, function (req, res) {//View a listing
  var offer = req.body.offer;
  var fk_listing_id = req.body.fk_listing_id;
  var fk_offeror_id = req.id;
  var status = "pending";
  offers.addOffer(offer, fk_listing_id, fk_offeror_id, status, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(201).json({ success: true });
    }
  });
});

app.get('/offer/', verifyToken, function (req, res) {//View all offers
  var userid = req.id
  offers.getOffers(userid, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(201).json({ success: true, result });
    }
  });
});

app.post('/offer/decision/', function (req, res) {//View all offers
  var status = req.body.status;
  var offerid = req.body.offerid;
  offers.AcceptOrRejectOffer(status, offerid, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(201).json({ success: true });
    }
  });
});

app.get('/offer/status/', verifyToken, function (req, res) {//View all offers
  var userid = req.id
  offers.getOfferStatus(userid, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(201).json({ success: true, result });
    }
  });
});

//Likes API
app.post('/likes/', verifyToken, function (req, res) {//View all offers
  var userid = req.id
  var listingid = req.body.listingid;
  likes.insertLike(userid, listingid, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(201).json({ success: true });
    }
  });
});

app.get('/likeorunlike/:listingid/', verifyToken, function (req, res) {//Like or Unlike
  var userid = req.id
  var listingid = req.params.listingid;
  likes.checklike(userid, listingid, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(200);
      if (result.length == 0) {
        likes.insertLike(userid, listingid, function (err, result) {
          if (err) {
            res.status(500).json({ success: false, message: err.message });
          } else {
            res.status(201).json({ success: true, action: "liked" });
          }
        });
      } else {
        likes.deleteLike(userid, listingid, function (err, result) {
          if (err) {
            res.status(500).json({ success: false, message: err.message });
          } else {
            res.status(200).json({ success: true, action: "unliked" });
          }
        });
      }
    }
  });
});

app.get('/likes/:listingid/', function (req, res) {//View all offers
  var listingid = req.params.listingid;
  likes.getLike(listingid, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(200).json({ success: true, amount: result.length });
    }
  });
});

//Images API

let storage = multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, __dirname + "/../public")
  },
  filename: function (req, file, cb) {
    req.filename = file.originalname.replace(path.extname(file.originalname), '') + '-' + Date.now() + path.extname(file.originalname);
    cb(null, req.filename);
  }
});

let upload = multer({
  storage: storage, limits: { fileSize: 5 * 1024 * 1024 }
});//limits check if he file size is equal to or below 5mb

app.post('/images/:fk_product_id/', upload.single('myfile'), function (req, res) {
  var fk_product_id = req.params.fk_product_id;
  var name = req.filename;
  images.uploadImage(name, fk_product_id, function (err, result) {
    if (err) {
      res.status(500).json({ success: false, message: err.message });
    } else {
      res.status(201).json({ success: true });
    }
  });
});

module.exports = app;