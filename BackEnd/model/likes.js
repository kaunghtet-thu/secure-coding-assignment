var db = require('./databaseConfig.js');

var likesDB = {
    insertLike: function (fk_liker_id,fk_listing_id, callback) {
        var conn = db.getConnection();

        conn.connect(function (err) {
            if (err) {
                console.log(err);
                return callback(err, null);
            }
            else {
                var sql = 'insert into likes(fk_liker_id,fk_listing_id) values(?,?)';
                conn.query(sql, [fk_liker_id,fk_listing_id], function (err, result) {
                    conn.end();
                    if (err) {
                        console.log("Err: " + err);
                        return callback(err, null);
                    } else {
                        return callback(null, result)
                    }
                })

            }
        })
    },
    deleteLike: function (fk_liker_id,fk_listing_id, callback) {
        var conn = db.getConnection();

        conn.connect(function (err) {
            if (err) {
                console.log(err);
                return callback(err, null);
            }
            else {
                var sql = 'delete from likes where fk_liker_id = ? and fk_listing_id = ?';
                conn.query(sql, [fk_liker_id,fk_listing_id], function (err, result) {
                    conn.end();
                    if (err) {
                        console.log("Err: " + err);
                        return callback(err, null);
                    } else {
                        return callback(null, result)
                    }
                })

            }
        })
    },
    checklike: function (fk_liker_id,fk_listing_id, callback) {
        var conn = db.getConnection();

        conn.connect(function (err) {
            if (err) {
                console.log(err);
                return callback(err, null);
            }
            else {
                var sql = 'select * from likes where fk_liker_id = ? and fk_listing_id='+fk_listing_id;
                conn.query(sql, [fk_liker_id], function (err, result) {
                    conn.end();
                    if (err) {
                        console.log("Err: " + err);
                        return callback(err, null);
                    } else {
                        return callback(null, result)
                    }
                })

            }
        })
    },
    getLike: function (fk_listing_id, callback) {
        var conn = db.getConnection();

        conn.connect(function (err) {
            if (err) {
                console.log(err);
                return callback(err, null);
            }
            else {
                var sql = 'select * from likes where fk_listing_id = ?';
                conn.query(sql, [fk_listing_id], function (err, result) {
                    conn.end();
                    if (err) {
                        console.log("Err: " + err);
                        return callback(err, null);
                    } else {
                        return callback(null, result)
                    }
                })

            }
        })
    },
}

module.exports = likesDB;