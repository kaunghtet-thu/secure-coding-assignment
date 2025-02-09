var db = require('./databaseConfig.js');

var imagesDB = {
    uploadImage: function (name,fk_product_id, callback) {
        var dbConn = db.getConnection();
        dbConn.connect(function (err) {
            if (err) {
                console.log(err);
                return callback(err, null);
            } else {
                var sql = "insert into images(name,fk_product_id) values(?,?)";
                dbConn.query(sql, [name,fk_product_id], function (err, result) {
                    dbConn.end()
                    if (err) {
                        console.log(err);
                        return callback(err, null);
                    } else {
                        return callback(null, result)
                    }
                });
            }

        })
    },
}

module.exports = imagesDB;