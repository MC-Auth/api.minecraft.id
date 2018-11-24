const util = require("../util");
const pinger = require("minecraft-pinger");
const crypto = require("crypto-js");
const Request = require("../db/schemas/request").model;
const AuthLog = require("../db/schemas/authlog").model;

module.exports = function (express, config) {
    let router = express.Router();

    router.get("/",function (req,res) {
       Request.count({},function (err,count) {
           res.json({
               pendingRequests:count
           })
       })
    });

    return router;
};