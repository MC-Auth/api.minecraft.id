const util = require("../util");
const pinger = require("minecraft-pinger");
const crypto = require("crypto-js");
const Request = require("../db/schemas/request").model;
const AuthLog = require("../db/schemas/authlog").model;

module.exports = function (express, config) {
    let router = express.Router();

    router.post("/usernameCheck", function (req, res) {
        let username = req.body.username;
        util.checkUsername(username).then((uuid) => {
            res.json({
                valid: true,
                username: username,
                uuid: uuid
            })
        }).catch(() => {
            res.json({
                valid: false,
                username: username,
                uuid: null
            })
        })
    });

    router.get("/serverStatus", function (req, res) {
        let info = {
            online: false
        };

        pinger.ping("server.minecraft.id", 25565, (err, result) => {
            console.log(result);

            res.json(info);
        });
    });

    return router;
};
