const util = require("../util");
const crypto = require("crypto-js");
const {authStart, authStatus} = require("./authFunctions");
const Request = require("../db/schemas/request").model;
const AuthLog = require("../db/schemas/authlog").model;
const Authentication = require("../db/schemas/authentication").model;

module.exports = function (express, config) {
    let router = express.Router();

    router.get("/start/:username", function (req, res) {
        let username = req.params.username;
        if (!username) {
            res.status(400).json({error: "Missing username"});
            return;
        }
        let callback = req.query.callback;
        if (!callback || !callback.startsWith("http")) {
            res.status(400).json({error: "Missing callback URL"})
            return;
        }
        let style = req.query.style || "default";

        function startNewAuth() {
            let requestId = "mca" + String(crypto.SHA1(username + "" + Date.now() + Math.random()));
            let requestSecret = "mcas" + username + config.gatewaySecret;

            authStart(requestId, requestSecret, callback, req.realAddress, username, true).catch((err) => {
                res.redirect(callback + "?mcauth_success=false&mcauth_status=ERROR&mcauth_msg=" + err.error);
            }).then((result) => {
                res.redirect("/auth/authorize/" + result.id + "?request_id=" + result.request_id + "&username=" + result.username + "&style=" + style);
            })
        }

        let tokenCookie = req.cookies["mcauth_token"];
        if (tokenCookie) {
            Authentication.findOne({username: username, token: util.base64decode(tokenCookie)}, function (err, authentication) {
                if (err) return console.error(err);
                if (!authentication) {
                    startNewAuth();
                } else {
                    let code = String(crypto.SHA256(Math.random() + "" + authentication.username + "" + authentication.uuid + Date.now()));

                    authentication.code = code;
                    authentication.updatedAt = new Date();
                    authentication.save(function (err) {
                        if (err) return console.error(err);

                        res.redirect(callback + "?mcauth_success=true&mcauth_status=VERIFIED&mcauth_msg=Code Renewed&mcauth_code=" + code);
                    })
                }
            })
        } else {
            startNewAuth();
        }


    });

    router.get("/__callback", function (req, res) {
        let id = req.query.id;
        let requestId = req.query.rid;
        let code = req.query.c;
        let username = req.query.u;

        if (requestId && !requestId.startsWith("mca")) {
            res.status(403).end();
            return;
        }

        let requestSecret = "mcas" + username + config.gatewaySecret;

        authStatus(id, requestId, requestSecret, code, true).catch((err) => {
            res.status(err.code).json(err);
        }).then((result) => {
            let actualCallback = result.callback;

            if (result.status !== "VERIFIED") {
                res.redirect(actualCallback + "?mcauth_success=false&mcauth_status=NOT_VERIFIED&mcauth_msg=" + result.fail_reason);
            } else {
                let token = String(crypto.SHA1(Math.random() + "" + result.username + "" + Date.now() + Math.random())) + String(crypto.SHA512(Math.random() + "" + result.username + Date.now() + result.uuid + Math.random()));
                let code = String(crypto.SHA256(Math.random() + "" + result.username + "" + result.uuid + Date.now()));

                let authentication = new Authentication({
                    username: result.username,
                    uuid: result.uuid,
                    token: token,
                    code: code,
                    updatedAt: new Date()
                });
                authentication.save(function (err) {
                    if (err) return console.error(err);

                    let expires = new Date(Date.now() + 2.628e+9);
                    res.cookie("mcauth_token", util.base64encode(token), {expires: expires, domain: ".minecraft.id", path: "/", secure: true});
                    res.redirect(actualCallback + "?mcauth_success=true&mcauth_status=VERIFIED&mcauth_msg=Verified&mcauth_code=" + code);
                })
            }
        });
    });


    router.post("/verify/:username", function (req, res) {
        let username = req.params.username;
        let code = req.body.code;
        if (!code) {
            res.status(400).json({error: "Missing code"})
            return;
        }

        Authentication.findOne({username: username, code: code}, function (err, authentication) {
            if (err) return console.error(err);
            if (!authentication) {
                res.json({
                    valid: false,
                    username: username
                })
            } else {
                authentication.code = undefined;
                authentication.save(function (err) {
                    if (err) return console.error(err);
                    res.json({
                        valid: true,
                        username: authentication.username,
                        uuid: authentication.uuid
                    })
                })
            }
        })
    });

    return router;
};
